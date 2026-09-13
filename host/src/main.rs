//! keycraft-host: what a node on this machine holds, decrypted with the
//! node's own key. Freenet keeps every delegate's secrets under
//! `<data-dir>/secrets/<delegate>/<blake3(key)>`, each file
//! `[0x01][24-byte XNonce][XChaCha20-Poly1305]` under a per-delegate key
//! derived from `<data-dir>/secrets/node_kek` (HKDF-SHA256, salt = the
//! delegate's bs58 address, info "freenet-delegate-dek-v1"). The machine's
//! owner can read their own disk; this is that, as a program the keycraft
//! extension can launch (Chrome native messaging) or a person can run.
//!
//!   keycraft-host list [--data-dir DIR] [--values]   every delegate, decoded where known; --values dumps other delegates' secrets
//!   keycraft-host install <extension id>      register as a native messaging host for Chrome
//!   keycraft-host export <delegate> --password P --out FILE [--data-dir DIR]
//!                                             a delegate's whole scope, sealed, as a bundle file
//!   keycraft-host import FILE --password P [--data-dir DIR]
//!                                             the bundle into this node's store, under this node's key
//!   (no arguments, stdin)                     native messaging: one JSON request per message
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

/// The craftworks keys delegate: `ks-index/user` names the sets, `ks/user/<name>`
/// is `[can_sign][signing 32][store 32]`.
const CRAFTWORKS_DELEGATE: &str = "938BBXKobVtwM2Yxey4D2pGEXojEMbXZUrxZLTtjS1RT";
const DEK_INFO: &[u8] = b"freenet-delegate-dek-v1";
const HOST_NAME: &str = "com.craftworks.keycraft";

#[derive(Serialize)]
struct Identity {
    name: String,
    owner: String,
    store_key: String,
    signing_key: String,
}

/// A River room's signing key: `signing_key:<origin bs58>:<room bs58>` → 32 bytes.
#[derive(Serialize)]
struct RiverRoom {
    origin: String,
    room: String,
    signing_key: String,
}

#[derive(Serialize)]
struct Delegate {
    address: String,
    kind: &'static str,
    /// craftworks: decoded identities
    identities: Vec<Identity>,
    /// River's chat delegate: one per room with a signing key
    river_rooms: Vec<RiverRoom>,
    /// any delegate: raw secrets by name when the name registry is readable, else by hash
    secrets: BTreeMap<String, String>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn dek(kek: &[u8; 32], delegate_bs58: &str) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(Some(delegate_bs58.as_bytes()), kek);
    let mut okm = [0u8; 32];
    hk.expand(DEK_INFO, &mut okm).expect("32-byte okm");
    XChaCha20Poly1305::new((&okm).into())
}

fn open_blob(cipher: &XChaCha20Poly1305, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() >= 25 && blob[0] == 0x01 {
        let nonce = XNonce::from_slice(&blob[1..25]);
        if let Ok(pt) = cipher.decrypt(nonce, &blob[25..]) {
            return Some(pt);
        }
    }
    // pre-nonce files: raw ciphertext under an all-zero nonce
    cipher.decrypt(XNonce::from_slice(&[0u8; 24]), blob).ok()
}

fn secret_file(dir: &Path, key: &[u8]) -> PathBuf {
    dir.join(bs58::encode(blake3::hash(key).as_bytes()).into_string())
}

fn read_secret(dir: &Path, cipher: &XChaCha20Poly1305, key: &[u8]) -> Option<Vec<u8>> {
    let blob = std::fs::read(secret_file(dir, key)).ok()?;
    open_blob(cipher, &blob)
}

fn craftworks(dir: &Path, cipher: &XChaCha20Poly1305) -> Vec<Identity> {
    let mut out = Vec::new();
    let Some(index) = read_secret(dir, cipher, b"ks-index/user") else {
        return out;
    };
    let names: Vec<String> = datacraft_keys_proto::decode(&index).unwrap_or_default();
    for name in names {
        let Some(v) = read_secret(dir, cipher, format!("ks/user/{name}").as_bytes()) else {
            continue;
        };
        if v.len() != 65 {
            continue;
        }
        let (signing, store) = (&v[1..33], &v[33..65]);
        let can_sign = v[0] == 1;
        let owner = if can_sign {
            hex(ed25519_public(signing).as_ref())
        } else {
            String::new()
        };
        out.push(Identity {
            name,
            owner,
            store_key: hex(store),
            signing_key: if can_sign { hex(signing) } else { String::new() },
        });
    }
    out
}

/// The public key of an ed25519 seed.
fn ed25519_public(seed: &[u8]) -> Vec<u8> {
    let Ok(seed): Result<[u8; 32], _> = seed.try_into() else {
        return Vec::new();
    };
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

/// Every secret file of a delegate by its raw key name: the `.keys`
/// registry (encrypted like the values) is a list of `[u32 LE len][key]`.
fn raw_secrets(dir: &Path, cipher: &XChaCha20Poly1305, values: bool) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    if let Some(pt) = std::fs::read(dir.join(".keys"))
        .ok()
        .and_then(|reg| open_blob(cipher, &reg))
    {
        let mut i = 0;
        while i + 4 <= pt.len() {
            let n = u32::from_le_bytes([pt[i], pt[i + 1], pt[i + 2], pt[i + 3]]) as usize;
            i += 4;
            if i + n > pt.len() {
                break;
            }
            let key = &pt[i..i + n];
            i += n;
            let file = bs58::encode(blake3::hash(key).as_bytes()).into_string();
            let label = match std::str::from_utf8(key) {
                Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
                _ => format!("0x{}", hex(key)),
            };
            names.insert(file, label);
        }
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let fname = e.file_name().to_string_lossy().into_owned();
        if fname.starts_with('.') || e.path().is_dir() {
            continue;
        }
        let Ok(blob) = std::fs::read(e.path()) else {
            continue;
        };
        if let Some(pt) = open_blob(cipher, &blob) {
            let label = names.get(&fname).cloned().unwrap_or(fname);
            out.insert(label, if values { hex(&pt) } else { format!("{} bytes", pt.len()) });
        }
    }
    out
}

/// `values`: include other delegates' secret values (hex). A native-messaging
/// reply is capped at 1 MB by Chrome, so the extension asks without.
fn list(data_dir: &Path, values: bool) -> Result<serde_json::Value, String> {
    let secrets = data_dir.join("secrets");
    let kek_bytes = std::fs::read(secrets.join("node_kek"))
        .map_err(|e| format!("{}: {e}", secrets.join("node_kek").display()))?;
    let kek: [u8; 32] = kek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "node_kek is not 32 bytes".to_string())?;
    let mut delegates = Vec::new();
    for e in std::fs::read_dir(&secrets).map_err(|e| e.to_string())?.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let address = e.file_name().to_string_lossy().into_owned();
        if bs58::decode(&address).into_vec().map(|v| v.len()) != Ok(32) {
            continue; // `local`, `users`, …
        }
        let cipher = dek(&kek, &address);
        let kind = if address == CRAFTWORKS_DELEGATE {
            "craftworks"
        } else {
            "other"
        };
        let identities = if kind == "craftworks" {
            craftworks(&e.path(), &cipher)
        } else {
            Vec::new()
        };
        let secrets = if kind == "craftworks" {
            BTreeMap::new()
        } else {
            raw_secrets(&e.path(), &cipher, values)
        };
        // River rooms: the raw values are needed whatever `values` says
        let river_rooms: Vec<RiverRoom> = raw_secrets(&e.path(), &cipher, true)
            .into_iter()
            .filter_map(|(k, v)| {
                let mut parts = k.strip_prefix("signing_key:")?.splitn(2, ':');
                let origin = parts.next()?.to_string();
                let room = parts.next()?.to_string();
                (v.len() == 64).then_some(RiverRoom {
                    origin,
                    room,
                    signing_key: v,
                })
            })
            .collect();
        let kind = if !river_rooms.is_empty() { "river" } else { kind };
        delegates.push(Delegate {
            address,
            kind,
            identities,
            river_rooms,
            secrets,
        });
    }
    Ok(json!({"data_dir": data_dir.display().to_string(), "delegates": delegates}))
}

// ---- bundles: a delegate's whole scope, moved between nodes as one sealed file.
// {v:1, delegate, from, secrets:[{k,v}]} (base64) → XChaCha20-Poly1305 under
// PBKDF2-HMAC-SHA256(password, salt, 310k). River's delegate is the case in
// hand: its room keys AND its room state travel, and on the other node River
// finds them under the same delegate address (or migrates them, as it does
// across its own releases).
const BUNDLE_MAGIC: &[u8] = b"KCB1";
const BUNDLE_ROUNDS: u32 = 310_000;

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(password).expect("hmac key");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..rounds {
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(password).expect("hmac key");
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

/// Every secret of one delegate scope, decrypted: (raw key, value).
fn scope_secrets(dir: &Path, cipher: &XChaCha20Poly1305) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut names: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    if let Some(pt) = std::fs::read(dir.join(".keys"))
        .ok()
        .and_then(|reg| open_blob(cipher, &reg))
    {
        let mut i = 0;
        while i + 4 <= pt.len() {
            let n = u32::from_le_bytes([pt[i], pt[i + 1], pt[i + 2], pt[i + 3]]) as usize;
            i += 4;
            if i + n > pt.len() {
                break;
            }
            let key = pt[i..i + n].to_vec();
            i += n;
            names.insert(bs58::encode(blake3::hash(&key).as_bytes()).into_string(), key);
        }
    }
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let fname = e.file_name().to_string_lossy().into_owned();
        if fname.starts_with('.') || e.path().is_dir() {
            continue;
        }
        let Some(key) = names.get(&fname) else {
            continue; // a value whose name the registry lost: it cannot be re-keyed by name
        };
        if let Some(pt) = std::fs::read(e.path()).ok().and_then(|b| open_blob(cipher, &b)) {
            out.push((key.clone(), pt));
        }
    }
    out
}

fn node_kek(data_dir: &Path) -> Result<[u8; 32], String> {
    let p = data_dir.join("secrets").join("node_kek");
    let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "node_kek is not 32 bytes".to_string())
}

fn export_bundle(data_dir: &Path, delegate: &str, password: &str) -> Result<(Vec<u8>, usize), String> {
    if bs58::decode(delegate).into_vec().map(|v| v.len()) != Ok(32) {
        return Err("not a delegate address".into());
    }
    let kek = node_kek(data_dir)?;
    let dir = data_dir.join("secrets").join(delegate);
    if !dir.is_dir() {
        return Err(format!("no delegate {delegate} on this node"));
    }
    let cipher = dek(&kek, delegate);
    let secrets = scope_secrets(&dir, &cipher);
    if secrets.is_empty() {
        return Err("that delegate has no readable secrets".into());
    }
    let body = json!({
        "v": 1,
        "delegate": delegate,
        "from": data_dir.display().to_string(),
        "secrets": secrets.iter().map(|(k, v)| json!({"k": b64(k), "v": b64(v)})).collect::<Vec<_>>(),
    })
    .to_string();
    let mut salt = [0u8; 16];
    getrandom_fill(&mut salt);
    let key = pbkdf2_sha256(password.as_bytes(), &salt, BUNDLE_ROUNDS);
    let c = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = c
        .encrypt(&nonce, body.as_bytes())
        .map_err(|_| "seal failed".to_string())?;
    let mut out = Vec::with_capacity(4 + 16 + 24 + ct.len());
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok((out, secrets.len()))
}

fn getrandom_fill(buf: &mut [u8]) {
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(buf);
}

fn open_bundle(bundle: &[u8], password: &str) -> Result<serde_json::Value, String> {
    if bundle.len() < 4 + 16 + 24 + 16 || &bundle[..4] != BUNDLE_MAGIC {
        return Err("not a keycraft bundle".into());
    }
    let key = pbkdf2_sha256(password.as_bytes(), &bundle[4..20], BUNDLE_ROUNDS);
    let c = XChaCha20Poly1305::new((&key).into());
    let pt = c
        .decrypt(XNonce::from_slice(&bundle[20..44]), &bundle[44..])
        .map_err(|_| "wrong password, or a damaged bundle".to_string())?;
    serde_json::from_slice(&pt).map_err(|e| e.to_string())
}

/// Write the bundle's secrets into this node's store under the bundle's
/// delegate address, encrypted with THIS node's key; the name registry is
/// merged. Existing values with the same name are replaced. Returns (delegate, written).
fn import_bundle(data_dir: &Path, bundle: &[u8], password: &str) -> Result<(String, usize), String> {
    let v = open_bundle(bundle, password)?;
    let delegate = v["delegate"].as_str().ok_or("bundle: no delegate")?.to_string();
    if bs58::decode(&delegate).into_vec().map(|v| v.len()) != Ok(32) {
        return Err("bundle: bad delegate address".into());
    }
    let kek = node_kek(data_dir)?;
    let cipher = dek(&kek, &delegate);
    let dir = data_dir.join("secrets").join(&delegate);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // what the registry already names
    let mut names: Vec<Vec<u8>> = scope_secrets(&dir, &cipher).into_iter().map(|(k, _)| k).collect();
    let mut written = 0;
    for e in v["secrets"].as_array().cloned().unwrap_or_default() {
        let k = unb64(e["k"].as_str().unwrap_or_default())?;
        let val = unb64(e["v"].as_str().unwrap_or_default())?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, val.as_slice())
            .map_err(|_| "encrypt failed".to_string())?;
        let mut blob = Vec::with_capacity(25 + ct.len());
        blob.push(0x01);
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ct);
        let path = secret_file(&dir, &k);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &blob).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        if !names.contains(&k) {
            names.push(k);
        }
        written += 1;
    }
    // the registry, re-sealed with every name
    let mut reg = Vec::new();
    for k in &names {
        reg.extend_from_slice(&(k.len() as u32).to_le_bytes());
        reg.extend_from_slice(k);
    }
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, reg.as_slice())
        .map_err(|_| "encrypt failed".to_string())?;
    let mut blob = vec![0x01];
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ct);
    let path = dir.join(".keys");
    let tmp = dir.join(".keys.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok((delegate, written))
}

/// The data directory of a running node on this machine, from its command line.
fn find_data_dir() -> Option<PathBuf> {
    let out = std::process::Command::new("ps")
        .args(["-axo", "args="])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if !line.contains("freenet") || !line.contains("--data-dir") {
            continue;
        }
        // the value runs to the next flag: paths may hold spaces ("Application Support")
        if let Some(rest) = line.split("--data-dir ").nth(1) {
            let value = rest.split(" --").next().unwrap_or(rest).trim();
            if !value.is_empty() {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

fn native_messaging() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        let mut len = [0u8; 4];
        if stdin.lock().read_exact(&mut len).is_err() {
            return;
        }
        let n = u32::from_le_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        if stdin.lock().read_exact(&mut buf).is_err() {
            return;
        }
        let req: serde_json::Value = serde_json::from_slice(&buf).unwrap_or(json!({}));
        let reply = match req["op"].as_str() {
            Some("list") => {
                let dir = req["data_dir"]
                    .as_str()
                    .map(PathBuf::from)
                    .or_else(find_data_dir);
                match dir {
                    Some(d) => match list(&d, req["values"].as_bool().unwrap_or(false)) {
                        Ok(v) => json!({"ok": v}),
                        Err(e) => json!({"error": e}),
                    },
                    None => json!({"error": "no running node found; pass data_dir"}),
                }
            }
            Some("ping") => json!({"ok": {"host": env!("CARGO_PKG_VERSION")}}),
            // a sealed bundle of one delegate's scope, written to a file (a reply is capped at 1 MB)
            Some("export") => {
                let dir = req["data_dir"].as_str().map(PathBuf::from).or_else(find_data_dir);
                let delegate = req["delegate"].as_str().unwrap_or_default().to_string();
                let password = req["password"].as_str().unwrap_or_default().to_string();
                match dir {
                    None => json!({"error": "no running node found; pass data_dir"}),
                    Some(d) if password.len() < 4 => json!({"error": format!("a bundle password is at least 4 characters ({})", d.display())}),
                    Some(d) => match export_bundle(&d, &delegate, &password) {
                        Ok((bytes, n)) => {
                            let out = req["out"].as_str().map(PathBuf::from).unwrap_or_else(|| {
                                let home = std::env::var("HOME").unwrap_or_default();
                                let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                                PathBuf::from(format!("{home}/Downloads/keycraft-{}-{stamp}.bundle", &delegate[..8]))
                            });
                            match std::fs::write(&out, &bytes) {
                                Ok(()) => json!({"ok": {"path": out.display().to_string(), "secrets": n, "bytes": bytes.len()}}),
                                Err(e) => json!({"error": format!("{}: {e}", out.display())}),
                            }
                        }
                        Err(e) => json!({"error": e}),
                    },
                }
            }
            // the bundle's bytes (base64, from the popup's file picker) into this node's store
            Some("import") => {
                let dir = req["data_dir"].as_str().map(PathBuf::from).or_else(find_data_dir);
                let password = req["password"].as_str().unwrap_or_default().to_string();
                match (dir, unb64(req["bundle"].as_str().unwrap_or_default())) {
                    (None, _) => json!({"error": "no running node found; pass data_dir"}),
                    (_, Err(e)) => json!({"error": format!("bundle: {e}")}),
                    (Some(d), Ok(bytes)) => match import_bundle(&d, &bytes, &password) {
                        Ok((delegate, n)) => json!({"ok": {"delegate": delegate, "written": n, "data_dir": d.display().to_string()}}),
                        Err(e) => json!({"error": e}),
                    },
                }
            }
            _ => json!({"error": "unknown op"}),
        };
        let bytes = reply.to_string().into_bytes();
        let _ = stdout.write_all(&(bytes.len() as u32).to_le_bytes());
        let _ = stdout.write_all(&bytes);
        let _ = stdout.flush();
    }
}

fn install(extension_id: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let dirs = if cfg!(target_os = "macos") {
        vec![
            format!("{home}/Library/Application Support/Google/Chrome/NativeMessagingHosts"),
            format!("{home}/Library/Application Support/Chromium/NativeMessagingHosts"),
            format!("{home}/Library/Application Support/Google/Chrome for Testing/NativeMessagingHosts"),
            format!("{home}/Library/Application Support/Microsoft Edge/NativeMessagingHosts"),
        ]
    } else {
        vec![
            format!("{home}/.config/google-chrome/NativeMessagingHosts"),
            format!("{home}/.config/chromium/NativeMessagingHosts"),
        ]
    };
    let manifest = json!({
        "name": HOST_NAME,
        "description": "keycraft: reads the secrets a Freenet node on this machine holds",
        "path": exe.display().to_string(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    });
    let mut first = None;
    for d in dirs {
        let p = Path::new(&d);
        if std::fs::create_dir_all(p).is_err() {
            continue;
        }
        let f = p.join(format!("{HOST_NAME}.json"));
        std::fs::write(&f, serde_json::to_string_pretty(&manifest).unwrap()).map_err(|e| e.to_string())?;
        first.get_or_insert(f);
    }
    first.ok_or_else(|| "no browser directory could be written".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => {
            let dir = args
                .iter()
                .position(|a| a == "--data-dir")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .or_else(find_data_dir);
            let values = args.iter().any(|a| a == "--values");
            match dir.ok_or_else(|| "no running node found; pass --data-dir".to_string()).and_then(|d| list(&d, values)) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        Some("export") => {
            let get = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let delegate = args.get(1).cloned().unwrap_or_default();
            let dir = get("--data-dir").map(PathBuf::from).or_else(find_data_dir);
            let (Some(password), Some(out), Some(dir)) = (get("--password"), get("--out"), dir) else {
                eprintln!("export <delegate> --password P --out FILE [--data-dir DIR]");
                std::process::exit(2)
            };
            match export_bundle(&dir, &delegate, &password) {
                Ok((bytes, n)) => match std::fs::write(&out, &bytes) {
                    Ok(()) => println!("{out}: {n} secrets, {} bytes", bytes.len()),
                    Err(e) => {
                        eprintln!("{out}: {e}");
                        std::process::exit(1)
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        Some("import") => {
            let get = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let file = args.get(1).cloned().unwrap_or_default();
            let dir = get("--data-dir").map(PathBuf::from).or_else(find_data_dir);
            let (Some(password), Some(dir)) = (get("--password"), dir) else {
                eprintln!("import FILE --password P [--data-dir DIR]");
                std::process::exit(2)
            };
            match std::fs::read(&file)
                .map_err(|e| format!("{file}: {e}"))
                .and_then(|b| import_bundle(&dir, &b, &password))
            {
                Ok((delegate, n)) => println!("{n} secrets into {} under {delegate}", dir.display()),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        Some("install") => match args.get(1) {
            Some(id) => match install(id) {
                Ok(p) => println!("installed: {}", p.display()),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            },
            None => {
                eprintln!("install <extension id>");
                std::process::exit(2)
            }
        },
        // Chrome launches the host with its origin (`chrome-extension://…/`) and,
        // on some platforms, `--parent-window=…`: native messaging
        Some(a) if a.starts_with("chrome-extension://") || a.starts_with("--parent-window") => {
            native_messaging()
        }
        Some(_) => {
            eprintln!("keycraft-host list [--data-dir DIR] [--values] | export <delegate> --password P --out FILE | import FILE --password P | install <extension id> | (stdin: native messaging)");
            std::process::exit(2)
        }
        None => native_messaging(),
    }
}
