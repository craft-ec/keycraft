//! keycraft-host: what a node on this machine holds, decrypted with the
//! node's own key. Freenet keeps every delegate's secrets under
//! `<data-dir>/secrets/<delegate>/<blake3(key)>`, each file
//! `[0x01][24-byte XNonce][XChaCha20-Poly1305]` under a per-delegate key
//! derived from `<data-dir>/secrets/node_kek` (HKDF-SHA256, salt = the
//! delegate's bs58 address, info "freenet-delegate-dek-v1"). The machine's
//! owner can read their own disk; this is that, as a program the keycraft
//! extension can launch (Chrome native messaging) or a person can run.
//!
//!   keycraft-host list [--data-dir DIR]       every delegate, decoded where known
//!   keycraft-host install <extension id>      register as a native messaging host for Chrome
//!   (no arguments, stdin)                     native messaging: one JSON request per message
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
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

#[derive(Serialize)]
struct Delegate {
    address: String,
    kind: &'static str,
    /// craftworks: decoded identities
    identities: Vec<Identity>,
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
fn raw_secrets(dir: &Path, cipher: &XChaCha20Poly1305) -> BTreeMap<String, String> {
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
            out.insert(label, hex(&pt));
        }
    }
    out
}

fn list(data_dir: &Path) -> Result<serde_json::Value, String> {
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
            raw_secrets(&e.path(), &cipher)
        };
        delegates.push(Delegate {
            address,
            kind,
            identities,
            secrets,
        });
    }
    Ok(json!({"data_dir": data_dir.display().to_string(), "delegates": delegates}))
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
                    Some(d) => match list(&d) {
                        Ok(v) => json!({"ok": v}),
                        Err(e) => json!({"error": e}),
                    },
                    None => json!({"error": "no running node found; pass data_dir"}),
                }
            }
            Some("ping") => json!({"ok": {"host": env!("CARGO_PKG_VERSION")}}),
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
            match dir.ok_or_else(|| "no running node found; pass --data-dir".to_string()).and_then(|d| list(&d)) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
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
        Some(_) => {
            eprintln!("keycraft-host list [--data-dir DIR] | install <extension id> | (stdin: native messaging)");
            std::process::exit(2)
        }
        None => native_messaging(),
    }
}
