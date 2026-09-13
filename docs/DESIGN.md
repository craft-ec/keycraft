# keycraft design

Short sentences. The delegate and the stack under it are `../datacraft`
and `../../freenet/*`, cited not repeated.

## 1. Why an extension, not a page

Every distributed network separates the wallet from the apps. A wallet that
is itself a page served by a node has two flaws we hit: its keys live in
that node's secret store (a folder per delegate, readable by nothing else,
and on the Mac node inside a temporary directory), and it cannot see any
other app's delegate. A browser extension has neither: the keys follow the
person's browser profile, and with a native helper it can read everything a
node on the machine holds.

| Where | Shows | Can do |
|---|---|---|
| the extension (popup) | every identity, which apps were allowed | create, rename, remove, export/import a keyfile, scan this machine's node and import what it holds |
| any craftworks app | the current identity's name in the header; a menu to switch | pick one; on first run, create one by name (the extension asks) |
| a node's keys delegate | (fallback when there is no extension) | what it always did |

## 2. The extension

- **Store**: `[{name, owner, store_key, signing_key, created_at}]` as JSON,
  AES-GCM under a key from the passphrase (PBKDF2-SHA256, 310k rounds),
  in `chrome.storage.sync` (≤ 8 KiB: some dozens of identities). The
  unlocked key sits in `chrome.storage.session` for the browser session.
- **Signer**: Ed25519 through WebCrypto (Chrome ≥ 137). A page sends the
  bytes to sign; the seed never leaves the service worker.
- **Page protocol** (content script on `*/v1/contract/web/*` and localhost):
  `window.postMessage({craftworksKeys: {id, op, …}})` →
  `{craftworksKeysReply: {id, ok | error}}`. Ops a page may use: `ping`,
  `list`, `create`, `put`, `get`, `storeKey`, `sign`. The first `storeKey`
  or `sign` of an identity by an app asks the person once (app = the
  contract id in the URL); `get`, `put` and `create` ask every time.
- **Fallback**: `craftworks-page::keys::Keys::install` pings the bridge for
  400 ms; with an answer every call goes to the extension, otherwise to the
  node's delegate as before.

## 3. The native helper

`keycraft-host` (Rust, Chrome native messaging, also a CLI):

- finds the running node's `--data-dir` from `ps`, or takes `--data-dir`;
- reads `secrets/node_kek` (32 bytes), derives each delegate's key
  (HKDF-SHA256, salt = the delegate's bs58 address, info
  `freenet-delegate-dek-v1`), and opens every `secrets/<delegate>/<blake3(key)>`
  file (`[0x01][24-byte XNonce][XChaCha20-Poly1305]`); the `.keys` registry
  (`[u32 LE len][key]…`) gives each secret its name;
- decodes the craftworks delegate (`ks-index/user`, `ks/user/<name>` =
  `[can_sign][seed 32][store 32]`) into identities with their owners; other
  delegates come back as named raw secrets (River: `signing_key:<origin>:<room>`
  and `…:rooms_data`).

The popup's *Scan this machine's node* lists what it found and imports the
craftworks identities. Measured on the Mac node: 2 identities and 9 other
delegates, River's rooms among them.

## 4. Next: typed keys

One identity today is ed25519 + a 32-byte store key. Wanted: several key
kinds under one name, so an identity can also be a Solana account (ed25519,
the same curve: the identity key *is* a Solana address), an Ethereum
account (secp256k1), or a store-only key for shared data.

In the extension a record gains a `kind`; no delegate change is needed:

```
KeyRecord { name, kind: Ed25519 | Secp256k1 | Store, public: bytes, created_at, label }
Request: Generate{name, kind}, Import{name, kind, secret}, Export, List, Sign{name, kind, msg}, Remove, Rename
```

Apps keep signing through craftworks-page `Keys`; a Solana or Ethereum
signer is one more `op`.

## 5. Next: usage history

Which apps an identity has used, and when, recorded where it follows the
identity: in its drive, not in the delegate (frozen, and per node).

- **What it owns** already says which apps created data: `papercraft` →
  papercraft, `social` → Dot/Grid, `/files` → filecraft.
- **Last used**: an xattr `craftworks.used.<app>` = unix time on the drive
  root, written by the app on open at most once a day (one small commit).
  keycraft lists apps by last use. A device that imports the keys sees the
  same history.

## 6. River moves as a bundle

River keeps everything per node in its own delegate scope: a signing key
per room and the room state (50–420 KB each). The extension's synced store
cannot hold that (8 KiB per item), and River's own protocol would need its
CBOR framing and per-release delegate address. So River moves as a file:

- **Export** (popup → helper): every secret of River's delegate scope,
  decrypted with node A's key, as `{v, delegate, from, secrets:[{k, v}]}`
  sealed under a password (PBKDF2-HMAC-SHA256 310k → XChaCha20-Poly1305,
  file `KCB1‖salt‖nonce‖ct`), written to `~/Downloads/keycraft-<delegate>-<time>.bundle`
  because a helper reply is capped at 1 MB.
- **Import** (popup file picker → helper): the bytes go to the helper (a
  request to the host may be large), which re-encrypts each secret with
  node B's key under the same delegate address and merges the name
  registry. The node reads secret files directly, so a running node sees
  them at once. River on node B finds its rooms under that address; a newer
  River migrates them the way it migrates its own older delegates, provided
  that address is in its legacy list.

Measured on the Mac node: 12 secrets (5 rooms), 894 KB bundle; wrong
password refused; import into a scratch store under a different node key
reads back all 12 by name; the native-messaging import request was 1.1 MB.
Not measured: River's UI on a second machine showing the rooms.
