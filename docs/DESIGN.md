# keycraft design

Short sentences. The delegate and the stack under it are `../datacraft`
and `../../freenet/*`, cited not repeated.

## 1. Why one app

Every distributed network separates the wallet from the apps: keys live in
one place, apps ask it to sign. Before keycraft each craftworks app had its
own Keys screen (generate, import, export) and a key-set dropdown; a person
saw keys everywhere and identity nowhere. Now:

| Where | Shows | Can do |
|---|---|---|
| keycraft | every identity on this node, its owner key, its drive and databases | create, import, export, rename, remove |
| any other app | the current identity's name in the header; a menu to switch when there are several | pick one; on first run, create one by name (onboarding, not key management) |

## 2. Screens

- **Identities**: one card per identity: name, owner key, what it owns
  (drive seq, the databases mounted in it), Show keys / Rename / Remove.
  Communities a person runs (key sets whose drive is marked `community`)
  are listed apart, never as someone to log in as.
- **Add**: create (a name), or import from another device (the keys shown
  by Show keys there). A store key alone imports read-only.
- **About**: the node, the delegate address, the log.

## 3. What the delegate allows

The keys delegate (`938BBXKobVtwM2Yxey4D2pGEXojEMbXZUrxZLTtjS1RT`) is
frozen: a changed byte is a new delegate with an empty store. Its requests
are Generate, Import, Export, List, StoreKey, Sign, Remove. So:

- **Rename** is export, import under the new name, remove the old. Keys,
  owner and everything on the network are unchanged; only the label on this
  node changes.
- **Remove** forgets the keys on this node. The data stays on the network;
  without a copy of the signing key nothing signed by that identity can be
  changed again. The page asks for the name to be typed.
- The label "home" on an existing key set is only the old default of the
  Generate box. Rename it. The identity's drive is a database named `home`
  inside its own address, and that name stays internal: pages say "drive"
  and "<name>'s files".

## 4. Next: typed keys (a v2 delegate)

One identity today is ed25519 + a 32-byte store key. Wanted: several key
kinds under one name, so an identity can also be a Solana account (ed25519,
the same curve: the identity key *is* a Solana address), an Ethereum
account (secp256k1), or a store-only key for shared data.

Because v1 is frozen, keycraft ships a v2 delegate owned by this repo:

```
KeyRecord { name, kind: Ed25519 | Secp256k1 | Store, public: bytes, created_at, label }
Request: Generate{name, kind}, Import{name, kind, secret}, Export, List, Sign{name, kind, msg}, Remove, Rename
```

keycraft talks to both delegates: v1 for what exists, v2 for new kinds, and
"Migrate" copies a v1 set into v2 (export, import) and removes it from v1.
Apps keep signing through craftworks-page `Keys`, which learns to look in
v2 first. Not before the accounts model has settled in every app.

## 5. Next: usage history

Which apps an identity has used, and when, recorded where it follows the
identity: in its drive, not in the delegate (frozen, and per node).

- **What it owns** already says which apps created data: `papercraft` →
  papercraft, `social` → Dot/Grid, `/files` → filecraft.
- **Last used**: an xattr `craftworks.used.<app>` = unix time on the drive
  root, written by the app on open at most once a day (one small commit).
  keycraft lists apps by last use. A device that imports the keys sees the
  same history.

## 6. Next: the browser extension

Keys portable across devices without pasting hex:

- A Chrome (MV3) extension holds a key store encrypted under a passphrase
  in `chrome.storage.sync`, so the browser profile carries it between
  devices; a passphrase-encrypted keyfile is the export.
- A content script on craftworks pages exposes `window.craftworksKeys`
  (list, import-into-node, export-from-node) by `postMessage`; keycraft
  shows "Save to extension" and "Load from extension" beside each identity,
  and any node's delegate can be filled from the extension in one click.
- The node's delegate stays the signer; the extension is a carrier. Pages
  never see a signing key from either.
