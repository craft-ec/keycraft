# keycraft progress

## Phase 1: the wallet (2026-09-13) — done
- [x] page crate `web/` (`Wallet`: identities, create, import, export, remove, rename = export+import+remove), page with Identities / Add / About; published as `Djf3MSYX28hhtxAY14QNSSYuiBEjeKxMEhZCCYayc4jL`
- [x] keys UI removed from filecraft, papercraft, datacraft (their Rust key methods dropped too); every app's identity menu links to keycraft; filecraft/papercraft have an Account view
- [x] verified live through the Hetzner tunnel: both identities listed with what they own in 5.1 s; rename `home` → `onlyabrak` in 1.5 s (so socialctl on Hetzner now needs `--key-set onlyabrak`)

## Phase 2: wording and usage stamps (2026-09-13) — done
- [x] "home" left every screen (crumb "test2 / files", "drive at seq N"); the drive is still named `home` inside its address
- [x] `Accounts::touch` (craftworks-page): xattr `craftworks.used` = {app: unix} on the drive root, written on open at most once a day; every app stamps; keycraft shows "used by: app · when". Verified live: filecraft stamped test2 in 3.4 s, keycraft showed "used by: filecraft · today"

## Phase 3: typed keys, the v2 delegate (§4) — not started

## Phase 4: the browser extension (§6) — written, NOT exercised
- [x] `extension/`: MV3, AES-GCM store under a PBKDF2 passphrase in `chrome.storage.sync`, unlocked key in `chrome.storage.session`; popup (unlock, list, remove, export/import keyfile); content script bridge `craftworksKeys` with a confirm() before any secret moves; keycraft page shows "In the keycraft extension" with Save to extension / Load into this node
- [ ] load unpacked in Chrome and exercise: unlock, save an identity from keycraft, load it on a second profile/device. The headless test browser cannot load extensions, so nothing here is verified beyond `node --check`
