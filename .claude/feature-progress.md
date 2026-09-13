# keycraft progress

## Phase 1: the wallet as a page (2026-09-13) — built, then DELETED the same day
- The page (`web/`, contract `Djf3MSYX…`) is gone: a wallet served by a node keeps its keys in that node's delegate folder and cannot see other apps' delegates (user: "keycraft on freenet is not the answer; handle the key via the chrome plugin"). The contract stays on the network unused.

## Phase 2: the extension as store and signer (2026-09-13)
- [x] `extension/`: sealed synced store, Ed25519 via WebCrypto, per-app approval remembered, popup (create, rename, remove, keyfile export/import), page bridge
- [x] `craftworks-page::keys`: extension backend behind the same `Keys` API (list, generate, import, export, store_key, signer); delegate fallback; every app rebuilt
- [x] every app: no key management, menu says identities live in the extension
- [ ] verified in a browser with the extension loaded (`extension/test/drive.mjs`): unlock → scan/import → filecraft read → a signed write. Google Chrome ignores unpacked extensions since 137; the harness uses Chrome for Testing 151 from the Playwright cache. First runs: extension loads; unlock timed out once (cause unknown), one run hung 14 min (pipe buffering hid output; now streamed and capped at 5 min)

## Phase 3: the native helper (2026-09-13)
- [x] `host/keycraft-host`: decrypts every delegate's secrets in a node's data dir (format in DESIGN §3); CLI `list`, native messaging `ping`/`list`, `install <id>`; verified on the Mac node (2 identities decoded with owners, 9 other delegates named, River's rooms among them); stdio protocol verified from Python
- [x] popup: Scan this machine's node → import craftworks identities
- [ ] verified from inside the extension (the harness step)

## Phase 4: River write-back (§6) — not started
## Phase 5: typed keys (§4) — not started

## Node facts
- The Mac node (port 7510) runs from `~/.claude/jobs/2a0aa3ae/tmp/net1/data` (set by me on 2026-09-12): its secrets are backed up to `~/Library/Application Support/freenet/node-7510-backup-20260913-2111`; moving the node to a durable dir needs a restart the user has not asked for yet
