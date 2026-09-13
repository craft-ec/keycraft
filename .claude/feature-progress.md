# keycraft progress

## Phase 1: the wallet as a page (2026-09-13) — built, then DELETED the same day
- The page (`web/`, contract `Djf3MSYX…`) is gone: a wallet served by a node keeps its keys in that node's delegate folder and cannot see other apps' delegates (user: "keycraft on freenet is not the answer; handle the key via the chrome plugin"). The contract stays on the network unused.

## Phase 2: the extension as store and signer (2026-09-13)
- [x] `extension/`: sealed synced store, Ed25519 via WebCrypto, per-app approval remembered, popup (create, rename, remove, keyfile export/import), page bridge
- [x] `craftworks-page::keys`: extension backend behind the same `Keys` API (list, generate, import, export, store_key, signer); delegate fallback; every app rebuilt
- [x] every app: no key management, menu says identities live in the extension
- [x] verified in Chrome for Testing 151 with the extension loaded (`extension/test/drive.mjs`, Playwright): unlock 0.1 s; filecraft with no identity → welcome creates one in the extension (two confirms: create, allow this app) → the drive is created with extension-signed commits (39 s of node time through the Hetzner tunnel) → use stamp 4 s → a folder write signed by the extension ok. Two bugs found by the harness: the worker must be `type: module` (its imports were a silent syntax error, every message hung), and popup-only ops must be gated by sender origin, not `sender.tab`
- Harness lessons: Google Chrome ignores unpacked extensions since 137 (use Chrome for Testing / Playwright's Chromium); a grep pipe block-buffers the output and looks like a hang; a call into the page's wasm while its own call is in flight traps (RefCell) — wait for the log first

## Phase 3: the native helper (2026-09-13)
- [x] `host/keycraft-host`: decrypts every delegate's secrets in a node's data dir (format in DESIGN §3); CLI `list`, native messaging `ping`/`list`, `install <id>`; verified on the Mac node (2 identities decoded with owners, 9 other delegates named, River's rooms among them); stdio protocol verified from Python
- [x] popup: Scan this machine's node → import craftworks identities
- [ ] verified from inside the extension: Chrome for Testing does not read the user-level NativeMessagingHosts manifests ("Specified native messaging host not found"), so the popup's scan is untested in a browser; needs real Chrome with the extension loaded unpacked (chrome://extensions → Load unpacked → keycraft/extension, then `keycraft-host install <id>`)

## Phase 4: River write-back (§6) — not started
## Phase 5: typed keys (§4) — not started

## Node facts
- The Mac node (port 7510) now runs from `~/Library/Application Support/freenet/node-7510/{data,config}` (moved 2026-09-13 at the user's request: stopped in 4 s, copied 450 MB, config paths rewritten, up in 3 s, a page served in 0.2 s; log at `node-7510/node.log`). The old copy under the job's tmp dir and the earlier secrets backup are leftovers. It is a plain background process, not launchd: it does not survive a reboot
