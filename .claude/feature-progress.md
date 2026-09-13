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

## Phase 4: River — REMOVED (2026-09-13)
- Built (helper decoded room keys; sealed bundle export/import re-keyed per node; popup buttons), then removed at the user's request: River keys each channel separately with no single identity, which does not fit the one-identity wallet. The helper still lists other delegates' secrets by name/size for inspection but no longer imports or moves any. Extension, popup and helper stripped of River/bundle code; `hmac`/`base64` deps dropped

## Phase 4 (old): River (superseded)
- [x] read: the helper decodes `signing_key:<origin>:<room>` into River rooms (5 on the Mac node); the extension keeps them as `river-room` records (owner = the room key's public half) and the popup lists them; pages never see them
- [x] write-back as a bundle file (DESIGN §6): helper `export`/`import` (CLI and native messaging), popup buttons; round trip verified into a differently keyed scratch store (12 secrets, 894 KB, wrong password refused, 1.1 MB import request). NOT verified: River's UI on a second machine
- [ ] (superseded) write-back routes considered — (a) River's own `StoreSigningKey` through the node's ws API (needs ciborium-encoded `ChatDelegateRequestMsg` + the freenet client framing, and River's delegate address per release); (b) the helper copying River's whole delegate scope between nodes (decrypt with node A's key, re-encrypt with node B's, update `.keys`; the room state `<origin>:room:<id>` must travel too, 50–420 KB each, or River shows no room). (b) needs no River code; the running node's in-memory index may not see files written behind it until restart
- PIN instead of passphrase (4–12 digits; Change PIN; Forgot PIN = reset the store) at the user's request; the tradeoff (a PIN is brute-forceable offline from the synced blob) stated to the user
- Chrome runs the helper with its origin as argv[1] (was rejected as bad usage → "Native host has exited"); a reply over 1 MB is refused ("Error when communicating") → other delegates' values are sizes unless `--values`
## Phase 5: typed keys (§4) — not started

## Node facts
- The Mac node (port 7510) now runs from `~/Library/Application Support/freenet/node-7510/{data,config}` (moved 2026-09-13 at the user's request: stopped in 4 s, copied 450 MB, config paths rewritten, up in 3 s, a page served in 0.2 s; log at `node-7510/node.log`). The old copy under the job's tmp dir and the earlier secrets backup are leftovers. It is a plain background process, not launchd: it does not survive a reboot

## Phase 6: one active identity (2026-09-13, user: "only 1 active key at a time so website not load all key")
- [x] the extension keeps one active identity (`active`/`setActive`; `create` makes the new one active); `list` (what a page sees) returns ONLY the active identity, `listAll` (the popup) shows all with an `active` flag and a Use button; `storeKey`/`sign` refuse any owner that is not active
- [x] proven at the mechanism level against the local node: seeded home + test2, set home active, `listAll` shows home active / test2 not, and a page's `accounts()` would receive only the active one
- [x] each app reloads its account when the active identity changes, but only once idle (a reload that raced an in-flight create would double-init a drive)
- PIN reset/change made worker-independent (the popup clears the store itself); manifest v0.2.0 shows in the popup title
- **Open, NOT single-active's fault:** fresh-identity creation intermittently fails with "table _meta already exists" ~40-90 s into `Fs::init`. Instrumented `Homes::ensure`: it runs init EXACTLY ONCE (seq=0, one owner), so the double-schema is inside `Fs::init` on a retried/slow commit — a freenet-vfs/pages robustness issue under node load, present before this change (3 earlier runs passed by luck of faster writes). The local node (7510) is heavily loaded (Edge tabs subscribing + network peers → summarize_contract_state rate-limited, 24k+ dropped), which is what makes the write slow enough to retry. Existing identities (with drives) load fine; only first-run creation of a NEW drive is affected
