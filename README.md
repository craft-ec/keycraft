# keycraft

The wallet of the craftworks suite, as a browser extension: your identities
live in your Chrome profile, encrypted under a passphrase and carried between
devices by Chrome sync. Pages ask the extension to sign and to hand over a
store key after you approve them once; a signing key never reaches a page or
a node. Every craftworks app (filecraft, papercraft, datacraft, Dot, Grid)
lists the extension's identities and lets you pick one, the way a dapp uses
a wallet.

| Part | What it is |
|---|---|
| `extension/` | Chrome (MV3): the sealed store, the Ed25519 signer, per-app approval, the popup (create, rename, remove, keyfile export/import, scan this machine's node) |
| `host/` | `keycraft-host`, a native program the extension launches: reads every delegate's secrets in a Freenet node's data directory with the node's own key, so what a node holds (ours, River's rooms, anything) can be pulled into the extension |
| `docs/DESIGN.md` | the model, the protocols, what is next (River write-back, typed keys) |

## Install

```
# the extension: chrome://extensions → Developer mode → Load unpacked → keycraft/extension
# the helper, registered for the extension id shown there
(cd host && cargo build --release && ./target/release/keycraft-host install <extension id>)
```

Without the extension, apps fall back to the keys delegate on the node they
are served from (`../datacraft/delegates/keys`).

## Test

`extension/test/drive.mjs` drives a Chromium with the extension loaded
(Google Chrome ignores unpacked extensions since 137; use Playwright's
Chromium or Chrome for Testing): unlock, scan the node, use filecraft with
the extension signing.
