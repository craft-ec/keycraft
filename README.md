# keycraft

The identities of a person on their node, as one app: the wallet of the
craftworks suite. Create, import, export, rename and remove identities here;
every other craftworks app (filecraft, papercraft, datacraft, Dot, Grid) only
lists them and lets you pick one, the way a dapp uses a wallet.

An identity is a signing key and a store key kept by the keys delegate on
the node (`../datacraft/delegates/keys`, frozen). Pages ask it to sign and
never see the key. Its home drive on the network lists what the identity
owns, so keycraft shows the same databases on every device the keys are on.

## Run

```
export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
export AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
(cd web && cargo build --release --target wasm32-unknown-unknown && \
  wasm-bindgen --target web --out-dir www target/wasm32-unknown-unknown/release/keycraft_web.wasm)
# dev: serve web/www on 8801 and open http://127.0.0.1:8798/?port=<node ws port>
fdev website init keycraft && fdev -p <node port> website publish web/www --key keycraft
```

| File | What it holds |
|---|---|
| `docs/DESIGN.md` | the screens, what the delegate can and cannot do, the road to typed keys, usage history and the browser extension |
