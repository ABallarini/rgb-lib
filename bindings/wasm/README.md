# rgb-lib wasm bindings

`wasm-bindgen` API for the [`rgb-lib`](../../) wallet, for browsers and other JavaScript runtimes
with no filesystem and no SQLite driver.

The crate is a thin shell over the shared implementation: wallets are built with
`Wallet::new_in_memory`, restored with `Wallet::from_snapshot`, persisted with `Wallet::flush` and
filled with the ordinary `rgb-lib` operations. No wallet or RGB logic is reimplemented here, and
`rgb-lib` is a path dependency with `default-features = false, features = ["wallet"]`, so the wasm
graph has no SQLite driver, Tokio or migration crate.

Like [`c-ffi`](../c-ffi) and [`uniffi`](../uniffi), this is a separate crate with its own
`Cargo.lock` and its own `[workspace]` table: it is not a member of the `rgb-lib` workspace, and
the root lockfile and default build are unchanged. It builds for `wasm32-unknown-unknown` only.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack   # or the installer from https://rustwasm.github.io/wasm-pack/

# browser / bundler-free ES module output
wasm-pack build bindings/wasm --target web --out-dir pkg

# Node smoke output (CommonJS)
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
```

## Consume

### Browser

```sh
wasm-pack build bindings/wasm --target web --out-dir pkg
cd bindings/wasm && python3 -m http.server 8080
# then open http://localhost:8080/demo/
```

[`demo/index.html`](demo/index.html) and [`demo/app.js`](demo/app.js) import the generated package
and use the full lifecycle: `load` on startup, `getAddress`, `snapshot`, `flush` to IndexedDB.

```js
import init, { RgbLibWallet } from "./pkg/rgb_lib_wasm.js";

await init();

// restores the snapshot stored under the name, or creates a wallet the first time
const wallet = await RgbLibWallet.load("my-wallet", mnemonic, "regtest");
const address = wallet.getAddress();
await wallet.flush(); // durable in IndexedDB once this resolves
```

### Node smoke

```sh
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
node bindings/wasm/smoke/smoke.cjs
```

The smoke script has no IndexedDB, so it covers create, wallet id, receive address, snapshot and
restore, and the error paths; `flush()`/`load()` are the browser path and are covered by the demo.

## API

| Item | Description |
| ---- | ----------- |
| `RgbLibWallet.create(name, mnemonic, network)` | New wallet, keys derived at `WitnessVersion::Taproot`. |
| `RgbLibWallet.restore(name, snapshot, mnemonic, network)` | Rebuild from the bytes of `snapshot()`. |
| `RgbLibWallet.load(name, mnemonic, network)` | Async: read the IndexedDB snapshot, restore it, or create the wallet when none exists. |
| `name()` | The durable snapshot key (the `name` passed in). |
| `id()` | The wallet identity: the master fingerprint of its keys. |
| `getAddress()` | New vanilla receive address. |
| `issueNia(ticker, name, precision, amounts)` | Issue a NIA asset, returns the asset ID. `amounts` is a `BigUint64Array`. |
| `snapshot()` | Serialize the whole state (database, BDK data, browser blobs, never the mnemonic). |
| `flush()` | Async: write the snapshot to IndexedDB, resolve once committed. |

`name` is the durable key: two wallets created with the same name share one snapshot entry, so keep
it stable per wallet. The snapshot never carries the mnemonic, and no error returned by the
bindings echoes it.

## Caveats

* `flush()` and `load()` need IndexedDB and therefore a browser. In Node use `snapshot()` and
  `restore()` instead, with the host's own storage.
* `issueNia()` allocates on an existing colored UTXO. A fresh wallet must be funded and synced
  before issuance succeeds; the browser demo does not go online yet.
* Wallet construction is synchronous (`create`/`restore`) and reading IndexedDB is not, hence
  `load()`; do not fall back to `create` when a stored snapshot fails to restore. `load()` returns
  the error instead.
