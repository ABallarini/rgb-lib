# rgb-lib wasm bindings

`wasm-bindgen` API for the [`rgb-lib`](../../) wallet, for browsers and other JavaScript runtimes with no filesystem and no SQLite driver.

The crate is a thin shell over the shared implementation: wallets are built with `Wallet::new_in_memory`, restored with `Wallet::from_snapshot`, persisted with `Wallet::flush` and filled with the ordinary `rgb-lib` operations. No wallet or RGB logic is reimplemented here, and `rgb-lib` is a path dependency with `default-features = false, features = ["wallet"]`, so the wasm graph has no SQLite driver, Tokio or migration crate.

Like [`c-ffi`](../c-ffi) and [`uniffi`](../uniffi), this is a separate crate with its own `Cargo.lock` and its own `[workspace]` table: it is not a member of the `rgb-lib` workspace, and the root lockfile and default build are unchanged. It builds for `wasm32-unknown-unknown` only.

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

[`demo/index.html`](demo/index.html) and [`demo/app.js`](demo/app.js) import the generated package and use the full lifecycle: `load` on startup, `getAddress`, `snapshot`, `flush` to IndexedDB.

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

The smoke script has no IndexedDB, so it covers create, wallet id, receive address, the offline reads (`getBtcBalance`, `listAssets`, `listTransfers`, `listUnspents`, `listTransactions`, `getWalletData`), snapshot and restore, the encrypted backup round trip (bytes out, public metadata, restore, wrong password), key generation and restore, watch-only creation/restore, the hub-free multisig subset, invoice parsing and the invalid-consignment rejection; `flush()`/`load()` are the browser path and are covered by the demo.

## API

| Item | Description |
| ---- | ----------- |
| `RgbLibWallet.create(name, mnemonic, network)` | New wallet, keys derived at `WitnessVersion::Taproot`. |
| `RgbLibWallet.restore(name, snapshot, mnemonic, network)` | Rebuild from the bytes of `snapshot()`. |
| `RgbLibWallet.load(name, mnemonic, network)` | Async: read the IndexedDB snapshot, restore it, or create the wallet when none exists. |
| `RgbLibWallet.createWatchOnly(name, keys, network)` | New watch-only wallet from public keys JSON (the core `SinglesigKeys` shape); a mnemonic in the keys is refused. |
| `RgbLibWallet.restoreWatchOnly(name, snapshot, keys, network)` | Rebuild a watch-only wallet from the bytes of `snapshot()` and its public keys. |
| `generateKeys(network)` | JSON: a fresh Taproot key set in the core `Keys` shape, mnemonic included. Secret: the host stores it. |
| `restoreKeys(network, mnemonic)` | JSON: the same key shape rebuilt from a mnemonic; invalid phrases give a fixed sanitized error. |
| `WasmInvoice.parse(invoice, network)` | Parse an RGB invoice; the network must match the one encoded in the invoice. |
| `invoiceData()` | JSON: the core `InvoiceData` shape (`recipient_id`, `asset_schema`, `asset_id`, `assignment`, `assignment_name`, `network`, `expiration_timestamp`, `transport_endpoints`, `public_key`, `encryption`, `unknown_query_params`). |
| `invoiceString()` | The invoice string the data was parsed from. |
| `validateConsignmentOffchain(bytes, txid, network)` | JSON: `valid`, `warnings`, `error` and `details` from validating a transfer consignment against its bundled witness data; invalid bytes and an invalid TXID throw. |
| `name()` | The durable snapshot key (the `name` passed in). |
| `id()` | The wallet identity: the master fingerprint of its keys. |
| `getWalletData()` | JSON: the data that defines the wallet (network, database type, allocation limit, supported schemas). |
| `getAddress()` | New vanilla receive address. |
| `getBtcBalance()` | JSON: vanilla and colored BTC balances, from local data only. |
| `getAssetBalance(asset_id)` | JSON: settled, future and spendable balance of an RGB asset. |
| `getAssetMetadata(asset_id)` | JSON: schema, supply, precision, ticker, details and token metadata of an RGB asset. |
| `listAssets()` | JSON: assets grouped by schema (`nia`, `uda`, `cfa`, `ifa`). |
| `listTransfers(asset_id?)` | JSON: RGB transfers, optionally filtered by asset ID. |
| `listUnspents(settled_only)` | JSON: unspents; `settled_only` excludes pending RGB allocations. |
| `listTransactions()` | JSON: known Bitcoin transactions, newest first. |
| `signPsbt(psbt)` | Sign a PSBT with the wallet keys and return the signed PSBT. |
| `finalizePsbt(psbt)` | Finalize a signed PSBT and return the finalized PSBT. |
| `deleteTransfers(batch_transfer_idx?, no_asset_only)` | Delete eligible failed transfers; returns whether any was deleted. |
| `issueNia(ticker, name, precision, amounts)` | Issue a NIA asset, returns the asset ID. `amounts` is a `BigUint64Array`. |
| `issueUda(ticker, name, details, precision)` | Issue a UDA asset, returns the asset ID. |
| `issueCfa(name, details, precision, amounts)` | Issue a CFA asset, returns the asset ID. |
| `issueIfa(ticker, name, precision, amounts, inflation_amounts, reject_list_url?)` | Issue an IFA asset, returns the asset ID. |
| `snapshot()` | Serialize the whole state (database, BDK data, browser blobs, never the mnemonic). |
| `backup(password)` | Encrypted backup archive as bytes: the native archive and encryption format, with the snapshot as its payload. |
| `restoreBackup(bytes, password)` | Rebuild this wallet from the bytes of `backup()`. A wrong password, a different wallet or a corrupt archive throws; it never creates a fresh wallet. |
| `backupInfo(bytes)` | JSON: public archive metadata (`version`, `scrypt_params`), no password needed. |
| `flush()` | Async: write the snapshot to IndexedDB, resolve once committed. |

`RgbLibMultisigWallet` is the hub-free multisig class: `create(name, keys, network)` and `restore(name, snapshot, keys, network)` take the core `MultisigKeys` JSON (`cosigners`, `threshold_colored`, `threshold_vanilla`), and the wallet exposes `name()`, `id()` (descriptor-derived), `getWalletData()`, `getKeys()`, `getDescriptors()`, `getAddress(index)` (descriptor-derived and deterministic, it does not persist the index), `snapshot()` and `flush()`.

Every read method returns a JSON string; it uses the `rgb-lib` serde field names (`snake_case`) and the host parses it. `getFeeEstimation`, `go_online`, sync, send, inflate and burn stay unavailable: they live behind the native-only `_online` feature, together with the hub-coordinated multisig operations.


`name` is the durable key: two wallets created with the same name share one snapshot entry, so keep it stable per wallet. The snapshot never carries the mnemonic, and no error returned by the bindings echoes it.

## Caveats

* `flush()` and `load()` need IndexedDB and therefore a browser. In Node use `snapshot()` and
  `restore()` instead, with the host's own storage.
* `issueNia()`, `issueUda()`, `issueCfa()` and `issueIfa()` allocate on an existing colored UTXO. A fresh wallet must be funded and synced before issuance succeeds; the browser demo does not go online yet.
* `generateKeys()` returns the mnemonic in its JSON. Store that secret yourself; `createWatchOnly()` takes only the public fields and refuses a key JSON that still carries a phrase.
* `RgbLibMultisigWallet` is hub-free: `getAddress(index)` derives from the descriptors without hub coordination, and `flush()` needs IndexedDB like the singlesig wallet.
* `backup()` and `restoreBackup()` derive the key with scrypt on the calling thread; the default parameters need 128 MiB and block the page until they finish. Pass the password yourself and keep it out of logs; it is never stored.
* The filesystem backup entry points of `rgb-lib` stay native: in the browser only the byte API above is available.
* The wasm build needs the Web Crypto API (`globalThis.crypto`) for randomness and backup key derivation. Browsers provide it; Node 19+ provides it by default, and Node 18 needs `--experimental-global-webcrypto` or `globalThis.crypto = require("node:crypto").webcrypto` as the smoke test does.
* Wallet construction is synchronous (`create`/`restore`) and reading IndexedDB is not, hence
  `load()`; do not fall back to `create` when a stored snapshot fails to restore. `load()` returns
  the error instead.
