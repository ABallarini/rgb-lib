# rgb-lib wasm bindings

`wasm-bindgen` API for the [`rgb-lib`](../../) wallet, for browsers and other JavaScript runtimes with no filesystem and no SQLite driver.

The crate is a thin shell over the shared implementation: wallets are built with `Wallet::new_in_memory`, restored with `Wallet::from_snapshot`, persisted with `Wallet::flush`, synced with `Wallet::sync_async`, receive proxy consignments with `Wallet::receive_transfer_async`/`Wallet::sync_online_async` and filled with the ordinary `rgb-lib` operations. No wallet or RGB logic is reimplemented here, and `rgb-lib` is a path dependency with `default-features = false, features = ["wallet", "esplora_async"]`, so the wasm graph has no SQLite driver, Tokio or migration crate.

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

The smoke script has no IndexedDB or indexer, so it covers create, wallet id, receive address, the offline reads (`getBtcBalance`, `listAssets`, `listTransfers`, `listUnspents`, `listTransactions`, `getWalletData`), the out-of-band `witnessReceive` invoice and the `blindReceive` core error without a colored UTXO, snapshot and restore, the encrypted backup round trip (bytes out, public metadata, restore, wrong password), key generation and restore, watch-only creation/restore, the hub-free multisig subset, invoice parsing, the invalid-consignment rejection, the offline rejection of an invalid `checkProxyUrl` endpoint and the re-entrant call guard (a second call while a `sync` is in flight throws `the wallet is busy with another operation`); `flush()`/`load()`, the online `sync`/`getTipHeight`/`getFeeEstimation` and a reachable proxy are covered by the browser demo and the opt-in regtest smoke.

CI runs the binding's own `wasm-bindgen-test` suite in headless Chrome: `create`, `getAddress`, `flush`, drop and `load` restore the wallet at the next address, `deleteSnapshot` removes the record and a later `flush` on the detached instance throws, the hub-free multisig wallet survives a flush/load round trip, and a refused local indexer and a transfer with no pending proxy invoice reject with sanitized errors while the wallet stays usable; a real proxy receive needs the opt-in regtest smoke, so it is not part of required CI.

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
| `checkProxyUrl(url)` | Async, read-only: validates an RGB transport endpoint (`rpc://host` or `rpcs://host`) with the shared parser, asks the proxy for `server.info` over browser `fetch` and resolves to `true` when it reports the supported protocol version. An invalid URL, an unreachable proxy or an unsupported version throws a sanitized error; no write is sent. |
| `name()` | The durable snapshot key (the `name` passed in). |
| `id()` | The wallet identity: the master fingerprint of its keys. |
| `getWalletData()` | JSON: the data that defines the wallet (network, database type, allocation limit, supported schemas). |
| `getAddress()` | New vanilla receive address. |
| `blindReceive(asset_id?, assignment, expiration_timestamp, min_confirmations, encryption?)` | JSON `ReceiveData` for an out-of-band blinded recipient: `invoice`, `recipient_id`, `expiration_timestamp`, `batch_transfer_idx`, `public_key`. Endpoints are fixed to empty, so no proxy is contacted and no reservation is made; `expiration_timestamp` is a `bigint`. `assignment` is the core serde shape (`{"Fungible":1000}`, `"NonFungible"`, `{"InflationRight":1000}` or `"Any"`), `encryption` is `required`, `unsupported` or `optional`. Needs a colored UTXO; otherwise the core `Insufficient allocations` error is thrown. |
| `witnessReceive(asset_id?, assignment, expiration_timestamp, min_confirmations, encryption?)` | The same out-of-band `ReceiveData` for a new witness script recipient; no colored UTXO is needed. |
| `getBtcBalance()` | JSON: vanilla and colored BTC balances, from local data only. |
| `sync(indexer_url, stop_gap?)` | Async: BDK full scan against Esplora (both keychains, `stop_gap` default 20). Applies the update and, in the same database transaction, reconciles the pending witness state and registers the newly seen colored TXOs, like the native full scan; call `flush()` for durable storage. No broadcast and no consignment is received. |
| `syncOnline(proxy_url, indexer_url, stop_gap?)` | Async: runs `sync`, then lists the transfers of each pending incoming proxy invoice and receives and ACKs each one addressed to this wallet. A receive left in `WaitingSafeHeight` or `WaitingBroadcast` is resumed; a `Settled` or `Failed` one is skipped. Flushes the handled receives before posting their `transfer.retrieved`; a failed post is retried by the next call. Returns JSON: the handled `batch_transfer_idx` values. Idempotent on re-run; a failure rolls back only that transfer. Call `flush()` afterwards. |
| `receiveTransfer(proxy_url, indexer_url, transfer_id)` | Async: receives, validates and ACKs one proxy transfer and broadcasts a released signed TX, in one wallet transaction. Flushes the handled receive before posting `transfer.retrieved`; a pending release is retried by the next call. Returns JSON: the handled `batch_transfer_idx`, or `null` when already handled. Throws for a transfer not addressed to this wallet. Call `flush()` afterwards. |
| `getTipHeight(indexer_url)` | Async: best-chain tip height from the Esplora endpoint. |
| `getFeeEstimation(indexer_url, blocks)` | Async: sat/vB estimate for confirmation within `blocks` (`1..=1008`); throws `Cannot estimate fees` when the endpoint has no fee history. |
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
| `flush()` | Async: guarded write of the snapshot to IndexedDB; rejects a stale writer sequence and resolves once committed. |
| `deleteSnapshot(name)` | Async: delete this wallet's IndexedDB snapshot, then detach the instance. `name` must equal `name()`; a missing record is not an error and every later `flush()` throws instead of recreating it. |

`RgbLibMultisigWallet` is the hub-free multisig class: `create(name, keys, network)`, `restore(name, snapshot, keys, network)` and `load(name, keys, network)` take the core `MultisigKeys` JSON (`cosigners`, `threshold_colored`, `threshold_vanilla`), and the wallet exposes `name()`, `id()` (descriptor-derived), `getWalletData()`, `getKeys()`, `getDescriptors()`, `getAddress(index)` (descriptor-derived and deterministic, it does not persist the index), `snapshot()`, `flush()` and `deleteSnapshot(name)`.

Every read method returns a JSON string; it uses the `rgb-lib` serde field names (`snake_case`) and the host parses it. `sync`, `syncOnline`, `receiveTransfer`, `getTipHeight` and `getFeeEstimation` reach the chain through the browser `fetch` backend; `sync` also reconciles the pending witness state and registers new colored TXOs in its transaction, as the native full scan does. `syncOnline` and `receiveTransfer` also reach the proxy, ACK at the same point the native driver does, resume a receive left in `WaitingSafeHeight` or `WaitingBroadcast`, flush the snapshot before calling `transfer.retrieved`, and retry a pending release (kept in the wallet files, so it survives a failed post and a reload) on the next call; persistence itself stays with `flush()`: no IndexedDB write happens inside the wallet transaction. `blindReceive` and `witnessReceive` create out-of-band invoices only; proxy invoice creation, send, inflate and burn stay unavailable: they live behind the native-only `_online` feature, together with `go_online` and the hub-coordinated multisig operations.


`name` is the durable key: two wallets created with the same name share one snapshot entry, so keep it stable per wallet. The snapshot never carries the mnemonic, and no error returned by the bindings echoes it.

Each wallet instance has a random non-secret writer id and tracks the snapshot sequence it last saw. `load()` adopts both from IndexedDB and `flush()` writes `{ bytes, writer, sequence }` in one transaction only when the stored sequence is not newer, so a stale tab's flush throws an error naming the stored sequence and its writer instead of overwriting the newer snapshot; call `load()` again to recover. A snapshot stored by an older release as a bare `Uint8Array` loads as writer `legacy` at sequence `0` and is migrated by the first flush. Keep one writer per wallet name: the guard rejects stale writes but does not merge divergent in-memory state.

`deleteSnapshot(name)` removes that one record and nothing else: it throws when `name` differs from `name()`, so it cannot touch another wallet's key, and a missing record is not an error. The in-memory wallet stays usable, but the instance is detached and every later `flush()` throws instead of silently recreating the deleted snapshot with its old sequence. Recreate the record deliberately by calling `load()` on a new instance, which starts at sequence `0`, or drop the instance.

## Out-of-band receive

`blindReceive` and `witnessReceive` delegate to the core `Wallet::blind_receive` and `Wallet::witness_receive` with `online = None` and an empty transport endpoint list, which selects the out-of-band exchange: the invoice carries no proxy endpoint, no reservation is made, and the host moves the invoice, consignment and ACK over its own channel.
`witnessReceive` works on a fresh wallet because it only derives a new script; `blindReceive` allocates on an existing colored UTXO and otherwise throws the core `Insufficient allocations` error, so it does not fake a UTXO.
The receive side stays native-only: the core `provide_out_of_band_consignment` and `provide_out_of_band_ack` live in the `_online` implementation, take an `Online` indexer and may broadcast, so this package creates the invoice but cannot complete the transfer.
Proxy receive is supported separately: `receiveTransfer` and `syncOnline` take the recipient proxy URL and an Esplora URL explicitly and run the shared receive driver. A stored proxy transfer ID is not treated as completion: a receive left in `WaitingSafeHeight` or `WaitingBroadcast` is resumed, while `Settled` and `Failed` are terminal. `WaitingConfirmations` settlement, expiry-based failure and the rest of the native refresh lifecycle still need the native wallet. Creating a proxy invoice still needs a proxy reservation and stays native, so the browser receives a proxy transfer whose invoice was created elsewhere with the same wallet keys.

## Caveats

* `flush()` and `load()` need IndexedDB and therefore a browser. In Node use `snapshot()` and
  `restore()` instead, with the host's own storage.
* A `flush()` that reports a stale sequence did not write anything: another instance committed a
  newer snapshot. Call `load()` again before retrying, and do not fall back to `restore()` with the
  old bytes.
* `deleteSnapshot()` needs IndexedDB like `flush()` and `load()`; it removes the wallet's whole durable state, so export `snapshot()` or `backup()` first if the host may want it back.
* `issueNia()`, `issueUda()`, `issueCfa()` and `issueIfa()` allocate on an existing colored UTXO. `sync()` alone does not create one, but `receiveTransfer()`/`syncOnline()` can receive a proxy consignment and color a UTXO; without one, issuance still needs the native flow.
* `generateKeys()` returns the mnemonic in its JSON. Store that secret yourself; `createWatchOnly()` takes only the public fields and refuses a key JSON that still carries a phrase.
* `RgbLibMultisigWallet` is hub-free: `getAddress(index)` derives from the descriptors without hub coordination, and `flush()` needs IndexedDB like the singlesig wallet.
* `backup()` and `restoreBackup()` derive the key with scrypt on the calling thread; the default parameters need 128 MiB and block the page until they finish. Pass the password yourself and keep it out of logs; it is never stored.
* The filesystem backup entry points of `rgb-lib` stay native: in the browser only the byte API above is available.
* The wasm build needs the Web Crypto API (`globalThis.crypto`) for randomness and backup key derivation. Browsers provide it; Node 19+ provides it by default, and Node 18 needs `--experimental-global-webcrypto` or `globalThis.crypto = require("node:crypto").webcrypto` as the smoke test does.
* Wallet construction is synchronous (`create`/`restore`) and reading IndexedDB is not, hence
  `load()`; do not fall back to `create` when a stored snapshot fails to restore. `load()` returns
  the error instead.
* One operation per wallet instance at a time: every method holds the instance until it returns or, for an async one, until it settles, and a call that starts while another is still in flight throws `the wallet is busy with another operation`. Await each call before starting the next one.
