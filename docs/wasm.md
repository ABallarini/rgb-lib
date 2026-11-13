# Browser (WASM) wallet

`rgb-lib` builds for `wasm32-unknown-unknown` over an in-memory database and browser storage. This document covers the supported API, how to build and consume the generated package, and what is deliberately not available yet.

The implementation is shared with the native wallet: the browser binding is a thin `wasm-bindgen` shell over `Wallet::new_in_memory`, `Wallet::from_snapshot`, `Wallet::snapshot` and `Wallet::flush`. No wallet or RGB logic is duplicated in the binding.

## Status at a glance

| Area | Status |
| ---- | ------ |
| Create, restore and load a singlesig wallet | Supported |
| Receive addresses (`getAddress`) | Supported |
| Out-of-band RGB receive invoices | Supported and exported (`blindReceive`, `witnessReceive`): no transport endpoints and no proxy reservation |
| Offline reads: balances, metadata, assets, transfers, unspents, transactions, wallet data | Supported |
| PSBT sign and finalize | Supported offline |
| Delete eligible failed transfers | Supported offline |
| Issue NIA, UDA, CFA, IFA and BFA assets | Supported, but the wallet must already hold a colored UTXO; a mainnet wallet lists only NIA, UDA and CFA, so IFA and BFA are refused there |
| Whole-wallet snapshot | Supported |
| IndexedDB persistence (`load`, `flush`, `deleteSnapshot`) | Supported in browsers |
| Watch-only wallets | Supported and exported (`createWatchOnly`, `restoreWatchOnly`) |
| Invoice parsing | Supported and exported (`WasmInvoice.parse`, `invoiceData`, `invoiceString`) |
| Consignment validation | Supported and exported (`validateConsignmentOffchain`), over the witnesses bundled in the consignment |
| Multisig, hub-free | Supported and exported (`RgbLibMultisigWallet`: construction, descriptors, descriptor-derived addresses, state, flush, restore) |
| Multisig hub paths | Not available on wasm |
| BDK online access (sync with DB reconciliation, tip height, fee estimation) | Supported over the async Esplora transport (`sync`, `getTipHeight`, `getFeeEstimation`) |
| RGB receive over a proxy (download, decrypt, validate, ACK/NACK, resume `WaitingSafeHeight`/`WaitingBroadcast`, `transfer.retrieved`) | Supported and exported (`receiveTransfer`, `syncOnline`) over the Fetch proxy client and the prefetched async chain resolver |
| BFA mint receive | Supported when the caller supplies an EVM endpoint (`receiveTransfer`/`syncOnline` `evm` argument): claims, mint locks and EVM reject lists are prefetched before the transaction, and `getReceivedMint` reports the checked mint (`MintLockExpired`, `MintLockNotFound`, `NoEvmRpcUrl` and chain mismatches are typed errors) |
| Proxy health check | Supported and exported (`checkProxyUrl`): read-only `server.info` over the Fetch proxy client |
| RGB transfers, send, proxy invoice reservation, media upload, hub coordination | **Not assembled**; the native-only `_online` paths stay off |
| Out-of-band consignment import and ACK | Native-only: `provide_out_of_band_consignment` and `provide_out_of_band_ack` take `Online` and may broadcast |
| Async Esplora and Fetch transports | Esplora is wired into the BDK sync and the receive validation; the Fetch proxy serves `checkProxyUrl` and the asynchronous receive; the Fetch EVM client serves claim, mint-lock and reject-list prefetch for BFA receive |
| Backups | Encrypted byte backup/restore supported; path-based filesystem backups native only |
| Legacy file migrations | Native only |
| Web Worker | Not required; optional future seam only |

The JS package exposes the singlesig offline subset, the read-only online reads and the proxy receive: create, restore, load, watch-only creation and restore, name, id, getAddress, blindReceive, witnessReceive, the balance, metadata, asset, transfer, unspent, transaction and wallet-data reads, getReceivedMint, signPsbt, finalizePsbt, deleteTransfers, NIA/UDA/CFA/IFA/BFA issuance, snapshot, flush and deleteSnapshot, sync, syncOnline, receiveTransfer, getTipHeight and getFeeEstimation, plus the free functions `generateKeys`, `restoreKeys` and `checkProxyUrl` and the hub-free `RgbLibMultisigWallet` class. Hub-coordinated multisig operations stay native-only.

The browser wallet is **online for its own BDK wallet and for proxy receives**: it can scan the chain, receive and ACK RGB consignments through a proxy, but it cannot create a proxy receive invoice, transfer RGB assets or send, which stay native-only.

## Build

### Prerequisites

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
```

`wasm-pack` 0.15.0 is the version pinned in `.github/workflows/wasm.yml`. The browser test runner also needs `wasm-bindgen-cli` matching the `wasm-bindgen` version in `Cargo.lock`, plus a Chrome/ChromeDriver pair.

### Root wallet build

The root crate compiles for wasm32 with the `wallet` feature and without SQLite, Tokio or the migration crate:

```sh
cargo check --lib --target wasm32-unknown-unknown --no-default-features --features wallet
RUSTFLAGS="-D warnings" cargo check --lib --target wasm32-unknown-unknown --no-default-features --features wallet
```

The browser HTTP transports compile only with `esplora_async`:

```sh
RUSTFLAGS="-D warnings" cargo check --lib --target wasm32-unknown-unknown \
  --no-default-features --features wallet,esplora_async
```

Do **not** enable `bitcoind`, `electrum` or `esplora` for wasm32: their dependencies and code are native-gated, so such a build does not compile.

### Features that matter for wasm

| Feature | Effect on wasm32 |
| ------- | ---------------- |
| `wallet` | Shared wallet code, in-memory database backend, browser clock, CSPRNG and IndexedDB storage |
| `esplora_async` | Async Esplora transport, wired into the BDK sync and the receive validation, plus the Fetch proxy client and the Fetch EVM client; wasm only |
| `sqlite` | Native only: SQLite driver and Tokio runtime; must stay off |
| `bitcoind`, `electrum`, `esplora` | Native blocking indexers; must stay off |
| `bdk_file_store_migration`, `rgb_fs_store_migration` | Native legacy imports; must stay off |
| `_online` | Internal marker for native online paths; not enabled by `esplora_async` and not for wasm |

### Dependency-graph and gate checks

```sh
bash scripts/wasm_graph_check.sh --self-test
bash scripts/wasm_graph_check.sh
bash scripts/wasm_gate.sh
```

`wasm_graph_check.sh` resolves the wasm graph and fails on `mio`, `libsqlite3-sys`, `ring`, native TLS, blocking HTTP, Tokio, hyper and native socket indexers, then builds and scans the wasm artifact. `wasm_gate.sh` runs the native and wasm checks together; it stops at compile checks and does not run the browser lifecycle test.

### Bindings package

```sh
# Browser: ES module package
wasm-pack build bindings/wasm --target web --out-dir pkg

# Node: CommonJS package
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
```

Both commands run from the repository root. The output lands in `bindings/wasm/pkg` and `bindings/wasm/pkg-node`. The generated package is named `rgb-lib-wasm`, is ESM for the `web` target, and ships `rgb_lib_wasm.js`, `rgb_lib_wasm_bg.wasm` and `rgb_lib_wasm.d.ts`.

`bindings/wasm` is a separate crate with its own `[workspace]` and `Cargo.lock`. It depends on `rgb-lib` with `default-features = false, features = ["wallet"]`, so the bindings package does not include the native database, the native indexers or the async transports.

### Node smoke test

```sh
wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
node bindings/wasm/smoke/smoke.cjs
```

The smoke covers create, wallet id, receive address, the offline reads (`getBtcBalance`, `listAssets`, `listTransfers`, `listUnspents`, `listTransactions`, `getWalletData`, `getReceivedMint`, `deleteTransfers`), the out-of-band `witnessReceive` invoice plus the `blindReceive` core error on a wallet without a colored UTXO, the `issueBfa` argument checks (zero mint rights, an invalid contract address) and its mainnet refusal, snapshot, restore, restore with a mismatched mnemonic, invalid-mnemonic error handling, `generateKeys`/`restoreKeys`, watch-only creation with address/snapshot/restore, the hub-free multisig subset (construction, id, descriptors, descriptor-derived address, snapshot, restore), invoice parsing, the invalid-consignment rejection, the offline rejection of an invalid `checkProxyUrl` endpoint and the re-entrant call guard (a second call while a `sync` is in flight throws `the wallet is busy with another operation`). Node has no IndexedDB, so `load()` and `flush()` are not exercised there.

### Browser lifecycle test

```sh
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_TEST_TIMEOUT=300
cargo test --lib --target wasm32-unknown-unknown \
  --no-default-features --features wallet,esplora_async
```

This needs Chrome and ChromeDriver. It runs the wallet lifecycle over a real IndexedDB: create, issue offline, flush, reload, restore, and verify the state and address index survived. It also runs the opt-in regtest Esplora smoke, which returns early unless `RGB_REGTEST_ESPLORA_URL` was baked in at compile time.

The same job runs the bindings crate's own browser suite. Besides the operation guard, it covers the durable path in a real IndexedDB: `create`, `getAddress`, `flush`, drop and `load` restore the wallet and hand out the next address, `deleteSnapshot` removes the record and a later `flush` on the detached instance throws, the hub-free multisig wallet survives a flush/load round trip, and a refused local indexer and a transfer with no pending proxy invoice reject with sanitized errors while the wallet stays usable. Those network cases use a refused URL: a real proxy receive and the opt-in regtest Esplora smoke are not part of required CI.

```sh
cargo test --manifest-path bindings/wasm/Cargo.toml --lib --target wasm32-unknown-unknown
```

Optional network smoke (not part of required CI, needs a controlled regtest Esplora endpoint):

```sh
export RGB_REGTEST_ESPLORA_URL=http://127.0.0.1:3002
bash scripts/wasm_online_smoke.sh
```

## Consume the generated package

The browser package exposes two classes, `RgbLibWallet` and `RgbLibMultisigWallet`, plus the free functions `generateKeys` and `restoreKeys`. It must be initialized before use. The sample assumes the generated `pkg/` directory is served next to the page module.

```ts
import init, { RgbLibWallet } from "./pkg/rgb_lib_wasm.js";

await init();

// Stable key for this wallet. The name is the durable snapshot key: include the network in it
// if one origin can hold wallets for more than one network.
const name = "mainnet-wallet-1";
const network = "mainnet";

// Load from IndexedDB, or create when no snapshot exists. Await it before using the wallet.
const mnemonic = await hostGetMnemonic(); // from the host's secret storage, never hard-coded
const wallet = await RgbLibWallet.load(name, mnemonic, network);

const address = wallet.getAddress();

// Issuance allocates on an existing colored UTXO. A fresh wallet has none, and the read-only
// sync below sees funding but does not color a UTXO; RGB issuance needs the native flow today.
const indexer = "https://your-esplora-endpoint";
await wallet.sync(indexer, 20); // BDK scan + DB reconciliation
const tipHeight = await wallet.getTipHeight(indexer);
const assetId = wallet.issueNia("DEMO", "Demo asset", 0, new BigUint64Array([1000n]));

const bytes = wallet.snapshot(); // Uint8Array; store it as private wallet data
await wallet.flush();            // resolves after the IndexedDB transaction commits
```

Offline restore without IndexedDB (for example in Node, or with host-owned storage):

```js
const { RgbLibWallet } = require("./pkg-node/rgb_lib_wasm.js");

const wallet = RgbLibWallet.create("smoke", mnemonic, "regtest");
const bytes = wallet.snapshot();
const restored = RgbLibWallet.restore("smoke", bytes, mnemonic, "regtest");
```

### API

| Item | Description |
| ---- | ----------- |
| `RgbLibWallet.create(name, mnemonic, network)` | Synchronous. New wallet with Taproot keys. |
| `RgbLibWallet.restore(name, snapshot, mnemonic, network)` | Synchronous. Rebuild from `snapshot()` bytes. Settings are validated against the snapshot; the supported schemas are taken from it, so a snapshot written before BFA support still restores. |
| `RgbLibWallet.load(name, mnemonic, network)` | Async. Read IndexedDB, restore, or create when no snapshot exists; adopts the stored writer and sequence. Await before use. |
| `RgbLibWallet.createWatchOnly(name, keys, network)` | Synchronous. New watch-only wallet from the core `SinglesigKeys` JSON; `mnemonic` must be absent or `null`, a phrase is refused. |
| `RgbLibWallet.restoreWatchOnly(name, snapshot, keys, network)` | Synchronous. Rebuild a watch-only wallet from `snapshot()` bytes and its public keys. |
| `generateKeys(network)` | JSON. A fresh Taproot key set in the core `Keys` shape (`mnemonic`, `xpub`, account xpubs, `master_fingerprint`, `witness_version`); the mnemonic is secret and the host stores it. |
| `restoreKeys(network, mnemonic)` | JSON. The same key shape rebuilt from a mnemonic; an invalid phrase gives a fixed sanitized error. |
| `WasmInvoice.parse(invoice, network)` | Parse an RGB invoice; the network must match the one encoded in the invoice. |
| `invoiceData()` | JSON. The core `InvoiceData` shape: `recipient_id`, `asset_schema`, `asset_id`, `assignment`, `assignment_name`, `network`, `expiration_timestamp`, `transport_endpoints`, `public_key`, `encryption` and `unknown_query_params`. |
| `invoiceString()` | The invoice string the data was parsed from. |
| `validateConsignmentOffchain(bytes, txid, network)` | JSON. `valid`, `warnings`, `error` and `details` from validating a transfer consignment against its bundled witness data; invalid bytes and an invalid TXID throw. A valid result does not prove the witness transaction has been broadcast. |
| `checkProxyUrl(url)` | Async, read-only. Validates an RGB transport endpoint (`rpc://host` or `rpcs://host`) with the shared parser, asks the proxy for `server.info` through `ProxyFetchClient` and resolves to `true` when it reports the supported protocol version. An invalid URL, an unreachable proxy or an unsupported version throws a sanitized error; no write is sent. |
| `name()` | The durable snapshot key passed to the constructor. |
| `id()` | Master fingerprint of the wallet keys. |
| `getWalletData()` | JSON. The data that defines the wallet: network, database type, allocation limit and supported schemas. |
| `getAddress()` | New vanilla receive address. |
| `blindReceive(asset_id?, assignment, expiration_timestamp, min_confirmations, encryption?)` | JSON. Out-of-band `ReceiveData` (`invoice`, `recipient_id`, `expiration_timestamp`, `batch_transfer_idx`, `public_key`) for a blinded recipient. Transport endpoints are fixed to empty, so no proxy is contacted and no reservation is made; `expiration_timestamp` is a `bigint` in JS. `assignment` is the core serde shape (`{"Fungible":1000}`, `"NonFungible"`, `{"InflationRight":1000}` or `"Any"`); `encryption` is `required`, `unsupported` or `optional`. A wallet without a colored UTXO throws the core `Insufficient allocations` error. |
| `witnessReceive(asset_id?, assignment, expiration_timestamp, min_confirmations, encryption?)` | JSON. The same out-of-band `ReceiveData` for a new witness script recipient; no colored UTXO is needed. |
| `getBtcBalance()` | JSON. Vanilla and colored BTC balances from local data; no chain sync. |
| `sync(indexer_url, stop_gap?)` | Async. BDK full scan against an Esplora endpoint: both keychains, `stop_gap` unused scripts per keychain (default 20). Applies the update and, in the same database transaction, reconciles the pending witness state and registers the newly seen colored TXOs, like the native full scan. Nothing is broadcast and no consignment is received; call `flush()` for durable storage. |
| `syncOnline(proxy_url, indexer_url, evm?, stop_gap?)` | Async. Runs the `sync` scan, then lists the transfers of each pending incoming proxy invoice and receives and ACKs each one addressed to this wallet. A receive left in `WaitingSafeHeight` or `WaitingBroadcast` is resumed; a `Settled` or `Failed` one is skipped. `evm` is `{ rpcUrl, maxMintLockBlocks }` or a map from decimal chain ID to that object, and is required to receive a BFA mint. It flushes the handled receives before posting their `transfer.retrieved`, so a failed post is retried by the next call. Returns JSON: the handled `batch_transfer_idx` values. A repeated call is idempotent; a failure rolls back only the transfer it happened on. Call `flush()` afterwards. |
| `receiveTransfer(proxy_url, indexer_url, transfer_id, evm?)` | Async. Receives, validates and ACKs one proxy transfer by ID and broadcasts a released signed TX. `evm` has the same shape as in `syncOnline`; a BFA mint without it throws `No EVM RPC URL configured for chain ID …`. The whole receive is one wallet transaction: a failure rolls it back. It flushes the handled receive before posting `transfer.retrieved`, and retries a pending release on the next call. Returns JSON: the handled `batch_transfer_idx`, or `null` when the transfer was already handled. A transfer not addressed to this wallet throws. Call `flush()` afterwards. |
| `getTipHeight(indexer_url)` | Async. Best-chain tip height reported by the Esplora endpoint. |
| `getFeeEstimation(indexer_url, blocks)` | Async. Fee estimate in sat/vB for confirmation within `blocks` (`1..=1008`), interpolated like the native Esplora indexer; an endpoint without fee history throws `Cannot estimate fees`. |
| `getAssetBalance(asset_id)` | JSON. Settled, future and spendable balance of an RGB asset. |
| `getAssetMetadata(asset_id)` | JSON. Schema, supply, precision, ticker, details and token metadata. |
| `listAssets()` | JSON. Assets grouped by schema in `nia`, `uda`, `cfa`, `ifa` and `bfa`. |
| `listTransfers(asset_id?)` | JSON. RGB transfers, optionally filtered by asset ID. |
| `listUnspents(settled_only)` | JSON. Unspents; `settled_only` excludes pending RGB allocations. |
| `listTransactions()` | JSON. Known Bitcoin transactions, newest first. |
| `signPsbt(psbt)` | Sign a PSBT with the wallet keys, return the signed PSBT. |
| `finalizePsbt(psbt)` | Finalize a signed PSBT, return the finalized PSBT. |
| `deleteTransfers(batch_transfer_idx?, no_asset_only)` | Delete eligible failed transfers; returns whether any was deleted. |
| `issueNia(ticker, name, precision, amounts)` | Issue a NIA asset; returns the asset ID. `amounts` is a `BigUint64Array` (or `bigint[]`). |
| `issueUda(ticker, name, details, precision)` | Issue a UDA asset; returns the asset ID. |
| `issueCfa(name, details, precision, amounts)` | Issue a CFA asset; returns the asset ID. |
| `issueIfa(ticker, name, precision, amounts, inflation_amounts, reject_list_url?)` | Issue an IFA asset; returns the asset ID. |
| `issueBfa(ticker, name, precision, mint_rights, chain_id, contract_address, reject_list_address?, link_right, linked_from_contract?, skip_contract_checks)` | Issue a BFA asset; returns the asset ID. `mint_rights` mint rights are issued on their own colored UTXOs and `chain_id` is a `bigint`. The bridge contract (`0x`-prefixed) is committed in the genesis. Refused on mainnet: the binding never enables reckless schemas. |
| `getReceivedMint(recipient_id)` | JSON. The core `ReceivedMint` of a checked mint (`opid`, `lock_id`, `amount`, `before_block`, `evm_chain_id`, `bridge_contract`), or `null` when no mint was checked for that recipient. |
| `snapshot()` | Whole wallet state as bytes: database, BDK data and browser blobs; never the mnemonic. |
| `flush()` | Async. Guarded write of `snapshot()` to IndexedDB: rejects a stale sequence, resolves once committed. |
| `deleteSnapshot(name)` | Async. Delete the IndexedDB record for `name` and detach the instance; `name` must equal `name()`, a missing record is not an error, and every later `flush()` throws instead of recreating it. |

`RgbLibMultisigWallet` is the hub-free multisig class:

| Item | Description |
| ---- | ----------- |
| `RgbLibMultisigWallet.create(name, keys, network)` | Synchronous. Keys are the core `MultisigKeys` JSON: `cosigners` (each `account_xpub_vanilla`, `account_xpub_colored`, `vanilla_keychain`, `master_fingerprint`), `threshold_colored` and `threshold_vanilla`. |
| `RgbLibMultisigWallet.restore(name, snapshot, keys, network)` | Synchronous. Rebuild from `snapshot()` bytes and the multisig keys. |
| `RgbLibMultisigWallet.load(name, keys, network)` | Async. Read IndexedDB, restore, or create when no snapshot exists; adopts the stored writer and sequence. |
| `name()` | The durable snapshot key passed to the constructor. |
| `id()` | Descriptor-derived wallet id; a multisig group has no single master fingerprint. |
| `getWalletData()` | JSON. Network, database type, allocation limit and supported schemas. |
| `getKeys()` | JSON. The cosigner set and thresholds. |
| `getDescriptors()` | JSON. The `colored` and `vanilla` descriptors. |
| `getAddress(index)` | Address at `index` of the vanilla receive descriptor, derived from the descriptors. Deterministic; it does not reveal or persist the index, because there is no hub to share it. |
| `snapshot()` | Whole wallet state as bytes. |
| `flush()` | Async. Guarded write of `snapshot()` to IndexedDB: rejects a stale sequence, resolves once committed. |
| `deleteSnapshot(name)` | Async. Delete the IndexedDB record for `name` and detach the instance, like the singlesig method. |

The JSON reads use the `rgb-lib` serde field names (`snake_case`), so the host parses them as returned without a second mapping layer. `network` accepts `mainnet`, `testnet`, `testnet4`, `regtest` and `signet`.

One operation per wallet instance at a time: every method holds the instance until it returns or, for an async one, until it settles, and a call that starts while another is still in flight throws the fixed `the wallet is busy with another operation` error. Await each call before starting the next one.

`syncOnline` and `receiveTransfer` ACK a valid consignment at the same point the native driver does (after apply, before the database commit) and flush the snapshot before calling `transfer.retrieved`, so the proxy deletes the consignment only after the handled receive is durable. The release marker travels in the wallet files, survives a failed post or a reload, and is retried by the next call before anything else is released; a flush failure returns its error and leaves the markers pending. The wallet transaction is in-memory, so no IndexedDB write happens inside it: the host must call `flush()` after either method to persist the new state. A failed receive drops the transaction and leaves the wallet unchanged; the downloaded consignment and its metadata stay in the wallet files and are reused on the next attempt.

The key helpers use that same shape: `generateKeys` and `restoreKeys` return the core `Keys` object, while `createWatchOnly` and `restoreWatchOnly` take the core `SinglesigKeys` object with `mnemonic` absent or `null`.

## Out-of-band RGB receive

`blindReceive` and `witnessReceive` create an RGB invoice whose transport endpoint list is empty, which the core treats as the out-of-band exchange: the host carries the invoice and, later, the consignment and ACK over its own channel.
The methods delegate to `Wallet::blind_receive` and `Wallet::witness_receive` with `online = None` and an empty endpoint list, so they never contact a proxy and never reserve the recipient ID on one.
Both return the core `ReceiveData` as JSON: `invoice`, `recipient_id`, `expiration_timestamp`, `batch_transfer_idx` and `public_key`.
`assignment` is the core serde shape (`{"Fungible":1000}`, `"NonFungible"`, `{"InflationRight":1000}` or `"Any"`), `encryption` is `required`, `unsupported` or `optional`, and `expiration_timestamp` must be a future UTC unix timestamp passed as a `bigint`.
`witnessReceive` needs no colored UTXO; `blindReceive` allocates on an existing colored UTXO and otherwise surfaces the core `Insufficient allocations` error instead of faking a UTXO.
The receive side of the out-of-band exchange is native-only: `provide_out_of_band_consignment` and `provide_out_of_band_ack` live in the `_online` wallet implementation, take an `Online` indexer and may broadcast a witness transaction, so the browser can create the invoice but cannot complete the transfer.
Proxy receive is separate and supported: `receiveTransfer` and `syncOnline` take the recipient proxy URL and an Esplora URL explicitly, list the pending invoices' transfers and run the shared receive driver. Creating a proxy invoice still needs a proxy reservation and stays native, so the browser can receive a proxy transfer whose invoice was created elsewhere with the same wallet keys.

## IndexedDB persistence

### Storage model

| Property | Value |
| -------- | ----- |
| Database | `rgb-lib` |
| Database version | `1` |
| Object store | `snapshots` |
| Key | The wallet `name` passed to `create`, `restore` or `load` |
| Value | `{ bytes: Uint8Array, writer: string, sequence: number }`; a legacy `Uint8Array` is still read |
| Writers | One read-write transaction per guarded `flush()` |

The snapshot itself is an `RGBWL` envelope, version `3`. Layout:

```text
magic "RGBWL" | version 3 | u32 manifest length | manifest JSON
| u32 files length | encoded browser files | database snapshot bytes
```

Version `2` snapshots (manifest plus database, no files section) still restore with an empty files adapter. Raw database snapshots without the envelope are rejected.

The manifest carries the non-secret wallet settings and is validated on restore. A v3 multisig snapshot has a zero manifest length because multisig has no settings manifest.

### Write and restore semantics

- **One transaction per flush.** `flush()` serializes the whole wallet and performs a single
  read-write IndexedDB transaction that both reads the stored sequence and writes the new record.
  It resolves only after the transaction commits.
- **Restore before ready.** `load()` reads IndexedDB first, then constructs the wallet
  synchronously from the bytes. The returned wallet is fully restored and adopts the stored writer
  id and sequence; there is no partially initialized state.
- **Stale writers are rejected.** Each wallet instance holds a writer id and the sequence it last
  saw. A flush writes `{ bytes, writer, sequence: expected + 1 }` only when the stored sequence is
  not greater than the expected one; otherwise the transaction aborts and the error names the
  stored sequence and its writer. Two overlapping flushes for the same key are serialized by
  IndexedDB: the first commits, the second is rejected instead of silently overwriting it. A
  different writer at an equal sequence is accepted, because it may be a new instance that loaded
  the latest state. Call `load()` again to adopt the newer state; still keep **one writer per
  wallet name** as the intended usage.
- **Legacy values migrate.** A snapshot stored before the guard as a bare `Uint8Array` loads as
  writer `legacy` and sequence `0`; the first guarded flush rewrites it as a record without losing
  the bytes. The unversioned `persistence::save_snapshot` compatibility function still overwrites
  the value with a bare `Uint8Array` and does not participate in the guard.
- **Abort keeps the previous snapshot.** A failed or aborted write rolls back. The last committed
  snapshot remains intact; the newest unflushed changes are lost.
- **Failed restore is an error.** A corrupt, truncated or unsupported snapshot makes `load()` or
  `restore()` fail. It never falls back to a fresh wallet, and the stored bytes are left untouched
  so the host can inspect or overwrite them.
- **Flush failure leaves the wallet usable.** The in-memory state is unchanged and a later flush
  can retry; a stale-sequence error means the instance must `load()` again first.
- **Deletion detaches the instance.** `deleteSnapshot(name)` delegates to the core
  `persistence::delete_snapshot`, which removes exactly that one `snapshots` key and treats a
  missing record as success. The binding refuses a `name` other than the wallet's own, so it can
  never remove another wallet's record. It then detaches the instance: every later `flush()`
  throws instead of recreating the deleted snapshot with a stale sequence. Recreate the record
  deliberately by calling `load()` on a new instance, which starts at sequence `0`, or drop the
  instance.
- **Unavailable storage.** Without a window or IndexedDB, `load()` and `flush()` fail before or
  during the transaction with an error. Quota failures surface as transaction errors; the previous
  snapshot is preserved.
- **One live wallet per mnemonic.** The root README warning applies unchanged: never run two wallet
  instances for the same keys. The sequence guard prevents silent clobbering of snapshots, but it
  does not merge divergent in-memory state, so it is not a substitute for one live instance.

### Storage limits and eviction

IndexedDB is subject to the browser's origin quota. The quota is shared with the rest of the origin, and browsers may evict origin data under storage pressure. A snapshot contains the whole wallet state, including media and consignment blobs, and **every flush rewrites the full snapshot**, so quota use grows with the wallet's files.

The library does not request persistent storage. A host that needs durability guarantees should call `navigator.storage.persist()` and check `navigator.storage.estimate()` before relying on IndexedDB, and should keep its own export of the snapshot if the data is valuable. To remove a wallet, call `wallet.deleteSnapshot(wallet.name())`: it deletes only that key, detaches the instance so a later flush cannot bring the record back, and is the supported replacement for editing the `snapshots` store of the `rgb-lib` database directly.

### Namespacing

There is one database and one object store, and the key is only the wallet `name`. There is no automatic per-network namespace. Two wallets with the same name on different networks share one entry and replace each other. Include the network in the name, for example `mainnet-wallet-1` versus `testnet-wallet-1`, or use a separate browser origin per environment.

### Secrets

- The mnemonic is used only to derive keys. It is never written to the snapshot, to IndexedDB or to
  an error message.
- `generateKeys()` and `restoreKeys()` return the mnemonic in their JSON: that output is secret and
  belongs in host-managed secure storage. `createWatchOnly()` and `restoreWatchOnly()` take no
  mnemonic and refuse a key JSON that carries one.
- Key-derivation errors are collapsed to a fixed message because the BIP39 parser can echo a word
  of the phrase.
- A snapshot is still sensitive: it contains addresses, balances, transfer data and blobs. Treat it
  as private wallet data, not as a public backup.
- An encrypted backup (`RgbLibWallet.backup`) protects the wallet state with the password-derived
  key, but the password itself is host-managed: it is never stored, returned or logged. Without it
  the archive cannot be restored, and a lost password means a lost backup.
- Keep the mnemonic in host-managed secure storage. Do not hard-code it in pages, log it, or put it
  in the `name` field.

## Web Worker usage

A Worker is **not required**. The binding and the wallet run on the page's main thread.

Backup key derivation and proxy proof of work run inline. `backup()` and `restoreBackup()` block the page for the scrypt derivation (the default parameters need 128 MiB), and the restore path rejects parameters above a fixed memory/work limit. Proof of work is bounded by the protocol's difficulty cap, not by local input size. A Worker-backed executor is not exposed.

## Indexers and HTTP

### What compiles

The root crate with `esplora_async` compiles the browser transport, resolver and proxy client:

| Component | Purpose |
| --------- | ------- |
| `EsploraTransport` | Async Esplora client over `fetch`: wallet full scan, block hash, broadcast, fee estimates and the other indexer reads |
| `EsploraResolver` | Async witness, block-header and chain-net answers for RGB validation |
| `ProxyFetchClient` | RGB proxy JSON-RPC over `fetch`, including in-memory multipart uploads |
| `EvmFetchClient` | EVM JSON-RPC over `fetch`: chain ID, finalized block, `eth_call` and reject-list reads, over the shared `evm_abi` payloads and decoders |

`EsploraTransport` is wired into `Wallet::sync_async` (exported as `sync`): a BDK full scan of both keychains whose update is applied to the shared wallet and persisted through the normal database transaction and `persist_bdk` seam. The same transaction runs the native sync bookkeeping: pending witness state is reconciled and colored TXOs new to the DB are registered. The same transport answers tip height, fee estimation, the witness and header questions of a proxy receive through `EsploraResolver`, and the broadcast of a released signed TX. `ProxyFetchClient` backs `checkProxyUrl` and every proxy call of `receiveTransfer`/`syncOnline`; the remaining proxy writes (invoice reservation, media upload, send) stay in the native-only flow.

`EvmFetchClient` is built from the same `evm_abi` selectors, calldata builders and result decoders as the native
blocking `EvmClient`, so the two transports cannot drift. It applies a 15 s deadline per request, caps a response body
at 1 MiB, retries only HTTP 502/503/504 and non-timeout transport errors, maps a reverted `eth_call` to `None` and
reports a chain-ID mismatch as the typed `EvmChainIdMismatch` error without ever including the endpoint URL.

## BFA mint receive

A BFA consignment carries claims (mint locks) living on the EVM chain its bridge commits to, and may declare an EVM
reject list. Both are resolved before the wallet transaction opens: `EvmReceiveOptions`/`EvmReceiveConfig` name the
endpoint and the maximum lock horizon, and the browser fetches the chain ID (checked against the bridge), the finalized
block, each claim's lock status as of it, whether the paying lock is already recorded, the latest block, the circulating
supply and the reject-list entries. A missing endpoint is `NoEvmRpcUrl`, a node on another chain is
`EvmChainIdMismatch`, a too-long claim set or reject list is refused, and the whole prefetch has a claim-count cap and a
wall-clock deadline. The shared receive driver then resolves the claims with that prefetched resolver: a lock not
finalized yet leaves the consignment waiting (`PendingMintLocks`, no colorings), an expired lock fails it with
`MintLockExpired`, and a paying mint is checked once and saved so `getReceivedMint` can report its `lock_id`, `amount`
and `before_block`. The ACK/NACK/retrieval ordering, the single-allocation rule and the per-UTXO slot limits are the
native ones, because the same driver runs both paths.

Still deferred on wasm: `mintBegin`/`mintEnd`, send, link and burn, which need the native `_online` flow; the browser can
currently receive and check a mint posted by a counterparty, not create one.

The bindings crate enables `wallet,esplora_async`, so the generated package contains the transport and the three read-only methods. No native blocking transport is in the wasm graph: `bitcoind`, `electrum` and `esplora` are native-only, and the graph check rejects their crates.

### Request bounds

`esplora-client` ignores `Builder::timeout` on wasm32, so `EsploraTransport` installs a `fetch` wrapper before it builds its client: every request under the indexer URL gets `AbortSignal.any([request.signal, AbortSignal.timeout(10000)])` and `cache: 'no-store'`, which also stops the browser serving stale chain data from an Esplora `cache-control: max-age`.

The deadline is the same 10 s constant the native Esplora and Electrum clients use (`INDEXER_TIMEOUT`), and the wrapper normalizes a trailing slash so a base URL with or without it is one entry; a stalled request therefore settles as a transport error instead of hanging, and the client's retry policy does not retry that error.

A browser without `AbortSignal.any` or `AbortSignal.timeout` falls back to a plain `fetch` with `no-store` and no per-request deadline; `sync`, `getTipHeight` and `getFeeEstimation` are then bounded only by the network stack.

One RGB chain prefetch (the witness and header answers a proxy receive validates against) has its own wall-clock budget of 60 s, checked before every request, on top of the 512-witness and 128-header count caps; it fails with a resolver error once the budget is spent and never returns a partial snapshot.

The prefetch runs before the database transaction opens, so no transaction is held across the network wait.

Remaining caveat: the retry backoff sleeper still needs `window.setTimeout`, so the online sync path stays browser-page-only; the wrapper patches `globalThis.fetch`, so the cache mode and deadline would apply in a Worker or Node, but the sleeper has to move to `globalThis.setTimeout` before that path works there.

### What is not assembled

The remaining RGB online flow (`RgbWalletOpsOnline`, `OnlineOptions`, `go_online`, proxy invoice reservation, transfers, send, media upload, hub coordination) is gated by the native-only `_online` feature. `esplora_async` deliberately does not enable it: the browser receive path is an additive async method in `wasm_online`/`receive_wasm`, not the native online trait.

For a consumer this means:

- a browser wallet can be created, restored, persisted, derive addresses, read its snapshot and **sync its BDK wallet** against Esplora, so new funding of its own addresses becomes visible in its BTC balance;
- it can **receive and ACK a pending proxy consignment** whose invoice was created for its keys, coloring the UTXO and importing an unknown contract;
- sending, proxy invoice creation and media upload still need the native flow, so the browser cannot start a transfer or reserve an invoice;
- `syncOnline` resumes a receive left in `WaitingSafeHeight` or `WaitingBroadcast`, and a terminal (`Settled`/`Failed`) one is skipped, but `WaitingConfirmations` settlement, expiry-based failure and the rest of the native refresh lifecycle still need the native wallet.

## Unsupported features and explicit errors

| Feature | On wasm32 |
| ------- | --------- |
| Filesystem backups (absolute paths, tempdirs) | Refused at the public entry points with an error saying the API needs a filesystem; use the byte API instead |
| Encrypted byte backups (create, restore, info) | Supported: `RgbLibWallet.backup`, `restoreBackup` and `backupInfo` use the native archive and encryption format, built and read in memory |
| Legacy BDK file-store migration | Compile-time absent |
| Legacy RGB filesystem-store migration | Finding an `rgb/` store in the adapter is an explicit error |
| Multisig hub coordination | Native `_online` only; the hub client and the hub-coordinated `MultisigWallet::get_address` are absent. `RgbLibMultisigWallet.getAddress(index)` derives from the descriptors instead. |
| RGB online flow (transfer, send, proxy invoice reservation, media upload, hub) | Not assembled; BDK sync and proxy receive are supported, see above |
| Out-of-band consignment import (`provide_out_of_band_consignment`) and ACK (`provide_out_of_band_ack`) | Native `_online` only: both core methods take an `Online` indexer and may broadcast, so they have no wasm-reachable form |
| Native log files | No file logger; the logger is discarded |
| `bdk_pending.json` crash recovery | Not needed; the in-memory database and snapshot are the only persistence steps |
| Web Worker | Not required, not implemented |

The supported hub-free multisig subset covers construction, descriptors, database mutations, flush and restore, and the exported class adds `id`, `getKeys`, `getDescriptors` and the descriptor-derived `getAddress(index)`. The hub-coordinated address, `goOnline`, voting and the multisig send flow are native-only.

## Adding a backend without duplicating wallet logic

A new backend is added inside this crate, not in the binding. The wallet logic stays in one place; only the narrow seams change.

### Database

The database seam is `RgbLibDatabase` (crate-internal), with a native `Sqlite` variant and a `Memory` variant. `Wallet::new` opens the target default; `Wallet::new_in_memory` selects the memory backend; `Wallet::from_snapshot` rebuilds it from bytes.

To add a backend:

1. Add a variant (or an equivalent backend type) to `RgbLibDatabase`.
2. Implement the transaction, commit, snapshot and restore behavior used by the existing variants.
3. Wire construction through `new_with_database` and a narrow public constructor such as
   `new_in_memory`.
4. Keep `snapshot()` returning `None` for a backend that persists itself, and `Some(bytes)` only for
   a backend the host must persist.

Do not put SQL, storage or network calls in the binding: the binding should only call the shared constructors and the snapshot/flush methods.

### Files and blobs

`WalletFiles` is the wallet-relative file seam. `NativeFiles` maps keys to a directory; `WasmFiles` keeps blobs in memory and travels them in the snapshot. An adapter that owns in-memory state implements `snapshot_state` and `restore_snapshot_state`.

A new adapter implements `WalletFiles`, is selected at wallet construction, and must preserve the logical keys documented in `src/wallet/files.rs` (`assets/`, `media_files/`, `transfers/` and so on). Native callers keep the same paths.

### Runtime, storage and chain

- **Durable storage:** implement the equivalent of `persistence::{save_snapshot, load_snapshot,
  delete_snapshot}` for the host. Keep the same contract: one commit boundary, restore before
  constructing the wallet, last committed write wins.
- **Chain access:** implement `AsyncChainResolver` and the transport operations. Validation,
  consumption and RGB state transitions stay in the shared wallet code.

The rule is simple: a backend supplies storage, runtime or transport primitives. It must not copy wallet, RGB or transaction logic.

## Relationship to `UTEXO-Protocol/rgb-lib-wasm`

`UTEXO-Protocol/rgb-lib-wasm` was used only as a reference while designing the in-memory backend and the browser storage model. It is **not required at runtime**, is not a dependency of this crate or of the generated package, and nothing here loads or links it. The supported package is the one built from `bindings/wasm` in this repository.

## Command verification

| Command | Verified by |
| ------- | ----------- |
| Root wasm checks, `wasm_graph_check.sh`, `wasm_gate.sh` | Local gate, 217 native tests |
| `wasm-pack build ... --target web` and `--target nodejs` | CI `wasm_bindings` job |
| `node bindings/wasm/smoke/smoke.cjs` | CI `wasm_bindings` job |
| Browser lifecycle `cargo test ... wallet,esplora_async` | CI `wasm_browser_lifecycle` job |
| `scripts/wasm_online_smoke.sh` | Documented opt-in script; requires a controlled regtest endpoint and browser runner, so it does not run in the default gate |

See [`bindings/wasm/README.md`](../bindings/wasm/README.md) for the shorter package-level notes and [`bindings/wasm/demo/index.html`](../bindings/wasm/demo/index.html) for a runnable browser example.
