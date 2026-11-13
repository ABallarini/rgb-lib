//! Opt-in browser smoke test for the read-only wasm online path.
//!
//! What "online" means on wasm today: the browser reaches an Esplora endpoint through `fetch`; the
//! async transport/resolver answer the chain questions the native indexer answers; and
//! [`Wallet::sync_async`](super::Wallet::sync_async) runs a read-only BDK full scan through that
//! transport, persisting the result through the wallet's own database seam. The RGB online flow
//! (`RgbWalletOpsOnline`, `OnlineOptions`, `go_online`, consignment reception, transfers) stays
//! gated by the native-only `_online` feature, which `esplora_async` deliberately does not enable;
//! this test still asserts that gate.
//!
//! The test is opt-in and deterministic:
//!
//! - it runs for real only when the crate is compiled with `RGB_REGTEST_ESPLORA_URL` set (a
//!   compile-time env var, read through `option_env!`). Without it the test returns early, which
//!   is the case in the default `wasm_browser_lifecycle` CI job: no regtest service is available
//!   there.
//! - it never broadcasts and never spends: every request is a read (tip height, block hash, block
//!   header, a block's first TX ID, that TX, its confirmations, the fee-estimate map, the
//!   resolver's witness/header/chain-net answers, and a wallet BDK full scan).
//! - the optional `RGB_REGTEST_PROXY_URL` enables one read-only proxy request (`server.info`).
//! - the optional `RGB_REGTEST_MNEMONIC` makes the funded-balance check real: the harness funds
//!   the first internal receive address of that mnemonic, and the test asserts the scan sees it.
//!
//! Run it through `scripts/wasm_online_smoke.sh`, which documents the controlled regtest setup
//! and exports the variables below. Temporal caveat: because the env vars are compile-time, a
//! value baked into a previous build is reused until the crate is rebuilt; the script touches this
//! file before running to force the rebuild.

use std::num::NonZeroU32;
use std::str::FromStr;

use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

use super::indexer_async::{EsploraResolver, EsploraTransport};
use super::resolver_async::AsyncChainResolver;
use super::*;
use crate::api::fetch::ProxyFetchClient;

wasm_bindgen_test_configure!(run_in_browser);

/// Esplora base URL of the controlled regtest environment, baked in at compile time.
const ESPLORA_URL: Option<&str> = option_env!("RGB_REGTEST_ESPLORA_URL");
/// Optional proxy base URL of the same environment, baked in at compile time.
const PROXY_URL: Option<&str> = option_env!("RGB_REGTEST_PROXY_URL");
/// Optional mnemonic whose first internal receive address the harness funds, baked in at compile
/// time. Without it the funded-balance assertion is skipped.
const FUNDED_MNEMONIC: Option<&str> = option_env!("RGB_REGTEST_MNEMONIC");
/// Optional proxy transfer ID, baked in at compile time, addressed to a pending proxy receive of
/// the `RGB_REGTEST_MNEMONIC` wallet. With it, the receive smoke runs for real; without it the
/// receive smoke returns early.
const RECEIVE_TRANSFER_ID: Option<&str> = option_env!("RGB_REGTEST_TRANSFER_ID");

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.filter(|v| !v.is_empty())
}

// Browser test for the fetch-level request deadline the transport installs. `esplora-client`
// ignores `Builder::timeout` on wasm32, so the only proof is a stalled `fetch` that has to be
// aborted by the wrapper.
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
let originalFetch = null;

export function installStalledFetch() {
    const g = globalThis;
    if (originalFetch === null) originalFetch = g.fetch;
    g.__stalledFetchCalls = 0;
    g.fetch = function (input) {
        g.__stalledFetchCalls += 1;
        return new Promise(function (_resolve, reject) {
            const signal = input && input.signal;
            // no deadline signal means the request would never settle: a bare promise it is
            if (!signal) return;
            if (signal.aborted) {
                reject(signal.reason);
                return;
            }
            signal.addEventListener('abort', function () {
                reject(signal.reason);
            }, { once: true });
        });
    };
}

export function restoreFetch() {
    if (originalFetch !== null) {
        globalThis.fetch = originalFetch;
        originalFetch = null;
    }
}

export function stalledFetchCalls() {
    return globalThis.__stalledFetchCalls || 0;
}

export function deadlineSupported() {
    const AbortSignalImpl = globalThis.AbortSignal;
    return !!(AbortSignalImpl && AbortSignalImpl.any && AbortSignalImpl.timeout);
}
"#)]
extern "C" {
    fn installStalledFetch();
    fn restoreFetch();
    fn stalledFetchCalls() -> u32;
    fn deadlineSupported() -> bool;
}

/// A stalled request must be aborted by the deadline the transport installed, not left pending.
///
/// `esplora-client` drops `Builder::timeout` on wasm32, so without the `fetch` wrapper this test
/// would never settle: the mock rejects only when the request signal aborts.
#[wasm_bindgen_test]
async fn a_stalled_fetch_is_aborted_within_the_request_deadline() {
    // the wrapper falls back to a plain fetch without a deadline on such a browser, so there is
    // no deadline to wait for here either
    if !deadlineSupported() {
        return;
    }
    installStalledFetch();
    let transport = EsploraTransport::new_with_timeout("https://esplora.invalid", 1)
        .expect("build the transport over the mocked fetch");
    let started = js_sys::Date::now();
    let result = transport.get_latest_block_height().await;
    let elapsed = js_sys::Date::now() - started;
    restoreFetch();

    assert!(
        result.is_err(),
        "a stalled request resolved instead of hitting the deadline"
    );
    assert_eq!(
        stalledFetchCalls(),
        1,
        "the stalled request must be issued once: a transport error is not retried"
    );
    assert!(
        elapsed < 5_000.0,
        "the stalled request took {elapsed} ms, above the 1000 ms deadline"
    );
}

#[wasm_bindgen_test]
#[ignore]
async fn regtest_esplora_online_smoke() {
    // The default browser CI job has no regtest service. Returning here keeps it green; the
    // script sets the variable and runs this test for real.
    let Some(url) = non_empty(ESPLORA_URL) else {
        return;
    };

    // The wallet online flow is not assembled on wasm: esplora_async must not enable _online.
    // Replace this guard when the transport is wired into WalletOnline.
    assert!(
        !cfg!(feature = "_online"),
        "esplora_async enabled the native online feature on wasm"
    );

    let transport = EsploraTransport::new(url).expect("build the browser Esplora transport");

    // Tip height and the hash of the tip block.
    let height = transport
        .get_latest_block_height()
        .await
        .expect("regtest Esplora tip height");
    assert!(height > 0, "regtest chain has no blocks: {height}");
    let tip_hash = transport
        .block_hash(height as usize)
        .await
        .expect("tip block hash");
    assert_eq!(tip_hash.len(), 64, "not a block hash: {tip_hash}");

    // Header and chain-net through the resolver, so both async answers the validation path needs
    // are exercised. Block 1 exists because height > 0.
    let resolver =
        EsploraResolver::new(EsploraTransport::new(url).expect("build the resolver transport"));
    resolver
        .check_chain_net(ChainNet::BitcoinRegtest)
        .await
        .expect("the endpoint serves regtest");
    let block_one_hash = transport.block_hash(1).await.expect("block 1 hash");
    let block_one_header = resolver
        .get_block_header(NonZeroU32::new(1).expect("1 is non-zero"))
        .await
        .expect("block 1 header through the resolver");
    assert_eq!(
        block_one_header.block_hash().to_string(),
        block_one_hash,
        "the resolver returned the header of another block"
    );

    // A known TX: the coinbase of block 1, addressed by its index in that block.
    let block_one_hash =
        crate::bitcoin::BlockHash::from_str(&block_one_hash).expect("parse block 1 hash");
    let txid = transport
        .get_txid_at_block_index(&block_one_hash, 0)
        .await
        .expect("block 1 first TX ID")
        .expect("block 1 has no transaction");
    let tx = transport
        .get_tx(&txid.to_string())
        .await
        .expect("fetch the block 1 coinbase")
        .expect("the indexer does not know the block 1 coinbase");
    assert_eq!(tx.compute_txid(), txid);
    let confirmations = transport
        .get_tx_confirmations(&txid.to_string())
        .await
        .expect("block 1 coinbase confirmations")
        .expect("the indexer does not know the block 1 coinbase");
    assert!(confirmations > 0, "the coinbase is not confirmed");

    // The same witness, resolved to its mined position.
    let witness = resolver
        .resolve_witness(txid)
        .await
        .expect("resolve the block 1 coinbase witness");
    match witness.witness_ord() {
        WitnessOrd::Mined(pos) => assert_eq!(pos.height().get(), 1),
        other => panic!("the block 1 coinbase did not resolve as mined: {other:?}"),
    }

    // Fee estimation. A controlled regtest indexer may have no fee history yet: electrs then
    // serves an empty map, which the transport maps to `CannotEstimateFees`. That is the explicit
    // current behaviour, not a transport failure; when the endpoint has estimates they must be
    // usable.
    match transport.fee_estimation(2).await {
        Ok(estimate) => assert!(
            estimate > 0.0,
            "the endpoint returned a non-positive fee estimate: {estimate}"
        ),
        Err(Error::CannotEstimateFees) => {}
        Err(e) => panic!("fee estimation failed: {e}"),
    }

    // Read-only BDK wallet sync. The wallet is built over the in-memory backend, so the scan
    // persists into the DB and the host-side snapshot carries it.
    let funded = non_empty(FUNDED_MNEMONIC);
    let keys = match funded {
        Some(mnemonic) => crate::keys::restore_keys(
            BitcoinNetwork::Regtest,
            mnemonic.to_string(),
            WitnessVersion::Taproot,
        )
        .expect("the harness mnemonic is valid"),
        None => crate::keys::generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot),
    };
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let wallet_data = WalletData {
        data_dir: String::new(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 5,
        supported_schemas: AssetSchema::VALUES.to_vec(),
        allow_reckless_schemas: false,
    };
    let mut wallet = Wallet::new_in_memory(wallet_data.clone(), wallet_keys.clone())
        .expect("wallet over the in-memory backend");
    let receive_address = wallet.get_address().expect("vanilla receive address");
    wallet
        .sync_async(url, None)
        .await
        .expect("read-only BDK wallet sync");

    let wallet_tip = wallet
        .tip_height_async(url)
        .await
        .expect("tip height through the wallet");
    assert!(
        wallet_tip >= height,
        "the wallet tip went backwards: {wallet_tip} < {height}"
    );
    match wallet.fee_estimation_async(url, 2).await {
        Ok(estimate) => assert!(
            estimate > 0.0,
            "the wallet returned a non-positive fee estimate: {estimate}"
        ),
        Err(Error::CannotEstimateFees) => {}
        Err(e) => panic!("wallet fee estimation failed: {e}"),
    }

    // The scan is in the wallet DB, not only in BDK's stage: a snapshot restore sees the same
    // balance without another network access.
    let balance = wallet
        .get_btc_balance(None, true)
        .expect("BTC balance after sync");
    let snapshot = wallet
        .snapshot()
        .expect("the in-memory wallet snapshots")
        .expect("the in-memory wallet produces a snapshot");
    let mut restored = Wallet::from_snapshot(&snapshot, wallet_data, wallet_keys)
        .expect("restore the synced wallet from its snapshot");
    let restored_balance = restored
        .get_btc_balance(None, true)
        .expect("BTC balance of the restored wallet");
    assert_eq!(
        restored_balance.vanilla.future, balance.vanilla.future,
        "the sync did not reach the persisted wallet state"
    );

    if funded.is_some() {
        assert!(
            balance.vanilla.future > 0,
            "no funds seen for the scanned address {receive_address}: fund it before the smoke"
        );
    }

    // Optional read-only proxy smoke: `server.info` changes nothing on the server.
    if let Some(proxy_url) = non_empty(PROXY_URL) {
        let client = ProxyFetchClient::new(proxy_url).expect("build the browser proxy client");
        let response = client.get_info().await.expect("proxy server.info");
        let info = response.result.expect("server.info result");
        assert!(
            !info.version.is_empty(),
            "the proxy reported an empty version"
        );
        assert!(!info.protocol_version.is_empty());
    }
}

/// Opt-in real proxy receive and ACK.
///
/// Runs only when the Esplora and proxy URLs are set **and** the harness prepared a pending proxy
/// transfer for the `RGB_REGTEST_MNEMONIC` wallet, named by `RGB_REGTEST_TRANSFER_ID`. Preparing it
/// needs the native sender flow (the browser cannot reserve a proxy invoice yet): create a
/// `blindReceive`/`witnessReceive` on a native wallet with these keys, with proxy transport
/// endpoints, and send to it from another wallet. Without that setup the test returns early, as it
/// does in the default browser CI job.
#[wasm_bindgen_test]
#[ignore]
async fn regtest_proxy_receive_smoke() {
    let (Some(esplora_url), Some(proxy_url), Some(transfer_id)) = (
        non_empty(ESPLORA_URL),
        non_empty(PROXY_URL),
        non_empty(RECEIVE_TRANSFER_ID),
    ) else {
        return;
    };
    let Some(mnemonic) = non_empty(FUNDED_MNEMONIC) else {
        return;
    };

    let keys = crate::keys::restore_keys(
        BitcoinNetwork::Regtest,
        mnemonic.to_string(),
        WitnessVersion::Taproot,
    )
    .expect("the harness mnemonic is valid");
    let wallet_data = WalletData {
        data_dir: String::new(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 5,
        supported_schemas: AssetSchema::VALUES.to_vec(),
        allow_reckless_schemas: false,
    };
    let mut wallet = Wallet::new_in_memory(wallet_data, SinglesigKeys::from_keys(&keys, None))
        .expect("wallet over the in-memory backend");

    // the online sync lists the pending invoices and receives what the proxy holds for them
    wallet
        .sync_online_async(proxy_url, esplora_url, None)
        .await
        .expect("online sync with a pending proxy receive");

    // receiving the named transfer again is idempotent: it must return the same batch transfer
    let first = wallet
        .receive_transfer_async(proxy_url, esplora_url, transfer_id)
        .await
        .expect("receive the prepared proxy transfer")
        .expect("the prepared transfer belongs to a batch transfer");
    let second = wallet
        .receive_transfer_async(proxy_url, esplora_url, transfer_id)
        .await
        .expect("re-receive is idempotent");
    assert_eq!(second, Some(first));

    // the ACK is recorded locally and the transfer moved past WaitingCounterparty
    let txn = wallet
        .database()
        .begin_transaction()
        .expect("open a read txn");
    let db_data = txn.get_db_data(false).expect("wallet data");
    let transfer = db_data
        .transfers
        .iter()
        .find(|t| t.proxy_transfer_id.as_deref() == Some(transfer_id))
        .expect("the received transfer is in the database");
    assert_eq!(transfer.ack, Some(true), "the ACK was not recorded");
    let batch = db_data
        .batch_transfers
        .iter()
        .find(|b| b.idx == first)
        .expect("the received batch transfer is in the database");
    assert!(
        matches!(
            batch.status,
            TransferStatus::WaitingBroadcast | TransferStatus::WaitingConfirmations
        ),
        "unexpected status after ACK: {:?}",
        batch.status
    );
}
