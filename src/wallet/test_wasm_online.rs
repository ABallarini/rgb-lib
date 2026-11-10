//! Opt-in browser smoke test for the async Esplora transport and resolver.
//!
//! What "online" means on wasm today: the browser can reach an Esplora endpoint through
//! `fetch`, and the async transport/resolver below answer the chain questions the native
//! indexer answers. The wallet online flow itself (`RgbWalletOpsOnline`, `OnlineOptions`,
//! `go_online`, sync, fee estimation on a wallet, transfers) is still gated by the native-only
//! `_online` feature: `esplora_async` deliberately does not enable it, and this test asserts
//! that gate instead of pretending the flow exists. Wiring the transport into `WalletOnline` is a
//! later step.
//!
//! The test is opt-in and deterministic:
//!
//! - it runs for real only when the crate is compiled with `RGB_REGTEST_ESPLORA_URL` set (a
//!   compile-time env var, read through `option_env!`). Without it the test returns early, which
//!   is the case in the default `wasm_browser_lifecycle` CI job: no regtest service is available
//!   there.
//! - it never broadcasts and never spends: every request is a read (tip height, block hash, block
//!   header, a block's first TX ID, that TX, its confirmations, the fee-estimate map, and the
//!   resolver's witness/header/chain-net answers).
//! - the optional `RGB_REGTEST_PROXY_URL` enables one read-only proxy request (`server.info`).
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

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.filter(|v| !v.is_empty())
}

#[wasm_bindgen_test]
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
