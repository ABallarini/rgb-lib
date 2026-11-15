//! Opt-in browser test for the BFA EVM claim prefetch and reject list transport.
//!
//! What it proves: [`PrefetchedClaims::fetch`] and [`PrefetchedClaims::fetch_reject_list`] reach a
//! JSON-RPC node through the real browser `fetch` backend, with the CORS preflight the browser
//! performs, and turn its answers into the statuses, the recorded flag, the expiration set and the
//! circulating supply the receive driver consumes. The reject list is read through the same
//! transport and its pages/decisions are asserted. The chain check runs before any lock is read,
//! and a failure never carries the RPC URL (hosted endpoints keep their API key in it).
//!
//! The node is the dependency-free mock in `scripts/mock_evm_rpc.mjs` (no anvil, no docker, no
//! external network). The test is opt-in and deterministic:
//!
//! - it runs for real only when the crate is compiled with `RGB_MOCK_EVM_RPC_URL` set (a
//!   compile-time env var, read through `option_env!`). Without it the test returns early, which is
//!   the case in a browser job that starts no mock.
//! - it never broadcasts and never spends: every request is a read.
//! - it asserts the exact JSON-RPC call order, so a change to what the prefetch asks for (or the
//!   block it asks as of) fails here.
//!
//! Run it locally the way `.github/workflows/wasm.yml` does: start
//! `node scripts/mock_evm_rpc.mjs --port 18545`, export `RGB_MOCK_EVM_RPC_URL=http://127.0.0.1:18545`
//! and run the wasm test target. The CI job also guards on the mock's `/__count`, so an early
//! return cannot pass silently.

use wasm_bindgen_test::wasm_bindgen_test;

use super::*;
use crate::api::evm_abi::MintLockStatus;
use crate::api::evm_claims::{EvmReceiveConfig, PrefetchedClaims};
use crate::no_wallet::validation::PendingClaims;

// `run_in_browser` is a per-binary setting, already applied by `test_wasm.rs`.

/// Base URL of the local mock JSON-RPC node, baked in at compile time.
const MOCK_RPC_URL: Option<&str> = option_env!("RGB_MOCK_EVM_RPC_URL");

/// EIP-155 chain ID the mock reports.
const CHAIN_ID: u64 = 31337;
/// Amount of the claim whose lock the mock records before the block it commits to.
const CONFIRMED_AMOUNT: u64 = 100;
/// Amount of the claim the mock records no lock for.
const PENDING_AMOUNT: u64 = 200;
/// Amount of the claim whose lock the mock records after the block it commits to.
const EXPIRED_AMOUNT: u64 = 300;
/// Maximum number of blocks after the latest one a received mint may commit to, in the test
/// config: only carried through, the prefetch never checks it.
const MAX_MINT_LOCK_BLOCKS: u64 = 100;

fn mock_base() -> &'static str {
    MOCK_RPC_URL
        .expect("the test returns early without the mock URL")
        .trim_end_matches('/')
}

/// The endpoint of the mock node, with an optional query profile (`?chain_id=1`, `?fail=500`).
fn rpc_url(query: &str) -> String {
    format!("{}/rpc{query}", mock_base())
}

fn config(query: &str) -> EvmReceiveConfig {
    EvmReceiveConfig {
        rpc_url: rpc_url(query),
        max_mint_lock_blocks: MAX_MINT_LOCK_BLOCKS,
    }
}

/// Read one of the mock's control endpoints (`/__health`, `/__calls`, `/__reset`, ...).
async fn control(path: &str) -> serde_json::Value {
    let url = format!("{}{path}", mock_base());
    let response = reqwest_fetch::Client::new()
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("mock control GET {path}: {e}"));
    let status = response.status();
    assert!(
        status.is_success(),
        "mock control GET {path}: HTTP {status}"
    );
    response
        .json()
        .await
        .unwrap_or_else(|e| panic!("mock control GET {path} body: {e}"))
}

/// Clear the mock's call log and counter, so the next phase asserts exactly its own requests.
async fn reset_mock() {
    control("/__reset").await;
}

/// The JSON-RPC requests the mock served since the last reset, in order.
async fn mock_calls() -> Vec<String> {
    control("/__calls")
        .await
        .get("calls")
        .and_then(serde_json::Value::as_array)
        .expect("the mock reports a calls array")
        .iter()
        .map(|call| call.as_str().expect("a call label is a string").to_string())
        .collect()
}

fn claim(b: u8, amount: u64, before_block: u64) -> Claim {
    Claim::Lock {
        opid: OpId::from([b; 32]),
        witness_id: RgbTxid::from_byte_array([b; 32]),
        amount,
        before_block,
    }
}

fn location() -> BridgeLocation {
    BridgeLocation::Evm(EvmContract {
        chain_id: CHAIN_ID,
        address: EvmAddress::default(),
    })
}

fn pending(claims: Vec<Claim>) -> PendingClaims {
    PendingClaims {
        bridge_location: location(),
        claims,
    }
}

/// An opout of the reject list entries the mock serves (`ty` 4000, the given `no`).
fn opout(b: u8, no: u16) -> Opout {
    Opout {
        op: OpId::from([b; 32]),
        ty: AssignmentType::with(4000),
        no,
    }
}

#[wasm_bindgen_test]
async fn bfa_claim_prefetch_and_reject_list_over_the_browser_transport() {
    if MOCK_RPC_URL.is_none() {
        return;
    }
    let confirmed = claim(1, CONFIRMED_AMOUNT, 18);
    let unconfirmed = claim(2, PENDING_AMOUNT, 30);
    let expired = claim(3, EXPIRED_AMOUNT, 18);

    // A node on another chain is refused before any lock is read: the mock's `?chain_id` profile
    // reports 1, so the mismatch is the node's, not the consignment's.
    reset_mock().await;
    let result =
        PrefetchedClaims::fetch(&config("?chain_id=1"), &pending(vec![confirmed.clone()])).await;
    assert!(
        matches!(
            result,
            Err(Error::EvmChainIdMismatch {
                expected: CHAIN_ID,
                actual: 1
            })
        ),
        "a node on another chain was not refused: {result:?}"
    );
    assert_eq!(
        mock_calls().await,
        ["eth_chainId"],
        "the chain must be checked before any lock is read"
    );

    // A transport failure never carries the URL, which hosted endpoints keep their API key in.
    // The mock's `?fail` profile answers the JSON-RPC request with that HTTP status.
    reset_mock().await;
    let secret = "api-key-0123456789";
    let failing = config(&format!("?fail=500&key={secret}"));
    let result = PrefetchedClaims::fetch(&failing, &pending(vec![confirmed.clone()])).await;
    let message = result
        .expect_err("the failing endpoint was not reported")
        .to_string();
    assert!(
        message.contains("HTTP status 500"),
        "unexpected error: {message}"
    );
    assert!(
        !message.contains(secret),
        "the error leaks the RPC URL: {message}"
    );

    // The reject list: `length()` at the finalized and at the latest block, then one `entries`
    // page, whose rejected and allowed entries are turned into decisions.
    reset_mock().await;
    let contract = EvmContract {
        chain_id: CHAIN_ID,
        address: EvmAddress::default(),
    };
    let list = PrefetchedClaims::fetch_reject_list(&config(""), &contract)
        .await
        .expect("reject list prefetch");
    assert!(list.rejects(&opout(0x44, 7)), "the rejected entry was lost");
    assert!(list.allows(&opout(0x55, 8)), "the allowed entry was lost");
    assert!(!list.allows(&opout(0x44, 7)));
    assert!(!list.rejects(&opout(0x55, 8)));
    assert_eq!(
        mock_calls().await,
        [
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBlockByNumber:finalized",
            "eth_call:0x1f7b6d32:0xf",
            "eth_call:0x1f7b6d32:latest",
            "eth_call:0x17b937e6:latest"
        ]
    );

    // The prefetch itself: the finalized block is 15, so a recorded lock below the block the claim
    // commits to is Confirmed, a missing one stays Pending while the lock could still be included,
    // and a lock recorded at or after that block is Expired. The `0xf` block parameter in the call
    // log below is what proves the calls read the finalized state; `latest` proves the recorded
    // flag and the supply read the head.
    reset_mock().await;
    let prefetched = PrefetchedClaims::fetch(
        &config(""),
        &pending(vec![
            confirmed.clone(),
            unconfirmed.clone(),
            expired.clone(),
        ]),
    )
    .await
    .expect("claim prefetch");

    assert_eq!(prefetched.chain_id(), CHAIN_ID);
    assert_eq!(prefetched.latest_block(), 19);
    assert_eq!(prefetched.max_mint_lock_blocks(), MAX_MINT_LOCK_BLOCKS);
    assert_eq!(prefetched.circulating_supply(), Some(1_000));

    assert_eq!(
        prefetched.lock_status(&confirmed),
        Some(MintLockStatus::Confirmed)
    );
    assert_eq!(
        prefetched.lock_status(&unconfirmed),
        Some(MintLockStatus::Pending)
    );
    assert_eq!(
        prefetched.lock_status(&expired),
        Some(MintLockStatus::Expired)
    );

    assert_eq!(prefetched.is_lock_recorded(&confirmed), Some(true));
    assert_eq!(prefetched.is_lock_recorded(&unconfirmed), Some(false));
    // recorded, but not before the block the claim commits to
    assert_eq!(prefetched.is_lock_recorded(&expired), Some(false));

    assert!(!prefetched.is_expired(&OpId::from([1; 32])));
    assert!(!prefetched.is_expired(&OpId::from([2; 32])));
    assert!(prefetched.is_expired(&OpId::from([3; 32])));

    assert!(prefetched.is_confirmed(&location(), &confirmed).unwrap());
    assert!(!prefetched.is_confirmed(&location(), &unconfirmed).unwrap());
    assert!(prefetched.is_confirmed(&location(), &expired).is_err());

    assert_eq!(
        mock_calls().await,
        [
            "eth_chainId",
            "eth_getBlockByNumber:finalized",
            "eth_call:0x2ce06e2d:0xf",
            "eth_call:0x2ce06e2d:latest",
            "eth_call:0x2ce06e2d:0xf",
            "eth_call:0x2ce06e2d:latest",
            "eth_call:0x2ce06e2d:0xf",
            "eth_call:0x2ce06e2d:latest",
            "eth_blockNumber",
            "eth_call:0x9358928b:latest"
        ],
        "the prefetch asked the node something else, or in another order"
    );

    // Left at the end so the CI guard on `/__count` sees a run that really happened: an early
    // return (or a prefetch that asked nothing) leaves the counter below this.
    let count = control("/__count")
        .await
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .expect("the mock reports a count");
    assert_eq!(count, 10, "unexpected number of JSON-RPC requests");
}
