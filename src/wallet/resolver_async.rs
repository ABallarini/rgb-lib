//! Async chain-resolution boundary.
//!
//! rgb-ops' `ResolveWitness` is synchronous, so no validation or consumption run can await inside
//! it. Both rgb-ops and rgb-consensus already separate the chain questions from the work that
//! answers them, which is what this module builds on:
//!
//! - `pending::Validator::start` / `next_bundle` / `finish` hand out one `WitnessTask` per
//!   witness, and `PendingValidation` owns its data, so phase 2 can be driven across an await;
//! - `stock.consume_consignment` (behind `import_contract` / `accept_transfer`) resolves every
//!   witness and header in a read-only pre-pass, before its own `store_transaction`;
//! - `stock.update_witnesses` resolves every candidate before its `store_transaction` too.
//!
//! Every one of those takes the answers from a `ResolveWitness`, synchronously. So the boundary is
//! a pair: [`AsyncChainResolver`] is the async source of the same three answers, and
//! [`PrefetchedChain`] is the sync `ResolveWitness` over what was fetched. Native builds keep
//! driving the blocking resolver as they are; the browser fetches through the async source and
//! hands the unchanged rgb-ops traits a prefetched resolver.
//!
//! The answers must be complete before the caller opens its DB transaction: rgb-lib opens its
//! `DbTxn` before validating a received consignment and keeping it open across the fetch is not an
//! option on a single-threaded browser.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use super::*;
use crate::bitcoin::block::Header;

/// Upper bound on the chain questions one consignment may cause the browser to fetch.
const MAX_PREFETCH_WITNESSES: usize = 512;
/// Upper bound on the block headers one consignment may cause the browser to fetch.
const MAX_PREFETCH_HEADERS: usize = 128;
/// Wall-clock budget for one whole prefetch, in milliseconds.
///
/// The count caps alone still let a slow endpoint hold the browser for `(512 + 128)` requests,
/// each up to its own transport deadline. This bounds the whole run instead: once it is spent the
/// prefetch stops asking and fails, so the caller never starts a validation on a partial snapshot.
const PREFETCH_DEADLINE_MS: u64 = 60_000;

/// Milliseconds on the platform clock, for the prefetch deadline.
///
/// Only differences matter, so the epoch is irrelevant: the browser's `Date.now` on wasm32,
/// `SystemTime` natively. A clock that cannot be read counts as `0`, which only makes a deadline
/// start earlier.
fn now_millis() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Fail once the prefetch budget is spent, before the next request is issued.
fn check_deadline(
    deadline_millis: u64,
    now: &impl Fn() -> u64,
) -> Result<(), WitnessResolverError> {
    if now() >= deadline_millis {
        return Err(WitnessResolverError::ResolverIssue(
            None,
            s!("chain prefetch exceeded its deadline"),
        ));
    }
    Ok(())
}

/// The chain answers a validation or consumption run needs, fetched asynchronously.
///
/// Method for method the async counterpart of `ResolveWitness`, so an adapter only has to change
/// how it fetches, and [`PrefetchedChain`] can feed the sync traits unchanged. Not object safe by
/// design: callers take it by generic parameter.
#[allow(dead_code)] // native builds drive the blocking resolver; the browser receive path uses this
pub(crate) trait AsyncChainResolver {
    /// Status of the witness TX with `witness_id`.
    async fn resolve_witness(
        &self,
        witness_id: RgbTxid,
    ) -> Result<WitnessStatus, WitnessResolverError>;

    /// Header of the block at `height` in the best chain.
    async fn get_block_header(&self, height: NonZeroU32) -> Result<Header, WitnessResolverError>;

    /// Check the resolver serves `chain_net`.
    async fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}

/// A [`ResolveWitness`] over answers fetched up front through an [`AsyncChainResolver`].
///
/// A witness or header outside the prefetched sets is an error, never a silent `Unresolved`: the
/// prefetch has to cover every question the run will ask, and a miss means the caller computed the
/// set wrongly, so failing loudly beats downgrading a witness the chain might know.
#[allow(dead_code)] // see `AsyncChainResolver`
#[derive(Debug)]
pub(crate) struct PrefetchedChain {
    chain_net: ChainNet,
    witnesses: BTreeMap<RgbTxid, WitnessStatus>,
    headers: BTreeMap<NonZeroU32, Header>,
}

#[allow(dead_code)]
impl PrefetchedChain {
    /// Fetch the witness statuses and block headers a run will ask for.
    ///
    /// Call this before beginning the DB transaction the validation or consumption then runs in.
    /// The chain net is checked first, so a resolver pointing at another chain fails before any
    /// witness is stored. The whole prefetch is bounded by [`PREFETCH_DEADLINE_MS`], checked
    /// before every request.
    pub(crate) async fn fetch<R: AsyncChainResolver>(
        resolver: &R,
        chain_net: ChainNet,
        witness_ids: impl IntoIterator<Item = RgbTxid>,
        heights: impl IntoIterator<Item = NonZeroU32>,
    ) -> Result<Self, WitnessResolverError> {
        let deadline_millis = now_millis().saturating_add(PREFETCH_DEADLINE_MS);
        Self::fetch_until(
            resolver,
            chain_net,
            witness_ids,
            heights,
            deadline_millis,
            now_millis,
        )
        .await
    }

    /// [`fetch`](Self::fetch) with the deadline and clock supplied by the caller.
    ///
    /// The clock seam is what lets the tests force an expiry without sleeping; production code
    /// always reaches this through `fetch`.
    async fn fetch_until<R: AsyncChainResolver, C: Fn() -> u64>(
        resolver: &R,
        chain_net: ChainNet,
        witness_ids: impl IntoIterator<Item = RgbTxid>,
        heights: impl IntoIterator<Item = NonZeroU32>,
        deadline_millis: u64,
        now: C,
    ) -> Result<Self, WitnessResolverError> {
        check_deadline(deadline_millis, &now)?;
        resolver.check_chain_net(chain_net).await?;
        let witness_ids: Vec<RgbTxid> = witness_ids.into_iter().collect();
        let heights: Vec<NonZeroU32> = heights.into_iter().collect();
        if witness_ids.len() > MAX_PREFETCH_WITNESSES || heights.len() > MAX_PREFETCH_HEADERS {
            return Err(WitnessResolverError::ResolverIssue(
                None,
                s!("consignment asks for more chain data than the prefetch limit"),
            ));
        }
        let mut witnesses = BTreeMap::new();
        for witness_id in witness_ids {
            check_deadline(deadline_millis, &now)?;
            let status = resolver.resolve_witness(witness_id).await?;
            witnesses.insert(witness_id, status);
        }
        let mut headers = BTreeMap::new();
        for height in heights {
            check_deadline(deadline_millis, &now)?;
            let header = resolver.get_block_header(height).await?;
            headers.insert(height, header);
        }
        Ok(Self {
            chain_net,
            witnesses,
            headers,
        })
    }
}

impl ResolveWitness for PrefetchedChain {
    fn resolve_witness(&self, witness_id: RgbTxid) -> Result<WitnessStatus, WitnessResolverError> {
        self.witnesses.get(&witness_id).cloned().ok_or_else(|| {
            WitnessResolverError::ResolverIssue(Some(witness_id), s!("witness was not prefetched"))
        })
    }

    fn get_block_header(&self, height: NonZeroU32) -> Result<Header, WitnessResolverError> {
        self.headers.get(&height).cloned().ok_or_else(|| {
            WitnessResolverError::ResolverIssue(None, s!("block header was not prefetched"))
        })
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        if self.chain_net == chain_net {
            Ok(())
        } else {
            Err(WitnessResolverError::WrongChainNet)
        }
    }
}

// Compile-time proof that the boundary plugs into the unchanged sync trait: rgb-ops keeps taking a
// `ResolveWitness`, so nothing in validation or consumption has to know about the async side.
const _: () = {
    const fn assert_resolve_witness<R: ResolveWitness>() {}
    assert_resolve_witness::<PrefetchedChain>();
};

// The tests need a runtime to drive the fetch future, and the crate only has one natively.
#[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::database::enums::AssetSchema;
    use crate::runtime::block_on;
    use crate::utils::BitcoinNetwork;
    use crate::wallet::setup_rgb;
    use crate::{RgbLibDatabase, RgbStock};

    /// What the fake was asked, in order, so the tests can prove how often and in which order the
    /// boundary fetches.
    #[derive(Default)]
    struct Calls {
        chain_nets: Vec<ChainNet>,
        witnesses: Vec<RgbTxid>,
        headers: Vec<NonZeroU32>,
    }

    /// Async source backed by canned answers, standing in for the browser transport.
    ///
    /// No network and no sleeping: every answer is deterministic and errors are injected through
    /// the `*_errors` maps, which are checked before the canned answer.
    struct FakeChain {
        witnesses: BTreeMap<RgbTxid, WitnessStatus>,
        headers: BTreeMap<NonZeroU32, Header>,
        chain_net: ChainNet,
        witness_errors: BTreeMap<RgbTxid, WitnessResolverError>,
        header_errors: BTreeMap<NonZeroU32, WitnessResolverError>,
        chain_net_error: Option<WitnessResolverError>,
        calls: Mutex<Calls>,
    }

    impl FakeChain {
        fn new(chain_net: ChainNet) -> Self {
            Self {
                witnesses: BTreeMap::new(),
                headers: BTreeMap::new(),
                chain_net,
                witness_errors: BTreeMap::new(),
                header_errors: BTreeMap::new(),
                chain_net_error: None,
                calls: Mutex::new(Calls::default()),
            }
        }

        fn calls(&self) -> (Vec<ChainNet>, Vec<RgbTxid>, Vec<NonZeroU32>) {
            let calls = self.calls.lock().expect("calls mutex is never poisoned");
            (
                calls.chain_nets.clone(),
                calls.witnesses.clone(),
                calls.headers.clone(),
            )
        }
    }

    impl AsyncChainResolver for FakeChain {
        async fn resolve_witness(
            &self,
            witness_id: RgbTxid,
        ) -> Result<WitnessStatus, WitnessResolverError> {
            self.calls
                .lock()
                .expect("calls mutex is never poisoned")
                .witnesses
                .push(witness_id);
            if let Some(error) = self.witness_errors.get(&witness_id) {
                return Err(error.clone());
            }
            self.witnesses.get(&witness_id).cloned().ok_or_else(|| {
                WitnessResolverError::ResolverIssue(
                    Some(witness_id),
                    s!("fake: witness TX is unknown"),
                )
            })
        }

        async fn get_block_header(
            &self,
            height: NonZeroU32,
        ) -> Result<Header, WitnessResolverError> {
            self.calls
                .lock()
                .expect("calls mutex is never poisoned")
                .headers
                .push(height);
            if let Some(error) = self.header_errors.get(&height) {
                return Err(error.clone());
            }
            self.headers.get(&height).cloned().ok_or_else(|| {
                WitnessResolverError::ResolverIssue(None, s!("fake: block header is unknown"))
            })
        }

        async fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
            self.calls
                .lock()
                .expect("calls mutex is never poisoned")
                .chain_nets
                .push(chain_net);
            if let Some(error) = &self.chain_net_error {
                return Err(error.clone());
            }
            if self.chain_net == chain_net {
                Ok(())
            } else {
                Err(WitnessResolverError::WrongChainNet)
            }
        }
    }

    /// Deterministic block header: only `nonce` varies, so two calls with the same nonce describe
    /// the same block and two different nonces describe a reorg.
    fn header(nonce: u32) -> Header {
        use crate::bitcoin::block::Version;
        use crate::bitcoin::hashes::Hash as _;
        use crate::bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

        Header {
            version: Version::from_consensus(2),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        }
    }

    fn height(height: u32) -> NonZeroU32 {
        NonZeroU32::new(height).expect("test heights are non-zero")
    }

    fn witness_tx() -> BdkTransaction {
        BdkTransaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    /// A TX the fake resolver does not know, so its id differs from `witness_tx`'s.
    fn other_witness_txid() -> RgbTxid {
        BdkTransaction {
            version: bdk_wallet::bitcoin::transaction::Version::ONE,
            ..witness_tx()
        }
        .compute_txid()
    }

    /// A resolver that does not support headers at all, to pin the `NotSupported` default.
    struct UnsupportedHeaderChain {
        chain_net: ChainNet,
    }

    impl AsyncChainResolver for UnsupportedHeaderChain {
        async fn resolve_witness(
            &self,
            _witness_id: RgbTxid,
        ) -> Result<WitnessStatus, WitnessResolverError> {
            Ok(WitnessStatus::Unresolved)
        }

        async fn get_block_header(
            &self,
            _height: NonZeroU32,
        ) -> Result<Header, WitnessResolverError> {
            // headers have no async counterpart on the native side yet
            Err(WitnessResolverError::NotSupported)
        }

        async fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
            if self.chain_net == chain_net {
                Ok(())
            } else {
                Err(WitnessResolverError::WrongChainNet)
            }
        }
    }

    /// A clock that advances one tick per read, so a test can pick which request overruns the
    /// budget without sleeping.
    fn ticking_clock() -> impl Fn() -> u64 {
        let tick = AtomicU64::new(0);
        move || tick.fetch_add(1, Ordering::SeqCst)
    }

    #[test]
    fn prefetched_answer_is_served_through_the_sync_trait() {
        let tx = witness_tx();
        let txid = tx.compute_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let status = WitnessStatus::Resolved(tx, WitnessOrd::Tentative);
        let block = header(1);
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(txid, status.clone());
        resolver.headers.insert(height(1), block);

        let prefetched = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [txid],
            [height(1)],
        ))
        .expect("prefetch");

        assert_eq!(
            ResolveWitness::resolve_witness(&prefetched, txid).expect("resolve"),
            status
        );
        assert_eq!(
            ResolveWitness::get_block_header(&prefetched, height(1)).expect("header"),
            block
        );
        assert_eq!(
            ResolveWitness::check_chain_net(&prefetched, chain_net),
            Ok(())
        );
    }

    #[test]
    fn repeated_resolutions_are_cache_hits_and_never_refetch() {
        let txid = witness_tx().compute_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(txid, WitnessStatus::Unresolved);
        resolver.headers.insert(height(2), header(2));

        let prefetched = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [txid],
            [height(2)],
        ))
        .expect("prefetch");
        for _ in 0..3 {
            assert_eq!(
                ResolveWitness::resolve_witness(&prefetched, txid),
                Ok(WitnessStatus::Unresolved)
            );
            assert_eq!(
                ResolveWitness::get_block_header(&prefetched, height(2)),
                Ok(header(2))
            );
        }

        let (chain_nets, witnesses, headers) = resolver.calls();
        assert_eq!(chain_nets, [chain_net], "the chain net is checked once");
        assert_eq!(witnesses, [txid], "the witness is fetched once");
        assert_eq!(headers, [height(2)], "the header is fetched once");
    }

    #[test]
    fn witness_outside_the_prefetch_set_is_an_error() {
        let txid = witness_tx().compute_txid();
        let other_txid = other_witness_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(txid, WitnessStatus::Unresolved);

        let prefetched =
            block_on(PrefetchedChain::fetch(&resolver, chain_net, [txid], [])).expect("prefetch");

        let error = ResolveWitness::resolve_witness(&prefetched, other_txid).unwrap_err();
        assert_matches!(
            error,
            WitnessResolverError::ResolverIssue(Some(id), _) if id == other_txid
        );
        assert_eq!(
            resolver.calls().1,
            [txid],
            "a miss is served from the map and never refetched"
        );
    }

    #[test]
    fn header_outside_the_prefetch_set_is_an_error_not_a_silent_answer() {
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.headers.insert(height(5), header(5));

        let prefetched = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(5)],
        ))
        .expect("prefetch");

        assert_eq!(
            ResolveWitness::get_block_header(&prefetched, height(6)).unwrap_err(),
            WitnessResolverError::ResolverIssue(None, s!("block header was not prefetched"))
        );
        assert_eq!(resolver.calls().2, [height(5)]);
    }

    #[test]
    fn a_fetch_that_asks_for_a_header_fails_before_any_answer_is_used() {
        let chain_net = ChainNet::BitcoinRegtest;
        let resolver = UnsupportedHeaderChain { chain_net };

        let error = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [NonZeroU32::new(1).unwrap()],
        ))
        .expect_err("header fetch is unsupported");

        assert_eq!(error, WitnessResolverError::NotSupported);
    }

    #[test]
    fn another_chain_net_is_rejected_before_fetching() {
        let resolver = FakeChain::new(ChainNet::BitcoinMainnet);

        let error = block_on(PrefetchedChain::fetch(
            &resolver,
            ChainNet::BitcoinRegtest,
            [],
            [height(1)],
        ))
        .expect_err("chain net mismatch");

        assert_eq!(error, WitnessResolverError::WrongChainNet);
        assert_eq!(
            resolver.calls(),
            (vec![ChainNet::BitcoinRegtest], vec![], vec![]),
            "a wrong chain net is caught before any witness or header is fetched"
        );
    }

    #[test]
    fn a_wrong_chain_net_declared_on_the_prefetched_chain_is_rejected() {
        let chain_net = ChainNet::BitcoinRegtest;
        let resolver = FakeChain::new(chain_net);
        let prefetched =
            block_on(PrefetchedChain::fetch(&resolver, chain_net, [], [])).expect("prefetch");

        assert_eq!(
            ResolveWitness::check_chain_net(&prefetched, ChainNet::BitcoinMainnet),
            Err(WitnessResolverError::WrongChainNet)
        );
    }

    #[test]
    fn a_prefetch_with_no_budget_left_makes_no_request() {
        let chain_net = ChainNet::BitcoinRegtest;
        let resolver = FakeChain::new(chain_net);

        // the clock is already at the deadline: even the chain-net check must not be issued
        let error = block_on(PrefetchedChain::fetch_until(
            &resolver,
            chain_net,
            [witness_tx().compute_txid()],
            [height(1)],
            1_000,
            || 1_000,
        ))
        .expect_err("the budget is already spent");

        assert_matches!(error, WitnessResolverError::ResolverIssue(None, _));
        assert_eq!(
            resolver.calls(),
            (vec![], vec![], vec![]),
            "no request is made once the deadline has passed"
        );
    }

    #[test]
    fn the_deadline_is_checked_before_every_request() {
        let first = witness_tx().compute_txid();
        let second = other_witness_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(first, WitnessStatus::Unresolved);
        resolver.witnesses.insert(second, WitnessStatus::Unresolved);
        resolver.headers.insert(height(1), header(1));

        // each clock read advances one tick: the chain-net check and the first witness fit in the
        // two-tick budget, the second witness starts past it
        let clock = ticking_clock();

        let error = block_on(PrefetchedChain::fetch_until(
            &resolver,
            chain_net,
            [first, second],
            [height(1)],
            2,
            clock,
        ))
        .expect_err("the budget expires mid-prefetch");

        assert_matches!(error, WitnessResolverError::ResolverIssue(None, _));
        assert_eq!(
            resolver.calls(),
            (vec![chain_net], vec![first], vec![]),
            "the expired request is never issued and later ones are not tried"
        );
    }

    #[test]
    fn an_expired_header_is_never_asked_for() {
        let txid = witness_tx().compute_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(txid, WitnessStatus::Unresolved);
        resolver.headers.insert(height(1), header(1));

        let clock = ticking_clock();

        // chain-net and the witness fit; the header starts past the budget
        let error = block_on(PrefetchedChain::fetch_until(
            &resolver,
            chain_net,
            [txid],
            [height(1)],
            2,
            clock,
        ))
        .expect_err("the header does not fit in the budget");

        assert_matches!(error, WitnessResolverError::ResolverIssue(None, _));
        assert_eq!(resolver.calls(), (vec![chain_net], vec![txid], vec![]));
    }

    #[test]
    fn chain_net_resolver_errors_are_propagated_unchanged() {
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.chain_net_error = Some(WitnessResolverError::ResolverIssue(
            None,
            s!("indexer is offline"),
        ));

        let error = block_on(PrefetchedChain::fetch(&resolver, chain_net, [], []))
            .expect_err("resolver error");

        assert_eq!(
            error,
            WitnessResolverError::ResolverIssue(None, s!("indexer is offline"))
        );
        assert_eq!(resolver.calls().1, Vec::<RgbTxid>::new());
    }

    #[test]
    fn a_failing_witness_stops_the_fetch_without_retrying_or_touching_later_ids() {
        let first = witness_tx().compute_txid();
        let second = other_witness_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let injected = WitnessResolverError::ResolverIssue(Some(first), s!("indexer is offline"));
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(second, WitnessStatus::Unresolved);
        resolver.witness_errors.insert(first, injected.clone());

        let error = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [first, second],
            [height(7)],
        ))
        .expect_err("witness resolution fails");

        assert_eq!(error, injected);
        assert_eq!(
            resolver.calls(),
            (vec![chain_net], vec![first], vec![]),
            "the failing witness is asked exactly once, no retry, later inputs untouched"
        );
    }

    #[test]
    fn fetch_asks_every_question_exactly_once() {
        let txid = witness_tx().compute_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.witnesses.insert(txid, WitnessStatus::Unresolved);
        resolver.headers.insert(height(1), header(1));
        resolver.headers.insert(height(2), header(2));

        block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [txid],
            [height(2), height(1)],
        ))
        .expect("prefetch");

        let (chain_nets, witnesses, headers) = resolver.calls();
        // the retry count lives in the transport's HTTP client (`INDEXER_RETRIES`); this boundary
        // makes one request per question and never retries by itself
        assert_eq!(chain_nets.len(), 1);
        assert_eq!(witnesses, [txid]);
        assert_eq!(headers, [height(2), height(1)], "fetched in input order");
    }

    #[test]
    fn fetched_maps_are_ordered_deterministically_regardless_of_input_order() {
        let first = witness_tx().compute_txid();
        let second = other_witness_txid();
        let chain_net = ChainNet::BitcoinRegtest;

        let fetch = |witnesses: [RgbTxid; 2], heights: [NonZeroU32; 2]| {
            let mut resolver = FakeChain::new(chain_net);
            resolver.witnesses.insert(
                first,
                WitnessStatus::Resolved(witness_tx(), WitnessOrd::Tentative),
            );
            resolver.witnesses.insert(second, WitnessStatus::Unresolved);
            resolver.headers.insert(height(1), header(1));
            resolver.headers.insert(height(9), header(9));
            block_on(PrefetchedChain::fetch(
                &resolver, chain_net, witnesses, heights,
            ))
            .expect("prefetch")
        };

        let forward = fetch([first, second], [height(1), height(9)]);
        let reverse = fetch([second, first], [height(9), height(1)]);

        // both name-keyed maps are `BTreeMap`s, so the prefetched resolver is byte-for-byte the
        // same regardless of the order the caller listed its questions in
        assert_eq!(format!("{forward:?}"), format!("{reverse:?}"));
        assert_eq!(
            ResolveWitness::resolve_witness(&forward, first),
            Ok(WitnessStatus::Resolved(witness_tx(), WitnessOrd::Tentative))
        );
        assert_eq!(
            ResolveWitness::resolve_witness(&forward, second),
            Ok(WitnessStatus::Unresolved)
        );
        assert_eq!(
            ResolveWitness::get_block_header(&forward, height(9)),
            Ok(header(9))
        );
    }

    #[test]
    fn a_zero_height_cannot_be_asked_for() {
        // the boundary takes `NonZeroU32`, so height underflow (block 0 or a subtraction to zero)
        // is impossible to express instead of silently asking for genesis
        assert!(NonZeroU32::new(0).is_none());

        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.headers.insert(height(1), header(1));
        let prefetched = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(1)],
        ))
        .expect("an ancient block is a normal header, not an error");
        assert_eq!(
            ResolveWitness::get_block_header(&prefetched, height(1)),
            Ok(header(1))
        );
    }

    #[test]
    fn a_reorg_after_the_prefetch_does_not_change_the_fetched_snapshot() {
        let chain_net = ChainNet::BitcoinRegtest;
        let old = header(10);
        let new = header(20);
        let mut resolver = FakeChain::new(chain_net);
        resolver.headers.insert(height(100), old);

        let before = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(100)],
        ))
        .expect("prefetch before the reorg");

        // same height, different block: the tip the resolver serves changed
        resolver.headers.insert(height(100), new);
        let after = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(100)],
        ))
        .expect("prefetch after the reorg");

        assert_eq!(
            ResolveWitness::get_block_header(&before, height(100)),
            Ok(old),
            "the prefetched chain is a point-in-time snapshot, not a live view"
        );
        assert_eq!(
            ResolveWitness::get_block_header(&after, height(100)),
            Ok(new),
            "a second prefetch sees the new best chain"
        );
        assert_eq!(resolver.calls().2, [height(100), height(100)]);
    }

    #[test]
    fn a_reorg_that_moves_the_tip_is_reflected_in_a_new_prefetch() {
        let chain_net = ChainNet::BitcoinRegtest;
        let mut resolver = FakeChain::new(chain_net);
        resolver.headers.insert(height(100), header(1));
        resolver.headers.insert(height(101), header(2));

        let before = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(100)],
        ))
        .expect("prefetch before the reorg");
        // the tip advances and the old tip block is reorged out: height 101 is now a different block
        resolver.headers.remove(&height(100));
        resolver.headers.insert(height(101), header(3));
        let after = block_on(PrefetchedChain::fetch(
            &resolver,
            chain_net,
            [],
            [height(101)],
        ))
        .expect("prefetch after the reorg");

        assert_eq!(
            ResolveWitness::get_block_header(&before, height(101)),
            Err(WitnessResolverError::ResolverIssue(
                None,
                s!("block header was not prefetched")
            )),
            "a height the snapshot did not cover is a miss, never a guessed header"
        );
        assert_eq!(
            ResolveWitness::get_block_header(&after, height(101)),
            Ok(header(3))
        );
    }

    #[test]
    fn an_invalid_resolver_answer_is_propagated_unchanged() {
        let txid = witness_tx().compute_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let injected = WitnessResolverError::IdMismatch {
            actual: other_witness_txid(),
            expected: txid,
        };
        let mut resolver = FakeChain::new(chain_net);
        resolver.witness_errors.insert(txid, injected.clone());

        let error = block_on(PrefetchedChain::fetch(&resolver, chain_net, [txid], []))
            .expect_err("invalid resolver data");

        assert_eq!(error, injected);
    }

    /// Seed a memory database with the NIA schema so the snapshot covers both the wallet tables and
    /// the RGB stock.
    fn seeded_memory_db() -> RgbLibDatabase {
        let db = RgbLibDatabase::new_memory();
        setup_rgb(&db, vec![AssetSchema::Nia], BitcoinNetwork::Regtest).expect("setup rgb");
        db
    }

    fn snapshot(db: &RgbLibDatabase) -> Vec<u8> {
        db.snapshot()
            .expect("snapshot")
            .expect("memory database has a snapshot")
    }

    /// A failed resolution while a transaction is open must leave the database untouched and drop
    /// every `on_commit` callback: the transaction is rolled back when it is dropped, exactly as
    /// the wallet path relies on when the resolver fails before it commits.
    ///
    /// The real rgb-ops paths resolve in a pre-pass before their own `store_transaction`, so in
    /// production the error usually lands before any write. This test also writes first, to prove
    /// the DB layer rolls back writes when the error escapes after one.
    #[test]
    fn failed_resolution_rolls_back_writes_and_drops_the_commit_callback() {
        let db = seeded_memory_db();
        let before = snapshot(&db);
        let committed = Arc::new(AtomicBool::new(false));

        let missing = other_witness_txid();
        let chain_net = ChainNet::BitcoinRegtest;
        let prefetched = block_on(PrefetchedChain::fetch(
            &FakeChain::new(chain_net),
            chain_net,
            [],
            [],
        ))
        .expect("empty prefetch");

        let result = {
            let txn = db.begin_transaction().expect("open txn");
            let flag = committed.clone();
            txn.on_commit(move || flag.store(true, Ordering::SeqCst));

            let result = (|| {
                let mut stock = RgbStock::new(&txn);
                // a write that must not survive the failed resolution
                stock
                    .upsert_witness(witness_tx().compute_txid(), WitnessOrd::Tentative)
                    .expect("seed write inside the transaction");
                // the resolution the run needed is missing from the prefetched chain
                ResolveWitness::resolve_witness(&prefetched, missing)?;
                Ok::<_, WitnessResolverError>(())
            })();
            // no commit: dropping the transaction is the rollback
            result
        };

        assert_matches!(
            result,
            Err(WitnessResolverError::ResolverIssue(Some(id), _)) if id == missing
        );
        assert!(
            !committed.load(Ordering::SeqCst),
            "commit callback must not run"
        );
        assert_eq!(
            snapshot(&db),
            before,
            "the database is row-for-row unchanged"
        );
    }

    /// Control for the rollback test: the same write and callback, committed, must be visible. This
    /// proves the rollback assertion above is not vacuous.
    #[test]
    fn a_committed_transaction_keeps_the_write_and_runs_the_callback() {
        let db = seeded_memory_db();
        let before = snapshot(&db);
        let committed = Arc::new(AtomicBool::new(false));

        let txn = db.begin_transaction().expect("open txn");
        let flag = committed.clone();
        txn.on_commit(move || flag.store(true, Ordering::SeqCst));
        {
            let mut stock = RgbStock::new(&txn);
            stock
                .upsert_witness(witness_tx().compute_txid(), WitnessOrd::Tentative)
                .expect("write inside the transaction");
        }
        txn.commit().expect("commit");

        assert!(committed.load(Ordering::SeqCst), "commit callback runs");
        assert_ne!(snapshot(&db), before, "the committed write is visible");
    }
}
