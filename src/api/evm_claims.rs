//! EVM claim (mint lock) prefetch for the browser receive.
//!
//! Claim resolution in rgb-ops is synchronous, so the browser cannot ask the EVM node while the
//! receive transaction is open. This module fetches every answer the shared receive driver will
//! ask for up front, inside one bounded run, and hands the driver a [`PrefetchedClaims`] that
//! implements [`ResolveClaim`] over them.
//!
//! The fetch is transport independent: natively it is exercised with a fake client, while on
//! wasm32 it runs over `EvmFetchClient`, the same shared ABI code the native blocking client
//! uses. A failure never carries the RPC URL, which hosted endpoints keep their API key in.

// native builds use the fetch logic only from the tests and the receive driver (wasm32)
#![cfg_attr(
    not(all(target_arch = "wasm32", feature = "esplora_async")),
    allow(dead_code)
)]

use std::collections::{HashMap, HashSet};

use super::evm_abi::{MintLockStatus, RejectListLog};
use super::*;
use crate::no_wallet::validation::{PendingClaims, RejectList};

#[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
use super::evm_fetch::EvmFetchClient;

/// Upper bound on the mint locks one receive may ask about.
///
/// Claims come from the consignment, which is not trusted: a consignment with thousands of mints
/// would otherwise make the browser perform that many RPC calls before it can open the wallet.
pub(crate) const MAX_PREFETCH_CLAIMS: usize = 64;

/// Wall-clock budget for one whole claim prefetch, in milliseconds.
const PREFETCH_DEADLINE_MS: u64 = 60_000;

/// Asynchronous EVM answers the claim prefetch needs.
///
/// Implemented by `EvmFetchClient` on wasm32 and by a fake in the native tests, so the fetch
/// logic is tested without a network or a `reqwest` dependency of its own.
pub(crate) trait ClaimEvmClient {
    /// EIP-155 chain ID reported by the node.
    async fn chain_id(&self) -> Result<u64, Error>;

    /// Number of the latest finalized block.
    async fn finalized_block_number(&self) -> Result<u64, Error>;

    /// Number of the latest block.
    async fn block_number(&self) -> Result<u64, Error>;

    /// Status of a lock as of `finalized_block`.
    async fn mint_lock_status(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
        finalized_block: u64,
    ) -> Result<MintLockStatus, Error>;

    /// Whether a lock is recorded as of the latest block, finalized or not.
    async fn mint_lock_recorded(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
    ) -> Result<bool, Error>;

    /// Circulating supply accounted by the contract, if any.
    async fn circulating_supply(&self, contract: &EvmAddress) -> Result<Option<u64>, Error>;

    /// All the entries of the reject list kept by `contract`.
    async fn reject_list_entries(&self, contract: &EvmAddress) -> Result<RejectListLog, Error>;
}

#[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
impl ClaimEvmClient for EvmFetchClient {
    async fn chain_id(&self) -> Result<u64, Error> {
        EvmFetchClient::chain_id(self).await
    }

    async fn finalized_block_number(&self) -> Result<u64, Error> {
        EvmFetchClient::finalized_block_number(self).await
    }

    async fn block_number(&self) -> Result<u64, Error> {
        EvmFetchClient::block_number(self).await
    }

    async fn mint_lock_status(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
        finalized_block: u64,
    ) -> Result<MintLockStatus, Error> {
        EvmFetchClient::mint_lock_status(
            self,
            contract,
            lock_id,
            amount,
            before_block,
            finalized_block,
        )
        .await
    }

    async fn mint_lock_recorded(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
    ) -> Result<bool, Error> {
        EvmFetchClient::mint_lock_recorded(self, contract, lock_id, amount, before_block).await
    }

    async fn circulating_supply(&self, contract: &EvmAddress) -> Result<Option<u64>, Error> {
        EvmFetchClient::circulating_supply(self, contract).await
    }

    async fn reject_list_entries(&self, contract: &EvmAddress) -> Result<RejectListLog, Error> {
        EvmFetchClient::reject_list_entries(self, contract).await
    }
}

/// The EVM endpoints a browser receive may use, by EIP-155 chain ID, with a default for a
/// consignment whose bridge chain is not named by the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvmReceiveOptions {
    /// One endpoint per bridge chain ID.
    pub chains: HashMap<u64, EvmReceiveConfig>,
    /// Endpoint used when the consignment's chain is not in [`Self::chains`].
    pub default: Option<EvmReceiveConfig>,
}

impl EvmReceiveOptions {
    /// Options with one endpoint per chain ID.
    pub fn by_chain(chains: HashMap<u64, EvmReceiveConfig>) -> Self {
        Self {
            chains,
            default: None,
        }
    }

    /// Options with a single endpoint, whatever the bridge chain ID.
    pub fn single(config: EvmReceiveConfig) -> Self {
        Self {
            chains: HashMap::new(),
            default: Some(config),
        }
    }

    /// The endpoint for `chain_id`, if configured.
    pub fn config(&self, chain_id: u64) -> Option<&EvmReceiveConfig> {
        self.chains.get(&chain_id).or(self.default.as_ref())
    }

    /// Whether no endpoint is configured.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty() && self.default.is_none()
    }
}

/// An EVM endpoint used while receiving a BFA consignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReceiveConfig {
    /// URL of the JSON-RPC endpoint connected to the bridge chain.
    pub rpc_url: String,
    /// Maximum number of blocks after the latest one the block a received mint commits to can be.
    pub max_mint_lock_blocks: u64,
}

/// The EVM answers a receive needs, fetched before its database transaction opens.
#[cfg_attr(
    all(target_arch = "wasm32", feature = "esplora_async"),
    allow(dead_code)
)]
#[derive(Debug)]
pub struct PrefetchedClaims {
    chain_id: u64,
    finalized_block: u64,
    latest_block: u64,
    statuses: HashMap<OpId, MintLockStatus>,
    paying_lock_recorded: HashMap<OpId, bool>,
    circulating_supply: Option<u64>,
    expired: HashSet<OpId>,
    max_mint_lock_blocks: u64,
}

impl PrefetchedClaims {
    /// EIP-155 chain ID of the node the answers come from.
    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Latest block of the external chain.
    pub(crate) fn latest_block(&self) -> u64 {
        self.latest_block
    }

    /// Maximum number of blocks after the latest one a received mint may commit to.
    pub(crate) fn max_mint_lock_blocks(&self) -> u64 {
        self.max_mint_lock_blocks
    }

    /// Circulating supply accounted by the bridge, if it accounts one.
    pub(crate) fn circulating_supply(&self) -> Option<u64> {
        self.circulating_supply
    }

    /// Status of the lock of `claim`, if it was prefetched.
    pub(crate) fn lock_status(&self, claim: &Claim) -> Option<MintLockStatus> {
        let Claim::Lock { opid, .. } = claim;
        self.statuses.get(opid).copied()
    }

    /// Whether the lock of `claim` was recorded as of the latest block, finalized or not.
    pub(crate) fn is_lock_recorded(&self, claim: &Claim) -> Option<bool> {
        let Claim::Lock { opid, .. } = claim;
        self.paying_lock_recorded.get(opid).copied()
    }

    /// Whether the mint of `opid` was found to never be confirmed.
    pub(crate) fn is_expired(&self, opid: &OpId) -> bool {
        self.expired.contains(opid)
    }

    /// Fetch every answer a receive of the claims in `pending` will ask for.
    ///
    /// The node is checked to serve the chain the asset's bridge lives on before any lock is
    /// read, and the whole run is bounded by [`MAX_PREFETCH_CLAIMS`] and a wall-clock deadline.
    #[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
    pub(crate) async fn fetch(
        config: &EvmReceiveConfig,
        pending: &PendingClaims,
    ) -> Result<Self, Error> {
        let client = EvmFetchClient::new(&config.rpc_url)?;
        Self::fetch_with(&client, config, pending).await
    }

    /// Read the reject list kept by an `IRgbRejectList` contract on the configured chain.
    #[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
    pub(crate) async fn fetch_reject_list(
        config: &EvmReceiveConfig,
        contract: &EvmContract,
    ) -> Result<RejectList, Error> {
        let client = EvmFetchClient::new(&config.rpc_url)?;
        Self::fetch_reject_list_with(&client, contract).await
    }

    /// [`Self::fetch_reject_list`] over any [`ClaimEvmClient`].
    pub(crate) async fn fetch_reject_list_with<C: ClaimEvmClient>(
        client: &C,
        contract: &EvmContract,
    ) -> Result<RejectList, Error> {
        let actual = client.chain_id().await?;
        if actual != contract.chain_id {
            return Err(Error::EvmChainIdMismatch {
                expected: contract.chain_id,
                actual,
            });
        }
        let log = client.reject_list_entries(&contract.address).await?;
        let (reject, allow) = log.decisions();
        Ok(RejectList::from_decisions(
            reject
                .into_iter()
                .map(|opout| (opout, false))
                .chain(allow.into_iter().map(|opout| (opout, true))),
        ))
    }

    /// [`Self::fetch`] over any [`ClaimEvmClient`].
    pub(crate) async fn fetch_with<C: ClaimEvmClient>(
        client: &C,
        config: &EvmReceiveConfig,
        pending: &PendingClaims,
    ) -> Result<Self, Error> {
        Self::fetch_until(client, config, pending, now_millis() + PREFETCH_DEADLINE_MS).await
    }

    /// [`Self::fetch_with`] with the deadline supplied by the caller, so tests can force it
    /// without sleeping.
    async fn fetch_until<C: ClaimEvmClient>(
        client: &C,
        config: &EvmReceiveConfig,
        pending: &PendingClaims,
        deadline_millis: u64,
    ) -> Result<Self, Error> {
        let BridgeLocation::Evm(EvmContract { chain_id, address }) = &pending.bridge_location;
        let (chain_id, address) = (*chain_id, *address);
        let actual = client.chain_id().await?;
        if actual != chain_id {
            return Err(Error::EvmChainIdMismatch {
                expected: chain_id,
                actual,
            });
        }
        if pending.claims.len() > MAX_PREFETCH_CLAIMS {
            return Err(Error::Network {
                details: format!(
                    "consignment carries {} mint locks, at most {MAX_PREFETCH_CLAIMS} supported",
                    pending.claims.len()
                ),
            });
        }

        check_deadline(deadline_millis)?;
        let finalized_block = client.finalized_block_number().await?;
        let mut statuses = HashMap::with_capacity(pending.claims.len());
        let mut expired = HashSet::new();
        let mut paying_lock_recorded = HashMap::with_capacity(pending.claims.len());
        for claim in &pending.claims {
            check_deadline(deadline_millis)?;
            let Claim::Lock {
                opid,
                amount,
                before_block,
                ..
            } = claim;
            let lock_id = LockId::from(claim);
            let status = client
                .mint_lock_status(&address, &lock_id, *amount, *before_block, finalized_block)
                .await?;
            if status == MintLockStatus::Expired {
                expired.insert(*opid);
            }
            statuses.insert(*opid, status);
            check_deadline(deadline_millis)?;
            paying_lock_recorded.insert(
                *opid,
                client
                    .mint_lock_recorded(&address, &lock_id, *amount, *before_block)
                    .await?,
            );
        }

        check_deadline(deadline_millis)?;
        let latest_block = client.block_number().await?;
        check_deadline(deadline_millis)?;
        let circulating_supply = client.circulating_supply(&address).await?;

        Ok(Self {
            chain_id,
            finalized_block,
            latest_block,
            statuses,
            paying_lock_recorded,
            circulating_supply,
            expired,
            max_mint_lock_blocks: config.max_mint_lock_blocks,
        })
    }
}

impl ResolveClaim for PrefetchedClaims {
    fn evm_chain_id(&self) -> Result<u64, ClaimResolverError> {
        Ok(self.chain_id)
    }

    fn is_confirmed(
        &self,
        _location: &BridgeLocation,
        claim: &Claim,
    ) -> Result<bool, ClaimResolverError> {
        let Claim::Lock { opid, .. } = claim;
        match self.statuses.get(opid) {
            Some(MintLockStatus::Confirmed) => Ok(true),
            Some(MintLockStatus::Pending) => Ok(false),
            Some(MintLockStatus::Expired) => Err(ClaimResolverError::Unconfirmed(*opid)),
            None => Err(ClaimResolverError::ResolverIssue(format!(
                "the lock of mint operation {opid} was not prefetched"
            ))),
        }
    }
}

/// Fail once the prefetch budget is spent, before the next request is issued.
fn check_deadline(deadline_millis: u64) -> Result<(), Error> {
    if now_millis() >= deadline_millis {
        return Err(Error::Network {
            details: s!("mint lock prefetch exceeded its deadline"),
        });
    }
    Ok(())
}

/// Milliseconds on the platform clock, for the prefetch deadline.
#[cfg(target_arch = "wasm32")]
fn now_millis() -> u64 {
    js_sys::Date::now() as u64
}

/// Milliseconds on the platform clock, for the prefetch deadline.
#[cfg(not(target_arch = "wasm32"))]
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
mod tests {
    use std::sync::Mutex;

    use super::super::evm_abi::RejectListEntry;
    use super::*;
    use crate::runtime::block_on;

    fn location(chain_id: u64) -> BridgeLocation {
        BridgeLocation::Evm(EvmContract {
            chain_id,
            address: EvmAddress::default(),
        })
    }

    fn claim(b: u8, amount: u64, before_block: u64) -> Claim {
        Claim::Lock {
            opid: OpId::from([b; 32]),
            witness_id: RgbTxid::from_byte_array([b; 32]),
            amount,
            before_block,
        }
    }

    fn pending(chain_id: u64, claims: Vec<Claim>) -> PendingClaims {
        PendingClaims {
            bridge_location: location(chain_id),
            claims,
        }
    }

    fn config() -> EvmReceiveConfig {
        EvmReceiveConfig {
            rpc_url: s!("http://evm.invalid"),
            max_mint_lock_blocks: 100,
        }
    }

    /// A fake node answering the questions the prefetch asks, recording their order.
    struct FakeEvm {
        chain_id: u64,
        finalized: u64,
        latest: u64,
        statuses: HashMap<LockId, MintLockStatus>,
        recorded: HashMap<LockId, bool>,
        supply: Option<u64>,
        reject_entries: Vec<RejectListEntry>,
        calls: Mutex<Vec<&'static str>>,
    }

    impl FakeEvm {
        fn new(chain_id: u64, finalized: u64, latest: u64) -> Self {
            Self {
                chain_id,
                finalized,
                latest,
                statuses: HashMap::new(),
                recorded: HashMap::new(),
                supply: None,
                reject_entries: vec![],
                calls: Mutex::new(vec![]),
            }
        }
    }

    impl ClaimEvmClient for FakeEvm {
        async fn chain_id(&self) -> Result<u64, Error> {
            self.calls.lock().unwrap().push("chain_id");
            Ok(self.chain_id)
        }

        async fn finalized_block_number(&self) -> Result<u64, Error> {
            self.calls.lock().unwrap().push("finalized");
            Ok(self.finalized)
        }

        async fn block_number(&self) -> Result<u64, Error> {
            self.calls.lock().unwrap().push("latest");
            Ok(self.latest)
        }

        async fn mint_lock_status(
            &self,
            _contract: &EvmAddress,
            lock_id: &LockId,
            _amount: u64,
            before_block: u64,
            finalized_block: u64,
        ) -> Result<MintLockStatus, Error> {
            self.calls.lock().unwrap().push("status");
            let _ = (before_block, finalized_block);
            Ok(self
                .statuses
                .get(lock_id)
                .copied()
                .unwrap_or(MintLockStatus::Pending))
        }

        async fn mint_lock_recorded(
            &self,
            _contract: &EvmAddress,
            lock_id: &LockId,
            _amount: u64,
            _before_block: u64,
        ) -> Result<bool, Error> {
            self.calls.lock().unwrap().push("recorded");
            Ok(self.recorded.get(lock_id).copied().unwrap_or(false))
        }

        async fn circulating_supply(&self, _contract: &EvmAddress) -> Result<Option<u64>, Error> {
            self.calls.lock().unwrap().push("supply");
            Ok(self.supply)
        }

        async fn reject_list_entries(
            &self,
            _contract: &EvmAddress,
        ) -> Result<RejectListLog, Error> {
            self.calls.lock().unwrap().push("reject_list");
            Ok(RejectListLog {
                entries: self.reject_entries.clone(),
                finalized: self.reject_entries.len(),
            })
        }
    }

    #[test]
    fn prefetch_confirms_a_lock_and_reads_supply() {
        let first = claim(1, 100, 20);
        let mut fake = FakeEvm::new(11, 15, 19);
        fake.statuses
            .insert(LockId::from(&first), MintLockStatus::Confirmed);
        fake.recorded.insert(LockId::from(&first), true);
        fake.supply = Some(1_000);
        let prefetched = block_on(PrefetchedClaims::fetch_with(
            &fake,
            &config(),
            &pending(11, vec![first.clone()]),
        ))
        .expect("prefetch");

        assert_eq!(prefetched.chain_id(), 11);
        assert_eq!(prefetched.finalized_block, 15);
        assert_eq!(prefetched.latest_block(), 19);
        assert_eq!(prefetched.circulating_supply(), Some(1_000));
        assert_eq!(
            prefetched.lock_status(&first),
            Some(MintLockStatus::Confirmed)
        );
        assert_eq!(prefetched.is_lock_recorded(&first), Some(true));
        assert!(!prefetched.is_expired(&OpId::from([1; 32])));
        assert!(prefetched.is_confirmed(&location(11), &first).unwrap());
        // the chain is checked before anything else, and the supply is read last
        assert_eq!(
            fake.calls.into_inner().unwrap(),
            [
                "chain_id",
                "finalized",
                "status",
                "recorded",
                "latest",
                "supply"
            ]
        );
    }

    #[test]
    fn prefetch_reports_pending_and_expired_locks() {
        let pending_claim = claim(2, 50, 100);
        let expired_claim = claim(3, 60, 5);
        let mut fake = FakeEvm::new(11, 8, 9);
        fake.statuses
            .insert(LockId::from(&pending_claim), MintLockStatus::Pending);
        fake.statuses
            .insert(LockId::from(&expired_claim), MintLockStatus::Expired);
        let prefetched = block_on(PrefetchedClaims::fetch_with(
            &fake,
            &config(),
            &pending(11, vec![pending_claim.clone(), expired_claim.clone()]),
        ))
        .expect("prefetch");
        assert!(
            !prefetched
                .is_confirmed(&location(11), &pending_claim)
                .unwrap()
        );
        assert!(
            prefetched
                .is_confirmed(&location(11), &expired_claim)
                .is_err()
        );
        assert_eq!(
            prefetched.lock_status(&expired_claim),
            Some(MintLockStatus::Expired)
        );
        assert!(prefetched.is_expired(&OpId::from([3; 32])));
    }

    #[test]
    fn prefetch_refuses_a_node_on_another_chain() {
        let fake = FakeEvm::new(12, 1, 2);
        let result = block_on(PrefetchedClaims::fetch_with(
            &fake,
            &config(),
            &pending(11, vec![claim(1, 1, 2)]),
        ));
        assert!(matches!(
            result,
            Err(Error::EvmChainIdMismatch {
                expected: 11,
                actual: 12
            })
        ));
        assert_eq!(fake.calls.into_inner().unwrap(), ["chain_id"]);
    }

    #[test]
    fn reject_list_prefetch_reads_the_contract_decisions() {
        let rejected = Opout {
            op: OpId::from([4; 32]),
            ty: AssignmentType::with(4000),
            no: 7,
        };
        let allowed = Opout {
            op: OpId::from([5; 32]),
            ty: AssignmentType::with(4000),
            no: 8,
        };
        let mut fake = FakeEvm::new(11, 1, 2);
        fake.reject_entries = vec![
            RejectListEntry {
                opout: rejected,
                reject: true,
            },
            RejectListEntry {
                opout: allowed,
                reject: false,
            },
        ];
        let contract = EvmContract {
            chain_id: 11,
            address: EvmAddress::default(),
        };
        let list = block_on(PrefetchedClaims::fetch_reject_list_with(&fake, &contract))
            .expect("reject list prefetch");
        assert!(list.rejects(&rejected));
        assert!(list.allows(&allowed));
        assert_eq!(
            fake.calls.into_inner().unwrap(),
            ["chain_id", "reject_list"]
        );
    }

    #[test]
    fn reject_list_prefetch_refuses_a_node_on_another_chain() {
        let fake = FakeEvm::new(12, 1, 2);
        let contract = EvmContract {
            chain_id: 11,
            address: EvmAddress::default(),
        };
        let result = block_on(PrefetchedClaims::fetch_reject_list_with(&fake, &contract));
        assert!(matches!(
            result,
            Err(Error::EvmChainIdMismatch {
                expected: 11,
                actual: 12
            })
        ));
    }

    #[test]
    fn options_find_an_endpoint_only_when_configured() {
        assert!(EvmReceiveOptions::default().config(11).is_none());
        let by_chain = EvmReceiveOptions::by_chain(HashMap::from([(11, config())]));
        assert!(by_chain.config(11).is_some());
        assert!(by_chain.config(12).is_none());
        let single = EvmReceiveOptions::single(config());
        assert!(single.config(12).is_some());
    }

    #[test]
    fn prefetch_stops_at_its_deadline() {
        let fake = FakeEvm::new(11, 1, 2);
        let result = block_on(PrefetchedClaims::fetch_until(
            &fake,
            &config(),
            &pending(11, vec![claim(1, 1, 2)]),
            0,
        ));
        assert!(matches!(result, Err(Error::Network { details }) if details.contains("deadline")));
        assert_eq!(fake.calls.into_inner().unwrap(), ["chain_id"]);
    }

    #[test]
    fn prefetch_refuses_too_many_claims() {
        let fake = FakeEvm::new(11, 1, 2);
        let claims = (0..=MAX_PREFETCH_CLAIMS as u8)
            .map(|b| claim(b, 1, 2))
            .collect();
        let result = block_on(PrefetchedClaims::fetch_with(
            &fake,
            &config(),
            &pending(11, claims),
        ));
        assert!(result.is_err());
        assert_eq!(fake.calls.into_inner().unwrap(), ["chain_id"]);
    }
}
