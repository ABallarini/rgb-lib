//! Receive phases shared by the drivers that accept an incoming consignment.
//!
//! The native driver (`online`) keeps the consignment fetch and its retry/caching policy, then
//! runs the driver below. The driver holds the per-consignment orchestration - prepare, validate,
//! reject list, media, apply, ACK/NACK - and reaches the network only through
//! [`ReceiveTransport`], so the same sequence runs over the native blocking client and the
//! browser's async transport.
//!
//! The wasm driver in `receive_wasm` supplies the browser transport and a prefetched resolver; the
//! remaining dead-code allowance covers helpers that are only used by one target.
#![cfg_attr(
    all(target_arch = "wasm32", not(feature = "_online")),
    allow(dead_code)
)]

#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::pin::pin;
use std::str::FromStr;
#[cfg(not(target_arch = "wasm32"))]
use std::task::{Context, Poll, Waker};

use super::*;

#[cfg(feature = "_online")]
use super::online::{broadcast_deadline, min_sender_retention_grace};
// validation steps shared with the standalone validation API
use crate::api::jsonrpc::{PostAckResponse, transfer_retrieved_message};
use crate::no_wallet::validation::{
    OffchainResolver, ResolveRejectList, pending_claims, validate_deterministic,
};
#[cfg(feature = "_online")]
use crate::no_wallet::validation::{PendingClaims, resolve_claims};
use rgbstd::validation::Validity;

use crate::error::IndexerError;
use base64::{Engine as _, engine::general_purpose};

/// Signed TX released to a recipient, saved to broadcast it again until the broadcast deadline
const RECEIVED_SIGNED_TX_FILE: &str = "rcv_signed.tx";

/// The wallet-side helpers the receive driver needs, shared by the native and browser wallets.
///
/// A plain [`WalletOffline`] wallet can run the receive phases: every network operation is reached
/// through [`ReceiveTransport`] and every chain lookup through the [`ResolveWitness`] the driver is
/// given, never through the wallet's own online data. The native wallet implements this with its
/// indexer-backed resolver, the browser one with the chain prefetched before the transaction opens.
pub trait ReceiveWallet: WalletOffline {
    /// Path of the signed TX released to a recipient, saved to broadcast it again until the
    /// broadcast deadline (v1.0-changes-spec.md 6.4).
    fn get_received_signed_tx_path(&self, recipient_id: &str) -> PathBuf {
        self.get_receive_consignment_path(recipient_id)
            .with_file_name(RECEIVED_SIGNED_TX_FILE)
    }

    /// Whether the data of a handled incoming transfer can be deleted from the recipient proxy
    /// (`transfer.retrieved`), which is not the case when other wallets sharing the invoice (e.g.
    /// multisig cosigners) still need to download it.
    fn releases_received_transfer_data(&self) -> bool {
        true
    }

    /// Whether the wallet accepts mints of bridged assets paying it (see
    /// [`get_received_mint`](RgbWalletOpsOffline::get_received_mint)).
    fn accepts_received_mints(&self) -> bool {
        true
    }

    fn get_hub_fail_status(&self, _batch_transfer_idx: i32) -> Result<bool, Error> {
        Ok(false)
    }

    fn set_hub_accept_status(&self, _batch_transfer_idx: i32) -> Result<Option<bool>, Error> {
        #[cfg(all(test, feature = "_online"))]
        if mock_hub_accept_pending() {
            return Ok(None);
        }
        Ok(Some(true))
    }

    fn set_hub_fail_status(&self, _batch_transfer_idx: i32) -> Result<(), Error> {
        Ok(())
    }

    /// Verify a downloaded blob against its expected plaintext hash, first decrypting it with the
    /// key shared with the counterparty as dictated by `encryption`, the mode the payload is
    /// expected in: the recipient's invoice preference for consignments and media, always
    /// `Required` for the signed TX. For `Optional` the encrypted form is tried first, falling back
    /// to cleartext; for `Unsupported` the blob is taken as cleartext. Anything that doesn't match
    /// the hash afterwards (e.g. a blob encrypted despite `Unsupported`) is rejected.
    fn decrypt_blob_with_shared_key(
        &self,
        raw: Vec<u8>,
        encryption: Encryption,
        own_seed: &[u8],
        counterparty_pubkey_hex: &str,
        hash_hex: &str,
    ) -> Result<Vec<u8>, Error> {
        crate::encryption::decrypt_blob_with_shared_key(
            raw,
            encryption,
            own_seed,
            counterparty_pubkey_hex,
            hash_hex,
        )
    }

    /// Decrypt the released signed TX, verify it and save it so it can be broadcast again until
    /// the broadcast deadline (v1.0-changes-spec.md 6.4), returning it for broadcasting.
    fn decrypt_save_received_tx(
        &self,
        recipient_id: &str,
        signed_tx_b64: &str,
        signed_tx_hash: &str,
        sender_pubkey_hex: &str,
        recipient_seed: &[u8],
    ) -> Result<BdkTransaction, Error> {
        let enc = general_purpose::STANDARD
            .decode(signed_tx_b64)
            .map_err(InternalError::from)?;
        let tx_bytes = self.decrypt_blob_with_shared_key(
            enc,
            Encryption::Required,
            recipient_seed,
            sender_pubkey_hex,
            signed_tx_hash,
        )?;
        let tx: BdkTransaction = bdk_wallet::bitcoin::consensus::encode::deserialize(&tx_bytes)
            .map_err(|e| Error::Internal {
                details: e.to_string(),
            })?;
        self.files().atomic_write(
            &self.wallet_key(&self.get_received_signed_tx_path(recipient_id))?,
            &tx_bytes,
        )?;
        Ok(tx)
    }

    /// rgb-ops only exposes a path-based loader (`RgbTransfer::load_file`); the browser receive
    /// loop has no filesystem path and will hand the decoded consignment in instead of using this.
    #[cfg(not(target_arch = "wasm32"))]
    fn load_received_consignment(&self, consignment_path: &Path) -> Result<RgbTransfer, Error> {
        RgbTransfer::load_file(consignment_path).map_err(|e| InternalError::from(e).into())
    }

    /// The browser has no filesystem path: read the saved bytes back through [`WalletFiles`] and
    /// decode the same strict-encoded container `RgbTransfer::load_file` reads natively.
    #[cfg(target_arch = "wasm32")]
    fn load_received_consignment(&self, consignment_path: &Path) -> Result<RgbTransfer, Error> {
        let key = self.wallet_key(consignment_path)?;
        let bytes = self.files().read(&key)?;
        RgbTransfer::load(bytes.as_slice()).map_err(|e| InternalError::from(e).into())
    }

    /// Keep the validated consignment while the transfer is pending, to avoid validating again.
    ///
    /// rgb-ops only saves a validated consignment to a path (`ValidConsignment::save_file`), so
    /// the native wallet writes it there. The browser wallet has no filesystem path: it skips this
    /// copy and revalidates on retry instead of writing bytes in a format rgb-ops does not expose.
    #[cfg(not(target_arch = "wasm32"))]
    fn save_valid_consignment_copy(
        &self,
        path: &Path,
        valid_consignment: &ValidTransfer,
    ) -> Result<(), Error> {
        atomic_write_with(path, |tmp| Ok(valid_consignment.save_file(tmp)?))
    }

    /// rgb-ops exposes only a path-based save; the browser wallet has no path to write (see the
    /// native implementation) and revalidates the consignment on retry instead.
    #[cfg(target_arch = "wasm32")]
    fn save_valid_consignment_copy(
        &self,
        _path: &Path,
        _valid_consignment: &ValidTransfer,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Save the mint paying a received consignment, so it can be checked and its lock waited for
    /// (see [`get_received_mint`](RgbWalletOpsOffline::get_received_mint)).
    fn save_received_mint(
        &self,
        recipient_id: &str,
        received_mint: &ReceivedMint,
    ) -> Result<(), Error> {
        let serialized = serde_json::to_string(received_mint).map_err(InternalError::from)?;
        let key = self.wallet_key(&self.get_received_mint_path(recipient_id))?;
        self.files().atomic_write(&key, serialized.as_bytes())
    }

    /// Key of the mint locks the received consignment at `consignment_path` waits for (see
    /// [`PendingMintLocks`]). Only the online driver waits for locks, but the key is part of the
    /// wallet's files on every build.
    fn get_receive_mint_locks_path(&self, consignment_path: &Path) -> PathBuf {
        consignment_path.with_extension("mint_locks.json")
    }

    #[cfg(feature = "_online")]
    fn consignment_file_digest(&self, consignment_path: &Path) -> Result<String, Error> {
        let bytes = self.files().read(&self.wallet_key(consignment_path)?)?;
        Ok(hex::encode(sha256_digest(&bytes)))
    }

    #[cfg(feature = "_online")]
    fn save_pending_mint_locks(
        &self,
        consignment_path: &Path,
        bridge_location: &BridgeLocation,
        claims: Vec<Claim>,
    ) -> Result<(), Error> {
        let BridgeLocation::Evm(EvmContract { chain_id, address }) = bridge_location;
        let pending_mint_locks = PendingMintLocks {
            consignment_digest: self.consignment_file_digest(consignment_path)?,
            evm_chain_id: *chain_id,
            bridge_contract: *address,
            claims,
        };
        let serialized = serde_json::to_string(&pending_mint_locks).map_err(InternalError::from)?;
        let key = self.wallet_key(&self.get_receive_mint_locks_path(consignment_path))?;
        self.files().atomic_write(&key, serialized.as_bytes())
    }

    /// Whether the received consignment at `consignment_path` is still waiting for the mint locks
    /// saved for it: none of them found expired and some not finalized yet. Anything else (no
    /// locks saved, or saved for another consignment, no lock left to wait for, one expired, an EVM
    /// RPC endpoint missing or on another chain) is left to the processing of the consignment.
    #[cfg(feature = "_online")]
    fn waiting_for_mint_locks(&self, consignment_path: &Path) -> Result<bool, Error> {
        let key = self.wallet_key(&self.get_receive_mint_locks_path(consignment_path))?;
        let Some(pending_mint_locks) = self
            .files()
            .read(&key)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PendingMintLocks>(&bytes).ok())
        else {
            return Ok(false);
        };
        if self.consignment_file_digest(consignment_path).ok()
            != Some(pending_mint_locks.consignment_digest)
        {
            return Ok(false);
        }
        let chain_id = pending_mint_locks.evm_chain_id;
        let Some(evm_rpc_url) = self.evm_rpc_url(chain_id) else {
            return Ok(false);
        };
        let evm_client = EvmClient::new(evm_rpc_url)?;
        let mint_resolver = MintClaimResolver::new(&evm_client);
        let bridge_location = BridgeLocation::Evm(EvmContract {
            chain_id,
            address: pending_mint_locks.bridge_contract,
        });
        let claim_resolver = match CheckedClaimResolver::with(&mint_resolver, bridge_location) {
            Ok(claim_resolver) => claim_resolver,
            Err(ClaimResolverError::WrongChainId { .. }) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let mut unconfirmed = 0;
        for claim in &pending_mint_locks.claims {
            if !claim_resolver.is_confirmed(claim)? {
                let Claim::Lock { opid, .. } = claim;
                if mint_resolver.is_expired(opid) {
                    return Ok(false);
                }
                unconfirmed += 1;
            }
        }
        if unconfirmed == 0 {
            return Ok(false);
        }
        info!(
            self.logger(),
            "{unconfirmed} mint lock(s) not found or not confirmed on the external chain yet, \
             will retry"
        );
        Ok(true)
    }

    /// The circulating supply the bridge contract at `contract` accounts as of the latest block
    /// (see [`EvmClient::circulating_supply`]), if it can be read.
    ///
    /// The supply is only informative: a failure to read it is logged, not reported.
    #[cfg(feature = "_online")]
    fn read_bridge_circulating_supply(
        &self,
        evm_client: &EvmClient,
        contract: &EvmAddress,
    ) -> Option<u64> {
        match evm_client.circulating_supply(contract) {
            Ok(Some(supply)) => Some(supply),
            Ok(None) => {
                debug!(
                    self.logger(),
                    "The bridge contract doesn't account the circulating supply"
                );
                None
            }
            Err(e) => {
                warn!(
                    self.logger(),
                    "Cannot read the circulating supply from the bridge contract: {e}"
                );
                None
            }
        }
    }

    /// Delete the validated copy of a received consignment
    fn delete_valid_consignment(&self, recipient_id: &str) -> Result<(), Error> {
        let consignment_path = self.get_receive_consignment_path(recipient_id);
        let key = self.wallet_key(&self.get_receive_valid_consignment_path(&consignment_path))?;
        self.files().remove(&key)
    }

    /// Clear the pending witness flag of the TXOs flagged for witness receives that are not pending
    /// anymore, as they would otherwise never become spendable. The TXOs are identified by their
    /// outpoint (the one registered when accepting the consignment) or by the script they pay (one
    /// detected by a sync, e.g. when the counterparty broadcasts before its consignment gets
    /// refused). Pending witness scripts are left to [`WalletCore::reconcile_pending_witness`],
    /// which keeps watching them for a grace time in case the counterparty broadcasts anyway.
    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn unflag_pending_witness_txos(
        &self,
        txn: &DbTxn,
        outpoints: &HashSet<Outpoint>,
        scripts: &HashSet<ScriptBuf>,
    ) -> Result<(), Error> {
        for txo in txn.iter_pending_witness_txos()? {
            let outpoint = txo.outpoint();
            let pays_script = || {
                self.bdk_wallet()
                    .tx_graph()
                    .get_txout(outpoint.clone().into())
                    .is_some_and(|txout| scripts.contains(&txout.script_pubkey))
            };
            if !outpoints.contains(&outpoint) && !pays_script() {
                continue;
            }
            let mut txo: DbTxoActMod = txo.into();
            txo.pending_witness = ActiveValue::Set(false);
            txn.update_txo(txo)?;
        }
        Ok(())
    }

    /// Clear the pending witness flag of the TXOs flagged for the witness receives of a batch
    /// transfer being failed.
    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn clean_failed_witness_receives(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<(), Error> {
        if !batch_transfer.incoming {
            return Ok(());
        }
        let mut outpoints = HashSet::new();
        let mut scripts = HashSet::new();
        for transfer in txn.get_batch_transfer_transfers(batch_transfer.idx)? {
            let vout = match transfer.recipient_type {
                Some(RecipientTypeFull::Witness { vout }) => vout,
                _ => continue,
            };
            if let (Some(txid), Some(vout)) = (&batch_transfer.txid, vout) {
                outpoints.insert(Outpoint {
                    txid: txid.clone(),
                    vout,
                });
            }
            if let Some(recipient_id) = transfer.recipient_id
                && let Some(script) = script_buf_from_recipient_id(recipient_id)?
            {
                scripts.insert(script);
            }
        }
        if outpoints.is_empty() && scripts.is_empty() {
            return Ok(());
        }
        self.unflag_pending_witness_txos(txn, &outpoints, &scripts)
    }

    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn fail_batch_transfer(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<DbBatchTransfer, Error> {
        self.set_hub_fail_status(batch_transfer.idx)?;
        self.clean_failed_witness_receives(txn, batch_transfer)?;
        txn.del_reserved_txos_for_batch_transfer(batch_transfer.idx)?;
        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        updated_batch_transfer.status = ActiveValue::Set(TransferStatus::Failed);
        txn.update_batch_transfer(&mut updated_batch_transfer)
    }

    /// The release a handled proxy receive leaves to its caller, once the receive is durable.
    fn pending_retrieval(
        &self,
        mode: &ReceiveMode,
        recipient_id: String,
        recipient_seed: Vec<u8>,
        handled: bool,
    ) -> Option<PendingRetrieval> {
        if !handled || !self.releases_received_transfer_data() {
            return None;
        }
        let ReceiveMode::Proxy(data) = mode else {
            return None;
        };
        Some(PendingRetrieval {
            proxy_url: data.proxy_url.clone(),
            transfer_id: data.transfer_id.clone(),
            recipient_id,
            recipient_seed,
        })
    }
}

/// Highest block height that is `min_confirmations` deep, given the chain tip.
pub(super) fn safe_height(tip_height: u32, min_confirmations: u8) -> u32 {
    tip_height
        .saturating_sub(min_confirmations as u32)
        .saturating_add(1)
}

/// The witness questions a receive run will ask the chain, in one set.
///
/// Validation asks for every bundled witness TX and, when a bundle carries an SPV proof, for the
/// header at the proof's height (a valid proof answers the witness without a lookup). Consumption
/// asks again for every bundled witness and, when their ord is invalid, for the other witnesses the
/// stock already knows for the same bundle. Fetching the union up front is what lets
/// [`PrefetchedChain`](super::resolver_async::PrefetchedChain) serve every question without a
/// network call inside validation or the transaction.
#[allow(dead_code)] // the native driver resolves lazily; the browser one prefetches
#[derive(Default)]
pub(super) struct PrefetchQuestions {
    pub(super) witness_ids: BTreeSet<RgbTxid>,
    pub(super) heights: BTreeSet<NonZeroU32>,
}

#[allow(dead_code)]
impl PrefetchQuestions {
    /// Record one bundle's witness and, when it ships a proof, the header height it names.
    fn record_bundle(&mut self, witness_id: RgbTxid, spv_height: Option<NonZeroU32>) {
        self.witness_ids.insert(witness_id);
        if let Some(height) = spv_height {
            self.heights.insert(height);
        }
    }

    /// The questions the consignment alone answers.
    pub(super) fn for_consignment(consignment: &RgbTransfer) -> Self {
        let mut questions = Self::default();
        for bundle in consignment.bundled_witnesses() {
            questions.record_bundle(
                bundle.witness_id(),
                bundle.spv_proof.as_ref().map(|proof| proof.block_height),
            );
        }
        questions
    }

    /// Add the alternative witnesses consumption re-resolves when a bundle's own witness is invalid
    /// (e.g. after a reorg). A bundle the stock does not know yet contributes none.
    #[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
    pub(super) fn add_known_alternatives(
        &mut self,
        stock: &RgbStock<'_>,
        consignment: &RgbTransfer,
    ) -> Result<(), Error> {
        for bundle in &consignment.bundles {
            self.witness_ids
                .extend(stock.bundle_witnesses(bundle.bundle.bundle_id())?);
        }
        Ok(())
    }
}

/// One pending incoming transfer of this wallet, with the rows the shared driver takes.
#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) struct PendingReceive {
    pub(super) batch: DbBatchTransfer,
    pub(super) asset_transfer: DbAssetTransfer,
    pub(super) transfer: DbTransfer,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
impl PendingReceive {
    /// The proxy transfer ID the sender posts this invoice's transfer under: derived from the
    /// invoice ID and the sender's public key, exactly like the native selection.
    pub(super) fn expected_transfer_id(&self, sender_pk: &str) -> Option<String> {
        let recipient_id = self.transfer.recipient_id.as_deref()?;
        let recipient_pk = hex::encode(self.transfer.recipient_pubkey.as_ref()?);
        Some(crate::encryption::transfer_id(
            &crate::encryption::invoice_id(recipient_id, &recipient_pk),
            sender_pk,
        ))
    }
}

/// Rebuild the receive mode of an already-applied transfer from its saved endpoints and metadata.
///
/// The native `wait_safe_height` and the browser resume path both need to ACK again without
/// downloading the consignment, so they share this lookup. A transfer without a transport endpoint
/// was received out of band.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) fn receive_mode_from_transfer<W: ReceiveWallet + ?Sized>(
    wallet: &W,
    txn: &DbTxn,
    transfer: &DbTransfer,
) -> Result<ReceiveMode, Error> {
    let recipient_id = transfer
        .recipient_id
        .clone()
        .ok_or_else(|| Error::Internal {
            details: s!("missing recipient ID"),
        })?;
    let tte_data = txn.get_transfer_transport_endpoints_data(transfer.idx)?;
    if tte_data.is_empty() {
        return Ok(ReceiveMode::OutOfBand {
            media_file_paths: vec![],
        });
    }
    let proxy_url = tte_data
        .iter()
        .find(|(tte, _)| tte.kind == TransportEndpointKind::RecipientProxy && tte.used)
        .map(|(_, te)| te.endpoint.clone())
        .ok_or_else(|| Error::Internal {
            details: s!("missing used recipient proxy endpoint"),
        })?;
    let consignment_meta_path = wallet.get_receive_consignment_meta_path(&recipient_id);
    let meta: ReceivedConsignmentMeta = serde_json::from_slice(
        &wallet
            .files()
            .read(&wallet.wallet_key(&consignment_meta_path)?)?,
    )
    .map_err(InternalError::from)?;
    let transfer_id = transfer
        .proxy_transfer_id
        .clone()
        .or(meta.transfer_id)
        .ok_or_else(|| Error::Internal {
            details: s!("missing transfer ID"),
        })?;
    Ok(ReceiveMode::Proxy(ProxyReceiveData {
        proxy_url,
        transfer_id,
        sender_proxy: meta.sender_transport_endpoint,
        sender_pubkey: meta.sender_pubkey,
        consignment_hash: meta.consignment_hash,
        recipient_encryption: transfer.recipient_encryption,
        batch: meta.batch,
    }))
}

/// The mined height of `txid`, if the resolver can see it.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
fn witness_height(chain: &impl ResolveWitness, txid: &str) -> Result<Option<u32>, Error> {
    let txid = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    match chain.resolve_witness(txid).map_err(|e| Error::Network {
        details: e.to_string(),
    })? {
        WitnessStatus::Resolved(_, WitnessOrd::Mined(witness_pos)) => {
            Ok(Some(witness_pos.height().get()))
        }
        _ => Ok(None),
    }
}

/// Whether a batch transfer is still in one of the states the native refresh handles.
///
/// The receive loop uses this to resume a receive that was applied but not completed, instead of
/// treating it as done. `Settled` and `Failed` are terminal.
fn non_terminal_receive_status(status: TransferStatus) -> bool {
    matches!(
        status,
        TransferStatus::WaitingCounterparty
            | TransferStatus::WaitingSafeHeight
            | TransferStatus::WaitingBroadcast
            | TransferStatus::WaitingConfirmations
    )
}

/// The pending incoming transfers that can still be received from a proxy.
///
/// Outgoing transfers are skipped by `incoming`, and only the non-terminal statuses native refresh
/// handles are selected: a transfer applied before, but left in `WaitingSafeHeight` or
/// `WaitingBroadcast`, is resumed instead of being treated as complete. Out-of-band invoices are
/// skipped too, as they have no proxy transfer to fetch.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) fn pending_receives(db_data: &DbData) -> Result<Vec<PendingReceive>, Error> {
    let mut pending = vec![];
    for batch in &db_data.batch_transfers {
        if !batch.incoming || !non_terminal_receive_status(batch.status) {
            continue;
        }
        let (asset_transfer, transfer) =
            batch.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
        if transfer.recipient_id.is_none()
            || transfer.recipient_pubkey.is_none()
            || batch.operation_secret_key.is_none()
            || transfer.uses_out_of_band_exchange()
        {
            continue;
        }
        pending.push(PendingReceive {
            batch: batch.clone(),
            asset_transfer,
            transfer,
        });
    }
    Ok(pending)
}

/// The incoming batch transfer bearing `transfer_id`, whatever its status.
fn receive_by_proxy_id<'a>(db_data: &'a DbData, transfer_id: &str) -> Option<&'a DbBatchTransfer> {
    db_data
        .transfers
        .iter()
        .filter(|t| t.proxy_transfer_id.as_deref() == Some(transfer_id))
        .find_map(|t| {
            db_data
                .asset_transfers
                .iter()
                .find(|at| at.idx == t.asset_transfer_idx)
                .and_then(|at| {
                    db_data
                        .batch_transfers
                        .iter()
                        .find(|b| b.idx == at.batch_transfer_idx && b.incoming)
                })
        })
}

/// The index of an incoming transfer already bearing `transfer_id`, if any, terminal or not.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) fn receive_transfer_idx(db_data: &DbData, transfer_id: &str) -> Option<i32> {
    receive_by_proxy_id(db_data, transfer_id).map(|b| b.idx)
}

/// The index of an incoming transfer that already reached a terminal status, if any.
///
/// A stored proxy transfer ID alone is not completion: a receive left in `WaitingSafeHeight`,
/// `WaitingBroadcast` or `WaitingConfirmations` must be resumed. Only `Settled` and `Failed`
/// transfers are skipped as already handled.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) fn already_handled(db_data: &DbData, transfer_id: &str) -> Option<i32> {
    receive_by_proxy_id(db_data, transfer_id)
        .filter(|b| b.status.settled() || b.status.failed())
        .map(|b| b.idx)
}

/// The minimum sender proxy retention grace, as the native online module defines it.
///
/// The browser driver runs without `_online`, so the pure helper it shares with the native driver
/// lives here instead of in that module.
#[cfg(not(feature = "_online"))]
pub(super) fn min_sender_retention_grace() -> u32 {
    super::MIN_SENDER_RETENTION_GRACE_SECS
}

/// The broadcast deadline of an operation, from the `expires_at` returned by `ack.post` and the
/// sender proxy retention grace. Shared verbatim with the native online module.
#[cfg(not(feature = "_online"))]
pub(super) fn broadcast_deadline(
    expires_at: Option<&str>,
    retention_grace: u32,
    invoice_expiration: Option<i64>,
) -> Option<i64> {
    let expiration = expires_at.and_then(|exp| exp.parse::<i64>().ok())?;
    let invoice_expiration = invoice_expiration?;
    if expiration < now().unix_timestamp() || expiration > invoice_expiration {
        return None;
    }
    Some(expiration.saturating_add(i64::from(retention_grace)))
}

/// Map the reason an indexer gave for refusing a broadcast to the wallet error that tells the
/// sender why, when that reason is one worth distinguishing.
///
/// Shared by the native and browser transports, so the same node response yields the same error.
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn broadcast_error(txid: &str, e: &IndexerError) -> Option<Error> {
    match e {
        #[cfg(feature = "bitcoind")]
        IndexerError::Bitcoind(e) => {
            let err_str = e.to_string();
            if err_str.contains("min relay fee not met")
                || err_str.contains("mempool min fee not met")
            {
                Some(Error::MinFeeNotMet {
                    txid: txid.to_string(),
                })
            } else if err_str.contains("Fee exceeds maximum configured")
                || err_str.contains("max-fee-exceeded")
            {
                Some(Error::MaxFeeExceeded {
                    txid: txid.to_string(),
                })
            } else {
                None
            }
        }
        #[cfg(feature = "electrum")]
        IndexerError::Electrum(e) => {
            let err_str = e.to_string();
            if err_str.contains("min relay fee not met")
                || err_str.contains("mempool min fee not met")
            {
                Some(Error::MinFeeNotMet {
                    txid: txid.to_string(),
                })
            } else if err_str.contains("Fee exceeds maximum configured") {
                Some(Error::MaxFeeExceeded {
                    txid: txid.to_string(),
                })
            } else {
                None
            }
        }
        #[cfg(any(feature = "esplora", feature = "esplora_async"))]
        IndexerError::Esplora(EsploraError::HttpResponse { message, .. }) => {
            if message.contains("min relay fee not met") {
                Some(Error::MinFeeNotMet {
                    txid: txid.to_string(),
                })
            } else if message.contains("Fee exceeds maximum configured") {
                Some(Error::MaxFeeExceeded {
                    txid: txid.to_string(),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A decoded consignment plus the identifiers every receive phase needs.
///
/// The proxy response metadata (transfer ID, proxy URLs, invoice data) stays in
/// [`ProxyReceiveData`]/[`ReceivedConsignmentMeta`] in this commit: it is assembled by the native
/// driver next to the HTTP calls it comes from.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) struct PreparedConsignment {
    pub(super) consignment: RgbTransfer,
    pub(super) contract_id: ContractId,
    pub(super) asset_id: String,
    pub(super) asset_schema: AssetSchema,
}

#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
impl PreparedConsignment {
    /// Assemble the data shared by every receive phase from an already-decoded consignment.
    pub(super) fn new(consignment: RgbTransfer) -> Result<Self, Error> {
        let contract_id = consignment.contract_id();
        let asset_id = contract_id.to_string();
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        Ok(Self {
            consignment,
            contract_id,
            asset_id,
            asset_schema,
        })
    }
}

/// Assemble the data shared by every receive phase from an already-decoded consignment.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) fn prepare_consignment(consignment: RgbTransfer) -> Result<PreparedConsignment, Error> {
    PreparedConsignment::new(consignment)
}

/// What a successful apply leaves for the driver.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) enum ApplyOutcome {
    /// unsafe history: the transaction was updated and the caller must stop before ACKing
    WaitingSafeHeight(DbBatchTransfer),
    /// the transfer is applied, the caller can post the ACK
    ReadyForAck { donation_tx: Option<BdkTransaction> },
}

/// Apply a validated consignment to the wallet database and files.
///
/// The caller has already loaded, decrypted and validated the consignment, and has fetched and
/// saved any media attachments (the only network step left in the unknown-asset branch).
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_received_consignment<W: ReceiveWallet + ?Sized>(
    wallet: &W,
    chain: &impl ResolveWitness,
    txn: &DbTxn,
    asset_transfer: &DbAssetTransfer,
    transfer: &DbTransfer,
    prepared: &PreparedConsignment,
    consignment_path: &Path,
    valid_consignment: ValidTransfer,
    receiving: HashMap<Opout, Assignment>,
    txid: String,
    vout: Option<u32>,
    terminal_tx: &BdkTransaction,
    unknown_asset: bool,
    stock: &mut RgbStock<'_>,
    updated_batch_transfer: &mut DbBatchTransferActMod,
) -> Result<ApplyOutcome, Error> {
    if asset_transfer.asset_id.is_none() {
        if unknown_asset {
            // unknown asset
            debug!(wallet.logger(), "Receiving unknown contract...");
            let valid_contract = valid_consignment.clone().into_valid_contract();

            stock
                .import_contract(valid_contract.clone(), chain)
                .expect("failure importing received contract");
            debug!(wallet.logger(), "Contract registered");
            wallet.save_new_asset_internal(
                txn,
                stock,
                prepared.contract_id,
                prepared.asset_schema,
                valid_contract,
                Some(valid_consignment.clone()),
            )?;
        }

        // add asset info to transfer if missing
        let mut updated_asset_transfer: DbAssetTransferActMod = asset_transfer.clone().into();
        updated_asset_transfer.asset_id = ActiveValue::Set(Some(prepared.asset_id.clone()));
        txn.update_asset_transfer(&mut updated_asset_transfer)?;
    }

    // keep the validated consignment while the transfer is pending, to avoid validating again
    let valid_consignment_path = wallet.get_receive_valid_consignment_path(consignment_path);
    wallet.save_valid_consignment_copy(&valid_consignment_path, &valid_consignment)?;

    debug!(
        wallet.logger(),
        "Consignment is valid. Receiving '{:?}' of contract '{}'", receiving, prepared.asset_id
    );

    updated_batch_transfer.txid = ActiveValue::Set(Some(txid.clone()));

    let utxo_idx = match transfer.recipient_type {
        Some(RecipientTypeFull::Blind { ref unblinded_utxo }) => {
            txn.get_txo(unblinded_utxo)?.expect("utxo must exist").idx
        }
        Some(RecipientTypeFull::Witness { .. }) => {
            let mut updated_transfer: DbTransferActMod = transfer.clone().into();
            updated_transfer.recipient_type =
                ActiveValue::Set(Some(RecipientTypeFull::Witness { vout }));
            txn.update_transfer(&mut updated_transfer)?;
            let db_utxo = DbTxoActMod {
                txid: ActiveValue::Set(txid.clone()),
                vout: ActiveValue::Set(vout.unwrap()),
                btc_amount: ActiveValue::Set(s!("0")),
                spent: ActiveValue::Set(false),
                exists: ActiveValue::Set(false),
                pending_witness: ActiveValue::Set(true),
                ..Default::default()
            };
            txn.set_txo(db_utxo)?
        }
        _ => return Err(InternalError::Unexpected.into()),
    };
    // a consignment can be processed again once its colorings are saved (e.g. by a watch-only
    // multisig wallet, while the cosigners haven't decided on it): replace them instead of
    // saving them twice
    txn.del_coloring(asset_transfer.idx)?;
    for assignment in receiving.into_values() {
        let db_coloring = DbColoringActMod {
            txo_idx: ActiveValue::Set(utxo_idx),
            asset_transfer_idx: ActiveValue::Set(asset_transfer.idx),
            r#type: ActiveValue::Set(ColoringType::Receive),
            assignment: ActiveValue::Set(assignment),
            ..Default::default()
        };
        txn.set_coloring(db_coloring)?;
    }

    // if the consignment contains unsafe history set status to WaitingSafeHeight and stop here
    let validation_status = valid_consignment.validation_status();
    if validation_status.validity() == Validity::Warnings {
        let unsafe_txids = collect_unsafe_history_txids(&validation_status.warnings, &txid);
        if !unsafe_txids.is_empty() {
            warn!(
                wallet.logger(),
                "Unsafe history detected in consignment: {unsafe_txids:?}"
            );
            updated_batch_transfer.status = ActiveValue::Set(TransferStatus::WaitingSafeHeight);
            return Ok(ApplyOutcome::WaitingSafeHeight(
                txn.update_batch_transfer(updated_batch_transfer)?,
            ));
        }
    }

    let donation_tx = donation_signed_tx(terminal_tx);

    Ok(ApplyOutcome::ReadyForAck { donation_tx })
}

/// The network operations the receive driver needs, one method per operation.
///
/// The driver waits on these, so one orchestration can run over the native blocking client and,
/// next, over the browser's async transport. Only the operations performed after the consignment
/// is on disk are here: fetching it, its retry policy and its caching stay in the caller that
/// owns them.
pub(crate) trait ReceiveTransport {
    /// The resolver of the reject lists the assets declare, reading them before the transaction
    /// opens where the target cannot fetch inside it.
    fn reject_list_resolver(&self) -> &dyn ResolveRejectList;

    /// Fetch and save the media of an unknown asset, returning whether all of it was saved.
    async fn fetch_and_save_attachments(
        &self,
        attachments: Vec<Attachment>,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
    ) -> Result<bool, Error>;

    /// The retention grace advertised by the sender proxy.
    async fn sender_retention_grace(&self, sender_proxy: &str) -> Result<u32, Error>;

    /// Sign and post an ACK (`ack: true`) or NACK (`ack: false`).
    async fn post_ack(
        &self,
        sender_proxy: &str,
        transfer_id: &str,
        ack: bool,
        consignment_hash: &str,
        recipient_seed: &[u8],
    ) -> Result<PostAckResponse, Error>;

    /// Tell the recipient proxy the consignment has been handled, returning whether the proxy
    /// accepted the release. Failures are only logged.
    #[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
    async fn mark_transfer_retrieved(
        &self,
        proxy_url: &str,
        transfer_id: &str,
        recipient_seed: &[u8],
    ) -> bool;

    /// Height of the best-chain tip, the anchor of the safe height a consignment is validated at.
    async fn tip_height(&self) -> Result<u32, Error>;

    /// Broadcast a signed transaction.
    async fn broadcast(&self, tx: BdkTransaction) -> Result<(), Error>;
}

/// [`ReceiveTransport`] over the existing blocking client.
///
/// Every operation is the native call it always was, performed inline: the future never suspends
/// and completes on its first poll.
#[cfg(feature = "_online")]
pub(crate) struct NativeReceiveTransport<'a, W: WalletOnline + ?Sized> {
    wallet: &'a W,
    reject_list_resolver: super::online::WalletRejectListResolver<'a>,
}

#[cfg(feature = "_online")]
impl<'a, W: WalletOnline + ?Sized> NativeReceiveTransport<'a, W> {
    pub(super) fn new(wallet: &'a W) -> Self {
        Self {
            wallet,
            reject_list_resolver: wallet.reject_list_resolver(),
        }
    }
}

#[cfg(feature = "_online")]
impl<W: WalletOnline + ?Sized> ReceiveTransport for NativeReceiveTransport<'_, W> {
    fn reject_list_resolver(&self) -> &dyn ResolveRejectList {
        &self.reject_list_resolver
    }

    async fn fetch_and_save_attachments(
        &self,
        attachments: Vec<Attachment>,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
    ) -> Result<bool, Error> {
        self.wallet
            .fetch_and_save_attachments(attachments, mode, recipient_seed)
    }

    async fn sender_retention_grace(&self, sender_proxy: &str) -> Result<u32, Error> {
        super::online::sender_proxy_retention_grace(sender_proxy)
    }

    async fn post_ack(
        &self,
        sender_proxy: &str,
        transfer_id: &str,
        ack: bool,
        consignment_hash: &str,
        recipient_seed: &[u8],
    ) -> Result<PostAckResponse, Error> {
        self.wallet.sign_and_post_ack(
            sender_proxy,
            transfer_id,
            ack,
            consignment_hash,
            recipient_seed,
        )
    }

    async fn mark_transfer_retrieved(
        &self,
        proxy_url: &str,
        transfer_id: &str,
        recipient_seed: &[u8],
    ) -> bool {
        self.wallet
            .mark_transfer_retrieved(proxy_url, transfer_id, recipient_seed);
        true
    }

    async fn tip_height(&self) -> Result<u32, Error> {
        self.wallet.indexer().get_latest_block_height()
    }

    async fn broadcast(&self, tx: BdkTransaction) -> Result<(), Error> {
        self.wallet.broadcast_tx(tx).map(|_| ())
    }
}

/// Run a receive future on the native synchronous boundary.
///
/// The native transport performs every operation inline and never suspends, so the driver
/// completes on its first poll, on the calling thread and inside the caller's database
/// transaction. `runtime::block_on` is not usable here: its `Send` bound excludes the borrowed
/// wallet and transaction (`DbTxn` is not `Sync`), and entering a runtime would change the context
/// the blocking HTTP client and the database calls run in.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn drive_native<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!(
            "the native receive transport never suspends, so the receive driver cannot be pending"
        ),
    }
}

/// Post the releases the receive driver returned, after the caller's durable save succeeded.
///
/// Posting them before the commit would let the proxy delete the only copy of a consignment whose
/// receive could still roll back; posting them after it means a crash in between leaves the proxy
/// data in place, and the transfer still completes from the local copy.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn release_retrievals<T: ReceiveTransport + ?Sized>(
    transport: &T,
    retrievals: &[PendingRetrieval],
) {
    for retrieval in retrievals {
        drive_native(transport.mark_transfer_retrieved(
            &retrieval.proxy_url,
            &retrieval.transfer_id,
            &retrieval.recipient_seed,
        ));
    }
}

/// The per-consignment receive driver, shared by the native and (next) browser paths.
///
/// A private extension trait, so the public [`WalletOnline`] surface stays unchanged.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(crate) trait ReceiveDriver: ReceiveWallet {
    /// Validate a consignment and apply it, ACKing it or refusing it.
    ///
    /// The caller has already fetched and decrypted the consignment to `consignment_path`, saved
    /// its metadata and marked the proxy endpoint used: those steps keep their retry/caching
    /// policy in the native caller. Everything from loading the file to posting the ACK or NACK
    /// is shared here. `chain` answers the witness and header lookups validation needs.
    ///
    /// A handled proxy receive also returns the `transfer.retrieved` its caller must post, once a
    /// save that includes the handled receive is durable: the proxy may delete the only copy of the
    /// consignment on that call, so it must never run before the commit.
    #[allow(clippy::too_many_arguments)]
    async fn drive_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<(Option<DbBatchTransfer>, Option<PendingRetrieval>), Error>;

    /// Resume an applied receive left in `WaitingSafeHeight`, without applying it again.
    ///
    /// The consignment is loaded and validated again at the current safe height; the ACK is
    /// posted only when the unsafe history it contains has reached that height. The transfer is
    /// never re-applied, so its colorings are not duplicated. The returned `transfer.retrieved`
    /// follows the same rule as [`Self::drive_receive`].
    #[allow(dead_code)] // only the browser resume path calls it today
    #[allow(clippy::too_many_arguments)]
    async fn resume_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: &ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<(Option<DbBatchTransfer>, Option<PendingRetrieval>), Error>;

    /// The phases of [`Self::drive_receive`], without releasing the proxy data.
    #[allow(clippy::too_many_arguments)]
    async fn drive_receive_inner<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: &ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
        resume: bool,
    ) -> Result<Option<DbBatchTransfer>, Error>;

    /// Sign and post the ACK (or the NACK a retention-grace failure calls for).
    #[allow(clippy::too_many_arguments)]
    async fn ack_consignment_via<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        transfer: &DbTransfer,
        updated_batch_transfer: &mut DbBatchTransferActMod,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
        // signed TX embedded in the consignment (donation flow), broadcast directly if present
        donation_tx: Option<BdkTransaction>,
        // whether the consignment is a mint paying the recipient, posted before its TX is signed
        mint_consignment: bool,
    ) -> Result<Option<DbBatchTransfer>, Error>;

    /// NACK the consignment on the proxy and fail the transfer locally.
    #[allow(clippy::too_many_arguments)]
    async fn refuse_consignment_via<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        txn: &DbTxn,
        mode: &ReceiveMode,
        recipient_id: &str,
        recipient_seed: &[u8],
        updated_batch_transfer: &mut DbBatchTransferActMod,
        // whether the consignment is a mint paying the recipient, posted before its TX is signed
        mint_consignment: bool,
    ) -> Result<Option<DbBatchTransfer>, Error>;
}

#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
impl<W: ReceiveWallet + ?Sized> ReceiveDriver for W {
    async fn drive_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<(Option<DbBatchTransfer>, Option<PendingRetrieval>), Error> {
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        let release_id = recipient_id.clone();
        let outcome = self
            .drive_receive_inner(
                transport,
                chain,
                txn,
                batch_transfer,
                asset_transfer,
                transfer,
                recipient_id,
                consignment_path,
                &mode,
                updated_batch_transfer,
                false,
            )
            .await?;

        // once the consignment has been handled (ACKed or refused), its data is saved locally and
        // the proxy can delete it, while the transfer keeps counting towards the invoice quota.
        // The caller posts this only after committing the handled receive.
        let retrieval =
            self.pending_retrieval(&mode, release_id, recipient_seed, outcome.is_some());
        Ok((outcome, retrieval))
    }

    async fn resume_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: &ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<(Option<DbBatchTransfer>, Option<PendingRetrieval>), Error> {
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        let release_id = recipient_id.clone();
        let outcome = self
            .drive_receive_inner(
                transport,
                chain,
                txn,
                batch_transfer,
                asset_transfer,
                transfer,
                recipient_id,
                consignment_path,
                mode,
                updated_batch_transfer,
                true,
            )
            .await?;
        let retrieval = self.pending_retrieval(mode, release_id, recipient_seed, outcome.is_some());
        Ok((outcome, retrieval))
    }

    async fn drive_receive_inner<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        chain: &impl ResolveWitness,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: &ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
        resume: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        let mut stock = self.rgb_stock(txn)?;
        // the recipient's per-operation Ed25519 secret seed (for ACK signing / decryption)
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        // the mint paying the recipient, once the consignment is found to carry one
        #[allow(unused_mut)] // mutated by the native claims handling only
        let mut received_mint: Option<ReceivedMint> = None;
        // refuse the consignment (see refuse_consignment_via), ending the processing. A mint is
        // known as such once checked (by an earlier refresh) or once its claims are read.
        // A macro and not a closure, as it returns from this function and a closure would have to
        // borrow `updated_batch_transfer` mutably (and `received_mint`) for the whole body
        macro_rules! refuse {
            () => {
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        &recipient_seed,
                        updated_batch_transfer,
                        received_mint.is_some() || self.has_received_mint(&recipient_id),
                    )
                    .await
            };
        }

        // a consignment waiting for mint locks has been validated as far as it can be without them
        #[cfg(feature = "_online")]
        if self.waiting_for_mint_locks(consignment_path)? {
            return Ok(None);
        }
        let consignment = match self.load_received_consignment(consignment_path) {
            Ok(c) => c,
            Err(e) => {
                error!(self.logger(), "Failed to load consignment file: {e}");
                refuse!();
            }
        };
        let prepared = prepare_consignment(consignment)?;
        let asset_schema = prepared.asset_schema;
        let asset_id = prepared.asset_id.clone();

        // check if the received schema is supported
        if !self.supports_schema(&asset_schema) {
            error!(
                self.logger(),
                "The wallet doesn't support the provided schema: {}", asset_schema
            );
            refuse!();
        }

        // check if DB transfer is connected to an asset
        if let Some(aid) = asset_transfer.asset_id.clone() {
            // check if asset transfer is connected to the asset we are actually receiving
            if aid != asset_id {
                error!(
                    self.logger(),
                    "Received a different asset than the expected one"
                );
                refuse!();
            }
        }

        // identify what pays this recipient (with the proxy exchange, the seal blinding derived
        // from the keys of both parties), to locate the payment once the consignment is validated
        let blinding = match mode {
            ReceiveMode::Proxy(data) => {
                let seed: [u8; 32] =
                    recipient_seed
                        .clone()
                        .try_into()
                        .map_err(|_| Error::Internal {
                            details: s!("invalid recipient secret key"),
                        })?;
                let sender_vk = hex::decode(&data.sender_pubkey)
                    .ok()
                    .and_then(|pk| verifying_key_from_bytes(&pk).ok());
                let Some(sender_vk) = sender_vk else {
                    error!(self.logger(), "Invalid sender pubkey");
                    refuse!();
                };
                Some(derive_shared(&ed25519_from_seed(&seed), &sender_vk)?.seal_blinding)
            }
            ReceiveMode::OutOfBand { .. } => None,
        };
        let matcher = transfer.receive_matcher(blinding)?;

        // validate consignment
        debug!(self.logger(), "Validating consignment...");
        let validation_safe_height = NonZeroU32::new(safe_height(
            transport.tip_height().await?,
            batch_transfer.min_confirmations,
        ));
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            build_ops_dag: asset_schema.supports_reject_list(),
            safe_height: validation_safe_height,
        };
        // phase 1: everything that only depends on the consignment itself, then the external
        // claims (mint locks) to confirm before resolving the witnesses
        #[cfg(all(test, feature = "_online"))]
        count_received_consignment_validation();
        let pending_and_claims =
            validate_deterministic(&prepared.consignment, asset_schema, &validation_config)
                .and_then(|mut pending| {
                    let claims = pending_claims(&mut pending, asset_schema)?;
                    Ok((pending, claims))
                });
        #[allow(unused_mut)] // mutated by the native claims handling only
        let (mut pending, pending_claims) = match pending_and_claims
            .map_err(|e| receive_checks::received_validation_error(e, self.logger()))
        {
            Ok(pending_and_claims) => pending_and_claims,
            Err(Error::InvalidConsignment) => refuse!(),
            Err(e) => return Err(e),
        };
        // claims live on an external chain, which the browser cannot query yet: a consignment
        // carrying a mint is refused rather than left waiting for it
        #[cfg(not(feature = "_online"))]
        if pending_claims.is_some() {
            error!(
                self.logger(),
                "Consignment carries a mint, which the browser wallet doesn't support yet"
            );
            return Err(Error::UnsupportedMint { asset_schema });
        }

        // locate the payment to us, now that the consignment structure has been validated
        let spent = receive_checks::known_spent_opouts(&prepared.consignment);
        let mut payments: Vec<_> =
            receive_checks::find_payments(&prepared.consignment, &matcher, &spent).collect();
        if payments.len() != 1 {
            if payments.is_empty() {
                error!(
                    self.logger(),
                    "Cannot find any unspent assignment paying this recipient"
                );
            } else {
                error!(
                    self.logger(),
                    "Consignment pays this recipient at {} destinations, refusing it as ambiguous",
                    payments.len()
                );
            }
            refuse!();
        }
        let ConsignmentPayment {
            bundle: paying_bundle,
            payment_seal,
            receiving,
        } = payments.remove(0);
        // for witness receives, the vout of the bundle witness TX being paid
        let vout = payment_seal.vout();
        let witness_id = paying_bundle.witness_id();
        let txid = witness_id.to_string();

        // an invoice is paid by a single allocation: a sender never needs more, as amounts can
        // always be merged, while each extra allocation weighs on the receiving UTXO (spending it
        // moves all of its allocations, which a bundle limits)
        let single_allocation = receiving.len() == 1;
        #[cfg(all(test, feature = "_online"))]
        let single_allocation = single_allocation || accept_multiple_allocations();
        if !single_allocation {
            error!(
                self.logger(),
                "Consignment pays this recipient {} allocations, refusing it",
                receiving.len()
            );
            refuse!();
        }

        // the mint paying this recipient, if any, is refused before it's checked, so that no lock
        // is made for it (see get_received_mint): by a wallet that doesn't accept mints; when
        // exchanged out-of-band, as mints are only sent through proxies (see mint_begin) and an
        // out-of-band receive is processed only when its consignment is provided, so nothing would
        // end the wait for the lock; unless the recipient receives the whole amount minted, which
        // the lock has to match, as otherwise the recipient making the lock would also pay for
        // allocations it doesn't receive (e.g. kept by the minter); unless it pays the amount the
        // invoice requests
        let mut paying_claim = None;
        if let Some(paying_opid) = receive_checks::paying_mint_opid(
            asset_schema,
            paying_bundle,
            receiving.keys().map(|opout| opout.op),
        ) {
            if !self.accepts_received_mints() {
                error!(
                    self.logger(),
                    "Consignment is a mint, which this wallet doesn't accept"
                );
                refuse!();
            }
            if matches!(mode, ReceiveMode::OutOfBand { .. }) {
                error!(
                    self.logger(),
                    "Consignment is a mint, which cannot be received out-of-band"
                );
                refuse!();
            }
            let claim = pending_claims.as_ref().and_then(|pending_claims| {
                pending_claims
                    .claims
                    .iter()
                    .find(|Claim::Lock { opid, .. }| *opid == paying_opid)
                    .cloned()
            });
            let minted = claim.as_ref().map(|Claim::Lock { amount, .. }| *amount);
            let received = receiving.values().map(|a| a.main_amount()).sum::<u64>();
            if minted != Some(received) || receiving.keys().any(|opout| opout.op != paying_opid) {
                error!(
                    self.logger(),
                    "Mint of {minted:?} pays this recipient {received} from it, refusing it"
                );
                refuse!();
            }
            if !receive_checks::mint_pays_requested(transfer, &receiving) {
                error!(
                    self.logger(),
                    "Mint pays this recipient {received}, not the amount its invoice requests"
                );
                refuse!();
            }
            paying_claim = claim;
        }
        let pays_mint = paying_claim.is_some();

        // a mint whose lock may have been made completes whatever the wallet does: refusing it then
        // would leave it on an output the wallet doesn't track, so the checks depending on the
        // state at the time they run (the bound on the lock block and the reject list) aren't
        // repeated for a mint checked by the wallet (see get_received_mint), the check being what
        // the lock relied on, nor run for one whose lock is already recorded (e.g. made before the
        // check by a bridge locking right away, or for a wallet restored from a backup older than
        // the check). The UTXO allocations are checked anyway (see below)
        let checked_mint = self.read_received_mint(&recipient_id)?.is_some();
        #[allow(unused_mut)] // mutated by the native claims handling only
        let mut committed_mint = checked_mint;

        // a UTXO holding more allocations of the asset than a bundle can spend would be frozen,
        // as spending it requires moving all of them, and one holding more allocations than the
        // wallet allows per UTXO goes against its setting: refuse a consignment that would cause
        // either (e.g. paying a UTXO the change of a send has just filled up). This is intended
        // even when some of the allocations counted are still pending, as their transfers settling
        // would take the UTXO past the limit, while waiting to know whether they fail would leave
        // this transfer pending. The other unpaid invoices on the UTXO count too, each for the
        // single allocation that pays it, as they were handed out with a slot reserved for it;
        // this also keeps counting a transfer whose colorings were rolled back after its ACK. A
        // mint whose lock may have been made is refused too, as that loses only the mint, while
        // accepting it would take the UTXO past the limit (freezing all the allocations of the
        // asset on it, the mint included, when past the one of a bundle)
        let receive_outpoint = match &transfer.recipient_type {
            Some(RecipientTypeFull::Blind { unblinded_utxo }) => unblinded_utxo.clone(),
            Some(RecipientTypeFull::Witness { .. }) => Outpoint {
                txid: txid.clone(),
                vout: vout.ok_or(InternalError::Unexpected)?,
            },
            _ => return Err(InternalError::Unexpected.into()),
        };
        let taken = receive_checks::count_utxo_taken_slots(
            txn,
            &receive_outpoint,
            &asset_id,
            transfer.idx,
            asset_transfer.idx,
        )?;
        let max_per_utxo = self.max_allocations_per_utxo() as usize;
        if taken.all + taken.invoices + receiving.len() > max_per_utxo {
            error!(
                self.logger(),
                "Consignment pays {} allocation(s) to a UTXO already holding {} and with {} other \
                 unpaid invoice(s), exceeding the {max_per_utxo} allowed per UTXO",
                receiving.len(),
                taken.all,
                taken.invoices,
            );
            refuse!();
        }
        if taken.asset + taken.invoices + receiving.len() > max_utxo_asset_allocations() {
            error!(
                self.logger(),
                "Consignment pays {} allocation(s) of the asset to a UTXO already holding {} and \
                 with {} other unpaid invoice(s), exceeding the {} a UTXO can hold and still be \
                 spent",
                receiving.len(),
                taken.asset,
                taken.invoices,
                max_utxo_asset_allocations()
            );
            refuse!();
        }
        // a transition can't spend more than u64::MAX of an asset, which BFA assets (with no
        // supply limit) can exceed: refuse a consignment that would take the amount of the asset
        // the UTXO holds or is due past it, as spending the UTXO moves all of it
        let received_amount: u128 = receiving
            .values()
            .map(|a| u128::from(a.main_amount()))
            .sum();
        if taken.asset_amount + received_amount > u128::from(u64::MAX) {
            error!(
                self.logger(),
                "Consignment pays {received_amount} of the asset to a UTXO already holding {}, \
                 exceeding the {} a UTXO can hold and still be spent",
                taken.asset_amount,
                u64::MAX
            );
            refuse!();
        }
        // a UTXO holds at most one mint right of an asset, as issued: refuse a consignment paying
        // one to a UTXO already holding one, or due to receive one (from a pending transfer or
        // another unpaid invoice requesting one, as for the slots above)
        let receives_mint_right = receiving.values().any(|a| *a == Assignment::MintRight);
        if receives_mint_right && taken.mint_rights > 0 {
            error!(
                self.logger(),
                "Consignment pays a mint right to a UTXO already holding or due to receive one"
            );
            refuse!();
        }

        // the paying witness TX may not have been broadcast yet, the others must be on-chain
        let resolver = OffchainResolver {
            witness_id: Some(witness_id),
            consignment: &prepared.consignment,
            fallback: chain,
        };

        #[allow(unused_mut)] // mutated by the native claims handling only
        let mut bridge_circulating_supply: Option<u64> = None;
        #[cfg(feature = "_online")]
        if let Some(PendingClaims {
            bridge_location,
            claims,
        }) = pending_claims
        {
            // the RPC endpoint configured for the chain the mint locks live on is checked to
            // actually be on it before being asked about the claims. A missing or misconfigured
            // endpoint is a local issue, not one with the consignment: keep it and retry at the
            // next refresh, without blocking the other transfers, until the transfer expires or,
            // once the mint has been checked (when it no longer expires by a timestamp), until its
            // lock is found expired
            let BridgeLocation::Evm(EvmContract { chain_id, address }) = &bridge_location;
            let (chain_id, address) = (*chain_id, *address);
            received_mint = paying_claim.as_ref().map(|claim| {
                let Claim::Lock {
                    opid,
                    amount,
                    before_block,
                    ..
                } = claim;
                ReceivedMint {
                    opid: opid.to_string(),
                    lock_id: LockId::from(claim).to_string(),
                    amount: *amount,
                    before_block: *before_block,
                    evm_chain_id: chain_id,
                    bridge_contract: address.to_string(),
                }
            });
            let Some(evm_rpc_url) = self.evm_rpc_url(chain_id) else {
                warn!(
                    self.logger(),
                    "Cannot resolve mint locks: no EVM RPC URL configured for chain ID \
                     {chain_id}, will retry"
                );
                return Ok(None);
            };
            let evm_client = EvmClient::new(evm_rpc_url)?;
            let mint_resolver = MintClaimResolver::new(&evm_client);
            let claim_resolver = match CheckedClaimResolver::with(&mint_resolver, bridge_location) {
                Ok(claim_resolver) => claim_resolver,
                Err(ClaimResolverError::WrongChainId { expected, actual }) => {
                    warn!(
                        self.logger(),
                        "Cannot resolve mint locks: the EVM RPC endpoint configured for chain \
                         ID {expected} is on chain ID {actual}, will retry"
                    );
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            debug!(
                self.logger(),
                "Resolving claims {:?} at bridge location {:?}",
                claims,
                claim_resolver.location()
            );

            // confirm each pending claim that has a matching lock recorded by the bridge contract
            // as of the latest finalized block of the external chain, included before the block
            // it commits to. A mint whose lock wasn't is refused right away, as it will never be
            // confirmed
            let unconfirmed = match resolve_claims(&mut pending, &claim_resolver, &claims, |opid| {
                mint_resolver.is_expired(opid)
            }) {
                Ok(unconfirmed) => unconfirmed,
                Err(e @ Error::MintLockExpired { .. }) => {
                    error!(self.logger(), "{e}");
                    refuse!();
                }
                Err(e) => return Err(e),
            };

            let paying_opid = paying_claim.as_ref().map(|Claim::Lock { opid, .. }| *opid);
            if let Some(opid) = &paying_opid
                && !unconfirmed.contains(opid)
            {
                debug!(self.logger(), "Mint lock already finalized");
                committed_mint = true;
            }

            // a missing mint lock doesn't make the consignment invalid, the lock may simply
            // not have happened yet or not be finalized yet: keep the (cached)
            // consignment and try again at the next refresh, until the lock expires
            if !unconfirmed.is_empty() {
                // the locks to look up at the next refreshes
                let mut waiting_for = unconfirmed.clone();
                // a checked mint is waited for until its lock is finalized or found expired, which
                // must not depend on other locks the check doesn't bound: the other mints the
                // consignment carries (in the paying bundle or in the history) have to be
                // confirmed before the mint is checked. Until then it's waited for like any other
                // receive, expiring with the invoice, looking up only those locks
                let others_unconfirmed = unconfirmed.iter().any(|opid| Some(*opid) != paying_opid);
                if received_mint.is_some() && !checked_mint && others_unconfirmed {
                    info!(
                        self.logger(),
                        "Mint not checked yet, waiting for the other mints it relies on"
                    );
                    waiting_for.retain(|opid| Some(*opid) != paying_opid);
                }
                // a mint is posted before its lock is made, so that its recipient can check it
                // first: check it now (once), assuming the lock is there, so the user knows whether
                // to make it, and what to lock (see get_received_mint)
                if let Some(received_mint) = &received_mint
                    && let Some(paying_claim) = &paying_claim
                    && !checked_mint
                    && !others_unconfirmed
                {
                    if !committed_mint
                        && evm_client.mint_lock_recorded(
                            &address,
                            &LockId::from(paying_claim),
                            received_mint.amount,
                            received_mint.before_block,
                        )?
                    {
                        debug!(self.logger(), "Mint lock already recorded");
                        committed_mint = true;
                    }
                    if !committed_mint {
                        // a checked mint is waited for until its lock is finalized or found
                        // expired, keeping the receiving UTXO unspendable: refuse one committing
                        // to a block further than configured, before anyone has a reason to make
                        // the lock
                        let max_mint_lock_blocks = self
                            .evm_chain(chain_id)
                            .expect("configured along with the EVM RPC URL")
                            .max_mint_lock_blocks;
                        let latest_block = evm_client.block_number()?;
                        if received_mint.before_block
                            > latest_block.saturating_add(max_mint_lock_blocks)
                        {
                            error!(
                                self.logger(),
                                "Mint lock has to be included before block {}, more than {} \
                                 blocks after the latest external chain block {}",
                                received_mint.before_block,
                                max_mint_lock_blocks,
                                latest_block
                            );
                            refuse!();
                        }
                    }
                    let mut assumed = pending.clone();
                    let unresolved: Vec<Claim> =
                        assumed.pending().unresolved_claims().cloned().collect();
                    for claim in &unresolved {
                        assumed
                            .pending()
                            .resolve_claim(claim)
                            .map_err(|e| Error::Internal {
                                details: format!("unexpected claim resolution error: {e}"),
                            })?;
                    }
                    let valid_consignment = match receive_checks::check_received_consignment(
                        assumed,
                        &resolver,
                        asset_schema,
                        &receiving,
                        !committed_mint,
                        self.logger(),
                        transport.reject_list_resolver(),
                    ) {
                        Ok(valid_consignment) => valid_consignment,
                        Err(Error::InvalidConsignment | Error::ConsignmentRejected { .. }) => {
                            refuse!()
                        }
                        Err(e) => return Err(e),
                    };
                    // the media of an unknown asset is fetched now rather than at settlement, as
                    // the recipient proxy may delete it before then, the mint being waited for past
                    // the invoice expiration (see get_received_mint)
                    if asset_transfer.asset_id.is_none()
                        && txn.check_asset_exists(asset_id.clone()).is_err()
                    {
                        let valid_contract = valid_consignment.into_valid_contract();
                        let attachments = receive_checks::extract_attachments(
                            &stock,
                            &valid_contract,
                            asset_schema,
                        )?;
                        if !transport
                            .fetch_and_save_attachments(attachments, mode, &recipient_seed)
                            .await?
                        {
                            refuse!();
                        }
                    }
                    self.save_received_mint(&recipient_id, received_mint)?;
                    // a backup taken before the check doesn't have it: mark one as required, so
                    // that a backup restored once the lock is made has the mint checked already
                    self.update_backup_info(txn, false)?;
                    info!(
                        self.logger(),
                        "Mint checked, waiting for its lock: {received_mint:?}"
                    );
                }
                // until the locks are finalized or one is found expired, the next refreshes only
                // look them up, without validating the consignment again
                let unconfirmed_claims = claims
                    .iter()
                    .filter(|claim| {
                        let Claim::Lock { opid, .. } = claim;
                        waiting_for.contains(opid)
                    })
                    .cloned()
                    .collect();
                self.save_pending_mint_locks(
                    consignment_path,
                    claim_resolver.location(),
                    unconfirmed_claims,
                )?;
                info!(
                    self.logger(),
                    "{} mint lock(s) not found or not confirmed on the external chain yet, will \
                     retry",
                    unconfirmed.len()
                );
                return Ok(None);
            }

            // the bridge accounts all the confirmed mints, saved as the asset's known circulating
            // supply once the consignment is accepted
            bridge_circulating_supply = self.read_bridge_circulating_supply(&evm_client, &address);
        }

        // phase 2 and the checks on what the consignment pays
        let valid_consignment = match receive_checks::check_received_consignment(
            pending,
            &resolver,
            asset_schema,
            &receiving,
            !committed_mint,
            self.logger(),
            transport.reject_list_resolver(),
        ) {
            Ok(valid_consignment) => valid_consignment,
            Err(Error::InvalidConsignment | Error::ConsignmentRejected { .. }) => refuse!(),
            Err(e) => return Err(e),
        };
        let validation_status = valid_consignment.validation_status().clone();
        if let Some(received_mint) = &received_mint {
            self.save_received_mint(&recipient_id, received_mint)?;
        }

        // the unknown-asset media is the only network step left in the apply phase's branch, so
        // the driver fetches it here and the phase below records the result
        let unknown_asset =
            asset_transfer.asset_id.is_none() && txn.check_asset_exists(asset_id.clone()).is_err();
        if unknown_asset {
            debug!(self.logger(), "Receiving unknown contract...");
            let valid_contract = valid_consignment.clone().into_valid_contract();
            let attachments =
                receive_checks::extract_attachments(&stock, &valid_contract, asset_schema)?;
            if !transport
                .fetch_and_save_attachments(attachments, mode, &recipient_seed)
                .await?
            {
                refuse!();
            }
        }

        let outcome = if resume {
            // the consignment was applied by an earlier attempt: never apply it again, or its
            // colorings would be duplicated. A `WaitingSafeHeight` receive still waits until the
            // unsafe history it carries has reached the current safe height before ACKing.
            if batch_transfer.status == TransferStatus::WaitingSafeHeight {
                let resume_safe_height = safe_height(
                    transport.tip_height().await?,
                    batch_transfer.min_confirmations,
                );
                for unsafe_txid in collect_unsafe_history_txids(&validation_status.warnings, &txid)
                {
                    let reached = witness_height(chain, &unsafe_txid)?
                        .is_some_and(|h| h <= resume_safe_height);
                    if !reached {
                        return Ok(None);
                    }
                }
            }
            ApplyOutcome::ReadyForAck {
                donation_tx: donation_signed_tx(&paying_bundle.tx),
            }
        } else {
            receive_checks::update_bfa_known_circulating_supply(
                txn,
                asset_id.clone(),
                bridge_circulating_supply,
            )?;
            apply_received_consignment(
                self,
                chain,
                txn,
                asset_transfer,
                transfer,
                &prepared,
                consignment_path,
                valid_consignment,
                receiving,
                txid,
                vout,
                &paying_bundle.tx,
                unknown_asset,
                &mut stock,
                updated_batch_transfer,
            )?
        };
        match outcome {
            ApplyOutcome::WaitingSafeHeight(batch_transfer) => Ok(Some(batch_transfer)),
            ApplyOutcome::ReadyForAck { donation_tx } => {
                self.ack_consignment_via(
                    transport,
                    txn,
                    batch_transfer,
                    transfer,
                    updated_batch_transfer,
                    mode,
                    &recipient_seed,
                    donation_tx,
                    pays_mint,
                )
                .await
            }
        }
    }

    async fn ack_consignment_via<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        transfer: &DbTransfer,
        updated_batch_transfer: &mut DbBatchTransferActMod,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
        // signed TX embedded in the consignment (donation flow), broadcast directly if present
        donation_tx: Option<BdkTransaction>,
        // whether the consignment is a mint paying the recipient, posted before its TX is signed
        mint_consignment: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "ACKing consignment...");

        let recipient_id = transfer
            .recipient_id
            .clone()
            .expect("transfer should have a recipient ID");

        // the sender proxy retention grace is how long after the operation expiration a released
        // signed TX can still be retrieved: a non-donation, non-mint transfer whose sender proxy
        // grants less than the acceptable minimum is NACKed (v1.0-changes-spec.md 6.4)
        let mut retention_grace = None;
        if let ReceiveMode::Proxy(data) = mode
            && donation_tx.is_none()
            && !mint_consignment
        {
            let grace = transport.sender_retention_grace(&data.sender_proxy).await?;
            if grace < min_sender_retention_grace() {
                warn!(
                    self.logger(),
                    "Sender proxy retention grace ({grace}s) is below the acceptable minimum"
                );
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        recipient_seed,
                        updated_batch_transfer,
                        mint_consignment,
                    )
                    .await;
            }
            retention_grace = Some(grace);
        }

        match self.set_hub_accept_status(batch_transfer.idx)? {
            Some(true) => {}
            Some(false) => return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?)),
            None => return Ok(None),
        }

        // record our own ACK on the transfer
        let record_own_ack = |txn: &DbTxn| -> Result<(), Error> {
            let mut updated_transfer: DbTransferActMod = transfer.clone().into();
            updated_transfer.ack = ActiveValue::Set(Some(true));
            txn.update_transfer(&mut updated_transfer)?;
            Ok(())
        };

        match mode {
            ReceiveMode::Proxy(_) if mint_consignment => {
                // a mint consignment is posted before its TX is signed, so the sender cannot
                // have registered the operation on its proxy (ack.prepare needs the signed TX):
                // there is nothing to ACK, the sender broadcasts the TX on its own once signed
                debug!(
                    self.logger(),
                    "Mint consignment, no ACK expected: waiting for the broadcast"
                );
                record_own_ack(txn)?;
                updated_batch_transfer.status = ActiveValue::Set(TransferStatus::WaitingBroadcast);
            }
            ReceiveMode::Proxy(data) => {
                let res = match transport
                    .post_ack(
                        &data.sender_proxy,
                        &data.transfer_id,
                        true,
                        &data.consignment_hash,
                        recipient_seed,
                    )
                    .await
                {
                    Ok(r) => r,
                    // the sender proxy may have no operation (e.g. donation): broadcast locally
                    Err(Error::OperationNotFound) if donation_tx.is_some() => {
                        record_own_ack(txn)?;
                        transport
                            .broadcast(donation_tx.expect("checked to be some"))
                            .await?;
                        updated_batch_transfer.status =
                            ActiveValue::Set(TransferStatus::WaitingConfirmations);
                        return Ok(Some(txn.update_batch_transfer(updated_batch_transfer)?));
                    }
                    // a NACK is already recorded for this recipient (only this wallet could have
                    // posted it, as ACKs are signed with its operation key): the sender fails the
                    // operation on seeing it, so there is nothing left to wait for
                    Err(Error::ProxyCannotChange { .. }) => {
                        warn!(
                            self.logger(),
                            "A NACK was already posted for this recipient, failing the transfer"
                        );
                        return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
                    }
                    Err(e) => return Err(e),
                };
                debug!(self.logger(), "Consignment ACK response: {:?}", res);

                record_own_ack(txn)?;

                // the shared deadline for broadcasting the TX, after which (plus a confirmation
                // margin) the transfer is failed if the TX is not confirmed
                if let Some(grace) = retention_grace {
                    updated_batch_transfer.broadcast_deadline =
                        ActiveValue::Set(broadcast_deadline(
                            res.expires_at.as_deref(),
                            grace,
                            batch_transfer.expiration,
                        ));
                }

                match (res.signed_tx, res.signed_tx_hash, res.sender_pk) {
                    (Some(signed_tx), Some(signed_tx_hash), Some(sender_pubkey)) => {
                        // the TX has been released: decrypt and broadcast it
                        let tx = self.decrypt_save_received_tx(
                            &recipient_id,
                            &signed_tx,
                            &signed_tx_hash,
                            &sender_pubkey,
                            recipient_seed,
                        )?;
                        transport.broadcast(tx).await?;
                        updated_batch_transfer.status =
                            ActiveValue::Set(TransferStatus::WaitingConfirmations);
                    }
                    _ if donation_tx.is_some() => {
                        // donation: the signed TX travels inside the consignment, broadcast it
                        transport
                            .broadcast(donation_tx.expect("checked to be some"))
                            .await?;
                        updated_batch_transfer.status =
                            ActiveValue::Set(TransferStatus::WaitingConfirmations);
                    }
                    _ => {
                        // the TX has not been released (yet): for a batch operation not all
                        // recipients have ACKed yet, for a non-batch one the proxy is not
                        // compliant. Either way wait for the broadcast, posting the ACK again until
                        // the TX is returned or the operation expires (v1.0-changes-spec.md 6.4)
                        if !data.batch {
                            warn!(
                                self.logger(),
                                "No signed TX released for a non-batch operation"
                            );
                        }
                        updated_batch_transfer.status =
                            ActiveValue::Set(TransferStatus::WaitingBroadcast);
                    }
                }
            }
            ReceiveMode::OutOfBand { .. } => {
                // out-of-band: no proxy operation to ACK; the counterparty ACK is exchanged out of
                // band. Broadcast the donation TX if present, otherwise wait for the broadcast.
                record_own_ack(txn)?;
                updated_batch_transfer.status = if let Some(tx) = donation_tx {
                    debug!(
                        self.logger(),
                        "Consignment contains the signed TX, broadcasting it"
                    );
                    transport.broadcast(tx).await?;
                    ActiveValue::Set(TransferStatus::WaitingConfirmations)
                } else {
                    debug!(
                        self.logger(),
                        "Consignment doesn't contain the signed TX, waiting for broadcast"
                    );
                    ActiveValue::Set(TransferStatus::WaitingBroadcast)
                };
            }
        }

        Ok(Some(txn.update_batch_transfer(updated_batch_transfer)?))
    }

    async fn refuse_consignment_via<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        txn: &DbTxn,
        mode: &ReceiveMode,
        recipient_id: &str,
        recipient_seed: &[u8],
        updated_batch_transfer: &mut DbBatchTransferActMod,
        // whether the consignment is a mint paying the recipient, posted before its TX is signed
        mint_consignment: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(
            self.logger(),
            "Refusing invalid consignment for {recipient_id}"
        );

        // only the proxy exchange has an operation to NACK; out-of-band just fails locally, and a
        // mint has its own ACK/NACK logic (see ack_consignment_via)
        if let ReceiveMode::Proxy(data) = mode
            && !mint_consignment
        {
            match transport
                .post_ack(
                    &data.sender_proxy,
                    &data.transfer_id,
                    false,
                    &data.consignment_hash,
                    recipient_seed,
                )
                .await
            {
                Ok(r) => debug!(self.logger(), "Consignment NACK response: {:?}", r),
                Err(Error::ProxyCannotChange { .. }) => {
                    warn!(self.logger(), "Found an ACK when trying NACK");
                }
                // the sender proxy may have no operation (e.g. donation): just fail locally
                Err(Error::OperationNotFound) => {}
                Err(e) => {
                    error!(self.logger(), "Failed to post NACK: {e}");
                    return Err(e);
                }
            };
        }

        // a refused receive has no TXO registered, but a sync may have detected one paying its
        // script if the counterparty has already broadcast
        let scripts = script_buf_from_recipient_id(recipient_id.to_string())?
            .into_iter()
            .collect();
        self.unflag_pending_witness_txos(txn, &HashSet::new(), &scripts)?;
        self.delete_valid_consignment(recipient_id)?;
        updated_batch_transfer.status = ActiveValue::Set(TransferStatus::Failed);
        Ok(Some(txn.update_batch_transfer(updated_batch_transfer)?))
    }
}

#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) fn collect_unsafe_history_txids(
    warnings: &[Warning],
    exclude_txid: &str,
) -> HashSet<String> {
    let mut txids = HashSet::new();
    for warning in warnings {
        if let Warning::UnsafeHistory(unsafe_history) = warning {
            for other_txids in unsafe_history.values() {
                for txid in other_txids {
                    let txid = txid.to_string();
                    if txid != *exclude_txid {
                        txids.insert(txid);
                    }
                }
            }
        }
    }
    txids
}

// return the signed witness tx embedded in the consignment, if present
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) fn donation_signed_tx(tx: &BdkTransaction) -> Option<BdkTransaction> {
    Some(tx)
        .filter(|tx| {
            !tx.input.is_empty()
                && tx
                    .input
                    .iter()
                    .all(|i| !i.witness.is_empty() || !i.script_sig.is_empty())
        })
        .cloned()
}

/// The canonical ACK/NACK content message digest used both when signing (recipient) and
/// verifying (sender) an ACK (SHA-256 of `recipient_id || true|false || consignment_hash`).
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn ack_digest(transfer_id: &str, ack: bool, consignment_hash: &str) -> [u8; 32] {
    let msg = format!(
        "{transfer_id}{}{consignment_hash}",
        if ack { "true" } else { "false" }
    );
    sha256_digest(msg.as_bytes())
}

/// Build the hex-encoded Ed25519 signature posted with an ACK/NACK, without posting it.
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn ack_signature(
    transfer_id: &str,
    ack: bool,
    consignment_hash: &str,
    recipient_seed: &[u8],
) -> Result<String, Error> {
    let seed: [u8; 32] = recipient_seed.try_into().map_err(|_| Error::Internal {
        details: s!("invalid recipient secret key"),
    })?;
    let sk = ed25519_from_seed(&seed);
    let digest = ack_digest(transfer_id, ack, consignment_hash);
    Ok(hex::encode(sign_ed25519(&sk, &digest)))
}

/// Build the hex-encoded Ed25519 signature posted with `transfer.retrieved`, `None` when the
/// recipient seed is malformed (the caller can only skip the call).
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn transfer_retrieved_signature(
    transfer_id: &str,
    recipient_seed: &[u8],
) -> Option<String> {
    let seed = <[u8; 32]>::try_from(recipient_seed).ok()?;
    let sk = ed25519_from_seed(&seed);
    let digest = sha256_digest(transfer_retrieved_message(transfer_id).as_bytes());
    Some(hex::encode(sign_ed25519(&sk, &digest)))
}

/// Parse a reject list into its `(reject, allow)` opouts.
///
/// Shared by the native blocking fetch and the browser one, so a list is validated the same way on
/// both transports. A malformed line fails the whole list: treating it as empty would silently
/// disable the issuer's reject policy.
#[cfg_attr(feature = "_online", allow(dead_code))] // used by the browser transport
pub(super) fn parse_reject_list(
    list: &str,
    logger: &Logger,
) -> Result<(HashSet<Opout>, HashSet<Opout>), Error> {
    let reject_list = list.trim();
    let mut opout_map = HashMap::with_capacity(reject_list.lines().count());
    for line in reject_list.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (is_allow, opout_str) = line.strip_prefix("!").map_or((false, line), |s| (true, s));
        let opout = Opout::from_str(opout_str).map_err(|_| {
            warn!(logger, "Invalid opout in reject list: {line}");
            Error::RejectListService {
                details: format!("invalid opout in reject list: {line}"),
            }
        })?;
        opout_map.insert(opout, is_allow);
    }
    let (allow_opouts, reject_opouts) = opout_map.into_iter().fold(
        (HashSet::new(), HashSet::new()),
        |(mut allow, mut reject), (o, allowed)| {
            if allowed {
                allow.insert(o);
            } else {
                reject.insert(o);
            }
            (allow, reject)
        },
    );

    Ok((reject_opouts, allow_opouts))
}

#[cfg(all(test, feature = "_online"))]
mod tests {
    use super::*;

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    use crate::utils::recipient_id_from_script_buf;

    /// A reject list resolver that has nothing to say, for the transports that don't reach it.
    struct NoRejectList;

    impl ResolveRejectList for NoRejectList {
        fn get_reject_list(&self, _source: &RejectListSource) -> Result<RejectList, Error> {
            Ok(RejectList::default())
        }
    }

    /// A transport that answers every operation without touching the network, recording the calls
    /// the receive driver makes.
    struct FakeTransport<'a> {
        calls: &'a std::cell::RefCell<Vec<&'static str>>,
    }

    impl ReceiveTransport for FakeTransport<'_> {
        fn reject_list_resolver(&self) -> &dyn ResolveRejectList {
            self.calls.borrow_mut().push("reject_list");
            &NoRejectList
        }

        async fn fetch_and_save_attachments(
            &self,
            _attachments: Vec<Attachment>,
            _mode: &ReceiveMode,
            _recipient_seed: &[u8],
        ) -> Result<bool, Error> {
            self.calls.borrow_mut().push("attachments");
            Ok(true)
        }

        async fn sender_retention_grace(&self, _sender_proxy: &str) -> Result<u32, Error> {
            self.calls.borrow_mut().push("retention_grace");
            Ok(0)
        }

        async fn post_ack(
            &self,
            _sender_proxy: &str,
            _transfer_id: &str,
            ack: bool,
            _consignment_hash: &str,
            _recipient_seed: &[u8],
        ) -> Result<PostAckResponse, Error> {
            self.calls
                .borrow_mut()
                .push(if ack { "ack" } else { "nack" });
            Ok(PostAckResponse {
                result: true,
                sender_pk: None,
                signed_tx: None,
                signed_tx_hash: None,
                expires_at: None,
            })
        }

        async fn mark_transfer_retrieved(
            &self,
            _proxy_url: &str,
            _transfer_id: &str,
            _recipient_seed: &[u8],
        ) -> bool {
            self.calls.borrow_mut().push("retrieved");
            true
        }

        async fn tip_height(&self) -> Result<u32, Error> {
            Ok(1)
        }

        async fn broadcast(&self, _tx: BdkTransaction) -> Result<(), Error> {
            self.calls.borrow_mut().push("broadcast");
            Ok(())
        }
    }

    /// The native bridge drives the transport's futures to completion on the calling thread, in
    /// the order the driver awaits them, without a runtime.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn drive_native_runs_the_transport_in_await_order() {
        let calls = std::cell::RefCell::new(vec![]);
        let transport = FakeTransport { calls: &calls };
        let caller = std::thread::current().id();

        let output = drive_native(async {
            transport.reject_list_resolver();
            transport.sender_retention_grace("proxy").await.unwrap();
            transport
                .post_ack("proxy", "id", true, "hash", &[])
                .await
                .unwrap();
            transport.mark_transfer_retrieved("proxy", "id", &[]).await;
            std::thread::current().id()
        });

        assert_eq!(output, caller);
        assert_eq!(
            calls.into_inner(),
            ["reject_list", "retention_grace", "ack", "retrieved"]
        );
    }

    /// The bridge returns the driver's error unchanged, like the synchronous code did.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn drive_native_propagates_the_transport_error() {
        struct Failing;

        impl ReceiveTransport for Failing {
            fn reject_list_resolver(&self) -> &dyn ResolveRejectList {
                &NoRejectList
            }

            async fn fetch_and_save_attachments(
                &self,
                _attachments: Vec<Attachment>,
                _mode: &ReceiveMode,
                _recipient_seed: &[u8],
            ) -> Result<bool, Error> {
                unreachable!()
            }

            async fn sender_retention_grace(&self, _sender_proxy: &str) -> Result<u32, Error> {
                unreachable!()
            }

            async fn post_ack(
                &self,
                _sender_proxy: &str,
                _transfer_id: &str,
                _ack: bool,
                _consignment_hash: &str,
                _recipient_seed: &[u8],
            ) -> Result<PostAckResponse, Error> {
                Err(Error::NoConsignment)
            }

            async fn mark_transfer_retrieved(
                &self,
                _proxy_url: &str,
                _transfer_id: &str,
                _recipient_seed: &[u8],
            ) -> bool {
                unreachable!()
            }

            async fn tip_height(&self) -> Result<u32, Error> {
                unreachable!()
            }

            async fn broadcast(&self, _tx: BdkTransaction) -> Result<(), Error> {
                unreachable!()
            }
        }

        let err = drive_native(async {
            Failing.post_ack("proxy", "id", true, "hash", &[]).await?;
            Ok::<(), Error>(())
        })
        .unwrap_err();
        assert!(matches!(err, Error::NoConsignment));
    }

    /// The native transport never suspends, which is what makes the single poll safe: a future
    /// that does suspend is a bug in the adapter, not something to wait on without a runtime.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[should_panic(expected = "never suspends")]
    fn drive_native_rejects_a_suspending_future() {
        drive_native(std::future::pending::<()>());
    }

    fn test_logger() -> Logger {
        Logger::root(slog::Discard, o!())
    }

    #[test]
    fn reject_list_parsing_is_shared_and_fails_closed() {
        let opout = "0000000000000000000000000000000000000000000000000000000000000000/0/1";
        let list = format!("  {opout}\n!{opout}\n\n");
        let (reject, allow) = parse_reject_list(&list, &test_logger()).unwrap();
        // the same opout in the list twice: the last entry wins, like the native parser
        assert!(reject.is_empty());
        assert_eq!(allow.len(), 1);

        let err = parse_reject_list("not-an-opout\n", &test_logger()).unwrap_err();
        assert_matches!(err, Error::RejectListService { .. });
    }

    #[test]
    fn transfer_retrieved_signature_matches_the_canonical_message() {
        let seed = [7u8; 32];
        let signature = transfer_retrieved_signature("transfer-id", &seed).unwrap();
        let sk = ed25519_from_seed(&seed);
        let digest = sha256_digest(transfer_retrieved_message("transfer-id").as_bytes());
        assert_eq!(signature, hex::encode(sign_ed25519(&sk, &digest)));
        assert_eq!(
            transfer_retrieved_signature("transfer-id", &seed).unwrap(),
            signature
        );
        assert!(transfer_retrieved_signature("transfer-id", &[1, 2, 3]).is_none());
    }

    #[test]
    fn ack_digest_matches_the_canonical_sha256() {
        // sha256("transfer-id" + "true" + "consignment-hash")
        assert_eq!(
            hex::encode(ack_digest("transfer-id", true, "consignment-hash")),
            "5061fa1bc0ff9fd969f3e2feaad2f32db3686278fe13457c736b41f5bb18ba7c"
        );
        // sha256("transfer-id" + "false" + "consignment-hash")
        assert_eq!(
            hex::encode(ack_digest("transfer-id", false, "consignment-hash")),
            "e479994ccdb8a65dbcdac2bc3519c977d66c4961228c135f55b9201abc716c30"
        );
    }

    #[test]
    fn ack_signature_is_deterministic_and_verifiable() {
        let seed = [7u8; 32];
        let signature = ack_signature("transfer-id", true, "consignment-hash", &seed).unwrap();
        assert_eq!(
            signature,
            ack_signature("transfer-id", true, "consignment-hash", &seed).unwrap()
        );

        let sk = ed25519_from_seed(&seed);
        let digest = ack_digest("transfer-id", true, "consignment-hash");
        assert!(verify_ed25519(
            &sk.verifying_key(),
            &digest,
            &hex::decode(&signature).unwrap()
        ));
    }

    #[test]
    fn ack_signature_rejects_a_malformed_seed() {
        let err = ack_signature("transfer-id", true, "consignment-hash", &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, Error::Internal { .. }));
    }

    /// A wallet on a throwaway SQLite directory, for the driver tests below: no indexer and no
    /// proxy is reached, so they need neither network nor docker.
    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    fn driver_wallet() -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::TempDir::new().unwrap();
        let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::SegWitV0);
        let wallet = Wallet::new(
            crate::wallet::test::get_test_wallet_data(dir.path().to_str().unwrap()),
            SinglesigKeys::from_keys(&keys, None),
        )
        .unwrap();
        (dir, wallet)
    }

    /// Insert one pending incoming transfer and return the rows the driver takes.
    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    fn insert_pending_receive(
        txn: &DbTxn,
        recipient_id: &str,
    ) -> (DbBatchTransfer, DbAssetTransfer, DbTransfer) {
        let batch_idx = txn
            .set_batch_transfer(DbBatchTransferActMod {
                status: ActiveValue::Set(TransferStatus::WaitingCounterparty),
                created_at: ActiveValue::Set(0),
                updated_at: ActiveValue::Set(0),
                min_confirmations: ActiveValue::Set(1),
                incoming: ActiveValue::Set(true),
                operation_secret_key: ActiveValue::Set(Some(vec![7u8; 32])),
                ..Default::default()
            })
            .unwrap();
        let batch = DbBatchTransfer {
            idx: batch_idx,
            txid: None,
            status: TransferStatus::WaitingCounterparty,
            created_at: 0,
            updated_at: 0,
            expiration: None,
            min_confirmations: 1,
            incoming: true,
            operation_secret_key: Some(vec![7u8; 32]),
            broadcast_deadline: None,
            retention_deadline: None,
        };

        let asset_transfer_idx = txn
            .set_asset_transfer(DbAssetTransferActMod {
                user_driven: ActiveValue::Set(false),
                batch_transfer_idx: ActiveValue::Set(batch_idx),
                asset_id: ActiveValue::Set(None),
                ..Default::default()
            })
            .unwrap();
        let asset_transfer = DbAssetTransfer {
            idx: asset_transfer_idx,
            user_driven: false,
            batch_transfer_idx: batch_idx,
            asset_id: None,
            transition_type: None,
        };

        let transfer_idx = txn
            .set_transfer(DbTransferActMod {
                asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                recipient_id: ActiveValue::Set(Some(recipient_id.to_string())),
                recipient_encryption: ActiveValue::Set(Encryption::Optional),
                ..Default::default()
            })
            .unwrap();
        let transfer = DbTransfer {
            idx: transfer_idx,
            asset_transfer_idx,
            requested_assignment: None,
            recipient_type: None,
            recipient_id: Some(recipient_id.to_string()),
            ack: None,
            invoice_string: None,
            recipient_pubkey: None,
            consignment_hash: None,
            recipient_encryption: Encryption::Optional,
            ack_signature: None,
            proxy_transfer_id: None,
            invoice_expiration: None,
        };

        (batch, asset_transfer, transfer)
    }

    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    fn proxy_mode() -> ReceiveMode {
        ReceiveMode::Proxy(ProxyReceiveData {
            proxy_url: s!("http://recipient-proxy"),
            transfer_id: s!("transfer-id"),
            sender_proxy: s!("http://sender-proxy"),
            sender_pubkey: s!("00"),
            consignment_hash: s!("consignment-hash"),
            recipient_encryption: Encryption::Optional,
            batch: false,
        })
    }

    /// An unreadable consignment is refused exactly like before the driver move: the NACK is
    /// posted, the transfer is failed - and all of it inside the caller's transaction, so a
    /// rollback leaves the transfer untouched. The proxy release is only returned: posting it
    /// before the caller's commit could delete the only copy of an uncommitted receive.
    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    #[test]
    fn drive_receive_refuses_an_unreadable_consignment_and_rolls_back() {
        let (dir, wallet) = driver_wallet();
        let recipient_id = recipient_id_from_script_buf(
            ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x11; 20]).unwrap(),
            ),
            BitcoinNetwork::Regtest,
        );
        let setup = wallet.database().begin_transaction().unwrap();
        let (batch, asset_transfer, transfer) = insert_pending_receive(&setup, &recipient_id);
        setup.commit().unwrap();
        let txn = wallet.database().begin_transaction().unwrap();
        let mut updated: DbBatchTransferActMod = batch.clone().into();

        let calls = std::cell::RefCell::new(vec![]);
        let transport = FakeTransport { calls: &calls };
        let chain = DumbResolver;
        let (outcome, retrieval) = drive_native(wallet.drive_receive(
            &transport,
            &chain,
            &txn,
            &batch,
            &asset_transfer,
            &transfer,
            recipient_id.clone(),
            &dir.path().join("missing.rgbcons"),
            proxy_mode(),
            &mut updated,
        ))
        .unwrap();

        assert_eq!(outcome.unwrap().status, TransferStatus::Failed);
        // the NACK goes out, but the release waits for the caller's save
        assert_eq!(calls.borrow().as_slice(), ["nack"]);
        let retrieval = retrieval.expect("the handled receive leaves its release to the caller");
        assert_eq!(retrieval.proxy_url, "http://recipient-proxy");
        assert_eq!(retrieval.transfer_id, "transfer-id");
        assert_eq!(retrieval.recipient_id, recipient_id);
        assert_eq!(retrieval.recipient_seed, vec![7u8; 32]);
        assert_eq!(
            txn.get_batch_transfer(batch.idx).unwrap().unwrap().status,
            TransferStatus::Failed
        );

        drop(txn);
        let txn = wallet.database().begin_transaction().unwrap();
        assert_eq!(
            txn.get_batch_transfer(batch.idx).unwrap().unwrap().status,
            TransferStatus::WaitingCounterparty
        );
        drop(txn);

        // the caller committed, so the release can go out now
        release_retrievals(&transport, std::slice::from_ref(&retrieval));
        assert_eq!(calls.into_inner(), ["nack", "retrieved"]);
    }

    /// The out-of-band ACK branch needs no transport: it records the ACK, moves the transfer to
    /// waiting for the broadcast and leaves both writes to the caller's transaction.
    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    #[test]
    fn ack_consignment_via_out_of_band_records_the_ack_and_rolls_back() {
        let (_dir, wallet) = driver_wallet();
        let recipient_id = recipient_id_from_script_buf(
            ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x22; 20]).unwrap(),
            ),
            BitcoinNetwork::Regtest,
        );
        let setup = wallet.database().begin_transaction().unwrap();
        let (batch, _asset_transfer, transfer) = insert_pending_receive(&setup, &recipient_id);
        setup.commit().unwrap();
        let txn = wallet.database().begin_transaction().unwrap();
        let mut updated: DbBatchTransferActMod = batch.clone().into();

        let calls = std::cell::RefCell::new(vec![]);
        let transport = FakeTransport { calls: &calls };
        let outcome = drive_native(wallet.ack_consignment_via(
            &transport,
            &txn,
            &batch,
            &transfer,
            &mut updated,
            &ReceiveMode::OutOfBand {
                media_file_paths: vec![],
            },
            &[],
            None,
            false,
        ))
        .unwrap();

        assert_eq!(outcome.unwrap().status, TransferStatus::WaitingBroadcast);
        let ack = txn
            .get_db_data(false)
            .unwrap()
            .transfers
            .into_iter()
            .find(|t| t.idx == transfer.idx)
            .unwrap()
            .ack;
        assert_eq!(ack, Some(true));

        drop(txn);
        let txn = wallet.database().begin_transaction().unwrap();
        assert_eq!(
            txn.get_batch_transfer(batch.idx).unwrap().unwrap().status,
            TransferStatus::WaitingCounterparty
        );
        assert_eq!(
            txn.get_db_data(false)
                .unwrap()
                .transfers
                .into_iter()
                .find(|t| t.idx == transfer.idx)
                .unwrap()
                .ack,
            None
        );
    }

    fn witness_tx() -> BdkTransaction {
        BdkTransaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    #[test]
    fn prefetch_questions_cover_every_bundle_witness_and_spv_height_once() {
        let mut questions = PrefetchQuestions::default();
        let first = witness_tx().compute_txid();
        let second = BdkTransaction {
            version: bdk_wallet::bitcoin::transaction::Version::ONE,
            ..witness_tx()
        }
        .compute_txid();
        let height = NonZeroU32::new(9).expect("non-zero");

        // the same witness in two bundles is one question, and only a proof adds a header
        questions.record_bundle(first, Some(height));
        questions.record_bundle(first, Some(height));
        questions.record_bundle(second, None);

        assert_eq!(questions.witness_ids.len(), 2);
        assert!(questions.witness_ids.contains(&first));
        assert!(questions.witness_ids.contains(&second));
        assert_eq!(questions.heights.len(), 1);
        assert!(questions.heights.contains(&height));
    }

    /// The browser selection: only pending, incoming, non-out-of-band transfers of this wallet are
    /// candidates; the expected proxy transfer ID matches the native derivation, and a transfer
    /// already carrying that ID is recognized as handled.
    #[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
    #[test]
    fn pending_receives_selects_the_native_candidates_and_matches_the_transfer_id() {
        let (_dir, wallet) = driver_wallet();
        let recipient_id = recipient_id_from_script_buf(
            ScriptBuf::new_p2wpkh(
                &bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x33; 20]).unwrap(),
            ),
            BitcoinNetwork::Regtest,
        );
        let txn = wallet.database().begin_transaction().unwrap();
        let (batch, _asset_transfer, transfer) = insert_pending_receive(&txn, &recipient_id);
        let recipient_pubkey = vec![0x44; 32];
        let mut updated_transfer: DbTransferActMod = transfer.clone().into();
        updated_transfer.recipient_pubkey = ActiveValue::Set(Some(recipient_pubkey.clone()));
        txn.update_transfer(&mut updated_transfer).unwrap();

        let db_data = txn.get_db_data(false).unwrap();
        let pending = pending_receives(&db_data).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].batch.idx, batch.idx);

        let sender_pk = hex::encode([0x55; 32]);
        let expected = transfer_id(
            &invoice_id(&recipient_id, &hex::encode(&recipient_pubkey)),
            &sender_pk,
        );
        assert_eq!(
            pending[0].expected_transfer_id(&sender_pk),
            Some(expected.clone())
        );
        assert_eq!(already_handled(&db_data, &expected), None);

        let mut updated_transfer: DbTransferActMod = transfer.clone().into();
        updated_transfer.proxy_transfer_id = ActiveValue::Set(Some(expected.clone()));
        txn.update_transfer(&mut updated_transfer).unwrap();
        let db_data = txn.get_db_data(false).unwrap();
        // a stored proxy ID alone is not completion: the receive is still waiting a counterparty
        assert_eq!(already_handled(&db_data, &expected), None);
        assert_eq!(receive_transfer_idx(&db_data, &expected), Some(batch.idx));

        // an applied receive left in WaitingBroadcast or WaitingSafeHeight stays a candidate
        for status in [
            TransferStatus::WaitingBroadcast,
            TransferStatus::WaitingSafeHeight,
            TransferStatus::WaitingConfirmations,
        ] {
            let mut updated_batch: DbBatchTransferActMod = batch.clone().into();
            updated_batch.status = ActiveValue::Set(status);
            txn.update_batch_transfer(&mut updated_batch).unwrap();
            let db_data = txn.get_db_data(false).unwrap();
            assert_eq!(
                pending_receives(&db_data).unwrap().len(),
                1,
                "{status:?} must be resumable"
            );
            assert_eq!(already_handled(&db_data, &expected), None);
        }

        // only Settled and Failed are terminal, so a repeated sync leaves them untouched
        for status in [TransferStatus::Settled, TransferStatus::Failed] {
            let mut updated_batch: DbBatchTransferActMod = batch.clone().into();
            updated_batch.status = ActiveValue::Set(status);
            txn.update_batch_transfer(&mut updated_batch).unwrap();
            let db_data = txn.get_db_data(false).unwrap();
            assert!(pending_receives(&db_data).unwrap().is_empty());
            assert_eq!(already_handled(&db_data, &expected), Some(batch.idx));
        }
    }

    #[test]
    fn safe_height_saturates_at_the_tip() {
        assert_eq!(safe_height(u32::MAX, 0), u32::MAX);
        assert_eq!(safe_height(u32::MAX, 1), u32::MAX);
        assert_eq!(safe_height(0, 0), 1);
    }

    #[test]
    fn broadcast_deadline_rejects_untrusted_expirations() {
        let now_ts = now().unix_timestamp();
        let grace = 10;
        // an expiration in the future, within the invoice expiration, gets the grace added
        let expires_at = (now_ts + 100).to_string();
        assert_eq!(
            broadcast_deadline(Some(&expires_at), grace, Some(now_ts + 200)),
            Some(now_ts + 100 + i64::from(grace))
        );
        // one in the past, or past the invoice expiration, or unparsable, is refused
        assert_eq!(broadcast_deadline(Some("1"), grace, Some(100)), None);
        assert_eq!(
            broadcast_deadline(Some(&(now_ts + 300).to_string()), grace, Some(now_ts + 200)),
            None
        );
        assert_eq!(
            broadcast_deadline(Some("9223372036854775807"), grace, None),
            None
        );
        assert_eq!(
            broadcast_deadline(Some("9223372036854775807"), grace, Some(100)),
            None
        );
    }
}
