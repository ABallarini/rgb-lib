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
#[cfg(not(target_arch = "wasm32"))]
use std::task::{Context, Poll, Waker};

use super::*;

#[cfg(feature = "_online")]
use super::online::{broadcast_deadline, min_sender_retention_grace};

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

    fn get_hub_fail_status(&self, _batch_transfer_idx: i32) -> Result<bool, Error> {
        Ok(false)
    }

    fn set_hub_accept_status(&self, _batch_transfer_idx: i32) -> Result<Option<bool>, Error> {
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

    /// Locate the consignment terminal paying this recipient.
    ///
    /// Returns the terminal witness bundle and, for witness receives, the vout being paid.
    ///
    /// The bundle and vout returned here together identify the one payment destination the transfer
    /// waits on and credits from. A consignment declaring more than one such destination for this
    /// recipient - a different witness TXID (so a different bundle), or a different vout of the
    /// same TXID - is refused instead of resolved arbitrarily: `terminals` is counterparty-supplied
    /// data, it is read before validation, and its iteration order (by bundle ID) carries no
    /// meaning, so picking one of several genuinely different destinations would credit an
    /// unpredictable one of them. Several terminal seals defined on the same vout of the same
    /// bundle are a different matter (see the dedup in `push_match` below): that is one
    /// destination described more than once, not several to choose between.
    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn find_terminal_bundle<'c>(
        &self,
        consignment: &'c RgbTransfer,
        matcher: &ReceiveMatcher,
    ) -> Option<(&'c WitnessBundle, Option<u32>)> {
        let mut matches: Vec<(&'c WitnessBundle, Option<u32>)> = vec![];
        let mut push_match = |witness_bundle: &'c WitnessBundle, vout: Option<u32>| {
            // several revealed seals of one bundle can be defined on the same witness output - one
            // per assignment, e.g. two assignment types paying this recipient, differing only by
            // blinding - so keying on bundle + vout counts them as the single payment they are,
            // instead of tripping the ambiguity check below
            //
            // a no-op for concealed seals, which are matched on presence alone and push `None` once
            // per bundle
            if !matches.iter().any(|(wb, v)| {
                wb.bundle.bundle_id() == witness_bundle.bundle.bundle_id() && *v == vout
            }) {
                matches.push((witness_bundle, vout));
            }
        };

        for (bundle_id, seals) in consignment.terminals.iter() {
            // this lookup happens before validation, so a bundle a terminal references is not
            // yet guaranteed to be present and is simply skipped here: validation later refuses
            // the consignment over it
            let Some(witness_bundle) = consignment
                .bundles
                .iter()
                .find(|wb| wb.bundle.bundle_id() == *bundle_id)
            else {
                continue;
            };
            match matcher {
                ReceiveMatcher::Blind(secret_seal) => {
                    if seals
                        .into_iter()
                        .any(|seal| seal == BuilderSeal::Concealed(*secret_seal))
                    {
                        push_match(witness_bundle, None);
                    }
                }
                ReceiveMatcher::Witness(script_pubkey, blinding) => {
                    let tx = &witness_bundle.tx;
                    for seal in seals {
                        // a witness receive is matched by the scriptPubKey at the vout the seal
                        // names, which a concealed seal does not expose - it belongs to the blind
                        // arm above
                        let BuilderSeal::Revealed(seal) = seal else {
                            continue;
                        };
                        // only a seal closed by this bundle's own witness TX is a payment made by
                        // it: one naming an explicit TXID points at another transaction, so its
                        // vout would be looked up against the wrong `tx` below
                        if seal.txid != TxPtr::WitnessTx {
                            continue;
                        }
                        // with the proxy exchange the blinding is derived from the keys of both
                        // parties, so a seal with a different one doesn't pay this transfer
                        if blinding.is_some_and(|b| b != seal.blinding) {
                            continue;
                        }
                        let vout = seal.vout.into_u32();
                        if tx
                            .output
                            .get(vout as usize)
                            .is_some_and(|out| out.script_pubkey == *script_pubkey)
                        {
                            push_match(witness_bundle, Some(vout));
                        }
                    }
                }
            }
        }

        if matches.len() > 1 {
            error!(
                self.logger(),
                "Consignment declares {} terminal payments to this recipient, refusing it as \
                 ambiguous",
                matches.len()
            );
            return None;
        }
        matches.into_iter().next()
    }

    // extract the assignments in a single bundle that pay the recipient identified by
    // `known_concealed` (blind receives) or by the witness `vout` (witness receives)
    fn assignments_for_bundle(
        &self,
        bundle: &WitnessBundle,
        vout: Option<u32>,
        known_concealed: Option<SecretSeal>,
    ) -> HashMap<Opout, Assignment> {
        let mut received = HashMap::new();
        for KnownTransition { transition, opid } in bundle.bundle.known_transitions.iter() {
            for (ass_type, typed_assigns) in transition.assignments.iter() {
                for (no, fungible_assignment) in typed_assigns.as_fungible().iter().enumerate() {
                    let opout = Opout::new(*opid, *ass_type, no as u16);
                    if let BuilderSeal::Concealed(seal) = fungible_assignment.seal
                        && Some(seal) == known_concealed
                    {
                        match *ass_type {
                            OS_ASSET => {
                                received.insert(
                                    opout,
                                    Assignment::Fungible(fungible_assignment.state.as_u64()),
                                );
                            }
                            OS_INFLATION => {
                                received.insert(
                                    opout,
                                    Assignment::InflationRight(fungible_assignment.state.as_u64()),
                                );
                            }
                            _ => {}
                        }
                    };
                    if let BuilderSeal::Revealed(seal) = fungible_assignment.seal
                        && seal.txid == TxPtr::WitnessTx
                        && Some(seal.vout.into_u32()) == vout
                    {
                        match *ass_type {
                            OS_ASSET => {
                                received.insert(
                                    opout,
                                    Assignment::Fungible(fungible_assignment.state.as_u64()),
                                );
                            }
                            OS_INFLATION => {
                                received.insert(
                                    opout,
                                    Assignment::InflationRight(fungible_assignment.state.as_u64()),
                                );
                            }
                            _ => {}
                        }
                    };
                }
                for (no, structured_assignment) in typed_assigns.as_structured().iter().enumerate()
                {
                    let opout = Opout::new(*opid, *ass_type, no as u16);
                    if let BuilderSeal::Concealed(seal) = structured_assignment.seal
                        && Some(seal) == known_concealed
                    {
                        received.insert(opout, Assignment::NonFungible);
                    }
                    if let BuilderSeal::Revealed(seal) = structured_assignment.seal
                        && seal.txid == TxPtr::WitnessTx
                        && Some(seal.vout.into_u32()) == vout
                    {
                        received.insert(opout, Assignment::NonFungible);
                    };
                }
            }
        }

        received
    }

    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn extract_attachments(
        &self,
        stock: &RgbStock<'_>,
        valid_contract: &ValidContract,
        asset_schema: AssetSchema,
    ) -> Result<Vec<Attachment>, Error> {
        let mut attachments = vec![];
        let contract_data = stock.consignment_data(valid_contract)?;
        match asset_schema {
            AssetSchema::Nia => {
                let contract = NiaWrapper::with(contract_data);
                if let Some(attachment) = contract.contract_terms().media {
                    attachments.push(attachment)
                }
            }
            AssetSchema::Uda => {
                let contract = UdaWrapper::with(contract_data);
                if let Some(attachment) = contract.contract_terms().media {
                    attachments.push(attachment)
                }
                let token_data = contract.token_data();
                if let Some(media) = token_data.media {
                    attachments.push(media)
                }
                attachments.extend(
                    token_data
                        .attachments
                        .to_unconfined()
                        .values()
                        .cloned()
                        .collect::<Vec<Attachment>>(),
                )
            }
            AssetSchema::Cfa => {
                let contract = CfaWrapper::with(contract_data);
                if let Some(attachment) = contract.contract_terms().media {
                    attachments.push(attachment)
                }
            }
            AssetSchema::Ifa => {
                let contract = IfaWrapper::with(contract_data);
                if let Some(attachment) = contract.contract_terms().media {
                    attachments.push(attachment)
                }
            }
        };
        Ok(attachments)
    }

    /// Whether a `schema` can carry a reject list.
    fn schema_supports_reject_list(schema: AssetSchema) -> bool {
        match schema {
            AssetSchema::Ifa => true,
            AssetSchema::Nia | AssetSchema::Uda | AssetSchema::Cfa => false,
        }
    }

    /// The reject list URL a contract declares, read off it the way its `schema` requires.
    ///
    /// Only for the schemas `schema_supports_reject_list` accepts.
    fn reject_list_url_for_schema(
        schema: AssetSchema,
        contract_data: ContractData<FilteredContractState>,
    ) -> Option<String> {
        match schema {
            AssetSchema::Ifa => IfaWrapper::with(contract_data)
                .reject_list_url()
                .map(|u| u.to_string()),
            AssetSchema::Nia | AssetSchema::Uda | AssetSchema::Cfa => {
                unreachable!("{schema} does not support a reject list")
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

    #[cfg(any(
        feature = "_online",
        all(feature = "esplora_async", target_arch = "wasm32")
    ))]
    fn check_dag(
        &self,
        dag_data: &OpoutsDagData,
        reject_opouts: &HashSet<Opout>,
        allow_opouts: &HashSet<Opout>,
        check_opouts: &HashSet<Opout>,
    ) -> Result<HashSet<Opout>, Error> {
        let (dag, index) = dag_data;
        let mut to_reject = HashSet::new();

        // for each opout we are checking, traverse its ancestor chain
        for check_opout in check_opouts {
            let &opout_node = index.get(check_opout).ok_or(Error::Internal {
                details: s!("opout not found in DAG"),
            })?;

            // traverse from this node to its ancestors, depth first
            let mut stack = vec![opout_node];
            let mut visited = HashSet::new();
            while let Some(node) = stack.pop() {
                if !visited.insert(node) {
                    continue;
                }
                let node_opout = &dag[node];
                // allow shields this path upward: do not traverse this branch further
                if allow_opouts.contains(node_opout) {
                    continue;
                }
                // encountering a reject node on an unshielded path: reject
                if reject_opouts.contains(node_opout) {
                    to_reject.insert(*check_opout);
                    break;
                }
                for (_edge, parent) in dag.parents(node).iter(dag) {
                    stack.push(parent);
                }
            }
        }
        Ok(to_reject)
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

/// The pending incoming transfers that can still be received from a proxy.
///
/// Outgoing transfers are skipped by `incoming`, and every status other than
/// `WaitingCounterparty` is terminal for the receive loop: an applied transfer is idempotently
/// skipped instead of being applied twice. Out-of-band invoices are skipped too, as they have no
/// proxy transfer to fetch.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) fn pending_receives(db_data: &DbData) -> Result<Vec<PendingReceive>, Error> {
    let mut pending = vec![];
    for batch in &db_data.batch_transfers {
        if !batch.incoming || batch.status != TransferStatus::WaitingCounterparty {
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

/// The index of an incoming transfer already bearing `transfer_id`, if any.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // used by the browser receive loop
pub(super) fn already_handled(db_data: &DbData, transfer_id: &str) -> Option<i32> {
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
pub(super) fn broadcast_deadline(expires_at: Option<&str>, retention_grace: u32) -> Option<i64> {
    expires_at
        .and_then(|exp| exp.parse::<i64>().ok())
        .and_then(|exp| exp.checked_add(i64::from(retention_grace)))
}

/// Map the reason an indexer gave for refusing a broadcast to the wallet error that tells the
/// sender why, when that reason is one worth distinguishing.
///
/// Shared by the native and browser transports, so the same node response yields the same error.
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

/// Outcome of the rgb-ops validation step.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) enum ConsignmentValidation {
    Valid(Box<ValidTransfer>),
    /// the consignment is invalid: the caller logs the details and refuses it
    Invalid(String),
}

/// Validate a consignment with the same rgb-ops call and error mapping the native receive uses.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) fn validate_consignment(
    consignment: &RgbTransfer,
    asset_schema: AssetSchema,
    resolver: &impl ResolveWitness,
    validation_config: &ValidationConfig,
) -> Result<ConsignmentValidation, Error> {
    match consignment
        .clone()
        .validate(&asset_schema.schema_rules(), resolver, validation_config)
    {
        Ok(consignment) => Ok(ConsignmentValidation::Valid(Box::new(consignment))),
        Err(ValidationError::InvalidConsignment(e)) => {
            Ok(ConsignmentValidation::Invalid(e.to_string()))
        }
        Err(ValidationError::ResolverError(e)) => Err(Error::Network {
            details: e.to_string(),
        }),
        Err(e) => Err(Error::Internal {
            details: format!("unexpected consignment validation error: {e}"),
        }),
    }
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
pub(super) trait ReceiveTransport {
    /// The reject and allow lists of a contract.
    async fn get_reject_list(&self, url: &str) -> Result<(HashSet<Opout>, HashSet<Opout>), Error>;

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

    /// Tell the recipient proxy the consignment has been handled. Failures are only logged.
    async fn mark_transfer_retrieved(
        &self,
        proxy_url: &str,
        transfer_id: &str,
        recipient_seed: &[u8],
    );

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
pub(super) struct NativeReceiveTransport<'a, W: WalletOnline + ?Sized> {
    wallet: &'a W,
}

#[cfg(feature = "_online")]
impl<'a, W: WalletOnline + ?Sized> NativeReceiveTransport<'a, W> {
    pub(super) fn new(wallet: &'a W) -> Self {
        Self { wallet }
    }
}

#[cfg(feature = "_online")]
impl<W: WalletOnline + ?Sized> ReceiveTransport for NativeReceiveTransport<'_, W> {
    async fn get_reject_list(&self, url: &str) -> Result<(HashSet<Opout>, HashSet<Opout>), Error> {
        self.wallet.get_reject_list(url)
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
    ) {
        self.wallet
            .mark_transfer_retrieved(proxy_url, transfer_id, recipient_seed);
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
pub(super) fn drive_native<F: Future>(future: F) -> F::Output {
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

/// The per-consignment receive driver, shared by the native and (next) browser paths.
///
/// A private extension trait, so the public [`WalletOnline`] surface stays unchanged.
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
pub(super) trait ReceiveDriver: ReceiveWallet {
    /// Validate a consignment and apply it, ACKing it or refusing it.
    ///
    /// The caller has already fetched and decrypted the consignment to `consignment_path`, saved
    /// its metadata and marked the proxy endpoint used: those steps keep their retry/caching
    /// policy in the native caller. Everything from loading the file to posting the ACK or NACK
    /// is shared here. `chain` answers the witness and header lookups validation needs.
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
    ) -> Result<Option<DbBatchTransfer>, Error>;

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
    ) -> Result<Option<DbBatchTransfer>, Error>;

    /// NACK the consignment on the proxy and fail the transfer locally.
    async fn refuse_consignment_via<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
        txn: &DbTxn,
        mode: &ReceiveMode,
        recipient_id: &str,
        recipient_seed: &[u8],
        updated_batch_transfer: &mut DbBatchTransferActMod,
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
    ) -> Result<Option<DbBatchTransfer>, Error> {
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
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
            )
            .await?;

        // once the consignment has been handled (ACKed or refused), its data is saved locally and
        // the proxy can delete it, while the transfer keeps counting towards the invoice quota
        if outcome.is_some()
            && self.releases_received_transfer_data()
            && let ReceiveMode::Proxy(data) = &mode
        {
            transport
                .mark_transfer_retrieved(&data.proxy_url, &data.transfer_id, &recipient_seed)
                .await;
        }

        Ok(outcome)
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
    ) -> Result<Option<DbBatchTransfer>, Error> {
        let mut stock = self.rgb_stock(txn)?;
        // the recipient's per-operation Ed25519 secret seed (for ACK signing / decryption)
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        let consignment = match self.load_received_consignment(consignment_path) {
            Ok(c) => c,
            Err(e) => {
                error!(self.logger(), "Failed to load consignment file: {e}");
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        &recipient_seed,
                        updated_batch_transfer,
                    )
                    .await;
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
            return self
                .refuse_consignment_via(
                    transport,
                    txn,
                    mode,
                    &recipient_id,
                    &recipient_seed,
                    updated_batch_transfer,
                )
                .await;
        }

        // check if DB transfer is connected to an asset
        if let Some(aid) = asset_transfer.asset_id.clone() {
            // check if asset transfer is connected to the asset we are actually receiving
            if aid != asset_id {
                error!(
                    self.logger(),
                    "Received a different asset than the expected one"
                );
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        &recipient_seed,
                        updated_batch_transfer,
                    )
                    .await;
            }
        }

        // a transfer consignment must declare the terminals it pays
        if prepared.consignment.terminals.is_empty() {
            error!(self.logger(), "Consignment declares no terminals");
            return self
                .refuse_consignment_via(
                    transport,
                    txn,
                    mode,
                    &recipient_id,
                    &recipient_seed,
                    updated_batch_transfer,
                )
                .await;
        }

        // locate the terminal paying us
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
                    return self
                        .refuse_consignment_via(
                            transport,
                            txn,
                            mode,
                            &recipient_id,
                            &recipient_seed,
                            updated_batch_transfer,
                        )
                        .await;
                };
                Some(derive_shared(&ed25519_from_seed(&seed), &sender_vk)?.seal_blinding)
            }
            ReceiveMode::OutOfBand { .. } => None,
        };
        let matcher = transfer.receive_matcher(blinding)?;
        let Some((terminal_bundle, vout)) =
            self.find_terminal_bundle(&prepared.consignment, &matcher)
        else {
            error!(
                self.logger(),
                "Cannot find a consignment terminal paying this recipient"
            );
            return self
                .refuse_consignment_via(
                    transport,
                    txn,
                    mode,
                    &recipient_id,
                    &recipient_seed,
                    updated_batch_transfer,
                )
                .await;
        };
        let witness_id = terminal_bundle.witness_id();
        let txid = witness_id.to_string();
        let known_concealed = match matcher {
            ReceiveMatcher::Blind(secret_seal) => Some(secret_seal),
            ReceiveMatcher::Witness(..) => None,
        };

        // validate consignment
        debug!(self.logger(), "Validating consignment...");
        let safe_height = NonZeroU32::new(safe_height(
            transport.tip_height().await?,
            batch_transfer.min_confirmations,
        ));
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            build_opouts_dag: Self::schema_supports_reject_list(asset_schema),
            safe_height,
        };
        let resolver = OffchainResolver {
            witness_id,
            consignment: &prepared.consignment,
            fallback: chain,
        };
        let valid_consignment = match validate_consignment(
            &prepared.consignment,
            asset_schema,
            &resolver,
            &validation_config,
        )? {
            ConsignmentValidation::Valid(consignment) => *consignment,
            ConsignmentValidation::Invalid(e) => {
                error!(self.logger(), "Consignment is invalid: {}", e);
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        &recipient_seed,
                        updated_batch_transfer,
                    )
                    .await;
            }
        };
        let validation_status = valid_consignment.validation_status();
        let validity = validation_status.validity();
        debug!(self.logger(), "Consignment validity: {:?}", validity);

        let receiving = self.assignments_for_bundle(terminal_bundle, vout, known_concealed);
        if receiving.is_empty() {
            error!(self.logger(), "Cannot find any receiving assignment");
            return self
                .refuse_consignment_via(
                    transport,
                    txn,
                    mode,
                    &recipient_id,
                    &recipient_seed,
                    updated_batch_transfer,
                )
                .await;
        }

        if Self::schema_supports_reject_list(asset_schema) {
            let url = if let Ok(ass) = txn.check_asset_exists(asset_id.clone()) {
                ass.reject_list_url
            } else {
                Self::reject_list_url_for_schema(
                    asset_schema,
                    stock.consignment_data(&valid_consignment)?,
                )
            };
            if let Some(url) = &url {
                let (reject_opouts, allow_opouts) = transport.get_reject_list(url).await?;

                let to_reject = self.check_dag(
                    validation_status
                        .dag_data_opt
                        .as_ref()
                        .expect("build_opouts_dag is set for schemas supporting a reject list"),
                    &reject_opouts,
                    &allow_opouts,
                    &receiving.clone().into_keys().collect(),
                )?;

                if !to_reject.is_empty() {
                    error!(
                        self.logger(),
                        "Found {} opout(s) that must be rejected",
                        to_reject.len()
                    );
                    return self
                        .refuse_consignment_via(
                            transport,
                            txn,
                            mode,
                            &recipient_id,
                            &recipient_seed,
                            updated_batch_transfer,
                        )
                        .await;
                } else {
                    info!(
                        self.logger(),
                        "Didn't find any opout(s) that should be rejected"
                    );
                }
            }
        }

        // the unknown-asset media is the only network step left in the apply phase's branch, so
        // the driver fetches it here and the phase below records the result
        let unknown_asset =
            asset_transfer.asset_id.is_none() && txn.check_asset_exists(asset_id.clone()).is_err();
        if unknown_asset {
            debug!(self.logger(), "Receiving unknown contract...");
            let valid_contract = valid_consignment.clone().into_valid_contract();
            let attachments = self.extract_attachments(&stock, &valid_contract, asset_schema)?;
            if !transport
                .fetch_and_save_attachments(attachments, mode, &recipient_seed)
                .await?
            {
                return self
                    .refuse_consignment_via(
                        transport,
                        txn,
                        mode,
                        &recipient_id,
                        &recipient_seed,
                        updated_batch_transfer,
                    )
                    .await;
            }
        }

        let outcome = match apply_received_consignment(
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
            &terminal_bundle.tx,
            unknown_asset,
            &mut stock,
            updated_batch_transfer,
        )? {
            ApplyOutcome::WaitingSafeHeight(batch_transfer) => Some(batch_transfer),
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
                )
                .await?
            }
        };

        Ok(outcome)
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
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "ACKing consignment...");

        let recipient_id = transfer
            .recipient_id
            .clone()
            .expect("transfer should have a recipient ID");

        // the sender proxy retention grace is how long after the operation expiration a released
        // signed TX can still be retrieved: a non-donation transfer whose sender proxy grants
        // less than the acceptable minimum is NACKed (v1.0-changes-spec.md 6.4)
        let mut retention_grace = None;
        if let ReceiveMode::Proxy(data) = mode
            && donation_tx.is_none()
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
                        ActiveValue::Set(broadcast_deadline(res.expires_at.as_deref(), grace));
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
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(
            self.logger(),
            "Refusing invalid consignment for {recipient_id}"
        );

        // only the proxy exchange has an operation to NACK; out-of-band just fails locally
        if let ReceiveMode::Proxy(data) = mode {
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
pub(super) fn ack_digest(transfer_id: &str, ack: bool, consignment_hash: &str) -> [u8; 32] {
    let msg = format!(
        "{transfer_id}{}{consignment_hash}",
        if ack { "true" } else { "false" }
    );
    sha256_digest(msg.as_bytes())
}

/// Build the hex-encoded Ed25519 signature posted with an ACK/NACK, without posting it.
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

    /// A transport that answers every operation without touching the network, recording the calls
    /// the receive driver makes.
    struct FakeTransport<'a> {
        calls: &'a std::cell::RefCell<Vec<&'static str>>,
    }

    impl ReceiveTransport for FakeTransport<'_> {
        async fn get_reject_list(
            &self,
            _url: &str,
        ) -> Result<(HashSet<Opout>, HashSet<Opout>), Error> {
            self.calls.borrow_mut().push("reject_list");
            Ok((HashSet::new(), HashSet::new()))
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
        ) {
            self.calls.borrow_mut().push("retrieved");
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
            transport.get_reject_list("url").await.unwrap();
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
            async fn get_reject_list(
                &self,
                _url: &str,
            ) -> Result<(HashSet<Opout>, HashSet<Opout>), Error> {
                Err(Error::NoConsignment)
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
                unreachable!()
            }

            async fn mark_transfer_retrieved(
                &self,
                _proxy_url: &str,
                _transfer_id: &str,
                _recipient_seed: &[u8],
            ) {
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
            Failing.get_reject_list("url").await?;
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
    /// posted, the proxy data is released, the transfer is failed - and all of it inside the
    /// caller's transaction, so a rollback leaves the transfer untouched.
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
        let outcome = drive_native(wallet.drive_receive(
            &transport,
            &chain,
            &txn,
            &batch,
            &asset_transfer,
            &transfer,
            recipient_id,
            &dir.path().join("missing.rgbcons"),
            proxy_mode(),
            &mut updated,
        ))
        .unwrap();

        assert_eq!(outcome.unwrap().status, TransferStatus::Failed);
        // the NACK goes out before the proxy data is released
        assert_eq!(calls.into_inner(), ["nack", "retrieved"]);
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
        assert_eq!(already_handled(&db_data, &expected), Some(batch.idx));

        // a terminal status is no longer a candidate, so a repeated sync leaves it untouched
        let mut updated_batch: DbBatchTransferActMod = batch.clone().into();
        updated_batch.status = ActiveValue::Set(TransferStatus::WaitingBroadcast);
        txn.update_batch_transfer(&mut updated_batch).unwrap();
        let db_data = txn.get_db_data(false).unwrap();
        assert!(pending_receives(&db_data).unwrap().is_empty());
    }

    #[test]
    fn safe_height_saturates_at_the_tip() {
        assert_eq!(safe_height(u32::MAX, 0), u32::MAX);
        assert_eq!(safe_height(u32::MAX, 1), u32::MAX);
        assert_eq!(safe_height(0, 0), 1);
    }

    #[test]
    fn broadcast_deadline_rejects_overflow() {
        assert_eq!(broadcast_deadline(Some("9223372036854775807"), 10), None);
        assert_eq!(broadcast_deadline(Some("100"), 10), Some(110));
    }
}
