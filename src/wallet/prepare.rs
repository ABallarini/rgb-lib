//! Preparation of outgoing operations.
//!
//! The steps building the PSBT and the transfer data of a send, a burn, a link or a mint, shared
//! by the native online wallet and, next, by the browser one: they only touch the database, the
//! BDK wallet and the transfer directory. The network steps they need are the hooks of
//! [`WalletPrepare`] or parameters (`check_recipients_transport_endpoints`), implemented by each
//! transport. Posting to a proxy is native only so far, as it reads the files to upload.

use super::*;

// items the native online module gets from the crate root only with `_online`, needed here by the
// shared preparation as well
#[cfg(feature = "_online")]
use crate::{
    api::proxy::{
        PostConsignmentData, ProxyClient, map_proxy_error, post_consignment_message,
        post_media_message, pow_difficulty_required,
    },
    encryption::{encrypt_to_tempfile, sign_ed25519, solve_pow},
    utils::{hash_file, proxy_max_media},
};
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
use crate::{
    database::entities::reserved_txo::ActiveModel as DbReservedTxoActMod,
    encryption::{derive_shared, ed25519_from_seed, verifying_key_from_bytes},
    no_wallet::validation::{
        RejectList, RejectListSource, genesis_reject_list_source, rejected_opouts,
    },
};
#[cfg(any(
    feature = "_online",
    all(feature = "esplora_async", target_arch = "wasm32")
))]
use std::{
    collections::hash_map::{DefaultHasher, Entry},
    hash::Hasher,
};

/// The minimum fee rate, in sat/vbyte, an operation can be prepared with.
const MIN_FEE_RATE: u64 = 1;

/// The assignments of a type an operation moves with a transition of the type's default type,
/// beside its main transition (see [`add_or_side_output`]).
#[derive(Default)]
struct SideTransfer {
    /// The inputs to spend
    inputs: Vec<(Opout, AllocatedState)>,
    /// The outputs to assign
    outputs: Vec<(BuilderSeal<GraphSeal>, AllocatedState)>,
    /// Set when the main transition can't assign this type but still spends it (a burn), and there
    /// is change: the output of this transition that the main transition then spends, as its seal
    /// and amount. The other outputs are the change.
    split: Option<(GraphSeal, u64)>,
}

/// The amount of `state`, 0 for a state that isn't an amount (e.g. a UDA token).
fn state_amount(state: &AllocatedState) -> u64 {
    match state {
        AllocatedState::Amount(amt) => amt.as_u64(),
        _ => 0,
    }
}

/// Assign `state` of type `ty` to `seal` with the main transition built by `builder`, if it can
/// assign the type, otherwise with the transition of the type's default type in `side_transfers`.
///
/// `main_assignment_types` are all the types the main transition can assign: one for a transfer,
/// two for an inflation (assets and inflation rights), none for a burn, whose change is assigned by
/// side transitions. `main_used` is set when the main transition assigns the state.
fn add_or_side_output(
    builder: TransitionBuilder,
    main_assignment_types: &HashSet<AssignmentType>,
    main_used: &mut bool,
    side_transfers: &mut BTreeMap<AssignmentType, SideTransfer>,
    ty: AssignmentType,
    seal: BuilderSeal<GraphSeal>,
    state: AllocatedState,
) -> Result<TransitionBuilder, Error> {
    if main_assignment_types.contains(&ty) {
        *main_used = true;
        return Ok(builder.add_owned_state_raw(ty, seal, state)?);
    }
    side_transfers
        .entry(ty)
        .or_default()
        .outputs
        .push((seal, state));
    Ok(builder)
}

/// The steps preparing an outgoing operation, from the selection of its inputs to the transfer
/// data it saves.
///
/// The network operations they need are the hooks below, so that the same authoring can run over
/// the native blocking client and, next, over the browser transport.
pub trait WalletPrepare: WalletOffline {
    /// Resolve the reject list of the given source, reading it over the network.
    fn resolve_reject_list(&self, source: &RejectListSource) -> Result<RejectList, Error>;

    /// Fast-sync the colored keychain, run when the index of a spent TXO is not known yet.
    fn sync_colored_fast(&mut self, txn: &DbTxn) -> Result<(), Error>;

    /// Whether an operation can pay a recipient with no transport endpoint, exchanging the
    /// consignment out of band.
    fn supports_out_of_band_exchange(&self) -> bool {
        true
    }

    fn check_fee_rate(&self, fee_rate: u64) -> Result<FeeRate, Error> {
        #[cfg(all(test, feature = "_online"))]
        if skip_check_fee_rate() {
            return Ok(FeeRate::from_sat_per_vb(fee_rate).unwrap());
        };
        if fee_rate < MIN_FEE_RATE {
            return Err(Error::InvalidFeeRate {
                details: format!("value under minimum {MIN_FEE_RATE}"),
            });
        }
        let Some(fee_rate) = FeeRate::from_sat_per_vb(fee_rate) else {
            return Err(Error::InvalidFeeRate {
                details: s!("value overflows"),
            });
        };
        Ok(fee_rate)
    }

    /// Apply to the local state a signed TX that has just been broadcast, so that its outputs show
    /// up without a sync and its inputs are spent: BDK, the DB TXOs and the reservations.
    ///
    /// Split from the broadcast itself (the native blocking indexer, the async transport on wasm),
    /// so that both transports end an operation here, in the same order.
    fn apply_broadcasted_tx(&mut self, txn: &DbTxn, tx: &BdkTransaction) -> Result<(), Error> {
        // apply the broadcast TX into BDK directly so its outputs are immediately visible
        // (revealed change SPKs match without needing a wallet sync)
        let seen_at = now().unix_timestamp() as u64;
        self.bdk_wallet_mut()
            .apply_unconfirmed_txs([(tx.clone(), seen_at)]);
        // the TX is on the network now and the enclosing transaction may still fail or take a
        // while to commit: keep a copy on disk so a crash cannot lose it
        self.flush_bdk_pending()?;

        // promote any newly-known colored UTXOs (e.g. the change output) from
        // exists=false to exists=true in the rgb_lib DB
        let pending_witness_scripts = self.reconcile_pending_witness(txn)?;
        self.update_db_colored_txos_from_bdk(txn, false, &pending_witness_scripts)?;

        let input_outpoints: Vec<Outpoint> = tx
            .input
            .iter()
            .map(|i| Outpoint::from(i.previous_output))
            .collect();
        for outpoint in &input_outpoints {
            if let Some(db_txo) = txn.get_txo(outpoint)? {
                let mut db_txo: DbTxoActMod = db_txo.into();
                db_txo.spent = ActiveValue::Set(true);
                txn.update_txo(db_txo)?;
            }
        }
        // the inputs are spent now, release the reservations of the pending transfer
        txn.del_colored_reserved_txos_by_outpoints(&input_outpoints)?;

        Ok(())
    }

    /// The local half of ending an operation, once its signed TX has been broadcast: the broadcast
    /// TX is applied (see [`Self::apply_broadcasted_tx`]), the fascia is consumed and the transfer
    /// data is saved or updated. The network call stays with the caller, so the native blocking
    /// indexer and the browser transport share this step.
    #[allow(clippy::too_many_arguments)]
    fn finalize_transfer_end_after_broadcast(
        &mut self,
        txn: &DbTxn,
        txid: String,
        tx: &BdkTransaction,
        psbt: &Psbt,
        info_contents: &InfoBatchTransfer,
        status: TransferStatus,
        consignment_hashes: &HashMap<String, String>,
        fascia: Fascia,
        sync_tte_used: bool,
    ) -> Result<i32, Error> {
        self.apply_broadcasted_tx(txn, tx)?;
        let mut stock = self.rgb_stock(txn)?;
        stock.consume_fascia(fascia, None)?;
        self.update_or_save_transfers(
            txn,
            txid,
            info_contents,
            status,
            consignment_hashes,
            sync_tte_used,
            psbt,
        )
    }

    /// Check that the operation of the given signed PSBT can still be ended. An operation saved by
    /// a non-dry-run begin is ended (e.g. again, retried after a crash) only while it's still
    /// initiated: one that has failed or progressed must not be broadcast again nor have its
    /// status brought back.
    fn check_end_initiated(&self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<(), Error> {
        let txid = signed_psbt.unsigned_tx.compute_txid().to_string();
        if let Some(existing) = txn
            .get_batch_transfers_by_txid(&txid)?
            .into_iter()
            .find(|batch_transfer| !batch_transfer.incoming)
            && existing.status != TransferStatus::Initiated
        {
            return Err(Error::CannotEndTransfer { txid });
        }
        Ok(())
    }

    fn reserve_colored_txos(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        let reservations: Vec<DbReservedTxoActMod> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| DbReservedTxoActMod {
                txid: ActiveValue::Set(i.previous_output.txid.to_string()),
                vout: ActiveValue::Set(i.previous_output.vout),
                reserved_for_colored: ActiveValue::Set(Some(batch_transfer_idx)),
                ..Default::default()
            })
            .collect();
        txn.set_reserved_txos(reservations)?;
        Ok(())
    }

    /// The number of allocations of an asset the inputs of an operation with the given main
    /// transition can hold: the ones a bundle can spend (see [`MAX_UTXO_ASSET_ALLOCATIONS`]), but
    /// one for a burn, as it can't return change: its inputs are first split by another transition
    /// of the bundle, whose output the burn spends, adding an entry to the input map.
    ///
    /// [`MAX_UTXO_ASSET_ALLOCATIONS`]: crate::wallet::offline::MAX_UTXO_ASSET_ALLOCATIONS
    fn max_input_allocations(main_transition: &TypeOfTransition) -> usize {
        match main_transition {
            TypeOfTransition::Burn => max_utxo_asset_allocations() - 1,
            _ => max_utxo_asset_allocations(),
        }
    }

    /// Select the UTXOs holding the assignments of the asset needed by an operation, adding them
    /// to `selected`, which tracks the ones selected for all the assets of the operation: a UTXO
    /// that would take the allocations of an asset held by them past `max_allocations` (see
    /// [`Self::max_input_allocations`]) is skipped. If skipping UTXOs leaves too few assignments,
    /// the selection is retried from the UTXOs with the most, so the fewest are selected.
    fn select_rgb_inputs(
        &self,
        asset_id: String,
        assignments_needed: &AssignmentsCollection,
        unspents: Vec<LocalUnspent>,
        selected: &mut SelectedInputs,
        max_allocations: usize,
    ) -> Result<AssetSpend, Error> {
        // the sum of the given amount of the settled allocations of the asset held by the given
        // UTXO, which the selection collects: the allocations of other assets don't count, as
        // their amounts may not fit together in a u64, while the ones of a single asset do
        let asset_sum = |unspent: &LocalUnspent, amount: fn(&Assignment) -> u64| -> u64 {
            unspent
                .rgb_allocations
                .iter()
                .filter(|a| a.asset_id.as_ref() == Some(&asset_id) && a.status.settled())
                .map(|a| amount(&a.assignment))
                .sum()
        };

        debug!(
            self.logger(),
            "Selecting inputs for asset '{}'...", asset_id
        );
        let mut mut_unspents = unspents;

        // sort unspents first by inflation rights amount, then main amount
        if assignments_needed.inflation > 0 {
            mut_unspents.sort_by_cached_key(|u| asset_sum(u, Assignment::inflation_amount));
        }
        if assignments_needed.fungible > 0 {
            mut_unspents.sort_by_cached_key(|u| asset_sum(u, Assignment::main_amount));
        }

        // the UTXOs selected for the other assets, to start over from when retrying
        let selected_before = selected.clone();
        let (mut asset_spend, skipped) = self.select_rgb_inputs_pass(
            &asset_id,
            assignments_needed,
            &mut_unspents,
            selected,
            max_allocations,
        );
        // the UTXOs selected first (e.g. the ones with the smallest amounts) may have taken the
        // place of a UTXO with enough assignments: retry from the ones with the most
        if skipped && !asset_spend.assignments_collected.enough(assignments_needed) {
            debug!(
                self.logger(),
                "Retrying input selection for asset '{}' from the largest UTXOs", asset_id
            );
            *selected = selected_before;
            mut_unspents.reverse();
            (asset_spend, _) = self.select_rgb_inputs_pass(
                &asset_id,
                assignments_needed,
                &mut_unspents,
                selected,
                max_allocations,
            );
        }
        if !asset_spend.assignments_collected.enough(assignments_needed) {
            return Err(Error::InsufficientAssignments {
                asset_id,
                available: asset_spend.assignments_collected,
            });
        }

        debug!(
            self.logger(),
            "Asset input assignments {:?}", asset_spend.assignments_collected
        );
        Ok(asset_spend)
    }

    /// A pass of `select_rgb_inputs`, selecting from `unspents` in their order, adding the UTXOs
    /// selected to `selected` and stopping once they hold the assignments needed. Also returns
    /// whether a UTXO was skipped for holding too many allocations.
    fn select_rgb_inputs_pass(
        &self,
        asset_id: &str,
        assignments_needed: &AssignmentsCollection,
        unspents: &[LocalUnspent],
        selected: &mut SelectedInputs,
        max_allocations: usize,
    ) -> (AssetSpend, bool) {
        let mut input_outpoints = Vec::new();
        let mut assignments_collected = AssignmentsCollection::default();
        let mut input_btc_amt: u64 = 0;
        let mut skipped = false;
        for unspent in unspents {
            // get spendable allocations for the required asset
            let asset_allocations: Vec<&LocalRgbAllocation> = unspent
                .rgb_allocations
                .iter()
                .filter(|a| a.asset_id.as_deref() == Some(asset_id) && a.status.settled())
                .collect();

            // skip UTXOs with no allocations
            if asset_allocations.is_empty() {
                continue;
            }

            // check if the unspent hosts any needed allocations
            let mut needed = false;
            if assignments_collected.fungible < assignments_needed.fungible
                && asset_allocations
                    .iter()
                    .any(|a| matches!(a.assignment, Assignment::Fungible(_)))
            {
                needed = true;
            }
            if !assignments_collected.non_fungible
                && assignments_needed.non_fungible
                && asset_allocations
                    .iter()
                    .any(|a| matches!(a.assignment, Assignment::NonFungible))
            {
                needed = true;
            }
            if assignments_collected.inflation < assignments_needed.inflation
                && asset_allocations
                    .iter()
                    .any(|a| matches!(a.assignment, Assignment::InflationRight(_)))
            {
                needed = true;
            }
            if !assignments_collected.link
                && assignments_needed.link
                && asset_allocations
                    .iter()
                    .any(|a| matches!(a.assignment, Assignment::LinkRight))
            {
                needed = true;
            }
            if assignments_collected.mint < assignments_needed.mint
                && asset_allocations
                    .iter()
                    .any(|a| matches!(a.assignment, Assignment::MintRight))
            {
                needed = true;
            }

            // skip UTXOs with no needed allocations
            if !needed {
                continue;
            }

            // skip UTXOs that would make the operation move more allocations of an asset than
            // a bundle can spend, or more of an asset than a transition can spend
            if !selected.select(unspent, max_allocations) {
                debug!(
                    self.logger(),
                    "Skipping UTXO {} as it adds too many allocations or too much of an asset",
                    unspent.utxo.outpoint()
                );
                skipped = true;
                continue;
            }

            // add selected allocations to collected assignments
            asset_allocations
                .iter()
                .for_each(|a| a.assignment.add_to_assignments(&mut assignments_collected));
            input_outpoints.push(unspent.utxo.outpoint());

            let utxo_btc_amt = unspent
                .utxo
                .btc_amount
                .parse::<u64>()
                .expect("DB should contain a valid BTC amount");
            input_btc_amt = input_btc_amt
                .checked_add(utxo_btc_amt)
                .expect("total input BTC value cannot exceed u64::MAX");

            // stop as soon as we have the needed assignments
            if assignments_collected.enough(assignments_needed) {
                break;
            }
        }

        (
            AssetSpend {
                input_outpoints,
                assignments_collected,
                input_btc_amt,
            },
            skipped,
        )
    }

    fn prepare_psbt(
        &mut self,
        input_outpoints: HashSet<BdkOutPoint>,
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Psbt, Option<BtcChange>), Error> {
        let change_addr = self.get_new_address()?.script_pubkey();
        let mut builder = self.bdk_wallet_mut().build_tx();
        builder
            .add_data(&[0; 32])
            .add_utxos(&input_outpoints.into_iter().collect::<Vec<_>>())
            .map_err(InternalError::from)?
            .manually_selected_only()
            .fee_rate(fee_rate)
            .ordering(bdk_wallet::tx_builder::TxOrdering::Untouched);
        for (script_buf, amount_sat) in witness_recipients {
            builder.add_recipient(script_buf.clone(), BdkAmount::from_sat(*amount_sat));
        }
        builder.drain_to(change_addr.clone());

        let mut psbt = builder.finish().map_err(|e| match e {
            bdk_wallet::error::CreateTxError::CoinSelection(InsufficientFunds {
                needed,
                available,
            }) => Error::InsufficientBitcoins {
                needed: needed.to_sat(),
                available: available.to_sat(),
            },
            bdk_wallet::error::CreateTxError::OutputBelowDustLimit(_) => {
                Error::OutputBelowDustLimit
            }
            _ => Error::Internal {
                details: e.to_string(),
            },
        })?;
        self.add_non_witness_utxos(&mut psbt);

        let btc_change = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey == change_addr)
            .map(|(i, o)| BtcChange {
                vout: i as u32,
                amount: o.value.to_sat(),
            });

        Ok((psbt, btc_change))
    }

    fn try_prepare_psbt(
        &mut self,
        input_unspents: &[LocalUnspent],
        all_inputs: &mut HashSet<BdkOutPoint>,
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Psbt, Option<BtcChange>), Error> {
        Ok(loop {
            break match self.prepare_psbt(all_inputs.clone(), witness_recipients, fee_rate) {
                Ok(res) => res,
                Err(Error::InsufficientBitcoins { .. }) => {
                    let used_txos: Vec<Outpoint> =
                        all_inputs.clone().into_iter().map(|o| o.into()).collect();
                    let mut free_utxos = self.get_available_allocations(
                        input_unspents,
                        used_txos.as_slice(),
                        Some(0),
                    )?;
                    // sort UTXOs by BTC amount
                    if !free_utxos.is_empty() {
                        // pre-parse BTC amounts to make sure no one will fail
                        for u in &free_utxos {
                            u.utxo
                                .btc_amount
                                .parse::<u64>()
                                .map_err(|e| Error::Internal {
                                    details: e.to_string(),
                                })?;
                        }
                        free_utxos.sort_by_key(|u| {
                            u.utxo
                                .btc_amount
                                .parse::<u64>()
                                .expect("DB should contain a valid BTC amount")
                        });
                    }
                    if let Some(a) = free_utxos.pop() {
                        all_inputs.insert(a.utxo.into());
                        continue;
                    }
                    return Err(Error::InsufficientAllocationSlots);
                }
                Err(e) => return Err(e),
            };
        })
    }

    fn get_beneficiary_seal(
        &self,
        local_recipient_data: &LocalRecipientData,
    ) -> BuilderSeal<GraphSeal> {
        match local_recipient_data {
            LocalRecipientData::Blind(secret_seal) => BuilderSeal::Concealed(*secret_seal),
            LocalRecipientData::Witness(witness_data) => {
                let graph_seal = if let Some(blinding) = witness_data.blinding {
                    GraphSeal::with_blinded_vout(witness_data.vout, blinding)
                } else {
                    GraphSeal::new_random_vout(witness_data.vout)
                };
                BuilderSeal::Revealed(graph_seal)
            }
        }
    }

    /// The pre-existing UTXOs that can receive the RGB change of an operation spending the UTXOs
    /// at `input_outpoints`, in order of preference, as [`Self::get_utxo`] picks them: empty ones
    /// first, then the ones due to receive allocations (keeping the others spendable), each by
    /// fewest slots taken. The inputs and the UTXOs spent by pending operations are excluded.
    fn get_change_utxos(
        &self,
        txn: &DbTxn,
        input_outpoints: &[Outpoint],
        unspents: &[LocalUnspent],
    ) -> Result<Vec<LocalUnspent>, Error> {
        let mut exclude_utxos = input_outpoints.to_vec();
        exclude_utxos.extend(self.get_reserved_colored_outpoints(txn)?);
        let mut utxos = self.get_available_allocations(unspents, &exclude_utxos, Some(u32::MAX))?;
        utxos.sort_by_key(|u| {
            let rank = if u.rgb_allocations.is_empty() {
                0
            } else if u.rgb_allocations.iter().any(|a| a.future()) {
                1
            } else {
                2
            };
            (rank, u.rgb_allocations.len() + u.pending_blinded as usize)
        });
        Ok(utxos)
    }

    /// Take the slot for an allocation of the asset with ID `asset_id` moved to the RGB change, of
    /// the given amount and whether it's a mint right, on a destination that can receive it (see
    /// [`ChangeSlots`]), returning it with the seal for it. As a UTXO holds at most one mint right
    /// of an asset, the UTXOs with an unpaid invoice requesting one count as holding it.
    fn take_change_seal(
        &self,
        txn: &DbTxn,
        change_slots: &mut ChangeSlots,
        btc_change: &Option<BtcChange>,
        asset_id: &str,
        amount: u128,
        mint_right: bool,
    ) -> Result<(ChangeDestination, BlindSeal<TxPtr>), Error> {
        if mint_right && !change_slots.knows_mint_right_invoices(asset_id) {
            change_slots
                .add_mint_right_invoices(asset_id, &txn.get_mint_right_invoice_utxos(asset_id)?);
        }
        let (destination, outpoint) = change_slots
            .take(asset_id, amount, mint_right)
            .ok_or(Error::InsufficientAllocationSlots)?;
        debug!(
            self.logger(),
            "Change destination for an allocation of asset '{asset_id}': {destination:?}"
        );
        let seal = match outpoint {
            Some(outpoint) => GraphSeal::from(self.get_blind_seal(outpoint).transmutate()),
            None => GraphSeal::new_random_vout(
                btc_change.as_ref().ok_or(InternalError::Unexpected)?.vout,
            ),
        };
        Ok((destination, seal))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_rgb_psbt(
        &self,
        txn: &DbTxn,
        psbt: &mut Psbt,
        transfer_info_map: &mut BTreeMap<String, InfoAssetTransfer>,
        transfer_dir: PathBuf,
        donation: bool,
        unspents: Vec<LocalUnspent>,
        stock: &mut RgbStock<'_>,
        min_confirmations: u8,
        expiration_timestamp: Option<i64>,
        btc_change: Option<BtcChange>,
        sender_transport_endpoint: Option<String>,
        operation_secret_key: Option<Vec<u8>>,
        rejected: &mut HashSet<Opout>,
        reject_lists: &mut HashMap<RejectListSource, RejectList>,
    ) -> Result<PrepareRgbPsbtResult, Error> {
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();

        let input_outpoints: Vec<Outpoint> =
            prev_outputs.iter().map(|o| Outpoint::from(*o)).collect();

        // the RGB change goes to the BTC change output, if any, then to pre-existing UTXOs, as many
        // as needed to keep each within the allocations allowed per UTXO, counting the slots
        // reserved by their unpaid invoices, which would otherwise be refused once paid, and the
        // allocations of an asset a bundle can spend
        let change_utxos = self.get_change_utxos(txn, &input_outpoints, &unspents)?;
        let mut change_slots = ChangeSlots::new(
            btc_change.is_some(),
            &change_utxos,
            self.max_allocations_per_utxo() as usize,
            max_utxo_asset_allocations(),
        );

        let mut asset_beneficiaries = bmap![];
        let mut extra_state = HashMap::<ContractId, Vec<(OutPoint, Opout, AllocatedState)>>::new();
        let mut input_opouts: HashMap<ContractId, HashMap<Opout, AllocatedState>> = HashMap::new();
        let mut opid = None;
        for (asset_id, transfer_info) in transfer_info_map.iter_mut() {
            let asset_utxos = transfer_info.asset_spend.input_outpoints.iter().cloned();
            let mut all_opout_state_vec = Vec::new();
            for (explicit_seal, opout_state_map) in stock.contract_assignments_for(
                transfer_info.asset_info.contract_id,
                asset_utxos.clone(),
            )? {
                all_opout_state_vec.extend(
                    opout_state_map
                        .into_iter()
                        .map(|(o, s)| (explicit_seal.to_outpoint(), o, s)),
                );
            }

            // sort by state globally (smaller to bigger)
            // (non-amount states first)
            all_opout_state_vec.sort_by_key(|(_, _, state)| state_amount(state));

            let mut inputs_added = AssignmentsCollection::default();
            let mut uda_state = None;
            let mut asset_transition_builder = stock.transition_builder(
                transfer_info.asset_info.contract_id,
                transfer_info.main_transition.transition_type().type_name(),
            )?;
            // the main transition only takes some assignment types as inputs and assignments:
            // the others are moved by a transition of their default type in the same bundle
            let schema = stock.contract_schema(transfer_info.asset_info.contract_id)?;
            let main_schema = &schema
                .transitions
                .get(&asset_transition_builder.transition_type())
                .expect("main transition missing from the schema")
                .transition_schema;
            let main_input_types: HashSet<AssignmentType> =
                main_schema.inputs.keys().copied().collect();
            let main_assignment_types: HashSet<AssignmentType> =
                main_schema.assignments.keys().copied().collect();
            let mut main_inputs = vec![];
            // whether the main transition assigns or records any state
            let mut main_used = false;
            let mut side_transfers: BTreeMap<AssignmentType, SideTransfer> = BTreeMap::new();
            // on a retry the assignments needed are increased by the rejected ones, so that the
            // selection looks past them, but mint rights can't be partially spent: adding more
            // than the operation needs would be useless and, for a mint (whose schema allows a
            // single mint right input), invalid. Any further one selected is moved as
            // extra state instead
            let inputs_needed = AssignmentsCollection {
                mint: transfer_info.original_assignments_needed.mint,
                ..transfer_info.assignments_needed.clone()
            };
            for (outpoint, opout, state) in all_opout_state_vec {
                let mut should_add_as_input = !rejected.contains(&opout);
                if should_add_as_input {
                    should_add_as_input =
                        inputs_added.opout_contributes(&opout, &state, &inputs_needed);
                }
                if !should_add_as_input {
                    extra_state
                        .entry(transfer_info.asset_info.contract_id)
                        .or_default()
                        .push((outpoint, opout, state.clone()));
                    continue;
                }

                inputs_added.add_opout_state(&opout, &state);
                transfer_info
                    .assignments_spent
                    .entry(outpoint)
                    .or_default()
                    .push(Assignment::from_opout_and_state(opout, &state));
                // there can be only a single state when contract is UDA
                uda_state = Some(state.clone());
                if main_input_types.contains(&opout.ty) {
                    main_inputs.push((opout, state.clone()));
                } else {
                    side_transfers
                        .entry(opout.ty)
                        .or_default()
                        .inputs
                        .push((opout, state.clone()));
                }
                input_opouts
                    .entry(transfer_info.asset_info.contract_id)
                    .or_default()
                    .insert(opout, state);
            }
            // the inputs left after excluding the rejected ones may not cover what the operation
            // needs, as for a rejected link right: selecting inputs again would select it again,
            // as it's the only one
            if !inputs_added.enough(&transfer_info.original_assignments_needed) {
                return Err(Error::InsufficientAssignments {
                    asset_id: asset_id.clone(),
                    available: inputs_added,
                });
            }

            let mut beneficiaries = vec![];
            for recipient in &transfer_info.recipients {
                let seal;
                match &recipient.assignment {
                    Assignment::Fungible(amt) => {
                        if *amt == 0 {
                            continue;
                        }
                        seal = self.get_beneficiary_seal(&recipient.local_recipient_data);
                        asset_transition_builder = add_or_side_output(
                            asset_transition_builder,
                            &main_assignment_types,
                            &mut main_used,
                            &mut side_transfers,
                            OS_ASSET,
                            seal,
                            Amount::from(*amt).into(),
                        )?;
                    }
                    Assignment::NonFungible => {
                        if let AllocatedState::Data(state) = uda_state.clone().unwrap() {
                            seal = self.get_beneficiary_seal(&recipient.local_recipient_data);
                            main_used = true;
                            asset_transition_builder = asset_transition_builder
                                .add_data(RGB_STATE_ASSET_OWNER, seal, Allocation::from(state))
                                .map_err(Error::from)?;
                        } else {
                            continue;
                        }
                    }
                    Assignment::InflationRight(amt) => {
                        if *amt == 0 {
                            continue;
                        }
                        seal = self.get_beneficiary_seal(&recipient.local_recipient_data);
                        asset_transition_builder = add_or_side_output(
                            asset_transition_builder,
                            &main_assignment_types,
                            &mut main_used,
                            &mut side_transfers,
                            OS_INFLATION,
                            seal,
                            Amount::from(*amt).into(),
                        )?;
                    }
                    Assignment::LinkRight => {
                        seal = self.get_beneficiary_seal(&recipient.local_recipient_data);
                        asset_transition_builder = add_or_side_output(
                            asset_transition_builder,
                            &main_assignment_types,
                            &mut main_used,
                            &mut side_transfers,
                            OS_LINK,
                            seal,
                            AllocatedState::Void,
                        )?;
                    }
                    Assignment::MintRight => {
                        seal = self.get_beneficiary_seal(&recipient.local_recipient_data);
                        asset_transition_builder = add_or_side_output(
                            asset_transition_builder,
                            &main_assignment_types,
                            &mut main_used,
                            &mut side_transfers,
                            OS_MINT,
                            seal,
                            AllocatedState::Void,
                        )?;
                    }
                    _ => unreachable!(),
                };

                beneficiaries.push((seal, recipient.recipient_id.clone()));
            }

            let change = inputs_added.change(&transfer_info.original_assignments_needed);

            if change != AssignmentsCollection::default() {
                transfer_info.change = change.clone();
                let mut change_outputs = vec![];
                if change.fungible > 0 {
                    change_outputs.push((
                        OS_ASSET,
                        Amount::from(change.fungible).into(),
                        Assignment::Fungible(change.fungible),
                    ));
                }
                if change.inflation > 0 {
                    change_outputs.push((
                        OS_INFLATION,
                        Amount::from(change.inflation).into(),
                        Assignment::InflationRight(change.inflation),
                    ));
                }
                for _ in 0..change.mint {
                    change_outputs.push((OS_MINT, AllocatedState::Void, Assignment::MintRight));
                }
                for (ty, state, assignment) in change_outputs {
                    // each allocation of the change takes its own slot
                    let (destination, seal) = self.take_change_seal(
                        txn,
                        &mut change_slots,
                        &btc_change,
                        asset_id,
                        u128::from(assignment.main_amount()),
                        ty == OS_MINT,
                    )?;
                    transfer_info
                        .change_destinations
                        .push((assignment, destination));
                    // a main transition that takes this type as input but can't assign it (e.g.
                    // a burn) can't return change. Its inputs are first split by a transition in
                    // the same bundle, which assigns the change to the change seal and what the
                    // main transition needs to a seal on an outpoint this TX spends. The main
                    // transition then spends that output
                    if !main_assignment_types.contains(&ty) && main_input_types.contains(&ty) {
                        let side = side_transfers.entry(ty).or_default();
                        if side.split.is_none() {
                            let (split_inputs, rest): (Vec<_>, Vec<_>) =
                                main_inputs.into_iter().partition(|(o, _)| o.ty == ty);
                            main_inputs = rest;
                            // the split inputs hold the change and what the main transition needs
                            let inputs_amount: u64 =
                                split_inputs.iter().map(|(_, s)| state_amount(s)).sum();
                            let needed = inputs_amount
                                .checked_sub(state_amount(&state))
                                .ok_or(InternalError::Unexpected)?;
                            side.inputs.extend(split_inputs);
                            let split_seal =
                                GraphSeal::rand_from(psbt.unsigned_tx.input[0].previous_output);
                            side.split = Some((split_seal, needed));
                            side.outputs.push((
                                BuilderSeal::Revealed(split_seal),
                                Amount::from(needed).into(),
                            ));
                        }
                    }
                    asset_transition_builder = add_or_side_output(
                        asset_transition_builder,
                        &main_assignment_types,
                        &mut main_used,
                        &mut side_transfers,
                        ty,
                        BuilderSeal::Revealed(seal),
                        state,
                    )?;
                }
            };

            // the transitions moving the assignment types the main transition doesn't, before
            // the main one, which may spend the output of a split
            for (ty, side) in side_transfers {
                let transition_type = schema.default_transition_for_assignment(&ty);
                let side_schema = &schema
                    .transitions
                    .get(&transition_type)
                    .expect("default transition missing from the schema")
                    .transition_schema;
                // a transition taking a single input of the type (e.g. propagating a mint right)
                // is needed for each input, each assigning at least one output
                let max_inputs = side_schema
                    .inputs
                    .get(&ty)
                    .map(|o| o.max_value() as usize)
                    .unwrap_or(usize::MAX);
                let chunks = side.inputs.len().div_ceil(max_inputs).max(1);
                if side.outputs.len() < chunks {
                    return Err(Error::Internal {
                        details: format!("not enough outputs to move assignments of type {ty}"),
                    });
                }
                // getting a builder from the stock loads the contract schema rules: get one and
                // clone it for each chunk
                let builder = stock.transition_builder_raw(
                    transfer_info.asset_info.contract_id,
                    transition_type,
                )?;
                let mut inputs = side.inputs.into_iter();
                let mut outputs = side.outputs.into_iter();
                for chunk in 0..chunks {
                    let mut side_builder = builder.clone();
                    for (opout, state) in inputs.by_ref().take(max_inputs) {
                        side_builder = side_builder.add_input(opout, state)?;
                    }
                    let take = if chunk + 1 == chunks { usize::MAX } else { 1 };
                    for (seal, state) in outputs.by_ref().take(take) {
                        side_builder = side_builder.add_owned_state_raw(ty, seal, state)?;
                    }
                    let side_transition = side_builder.complete_transition()?;
                    if let Some((split_seal, needed)) = side.split
                        && let Some(no) = side_transition.assignments.get(&ty).and_then(|a| {
                            a.as_fungible()
                                .iter()
                                .position(|a| a.revealed_seal() == Some(split_seal))
                        })
                    {
                        main_inputs.push((
                            Opout::new(side_transition.id(), ty, no as u16),
                            Amount::from(needed).into(),
                        ));
                    }
                    psbt.push_rgb_transition(side_transition)
                        .map_err(InternalError::from)?;
                }
            }
            for (opout, state) in main_inputs {
                asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
            }

            // add necessary globals/metadata to transition
            match transfer_info.main_transition {
                MainTransition::Inflate => {
                    let inflation = transfer_info.original_assignments_needed.inflation;
                    main_used = true;
                    asset_transition_builder = asset_transition_builder
                        .add_global_state(RGB_GLOBAL_ISSUED_SUPPLY, Amount::from(inflation))
                        .unwrap()
                        .add_metadata(
                            RGB_METADATA_ALLOWED_INFLATION,
                            Amount::from(change.inflation),
                        )
                        .unwrap();
                }
                MainTransition::Burn { burn_reason } => {
                    let burn = transfer_info.original_assignments_needed.fungible;
                    main_used = true;
                    asset_transition_builder = asset_transition_builder
                        .add_global_state(RGB_GLOBAL_BURNED_ASSET, Amount::from(burn))
                        .unwrap();
                    if let Some(burn_reason) = burn_reason {
                        asset_transition_builder = asset_transition_builder
                            .add_global_state(RGB_GLOBAL_BURN_REASON, burn_reason)?;
                    }
                }
                MainTransition::Link { linked_to_contract } => {
                    main_used = true;
                    asset_transition_builder = asset_transition_builder
                        .add_global_state(RGB_GLOBAL_LINKED_TO_CONTRACT, linked_to_contract)?;
                }
                MainTransition::Mint { before_block } => {
                    #[allow(unused_mut)]
                    let mut amount_to_mint = transfer_info
                        .recipients
                        .iter()
                        .map(|r| r.assignment.main_amount())
                        .sum::<u64>();
                    #[cfg(all(test, feature = "_online"))]
                    if let Some(kept) = mock_mint_kept_amount() {
                        asset_transition_builder = asset_transition_builder.add_owned_state_raw(
                            OS_ASSET,
                            BuilderSeal::Revealed(GraphSeal::new_random_vout(0)),
                            Amount::from(kept).into(),
                        )?;
                        amount_to_mint += kept;
                    }
                    asset_transition_builder = asset_transition_builder
                        .add_global_state(RGB_GLOBAL_ISSUED_SUPPLY, Amount::from(amount_to_mint))?
                        .add_metadata(RGB_METADATA_BEFORE_BLOCK, BlockNumber::from(before_block))?;
                }
                MainTransition::Transfer => {}
            }

            // a transition must spend something: the main transition is left out when it spends
            // nothing and does nothing (e.g. a transfer of rights only, which side transitions
            // move), while one assigning or recording state without spending anything would
            // create it from nothing
            if asset_transition_builder.has_inputs() {
                let transition = asset_transition_builder.complete_transition()?;
                #[cfg(all(test, feature = "_online"))]
                let transition = mock_spam_recipient_assignments(transition);
                #[cfg(all(test, feature = "_online"))]
                mock_spam_hidden_spends(psbt, &transition);
                if matches!(transfer_info.main_transition, MainTransition::Mint { .. }) {
                    opid = Some(transition.id().to_string());
                }
                psbt.push_rgb_transition(transition)
                    .map_err(InternalError::from)?;
            } else if main_used {
                return Err(Error::Internal {
                    details: s!("main transition assigning or recording state without inputs"),
                });
            }
            asset_beneficiaries.insert(asset_id.clone(), beneficiaries);
        }

        for (id, state) in stock.assignments_by_contract(prev_outputs.clone())? {
            // the allocations of an asset of the batch on the inputs selected for it are moved by
            // its transitions, the ones on the inputs selected for another asset are moved by
            // extra transitions instead, which its consignment doesn't carry, so that the
            // recipients don't learn about them and their history
            let asset_utxos = transfer_info_map
                .get(&id.to_string())
                .map(|t| &t.asset_spend.input_outpoints);
            for (explicit_seal, opout_state_map) in state {
                if asset_utxos.is_some_and(|u| u.contains(&explicit_seal.to_outpoint().into())) {
                    continue;
                }
                extra_state.entry(id).or_default().extend(
                    opout_state_map
                        .into_iter()
                        .map(|(o, s)| (explicit_seal.to_outpoint(), o, s)),
                );
            }
        }

        let mut extra_allocations = ExtraAllocations::new();
        // a UTXO may hold many allocations, each moved by its own transition: push them all at
        // once, as pushing them one by one rewrites the consumers of the contract every time
        let mut extra_transitions = vec![];
        for (cid, opout_state_map) in extra_state {
            let schema = stock.contract_schema(cid)?;
            // getting a builder from the stock loads the contract schema rules: get one per
            // transition type and clone it for each allocation
            let mut builders: HashMap<TransitionType, TransitionBuilder> = HashMap::new();
            for (outpoint, opout, state) in opout_state_map {
                let transition_type = schema.default_transition_for_assignment(&opout.ty);
                let mut extra_builder = match builders.entry(transition_type) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => entry
                        .insert(stock.transition_builder_raw(cid, transition_type)?)
                        .clone(),
                };
                let assignment = Assignment::from_opout_and_state(opout, &state);
                // a UTXO holds at most one mint right of an asset
                let (destination, seal) = self.take_change_seal(
                    txn,
                    &mut change_slots,
                    &btc_change,
                    &cid.to_string(),
                    u128::from(assignment.main_amount()),
                    opout.ty == OS_MINT,
                )?;
                extra_builder = extra_builder
                    .add_input(opout, state.clone())?
                    .add_owned_state_raw(opout.ty, seal, state)?;
                let extra_transition = extra_builder.complete_transition()?;
                extra_allocations
                    .entry(cid.to_string())
                    .or_default()
                    .entry(outpoint)
                    .or_default()
                    .push((assignment, destination));
                extra_transitions.push(extra_transition);
            }
        }
        psbt.push_rgb_transitions(extra_transitions)
            .map_err(InternalError::from)?;

        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output")
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        let entropy = rand::rng().random_range(0..u64::MAX);

        opreturn_output
            .set_mpc_entropy(entropy)
            .map_err(InternalError::from)?;

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        let fascia = psbt.rgb_commit().map_err(InternalError::from)?;
        strip_rgb_data(psbt);
        check_psbt_parsable(psbt)?;
        let transfer_key = self.wallet_key(&transfer_dir)?;
        self.files().create_dir_all(&transfer_key)?;
        self.write_fascia_at(&transfer_key.join(FASCIA_FILE)?, &fascia)?;

        let witness_txid = psbt.get_txid();
        for (asset_id, transfer_info) in transfer_info_map.iter_mut() {
            let beneficiaries = asset_beneficiaries[asset_id].clone();
            let (beneficiaries_witness, beneficiaries_blinded) = beneficiaries.iter().fold(
                (Vec::new(), Vec::new()),
                |(mut witness, mut blinded), (builder_seal, _)| {
                    match builder_seal {
                        BuilderSeal::Revealed(seal) => {
                            let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                            witness.push(explicit_seal);
                        }
                        BuilderSeal::Concealed(secret_seal) => {
                            blinded.push(*secret_seal);
                        }
                    }
                    (witness, blinded)
                },
            );
            transfer_info.beneficiaries_blinded = beneficiaries_blinded;
            transfer_info.beneficiaries_witness = beneficiaries_witness;

            // every operation is checked, so that none spends a rejected allocation: a recipient
            // would refuse it, and an operation with no recipient (an inflation or a burn) would
            // carry rejected history
            let reject_list_source = genesis_reject_list_source(
                transfer_info.asset_info.schema,
                &stock.genesis(transfer_info.asset_info.contract_id)?,
            )?;
            let should_build_dag = reject_list_source.is_some();

            #[cfg(all(test, feature = "_online"))]
            let should_build_dag = if skip_build_dag() {
                false
            } else {
                should_build_dag
            };

            if should_build_dag {
                let (_, ops_dag, _) = stock.transfer_from_fascia_with_dag(
                    transfer_info.asset_info.contract_id,
                    transfer_info.beneficiaries_witness.clone(),
                    transfer_info.beneficiaries_blinded.clone(),
                    transfer_info.requested_opids(&fascia),
                    &fascia,
                )?;

                // a list is fetched once per operation, so that its retries don't download it
                // again and all decide on the same version of it
                let source = reject_list_source.unwrap();
                if !reject_lists.contains_key(&source) {
                    let reject_list = self.resolve_reject_list(&source)?;
                    reject_lists.insert(source.clone(), reject_list);
                }
                let reject_list = &reject_lists[&source];
                let asset_opouts = input_opouts
                    .get(&transfer_info.asset_info.contract_id)
                    .unwrap();
                let asset_input_opouts = asset_opouts.keys().cloned().collect();
                let to_reject = rejected_opouts(&ops_dag, reject_list, &asset_input_opouts)?;
                if !to_reject.is_empty() {
                    warn!(
                        self.logger(),
                        "Found {} rejected input opout(s), retrying transfer",
                        to_reject.len()
                    );
                    // update assignments_needed to account for rejected amounts
                    for rejected_opout in &to_reject {
                        if let Some(state) = asset_opouts.get(rejected_opout) {
                            transfer_info
                                .assignments_needed
                                .add_opout_state(rejected_opout, state);
                        }
                        rejected.insert(*rejected_opout);
                    }
                    return Ok(PrepareRgbPsbtResult::Retry);
                }
            }
        }

        let created_at = now().unix_timestamp();

        // save batch transfer data to file (for operation finalization)
        let info_batch_transfer = InfoBatchTransfer {
            btc_change,
            extra_allocations,
            donation,
            min_confirmations,
            expiration_timestamp,
            created_at,
            entropy,
            transfers: transfer_info_map.clone(),
            sender_transport_endpoint,
            operation_secret_key,
        };
        let serialized_info =
            serde_json::to_string(&info_batch_transfer).map_err(InternalError::from)?;
        let info_file = transfer_dir.join(TRANSFER_DATA_FILE);
        self.files()
            .atomic_write(&self.wallet_key(&info_file)?, serialized_info.as_bytes())?;

        Ok(PrepareRgbPsbtResult::Success(Box::new(
            BeginOperationData {
                psbt: psbt.clone(),
                transfer_dir: transfer_dir.clone(),
                info_batch_transfer,
                batch_transfer_idx: None,
                opid,
            },
        )))
    }

    fn save_transfers(
        &mut self,
        txn: &DbTxn,
        txid: String,
        info_contents: &InfoBatchTransfer,
        status: TransferStatus,
        consignment_hashes: &HashMap<String, String>,
        psbt: &Psbt,
    ) -> Result<i32, Error> {
        let batch_transfer = DbBatchTransferActMod {
            txid: ActiveValue::Set(Some(txid.clone())),
            status: ActiveValue::Set(status),
            expiration: ActiveValue::Set(info_contents.expiration_timestamp),
            created_at: ActiveValue::Set(info_contents.created_at),
            min_confirmations: ActiveValue::Set(info_contents.min_confirmations),
            incoming: ActiveValue::Set(false),
            operation_secret_key: ActiveValue::Set(info_contents.operation_secret_key.clone()),
            ..Default::default()
        };
        let batch_transfer_idx = txn.set_batch_transfer(batch_transfer)?;
        let sender_pubkey_hex = match &info_contents.operation_secret_key {
            Some(seed) => {
                let seed: [u8; 32] = seed.clone().try_into().map_err(|_| Error::Internal {
                    details: s!("invalid operation secret key"),
                })?;
                Some(hex::encode(
                    ed25519_from_seed(&seed).verifying_key().to_bytes(),
                ))
            }
            None => None,
        };

        // until the TX is broadcast, reserve all its inputs, including the ones with no
        // allocations (e.g. added to pay the fee), so they can't be selected by other operations
        if matches!(
            status,
            TransferStatus::Initiated | TransferStatus::WaitingCounterparty
        ) {
            self.reserve_colored_txos(txn, psbt, batch_transfer_idx)?;
        }

        let mut change_utxo_idxs: HashMap<ChangeDestination, i32> = HashMap::new();

        for (asset_id, transfer_info) in info_contents.transfers.iter() {
            // hash of the plaintext consignment for this asset, if already generated: a non-dry-run
            // begin saves the transfers before generating the consignments (see the backfill in
            // update_or_save_transfers) and an inflation never produces one
            let consignment_hash = consignment_hashes.get(asset_id).cloned();
            let asset_transfer = DbAssetTransferActMod {
                user_driven: ActiveValue::Set(true),
                batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
                asset_id: ActiveValue::Set(Some(asset_id.clone())),
                transition_type: ActiveValue::Set(Some(
                    transfer_info.main_transition.transition_type(),
                )),
                ..Default::default()
            };
            let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;

            for (outpoint, assignments) in &transfer_info.assignments_spent {
                let outpoint: Outpoint = (*outpoint).into();
                let txo_idx = self.get_or_sync_txo_idx(txn, &outpoint)?;

                for assignment in assignments {
                    let db_coloring = DbColoringActMod {
                        txo_idx: ActiveValue::Set(txo_idx),
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        r#type: ActiveValue::Set(ColoringType::Input),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    };
                    txn.set_coloring(db_coloring)?;
                }
            }
            for (assignment, destination) in &transfer_info.change_destinations {
                let db_coloring = DbColoringActMod {
                    txo_idx: ActiveValue::Set(self.get_change_utxo_idx(
                        txn,
                        &txid,
                        info_contents,
                        destination,
                        &mut change_utxo_idxs,
                    )?),
                    asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                    r#type: ActiveValue::Set(ColoringType::Change),
                    assignment: ActiveValue::Set(assignment.clone()),
                    ..Default::default()
                };
                txn.set_coloring(db_coloring)?;
            }

            // an operation that pays no one (a burn or a link) has no recipient to iterate, but it
            // still gets a transfer row, to record the assignment it requested and the hash of the
            // consignment proving it
            let requested_assignment = match transfer_info.main_transition {
                MainTransition::Burn { .. } => Some(Assignment::Fungible(
                    transfer_info.original_assignments_needed.fungible,
                )),
                MainTransition::Link { .. } => Some(Assignment::LinkRight),
                MainTransition::Inflate
                | MainTransition::Transfer
                | MainTransition::Mint { .. } => None,
            };
            if let Some(requested_assignment) = requested_assignment {
                let transfer = DbTransferActMod {
                    asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                    requested_assignment: ActiveValue::Set(Some(requested_assignment)),
                    consignment_hash: ActiveValue::Set(consignment_hash.clone()),
                    recipient_encryption: ActiveValue::Set(Encryption::Unsupported),
                    ..Default::default()
                };
                txn.set_transfer(transfer)?;
            }

            for recipient in &transfer_info.recipients {
                // the transfer ID on the proxies, only for a proxy recipient
                let proxy_transfer_id = match &sender_pubkey_hex {
                    Some(sender_pk) if !recipient.public_key.is_empty() => {
                        Some(recipient.proxy_ids(sender_pk).1)
                    }
                    _ => None,
                };
                let (rcpt_id, rcpt_type, req_ass) = match transfer_info.main_transition {
                    MainTransition::Inflate => {
                        let local_witness_data = if let LocalRecipientData::Witness(lwd) =
                            &recipient.local_recipient_data
                        {
                            lwd
                        } else {
                            unreachable!("inflation uses witness recipients")
                        };
                        let vout = local_witness_data.vout;
                        let txo_idx = match txn.get_txo(&Outpoint {
                            txid: txid.clone(),
                            vout,
                        })? {
                            Some(txo) => txo.idx,
                            None => {
                                let db_utxo = DbTxoActMod {
                                    txid: ActiveValue::Set(txid.clone()),
                                    vout: ActiveValue::Set(vout),
                                    btc_amount: ActiveValue::Set(
                                        local_witness_data.amount_sat.to_string(),
                                    ),
                                    spent: ActiveValue::Set(false),
                                    exists: ActiveValue::Set(false),
                                    pending_witness: ActiveValue::Set(false),
                                    ..Default::default()
                                };
                                txn.set_txo(db_utxo)?
                            }
                        };
                        let db_coloring = DbColoringActMod {
                            txo_idx: ActiveValue::Set(txo_idx),
                            asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                            r#type: ActiveValue::Set(ColoringType::Issue),
                            assignment: ActiveValue::Set(recipient.assignment.clone()),
                            ..Default::default()
                        };
                        txn.set_coloring(db_coloring)?;
                        (
                            Some(recipient.recipient_id.clone()),
                            Some(RecipientTypeFull::Witness { vout: Some(vout) }),
                            recipient.assignment.clone(),
                        )
                    }
                    MainTransition::Burn { .. } | MainTransition::Link { .. } => {
                        unreachable!("an operation with no recipient has none to iterate")
                    }
                    MainTransition::Transfer | MainTransition::Mint { .. } => (
                        Some(recipient.recipient_id.clone()),
                        None,
                        recipient.assignment.clone(),
                    ),
                };

                let recipient_pubkey = if recipient.public_key.is_empty() {
                    None
                } else {
                    Some(recipient.public_key.clone())
                };
                let transfer = DbTransferActMod {
                    asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                    requested_assignment: ActiveValue::Set(Some(req_ass)),
                    recipient_id: ActiveValue::Set(rcpt_id),
                    recipient_type: ActiveValue::Set(rcpt_type),
                    recipient_pubkey: ActiveValue::Set(recipient_pubkey),
                    consignment_hash: ActiveValue::Set(consignment_hash.clone()),
                    recipient_encryption: ActiveValue::Set(recipient.encryption),
                    proxy_transfer_id: ActiveValue::Set(proxy_transfer_id),
                    invoice_expiration: ActiveValue::Set(recipient.invoice_expiration),
                    ..Default::default()
                };
                let transfer_idx = txn.set_transfer(transfer)?;
                let out_of_band = recipient.transport_endpoints.is_empty();
                for transport_endpoint in &recipient.transport_endpoints {
                    self.save_transfer_transport_endpoint(txn, transfer_idx, transport_endpoint)?;
                }
                // the sender proxy endpoint (where the ACK is collected and the signed TX released)
                // only concerns proxy recipients: an out-of-band recipient is not registered there
                if let (Some(endpoint), false) =
                    (&info_contents.sender_transport_endpoint, out_of_band)
                {
                    let url = self.convert_transport_endpoint_url(endpoint)?;
                    self.save_sender_transport_endpoint(txn, transfer_idx, &url)?;
                }
            }
        }

        for (asset_id, txo_assignments) in &info_contents.extra_allocations {
            // allocations on spent UTXOs that the operation doesn't use (of other assets, or of
            // this asset but not needed or rejected) are moved to change, each with their default
            // transition (e.g. TransferLink for a link right), so one asset may get transitions of
            // several types; since they just move state back to the wallet, a single Transfer is
            // recorded
            let asset_transfer = DbAssetTransferActMod {
                user_driven: ActiveValue::Set(false),
                batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
                asset_id: ActiveValue::Set(Some(asset_id.clone())),
                transition_type: ActiveValue::Set(Some(TypeOfTransition::Transfer)),
                ..Default::default()
            };
            let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;
            for (outpoint, assignments) in txo_assignments {
                let outpoint: Outpoint = (*outpoint).into();
                let input_idx = self.get_or_sync_txo_idx(txn, &outpoint)?;
                for (assignment, destination) in assignments {
                    let db_coloring = DbColoringActMod {
                        txo_idx: ActiveValue::Set(input_idx),
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        r#type: ActiveValue::Set(ColoringType::Input),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    };
                    txn.set_coloring(db_coloring)?;
                    let change_idx = self.get_change_utxo_idx(
                        txn,
                        &txid,
                        info_contents,
                        destination,
                        &mut change_utxo_idxs,
                    )?;
                    let db_coloring = DbColoringActMod {
                        txo_idx: ActiveValue::Set(change_idx),
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        r#type: ActiveValue::Set(ColoringType::Change),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    };
                    txn.set_coloring(db_coloring)?;
                }
            }
        }

        Ok(batch_transfer_idx)
    }

    fn update_or_save_transfers(
        &mut self,
        txn: &DbTxn,
        txid: String,
        info_contents: &InfoBatchTransfer,
        status: TransferStatus,
        consignment_hashes: &HashMap<String, String>,
        sync_tte_used: bool,
        psbt: &Psbt,
    ) -> Result<i32, Error> {
        // in a send-to-oneself, the txid is shared between send and receive transfers; only the
        // outgoing batch transfer should be updated here, incoming ones must be ignored so the send
        // transfers are created
        if let Some(existing) = txn
            .get_batch_transfers_by_txid(&txid)?
            .into_iter()
            .find(|batch_transfer| !batch_transfer.incoming)
        {
            let mut updated: DbBatchTransferActMod = existing.clone().into();
            updated.status = ActiveValue::Set(status);
            txn.update_batch_transfer(&mut updated)?;

            // a non-dry-run begin saves the transfers before generating the consignments, so their
            // consignment_hash is None: backfill it now that the consignments exist (for a transfer
            // or a burn, an inflation never produces one)
            for (asset_id, consignment_hash) in consignment_hashes {
                for transfer in txn.get_transfers_for_asset(existing.idx, asset_id)? {
                    if transfer.consignment_hash.is_none() {
                        let mut updated_transfer: DbTransferActMod = transfer.into();
                        updated_transfer.consignment_hash =
                            ActiveValue::Set(Some(consignment_hash.clone()));
                        txn.update_transfer(&mut updated_transfer)?;
                    }
                }
            }

            if sync_tte_used {
                let asset_transfers = txn.iter_asset_transfers()?;
                let transfers = txn.iter_transfers()?;
                let batch_data = existing.get_transfers(&asset_transfers, &transfers)?;
                // copy the used flags set while posting consignments to the DB rows persisted by
                // a non-dry-run begin; only actual recipients have transport endpoints, so
                // non-user-driven asset transfers (extra allocations) are never visited
                let db_transfers: Vec<&DbTransfer> = batch_data
                    .asset_transfers_data
                    .iter()
                    .flat_map(|a| a.transfers.iter())
                    .collect();
                for recipient in info_contents.transfers.values().flat_map(|t| &t.recipients) {
                    let db_transfer = db_transfers
                        .iter()
                        .find(|t| {
                            t.recipient_id.as_deref() == Some(recipient.recipient_id.as_str())
                        })
                        .expect("transfer should be set");
                    let tte_data = txn.get_transfer_transport_endpoints_data(db_transfer.idx)?;
                    for (tte, te) in tte_data {
                        // only the RecipientProxy kind is of interest here
                        if tte.kind != TransportEndpointKind::RecipientProxy {
                            continue;
                        }
                        let local_used = recipient
                            .transport_endpoints
                            .iter()
                            .find(|lte| lte.endpoint == te.endpoint)
                            .is_some_and(|lte| lte.used);
                        if tte.used != local_used {
                            let mut updated_tte: DbTransferTransportEndpointActMod = tte.into();
                            updated_tte.used = ActiveValue::Set(local_used);
                            txn.update_transfer_transport_endpoint(&mut updated_tte)?;
                        }
                    }
                }
            }
            Ok(existing.idx)
        } else {
            self.save_transfers(txn, txid, info_contents, status, consignment_hashes, psbt)
        }
    }

    fn get_input_unspents(&self, unspents: &[LocalUnspent]) -> Result<Vec<LocalUnspent>, Error> {
        let mut input_unspents = unspents.to_vec();
        // consider the following UTXOs unspendable:
        // - incoming and pending
        // - outgoing and in initiated or waiting counterparty status
        // - pending incoming witness
        // - pending incoming blinded
        // - inexistent
        input_unspents.retain(|u| {
            !(u.rgb_allocations
                .iter()
                .any(|a| a.incoming && a.status.pending()))
                && !(u.rgb_allocations.iter().any(|a| {
                    !a.incoming && (a.status.initiated() || a.status.waiting_counterparty())
                }))
                && !u.utxo.pending_witness
                && u.pending_blinded == 0
                && u.utxo.exists
        });
        Ok(input_unspents)
    }

    fn get_transfer_begin_data<'txn>(
        &mut self,
        txn: &'txn DbTxn,
        fee_rate: u64,
    ) -> Result<
        (
            FeeRate,
            Vec<LocalUnspent>,
            Vec<LocalUnspent>,
            RgbStock<'txn>,
        ),
        Error,
    > {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        let db_data = txn.get_db_data(false)?;

        let utxos = txn.get_unspent_txos(db_data.txos)?;

        let mut unspents = txn.get_rgb_allocations(
            utxos,
            Some(db_data.colorings),
            Some(db_data.batch_transfers),
            Some(db_data.asset_transfers),
            Some(db_data.transfers),
        )?;
        // UTXOs reserved to be spent by a pending operation can't be used
        let reserved: HashSet<Outpoint> = self
            .get_reserved_colored_outpoints(txn)?
            .into_iter()
            .collect();
        unspents.retain(|u| !reserved.contains(&u.utxo.outpoint()));

        #[cfg(all(test, feature = "_online"))]
        let input_unspents = mock_input_unspents(self, &unspents);
        #[cfg(not(all(test, feature = "_online")))]
        let input_unspents = self.get_input_unspents(&unspents)?;

        let stock = self.rgb_stock(txn)?;

        Ok((fee_rate_checked, unspents, input_unspents, stock))
    }

    /// Check that a recipient `assignment` is valid for an asset with the given `schema`.
    fn check_recipient_assignment(
        assignment: &Assignment,
        schema: AssetSchema,
    ) -> Result<(), Error> {
        if !schema.supports_assignment(assignment) {
            return Err(Error::InvalidAssignment);
        }
        if matches!(
            assignment,
            Assignment::Fungible(0) | Assignment::InflationRight(0)
        ) {
            return Err(Error::InvalidAmountZero);
        }
        Ok(())
    }

    /// Parse and validate the given recipient into a [`LocalRecipient`], along with the output
    /// (script and amount) to add to the TX for a witness recipient, which gets the given `vout`.
    /// A recipient with no transport endpoints uses the out-of-band exchange.
    ///
    /// Whether the transport endpoints are usable is left to the caller, as it contacts them (see
    /// `check_recipients_transport_endpoints`).
    #[allow(clippy::too_many_arguments)]
    fn parse_recipient(
        &self,
        recipient: &Recipient,
        schema: AssetSchema,
        chainnet: ChainNet,
        vout: u32,
        operation_sk: &ed25519_dalek::SigningKey,
        now_ts: i64,
        mint: bool,
    ) -> Result<(LocalRecipient, Option<(ScriptBuf, u64)>), Error> {
        Self::check_recipient_assignment(&recipient.assignment, schema)?;

        let xchainnet_beneficiary = XChainNet::<Beneficiary>::from_str(&recipient.recipient_id)
            .map_err(|_| Error::InvalidRecipientID)?;

        if xchainnet_beneficiary.chain_network() != chainnet {
            return Err(Error::InvalidRecipientNetwork);
        }

        // a proxy recipient needs a usable transport endpoint, its Ed25519 public key (to encrypt
        // data for it and verify its ACK) and an invoice expiration (after which a transfer to it
        // cannot be created), while the out-of-band exchange has no use for any of them
        let (transport_endpoints, public_key, recipient_vk, invoice_expiration) =
            if recipient.transport_endpoints.is_empty() {
                if !self.supports_out_of_band_exchange() {
                    return Err(Error::UnsupportedTransportType);
                }
                // no transport endpoint is stored: its absence marks the transfer as out-of-band
                (vec![], vec![], None, None)
            } else {
                self.check_transport_endpoints(&recipient.transport_endpoints)?;
                let mut transport_endpoints: Vec<LocalTransportEndpoint> = vec![];
                for endpoint_str in &recipient.transport_endpoints {
                    let transport_endpoint = TransportEndpoint::new(endpoint_str.clone())?;
                    transport_endpoints.push(LocalTransportEndpoint {
                        transport_type: transport_endpoint.transport_type,
                        endpoint: transport_endpoint.endpoint,
                        used: false,
                        usable: false,
                    });
                }

                let public_key_hex =
                    recipient
                        .public_key
                        .as_deref()
                        .ok_or_else(|| Error::InvalidPubkey {
                            details: s!("missing recipient public key"),
                        })?;
                let public_key = hex::decode(public_key_hex).map_err(|_| Error::InvalidPubkey {
                    details: s!("recipient public key is not valid hex"),
                })?;
                let recipient_vk = verifying_key_from_bytes(&public_key)?;

                // a mint is the exception: it expires by the external chain block its lock has to
                // be included before, never by a timestamp, so its recipient must have no
                // expiration
                let invoice_expiration = if mint {
                    if recipient.expiration_timestamp.is_some() {
                        return Err(Error::InvalidRecipientData {
                            details: s!("a mint recipient cannot have an expiration"),
                        });
                    }
                    None
                } else {
                    let invoice_expiration = recipient.expiration_timestamp.ok_or_else(|| {
                        Error::InvalidRecipientData {
                            details: s!("missing invoice expiration"),
                        }
                    })? as i64;
                    if invoice_expiration <= now_ts {
                        return Err(Error::InvoiceExpired);
                    }
                    // the invoice expiration comes from the counterparty and bounds the broadcast
                    // deadline, so it cannot be arbitrarily far in the future either
                    if invoice_expiration > now_ts + i64::from(MAX_EXPIRATION_SECS) {
                        return Err(Error::InvalidExpiration);
                    }
                    Some(invoice_expiration)
                };

                (
                    transport_endpoints,
                    public_key,
                    Some(recipient_vk),
                    invoice_expiration,
                )
            };

        let (local_recipient_data, witness_output) = match xchainnet_beneficiary.into_inner() {
            Beneficiary::BlindedSeal(secret_seal) => {
                if recipient.witness_data.is_some() {
                    return Err(Error::InvalidRecipientData {
                        details: s!("cannot provide witness data for a blinded recipient"),
                    });
                }
                (LocalRecipientData::Blind(secret_seal), None)
            }
            Beneficiary::WitnessVout(pay_2_vout, _) => {
                let Some(ref witness_data) = recipient.witness_data else {
                    return Err(Error::InvalidRecipientData {
                        details: s!("missing witness data for a witness recipient"),
                    });
                };
                // the blinding of a proxy recipient seal is derived from the keys of both parties
                // (v1.0-changes-spec.md A.11), so the sender cannot choose it as it does for an
                // out-of-band recipient, which has no key
                let blinding = match &recipient_vk {
                    None => witness_data.blinding,
                    Some(recipient_vk) => {
                        if witness_data.blinding.is_some() {
                            return Err(Error::InvalidRecipientData {
                                details: s!(
                                    "cannot provide a blinding for a witness recipient with transport endpoints"
                                ),
                            });
                        }
                        Some(derive_shared(operation_sk, recipient_vk)?.seal_blinding)
                    }
                };
                let local_witness_data = LocalWitnessData {
                    amount_sat: witness_data.amount_sat,
                    blinding,
                    vout,
                };
                (
                    LocalRecipientData::Witness(local_witness_data),
                    Some((pay_2_vout.to_script(), witness_data.amount_sat)),
                )
            }
        };

        Ok((
            LocalRecipient {
                recipient_id: recipient.recipient_id.clone(),
                local_recipient_data,
                assignment: recipient.assignment.clone(),
                transport_endpoints,
                public_key,
                encryption: recipient.encryption,
                invoice_expiration,
            },
            witness_output,
        ))
    }

    /// Mark which transport endpoints of the given recipients (parsed by `parse_recipient`) are
    /// usable, contacting each distinct endpoint once, however many recipients share it, and refuse
    /// a proxy recipient with none.
    fn check_recipients_transport_endpoints<'a>(
        recipients: impl IntoIterator<Item = &'a mut LocalRecipient>,
        proxy_usable: impl Fn(&str) -> bool,
    ) -> Result<(), Error> {
        let mut usable_endpoints: HashMap<String, bool> = HashMap::new();
        for local_recipient in recipients {
            if local_recipient.transport_endpoints.is_empty() {
                continue;
            }
            for transport_endpoint in &mut local_recipient.transport_endpoints {
                transport_endpoint.usable = *usable_endpoints
                    .entry(transport_endpoint.endpoint.clone())
                    .or_insert_with(|| proxy_usable(&transport_endpoint.endpoint));
            }
            if !local_recipient.transport_endpoints.iter().any(|t| t.usable) {
                return Err(Error::InvalidTransportEndpoints {
                    details: s!("no valid transport endpoints"),
                });
            }
        }
        Ok(())
    }

    fn setup_transfer_directory(&self, receive_ids: Vec<String>) -> Result<PathBuf, Error> {
        let mut receive_ids_dedup = receive_ids.clone();
        receive_ids_dedup.sort();
        receive_ids_dedup.dedup();
        if receive_ids.len() != receive_ids_dedup.len() {
            return Err(Error::RecipientIDDuplicated);
        }
        let mut hasher = DefaultHasher::new();
        receive_ids.hash(&mut hasher);
        let transfer_id = hasher.finish().to_string();
        let transfer_key = self.transfer_key(&transfer_id)?;
        if self.files().exists(&transfer_key)? {
            self.files().remove_dir_all(&transfer_key)?;
        }
        Ok(self.get_transfer_dir(&transfer_id))
    }

    /// Prepare the PSBT of an operation on a single asset (an inflation, a burn or a mint),
    /// retrying, as a send does, without the inputs found rejected by the asset's reject list:
    /// more inputs are then selected to make up for them, failing if there aren't enough.
    ///
    /// Only a mint has a counterparty, so only it has a sender proxy and an operation key, while
    /// none has an expiration: a mint expires by the external chain block its lock has to be
    /// included before.
    #[allow(clippy::too_many_arguments)]
    fn prepare_single_asset_psbt(
        &mut self,
        txn: &DbTxn,
        transfer_info: InfoAssetTransfer,
        transfer_dir: PathBuf,
        unspents: Vec<LocalUnspent>,
        input_unspents: &[LocalUnspent],
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate_checked: FeeRate,
        min_confirmations: u8,
        sender_transport_endpoint: Option<String>,
        operation_secret_key: Option<Vec<u8>>,
        stock: &mut RgbStock<'_>,
        mut reject_lists: HashMap<RejectListSource, RejectList>,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        let asset_id = transfer_info.asset_info.contract_id.to_string();
        let mut rejected = HashSet::new();
        let mut transfer_info_map = BTreeMap::from([(asset_id.clone(), transfer_info.clone())]);
        loop {
            match self.prepare_transfer_psbt(
                txn,
                &mut transfer_info_map,
                transfer_dir.clone(),
                false,
                unspents.clone(),
                input_unspents,
                witness_recipients,
                fee_rate_checked,
                min_confirmations,
                None,
                sender_transport_endpoint.clone(),
                operation_secret_key.clone(),
                stock,
                &mut rejected,
                &mut reject_lists,
                dry_run,
            )? {
                PrepareTransferPsbtResult::Retry => {
                    // start over from the original transfer info, with the assignments needed
                    // increased by the rejected ones
                    let assignments_needed =
                        transfer_info_map[&asset_id].assignments_needed.clone();
                    let asset_spend = self.select_rgb_inputs(
                        asset_id.clone(),
                        &assignments_needed,
                        input_unspents.to_vec(),
                        &mut SelectedInputs::default(),
                        Self::max_input_allocations(
                            &transfer_info.main_transition.transition_type(),
                        ),
                    )?;
                    transfer_info_map = BTreeMap::from([(
                        asset_id.clone(),
                        InfoAssetTransfer {
                            asset_spend,
                            assignments_needed,
                            ..transfer_info.clone()
                        },
                    )]);
                }
                PrepareTransferPsbtResult::Success(begin_operation_data) => {
                    return Ok(*begin_operation_data);
                }
            }
        }
    }

    fn prepare_transfer_psbt(
        &mut self,
        txn: &DbTxn,
        transfer_info_map: &mut BTreeMap<String, InfoAssetTransfer>,
        transfer_dir: PathBuf,
        donation: bool,
        unspents: Vec<LocalUnspent>,
        input_unspents: &[LocalUnspent],
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate_checked: FeeRate,
        min_confirmations: u8,
        expiration_timestamp: Option<i64>,
        sender_transport_endpoint: Option<String>,
        operation_secret_key: Option<Vec<u8>>,
        stock: &mut RgbStock<'_>,
        rejected: &mut HashSet<Opout>,
        reject_lists: &mut HashMap<RejectListSource, RejectList>,
        dry_run: bool,
    ) -> Result<PrepareTransferPsbtResult, Error> {
        // prepare BDK PSBT
        let mut all_inputs: HashSet<BdkOutPoint> = transfer_info_map
            .values()
            .flat_map(|ti| {
                ti.asset_spend
                    .input_outpoints
                    .iter()
                    .map(|o| o.clone().into())
            })
            .collect();
        let (mut psbt, btc_change) = self.try_prepare_psbt(
            input_unspents,
            &mut all_inputs,
            witness_recipients,
            fee_rate_checked,
        )?;
        psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_op_return([]);

        // prepare RGB PSBT
        let begin_operation_data = match self.prepare_rgb_psbt(
            txn,
            &mut psbt,
            transfer_info_map,
            transfer_dir.clone(),
            donation,
            unspents,
            stock,
            min_confirmations,
            expiration_timestamp,
            btc_change,
            sender_transport_endpoint,
            operation_secret_key,
            rejected,
            reject_lists,
        )? {
            PrepareRgbPsbtResult::Retry => return Ok(PrepareTransferPsbtResult::Retry),
            PrepareRgbPsbtResult::Success(begin_operation_data) => begin_operation_data,
        };

        // rename transfer directory
        let txid = psbt
            .clone()
            .extract_tx()
            .map_err(InternalError::from)?
            .compute_txid()
            .to_string();
        let new_transfer_dir = self.get_transfer_dir(&txid);
        self.files().rename(
            &self.wallet_key(&transfer_dir)?,
            &self.wallet_key(&new_transfer_dir)?,
        )?;

        // persist the unsigned PSBT
        self.files().atomic_write(
            &self.wallet_key(&new_transfer_dir.join(UNSIGNED_PSBT_FILE))?,
            begin_operation_data.psbt.to_string().as_bytes(),
        )?;

        // update transfer_dir to the new (renamed) directory
        let mut begin_operation_data = begin_operation_data;
        begin_operation_data.transfer_dir = new_transfer_dir;

        if !dry_run {
            // save transfer to DB with Initiated status to reserve the UTXOs; no consignment has
            // been generated yet, their hashes get backfilled when the operation ends
            let batch_transfer_idx = self.save_transfers(
                txn,
                txid,
                &begin_operation_data.info_batch_transfer,
                TransferStatus::Initiated,
                &HashMap::new(),
                &begin_operation_data.psbt,
            )?;
            begin_operation_data.batch_transfer_idx = Some(batch_transfer_idx);
        }

        Ok(PrepareTransferPsbtResult::Success(begin_operation_data))
    }

    /// Hash (SHA-256) the plaintext consignment generated for each asset of the batch transfer in
    /// the given transfer directory, keyed by asset ID. Every asset must have its consignment on
    /// disk already, so this is only for operations producing one (a transfer, a burn or a mint),
    /// once the consignments have been generated.
    fn consignment_hashes(
        &self,
        transfer_dir: &Path,
        info_contents: &InfoBatchTransfer,
    ) -> Result<HashMap<String, String>, Error> {
        let mut consignment_hashes = HashMap::new();
        for asset_id in info_contents.transfers.keys() {
            let atd = self.get_asset_transfer_dir(transfer_dir, asset_id);
            let cpath = self.get_send_consignment_path_impl(&atd);
            let bytes = self.files().read(&self.wallet_key(&cpath)?)?;
            consignment_hashes.insert(asset_id.clone(), hash_file_bytes(&bytes));
        }
        Ok(consignment_hashes)
    }

    /// Post the consignment of each asset and the media of an operation to the transport endpoints
    /// of its proxy recipients, marking the ones that accepted them as used.
    ///
    /// Native only so far: it reads the files to upload, which the browser transport will post
    /// over its async client instead.
    #[cfg(feature = "_online")]
    #[allow(clippy::too_many_arguments)]
    fn post_transfer_data(
        &self,
        recipients: &mut Vec<LocalRecipient>,
        asset_transfer_dir: PathBuf,
        medias: HashSet<Media>,
        sender_sk: &ed25519_dalek::SigningKey,
        sender_pubkey_hex: &str,
        sender_transport_endpoint: Option<&str>,
        consignment_hash: &str,
        batch: bool,
    ) -> Result<(), Error> {
        let consignment_path = self.get_send_consignment_path_impl(&asset_transfer_dir);
        // media are identified per transfer by media_id, signing and encryption are deterministic,
        // so the same digest yields idempotent media.post calls within a transfer.
        let media_count = medias
            .iter()
            .map(|m| m.get_digest())
            .collect::<HashSet<_>>()
            .len();
        for recipient in recipients {
            let recipient_id = &recipient.recipient_id;
            if recipient.transport_endpoints.is_empty() {
                debug!(
                    self.logger(),
                    "No transport endpoints (out-of-band exchange), skipping post for recipient ID: {recipient_id}"
                );
                continue;
            }
            let sender_transport_endpoint =
                sender_transport_endpoint.ok_or_else(|| Error::Internal {
                    details: s!("missing sender transport endpoint"),
                })?;
            let recipient_vk = verifying_key_from_bytes(&recipient.public_key)?;
            let derived = derive_shared(sender_sk, &recipient_vk)?;
            let encrypt = recipient.encryption != Encryption::Unsupported;
            let (invoice_id, transfer_id) = recipient.proxy_ids(sender_pubkey_hex);

            // the (optionally encrypted) consignment, signed along with the hash of the uploaded
            // bytes, is the same for every transport endpoint
            let enc_tmp = if encrypt {
                Some(encrypt_to_tempfile(
                    &consignment_path,
                    &derived.sym_key,
                    consignment_hash,
                )?)
            } else {
                None
            };
            let post_path: &Path = match &enc_tmp {
                Some(tmp) => tmp.path(),
                None => consignment_path.as_path(),
            };
            let blob_hash = hash_file(post_path)?;
            let consignment_data = PostConsignmentData {
                invoice_id,
                transfer_id: transfer_id.clone(),
                sender_transport_endpoint: sender_transport_endpoint.to_string(),
                sender_pk: sender_pubkey_hex.to_string(),
                consignment_hash: consignment_hash.to_string(),
                batch,
                signature: hex::encode(sign_ed25519(
                    sender_sk,
                    &sha256_digest(
                        post_consignment_message(&transfer_id, consignment_hash, &blob_hash)
                            .as_bytes(),
                    ),
                )),
            };

            let mut found_valid = false;
            // the error of the last endpoint that refused to create the transfer, if any
            let mut refusal = None;
            for transport_endpoint in recipient.transport_endpoints.iter_mut() {
                if transport_endpoint.transport_type != TransportType::JsonRpc
                    || !transport_endpoint.usable
                {
                    debug!(
                        self.logger(),
                        "Skipping transport endpoint {:?}", transport_endpoint
                    );
                    continue;
                }
                let proxy_url = transport_endpoint.endpoint.clone();
                debug!(
                    self.logger(),
                    "Posting consignment for recipient ID: {recipient_id}"
                );
                let proxy_client = ProxyClient::new(&proxy_url)?;

                // skip a proxy that would refuse some of the media after the consignment is posted,
                // or that doesn't tell how many it accepts (unreachable or invalid max_media)
                if media_count > 0 {
                    let max_media = proxy_client
                        .get_info()
                        .ok()
                        .and_then(|res| res.result)
                        .as_ref()
                        .and_then(proxy_max_media);
                    let Some(max_media) = max_media else {
                        debug!(self.logger(), "Proxy {proxy_url} doesn't report max media");
                        continue;
                    };
                    if media_count > max_media {
                        debug!(
                            self.logger(),
                            "Proxy {proxy_url} accepts {max_media} media, {media_count} needed"
                        );
                        refusal = Some(Error::ProxyTooManyMedia);
                        continue;
                    }
                }

                match self.post_consignment_with_pow(&proxy_client, &consignment_data, post_path)? {
                    Ok(()) => {}
                    // the transfer cannot be created on this transport endpoint
                    Err(
                        e @ (Error::InvoiceNotReserved
                        | Error::InvoiceExpired
                        | Error::InvoiceQuotaExceeded
                        | Error::TransferIDDeleted
                        | Error::ProxyDraining),
                    ) => {
                        refusal = Some(e);
                        continue;
                    }
                    Err(e @ Error::ProxyCannotChange { .. }) => return Err(e),
                    Err(_) => continue,
                }

                // post the (optionally encrypted) media attachment(s)
                for media in &medias {
                    let digest = media.get_digest();
                    let media_id = derived.media_id(&digest);
                    let media_tmp = if encrypt {
                        Some(encrypt_to_tempfile(
                            Path::new(&media.file_path),
                            &derived.sym_key,
                            &digest,
                        )?)
                    } else {
                        None
                    };
                    let media_post_path: &Path = match &media_tmp {
                        Some(tmp) => tmp.path(),
                        None => Path::new(&media.file_path),
                    };
                    let media_blob_hash = hash_file(media_post_path)?;
                    let media_signature = hex::encode(sign_ed25519(
                        sender_sk,
                        &sha256_digest(
                            post_media_message(&transfer_id, &media_id, &media_blob_hash)
                                .as_bytes(),
                        ),
                    ));
                    let media_res = proxy_client.post_media(
                        &transfer_id,
                        &media_id,
                        media_post_path,
                        &media_signature,
                    )?;
                    debug!(self.logger(), "Attachment POST response: {:?}", media_res);
                    if let Some(err) = media_res.error {
                        return Err(map_proxy_error(err));
                    }
                }

                transport_endpoint.used = true;
                found_valid = true;
                break;
            }
            if !found_valid {
                return Err(refusal.unwrap_or(Error::NoValidTransportEndpoint));
            }
        }

        Ok(())
    }

    /// Post a consignment, computing the proof of work the recipient proxy requires: a proxy under
    /// attack can raise the difficulty at any time, in which case it reports the current one and
    /// the post is retried with a new proof of work, a limited number of times.
    ///
    /// The outer result is for errors that should stop the operation, the inner one for errors
    /// specific to the proxy, which allow trying another transport endpoint.
    #[cfg(feature = "_online")]
    fn post_consignment_with_pow(
        &self,
        proxy_client: &ProxyClient,
        data: &PostConsignmentData,
        consignment_path: &Path,
    ) -> Result<Result<(), Error>, Error> {
        const MAX_POW_ATTEMPTS: u8 = 3;
        let mut difficulty = 0;
        for _ in 0..MAX_POW_ATTEMPTS {
            let pow_timestamp = now().unix_timestamp().to_string();
            let pow_nonce =
                crate::encryption::solve_pow(&data.transfer_id, &pow_timestamp, difficulty);
            let res = proxy_client.post_consignment(
                data,
                consignment_path,
                &pow_timestamp,
                &pow_nonce,
            )?;
            debug!(self.logger(), "Consignment POST response: {:?}", res);
            let Some(err) = res.error else {
                // skip proxies with a non-compliant API
                return Ok(match res.result {
                    Some(_) => Ok(()),
                    None => Err(Error::Proxy {
                        details: s!("missing consignment.post result"),
                    }),
                });
            };
            match pow_difficulty_required(&err) {
                Some(required) if required <= MAX_POW_DIFFICULTY => {
                    debug!(
                        self.logger(),
                        "Proof of work difficulty {required} required, retrying"
                    );
                    difficulty = required;
                }
                Some(required) => {
                    warn!(
                        self.logger(),
                        "Proof of work difficulty {required} exceeds the maximum accepted"
                    );
                    return Ok(Err(map_proxy_error(err)));
                }
                None => return Ok(Err(map_proxy_error(err))),
            }
        }
        Ok(Err(Error::Proxy {
            details: s!("proof of work not accepted"),
        }))
    }

    /// The index of the TXO receiving the RGB change at `destination`, saving the new Bitcoin
    /// output of the TX with ID `txid` if needed, and caching the indexes in `change_utxo_idxs`.
    fn get_change_utxo_idx(
        &self,
        txn: &DbTxn,
        txid: &str,
        info_contents: &InfoBatchTransfer,
        destination: &ChangeDestination,
        change_utxo_idxs: &mut HashMap<ChangeDestination, i32>,
    ) -> Result<i32, Error> {
        if let Some(idx) = change_utxo_idxs.get(destination) {
            return Ok(*idx);
        }
        let idx = match destination {
            ChangeDestination::BtcChange => {
                let btc_change = info_contents
                    .btc_change
                    .as_ref()
                    .expect("change to the BTC change output");
                match txn.get_txo(&Outpoint {
                    txid: txid.to_string(),
                    vout: btc_change.vout,
                })? {
                    Some(txo) => txo.idx,
                    None => {
                        let db_utxo = DbTxoActMod {
                            txid: ActiveValue::Set(txid.to_string()),
                            vout: ActiveValue::Set(btc_change.vout),
                            btc_amount: ActiveValue::Set(btc_change.amount.to_string()),
                            spent: ActiveValue::Set(false),
                            exists: ActiveValue::Set(false),
                            pending_witness: ActiveValue::Set(false),
                            ..Default::default()
                        };
                        txn.set_txo(db_utxo)?
                    }
                }
            }
            ChangeDestination::Utxo(outpoint) => txn.get_txo(outpoint)?.expect("should exist").idx,
        };
        change_utxo_idxs.insert(destination.clone(), idx);
        Ok(idx)
    }

    /// Prepare the PSBT of an operation that pays no one (a burn or a link), spending the
    /// `assignments_needed` of `asset` with the `main_transition`.
    ///
    /// The operation assigns nothing to anyone, so it gets no recipient output and records no
    /// recipient: a random ID names its transfer directory until the TXID replaces it, and the
    /// transfer row recording the operation is saved on its own.
    ///
    /// `reject_lists` carries the lists the caller already resolved: the browser resolves them
    /// before its transaction opens, as it cannot fetch while one is.
    #[allow(clippy::too_many_arguments)]
    fn begin_without_recipient_impl(
        &mut self,
        txn: &DbTxn,
        asset: DbAsset,
        assignments_needed: AssignmentsCollection,
        main_transition: MainTransition,
        fee_rate: u64,
        min_confirmations: u8,
        reject_lists: HashMap<RejectListSource, RejectList>,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        let (fee_rate_checked, unspents, input_unspents, mut stock) =
            self.get_transfer_begin_data(txn, fee_rate)?;

        let asset_spend = self.select_rgb_inputs(
            asset.id.clone(),
            &assignments_needed,
            input_unspents.clone(),
            &mut SelectedInputs::default(),
            Self::max_input_allocations(&main_transition.transition_type()),
        )?;

        let contract_id = ContractId::from_str(&asset.id).expect("invalid contract ID");
        let asset_info = AssetInfo {
            contract_id,
            schema: asset.schema,
            reject_list_url: asset.reject_list_url,
        };
        let transfer_info = InfoAssetTransfer {
            asset_info,
            recipients: vec![],
            asset_spend,
            change: AssignmentsCollection::default(),
            original_assignments_needed: assignments_needed.clone(),
            assignments_needed,
            assignments_spent: HashMap::new(),
            change_destinations: vec![],
            main_transition,
            beneficiaries_blinded: vec![],
            beneficiaries_witness: vec![],
        };
        // the operation has no recipient, so there's no recipient ID to name its transfer
        // directory: a random one keeps concurrent operations apart until the TXID replaces it
        let dir_id = rand::rng().random_range(0..u64::MAX).to_string();
        let transfer_dir = self.setup_transfer_directory(vec![dir_id])?;

        self.prepare_single_asset_psbt(
            txn,
            transfer_info,
            transfer_dir,
            unspents,
            &input_unspents,
            &vec![],
            fee_rate_checked,
            min_confirmations,
            None,
            None,
            &mut stock,
            reject_lists,
            dry_run,
        )
    }

    /// Prepare the PSBT to burn the given `amount` of the asset `asset_id`, checking the burn is
    /// supported by its schema and the reason is well-formed.
    #[allow(clippy::too_many_arguments)]
    fn burn_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        amount: u64,
        burn_reason: Option<String>,
        fee_rate: u64,
        min_confirmations: u8,
        reject_lists: HashMap<RejectListSource, RejectList>,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        let asset = txn.check_asset_exists(asset_id)?;
        let schema = asset.schema;
        self.check_schema_support(&schema)?;
        if !schema.supports_burn() {
            return Err(Error::UnsupportedBurn {
                asset_schema: schema,
            });
        }

        if amount == 0 {
            return Err(Error::NoBurnAmount);
        }

        let burn_reason = burn_reason
            .map(|reason| self.check_burn_reason(reason))
            .transpose()?;

        let assignments_needed = AssignmentsCollection {
            fungible: amount,
            ..Default::default()
        };
        self.begin_without_recipient_impl(
            txn,
            asset,
            assignments_needed,
            MainTransition::Burn { burn_reason },
            fee_rate,
            min_confirmations,
            reject_lists,
            dry_run,
        )
    }

    /// Prepare the PSBT to link the asset `asset_id` to `linked_to_contract`, checking the link is
    /// supported by its schema and the contract it points to, unless `skip_contract_checks` is
    /// set.
    #[allow(clippy::too_many_arguments)]
    fn link_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        linked_to_contract: String,
        fee_rate: u64,
        min_confirmations: u8,
        skip_contract_checks: bool,
        reject_lists: HashMap<RejectListSource, RejectList>,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        let asset = txn.check_asset_exists(asset_id)?;
        let schema = asset.schema;
        self.check_schema_support(&schema)?;
        if !schema.supports_link() {
            return Err(Error::UnsupportedLink {
                asset_schema: schema,
            });
        }

        let linked_to_contract =
            ContractId::from_str(&linked_to_contract).map_err(|_| Error::InvalidContractId {
                contract_id: linked_to_contract,
            })?;
        // the link right can be spent only once, linking the asset to itself would waste it
        if linked_to_contract.to_string() == asset.id {
            return Err(Error::CannotLinkToItself);
        }
        if !skip_contract_checks {
            self.check_linked_to_contract(txn, &linked_to_contract, &asset.id)?;
        }

        let assignments_needed = AssignmentsCollection {
            link: true,
            ..Default::default()
        };
        self.begin_without_recipient_impl(
            txn,
            asset,
            assignments_needed,
            MainTransition::Link { linked_to_contract },
            fee_rate,
            min_confirmations,
            reject_lists,
            dry_run,
        )
    }

    /// Everything ending an operation that pays no one (a burn or a link) produces before its
    /// signed TX reaches the network: the checks, the witness TX in the transfer data and the
    /// consignment proving the operation.
    fn prepare_without_recipient_end(
        &self,
        txn: &DbTxn,
        signed_psbt: &Psbt,
        main_transition: TypeOfTransition,
    ) -> Result<WithoutRecipientEnd, Error> {
        self.check_end_initiated(txn, signed_psbt)?;
        let (txid, transfer_dir, info_contents, mut fascia) =
            self.get_transfer_end_data(signed_psbt)?;

        // the data must be of this operation: another one would be completed skipping its checks
        // and steps
        if !info_contents.is_operation(&main_transition) {
            return Err(Error::WrongOperation { txid });
        }

        // embed the signed transaction, then generate the consignment proving the operation
        let tx = signed_psbt
            .clone()
            .extract_tx()
            .map_err(InternalError::from)?;
        fascia.update_witness_tx(tx);
        self.gen_consignments(txn, &fascia, &info_contents.transfers, &transfer_dir)?;
        let consignment_hashes = self.consignment_hashes(&transfer_dir, &info_contents)?;

        Ok(WithoutRecipientEnd {
            txid,
            info_contents,
            consignment_hashes,
            fascia,
        })
    }

    /// Complete an operation that pays no one (a burn or a link) once its signed TX has been
    /// broadcast, recording the transfer and the contract a link points to.
    fn finalize_without_recipient_end(
        &mut self,
        txn: &DbTxn,
        signed_psbt: &Psbt,
        end: WithoutRecipientEnd,
        tx: &BdkTransaction,
    ) -> Result<(OperationResult, InfoBatchTransfer), Error> {
        let WithoutRecipientEnd {
            txid,
            info_contents,
            consignment_hashes,
            fascia,
        } = end;
        let batch_transfer_idx = self.finalize_transfer_end_after_broadcast(
            txn,
            txid.clone(),
            tx,
            signed_psbt,
            &info_contents,
            TransferStatus::WaitingConfirmations,
            &consignment_hashes,
            fascia,
            false,
        )?;
        self.record_link_contract(txn, &info_contents)?;

        let res = OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        };
        Ok((res, info_contents))
    }

    /// Record the contract each link transition of `info_contents` points to on its asset: the link
    /// transition assigns nothing, so no consignment of a later operation carries it and the link
    /// is known only to this wallet, once broadcast.
    fn record_link_contract(
        &self,
        txn: &DbTxn,
        info_contents: &InfoBatchTransfer,
    ) -> Result<(), Error> {
        for (asset_id, transfer_info) in &info_contents.transfers {
            if let MainTransition::Link { linked_to_contract } = transfer_info.main_transition {
                let mut asset: DbAssetActMod = txn.check_asset_exists(asset_id.clone())?.into();
                asset.linked_to_contract = ActiveValue::Set(Some(linked_to_contract.to_string()));
                txn.update_asset(&mut asset)?;
            }
        }
        Ok(())
    }

    /// The index of the TXO at `outpoint`, syncing the wallet first if it's not known yet.
    fn get_or_sync_txo_idx(&mut self, txn: &DbTxn, outpoint: &Outpoint) -> Result<i32, Error> {
        Ok(match txn.get_txo(outpoint)? {
            Some(txo) => txo.idx,
            None => {
                self.sync_colored_fast(txn)?;
                let bdk_utxo = txn.get_txo(outpoint)?.expect("should exist");
                let new_db_utxo: DbTxoActMod = bdk_utxo.clone().into();
                txn.set_txo(new_db_utxo)?
            }
        })
    }
}

/// What ending an operation that pays no one (a burn or a link) produces before its signed TX is
/// broadcast (see [`WalletPrepare::prepare_without_recipient_end`]): the network step stays with
/// the transport, the rest is shared.
pub struct WithoutRecipientEnd {
    /// ID of the TX anchoring the operation
    pub(crate) txid: String,
    /// The transfer data of the operation, updated with the TX of the witness
    pub(crate) info_contents: InfoBatchTransfer,
    /// SHA-256 hash of the consignment generated for each asset of the operation
    pub(crate) consignment_hashes: HashMap<String, String>,
    /// The fascia of the operation, to consume once the TX is broadcast
    pub(crate) fascia: Fascia,
}
