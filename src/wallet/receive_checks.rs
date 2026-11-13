//! Receive checks shared by the native and browser receive drivers.
//!
//! These are the wallet-free parts of receiving a consignment: locating the payment to the
//! recipient, counting the slots it takes on the receiving UTXO, reading the asset media and
//! checking the received allocations against the reject list. They take the database transaction,
//! the stock and the log explicitly, so both drivers can run them without owning a wallet type.

#![cfg_attr(
    all(target_arch = "wasm32", not(feature = "_online")),
    allow(dead_code)
)] // the browser driver that uses them is wired in a later step

use super::*;

use crate::no_wallet::validation::{ResolveRejectList, check_reject_list, resolve_witnesses};
use schemata::{BfaWrapper, CfaWrapper, NiaWrapper, UdaWrapper};

/// The outputs spent within the consignment by its known transitions. The bundle input maps
/// can't be used instead: the validation only checks their entries for the known transitions,
/// so a sender could list as spent by a transition missing from the consignment any output,
/// e.g. to hide assignments paying this recipient. The inputs of a known transition are
/// checked by the validation instead, which also requires the witness TX to close their seals,
/// so only this wallet can spend an output paying it.
pub(super) fn known_spent_opouts(consignment: &RgbTransfer) -> BTreeSet<Opout> {
    consignment
        .bundles
        .iter()
        .flat_map(|wb| wb.bundle.known_transitions.iter())
        .flat_map(|kt| kt.transition.inputs.iter().copied())
        .collect()
}

/// Locate the destinations at which the consignment pays this recipient: each is a bundle and,
/// for witness receives, a vout of its witness TX, with the assignments to the recipient's seal
/// that are unspent within the consignment. What is received must be unspent within the
/// consignment: only this wallet can spend it, so a consignment spending it is not paying this
/// wallet.
///
/// The spent outputs are the inputs of the known transitions (see `known_spent_opouts`), which
/// only the deterministic validation checks, so the result can be trusted only for a
/// consignment that went through it.
///
/// Several assignments to the same vout of the same bundle are one destination paid more than
/// once (e.g. two assignment types paying this recipient, differing only by blinding). Callers
/// refuse a consignment paying this recipient at more than one destination - a different
/// witness TXID (so a different bundle), or a different vout of the same TXID - as a transfer
/// waits on and credits from a single one.
///
/// `spent` are the consignment's spent outputs (see `known_spent_opouts`), which callers
/// matching several transfers against a consignment compute once.
pub(super) fn find_payments<'c, 'a>(
    consignment: &'c RgbTransfer,
    matcher: &'a ReceiveMatcher,
    spent: &'a BTreeSet<Opout>,
) -> impl Iterator<Item = ConsignmentPayment<'c>> + 'a
where
    'c: 'a,
{
    consignment.bundles.iter().flat_map(move |witness_bundle| {
        // the seals at which this bundle pays the recipient
        let mut payment_seals: Vec<PaymentSeal> = vec![];
        let mut push_payment_seal = |payment_seal: PaymentSeal| {
            if !payment_seals.contains(&payment_seal) {
                payment_seals.push(payment_seal);
            }
        };
        let seals = witness_bundle
            .bundle
            .known_transitions
            .iter()
            .flat_map(|kt| kt.transition.assignments.values())
            .flat_map(|typed_assigns| typed_assigns.seals());
        match matcher {
            ReceiveMatcher::Blind(secret_seal) => {
                let payment_seal = PaymentSeal::Concealed(*secret_seal);
                if seals.into_iter().any(|seal| payment_seal.matches(seal)) {
                    push_payment_seal(payment_seal);
                }
            }
            ReceiveMatcher::Witness(script_pubkey, blinding) => {
                let tx = &witness_bundle.tx;
                for seal in seals {
                    // a witness receive is matched by the scriptPubKey at the vout the seal
                    // names, which a concealed seal does not expose - it belongs to the blind
                    // arm above
                    let BuilderSeal::Revealed(seal) = *seal else {
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
                        push_payment_seal(PaymentSeal::WitnessVout(vout));
                    }
                }
            }
        }

        payment_seals.into_iter().filter_map(move |payment_seal| {
            let mut receiving = assignments_for_bundle(witness_bundle, payment_seal);
            receiving.retain(|opout, _| !spent.contains(opout));
            (!receiving.is_empty()).then_some(ConsignmentPayment {
                bundle: witness_bundle,
                payment_seal,
                receiving,
            })
        })
    })
}

/// The slots taken on the TXO at `outpoint`, if known and unspent, besides the ones of the
/// transfer with index `transfer_idx` (of the asset transfer with index `asset_transfer_idx`):
/// the allocations of the asset with ID `asset_id` and of all assets it holds or is due to
/// receive from transfers that haven't failed, and its other unpaid invoices, each due to
/// receive an allocation of any asset. The mint rights of the asset are counted apart,
/// together with the other unpaid invoices requesting one. The allocations of the transfer
/// itself are excluded, as its consignment can be processed again once they're saved (e.g. by
/// a watch-only multisig wallet, which waits for the cosigners to decide before ACKing it).
pub(super) fn count_utxo_taken_slots(
    txn: &DbTxn,
    outpoint: &Outpoint,
    asset_id: &str,
    transfer_idx: i32,
    asset_transfer_idx: i32,
) -> Result<TakenSlots, Error> {
    let Some(txo) = txn.get_txo(outpoint)? else {
        return Ok(TakenSlots::default());
    };
    if txo.spent {
        return Ok(TakenSlots::default());
    }
    let invoices = txn.get_utxo_unpaid_invoices(outpoint, transfer_idx)?;
    let mint_right_invoices = invoices
        .iter()
        .filter(|(t, aid)| t.requests_mint_right(aid.as_deref(), asset_id))
        .count();
    Ok(TakenSlots {
        asset: txn.count_txo_incoming_colorings(txo.idx, Some(asset_id), asset_transfer_idx)?,
        asset_amount: txn.txo_incoming_amount(txo.idx, asset_id, asset_transfer_idx)?,
        all: txn.count_txo_incoming_colorings(txo.idx, None, asset_transfer_idx)?,
        invoices: invoices.len(),
        mint_rights: txn.count_txo_incoming_mint_rights(txo.idx, asset_id, asset_transfer_idx)?
            + mint_right_invoices,
    })
}

/// The assignments in a single bundle that pay the recipient at `payment_seal`.
pub(super) fn assignments_for_bundle(
    bundle: &WitnessBundle,
    payment_seal: PaymentSeal,
) -> HashMap<Opout, Assignment> {
    let mut received = HashMap::new();
    for KnownTransition { transition, opid } in bundle.bundle.known_transitions.iter() {
        for (ass_type, typed_assigns) in transition.assignments.iter() {
            // the seals of the assignments, whatever kind they are: a TypedAssigns holds a
            // single kind, so only one of these is not empty
            let seals = typed_assigns
                .as_fungible()
                .iter()
                .map(|a| &a.seal)
                .chain(typed_assigns.as_structured().iter().map(|a| &a.seal))
                .chain(typed_assigns.as_declarative().iter().map(|a| &a.seal));
            for (no, seal) in seals.enumerate() {
                if !payment_seal.matches(seal) {
                    continue;
                }
                let no = no as u16;
                if let Some(assignment) =
                    Assignment::from_typed_assigns(*ass_type, typed_assigns, no)
                {
                    received.insert(Opout::new(*opid, *ass_type, no), assignment);
                }
            }
        }
    }

    received
}

/// The media of a contract, from the data of the consignment that carries it.
pub(super) fn extract_attachments(
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
        AssetSchema::Bfa => {
            let contract = BfaWrapper::with(contract_data);
            if let Some(attachment) = contract.contract_terms().media {
                attachments.push(attachment)
            }
        }
    };
    Ok(attachments)
}

/// The operation ID of the mint paying a recipient, if any: the mint transition of
/// `paying_bundle` that created any of the allocations received, `receiving_ops` being the
/// operations those allocations come from, as opposed to the other mints a consignment may carry
/// (in the paying bundle or in the history).
pub(super) fn paying_mint_opid(
    asset_schema: AssetSchema,
    paying_bundle: &WitnessBundle,
    receiving_ops: impl IntoIterator<Item = OpId>,
) -> Option<OpId> {
    if !asset_schema.supports_mint() {
        return None;
    }
    let receiving_ops: HashSet<OpId> = receiving_ops.into_iter().collect();
    paying_bundle
        .bundle
        .known_transitions
        .iter()
        .find(|kt| kt.transition.transition_type == TS_MINT && receiving_ops.contains(&kt.opid))
        .map(|kt| kt.opid)
}

/// Whether a received mint pays what the invoice requests, if it requests anything: the lock
/// on the external chain has to match the amount minted, so a mint of another amount than the
/// agreed one is refused before the lock is made.
///
/// A mint only pays a fungible amount, so an invoice requesting any other assignment (e.g. a
/// right) can't be paid by one.
pub(super) fn mint_pays_requested(
    transfer: &DbTransfer,
    receiving: &HashMap<Opout, Assignment>,
) -> bool {
    match transfer.requested_assignment {
        // an invoice asking for a specific amount has to be paid exactly that
        Some(Assignment::Fungible(requested)) if requested > 0 => {
            receiving.values().map(|a| a.main_amount()).sum::<u64>() == requested
        }
        // one asking for the fungible state with no amount (`Fungible(0)`), or for no state at
        // all (`Any`), is paid by any amount, as is a transfer that requested nothing (an
        // issuance, which never receives a mint)
        Some(Assignment::Fungible(_) | Assignment::Any) | None => true,
        // a mint pays neither a right nor a non-fungible allocation
        Some(_) => false,
    }
}

/// Set the known circulating supply of the BFA asset with ID `asset_id` to the one read from
/// its bridge contract, if any.
///
/// The supply read is the latest one, as of a later finalized block, so it replaces the known
/// one whether higher or lower (tokens being released from the bridge).
pub(super) fn update_bfa_known_circulating_supply(
    txn: &DbTxn,
    asset_id: String,
    supply: Option<u64>,
) -> Result<(), Error> {
    let Some(supply) = supply else {
        return Ok(());
    };
    let db_asset = txn.get_asset(asset_id)?.expect("asset must exist");
    let mut updated_asset: DbAssetActMod = db_asset.into();
    updated_asset.known_circulating_supply = ActiveValue::Set(Some(supply.to_string()));
    txn.update_asset(&mut updated_asset)?;
    Ok(())
}

/// Map an error validating a consignment received by this wallet, logging it: an invalid
/// consignment is reported as an [`Error::InvalidConsignment`], to be refused.
pub(super) fn received_validation_error(e: Error, logger: &Logger) -> Error {
    match e {
        Error::ConsignmentValidationFailed { details } => {
            error!(logger, "Consignment is invalid: {}", details);
            Error::InvalidConsignment
        }
        e => {
            if let Error::Network { .. } = e {
                warn!(logger, "Network error during consignment validation");
            }
            e
        }
    }
}

/// Phase 2 of the validation of a consignment received by this wallet, followed, if
/// `with_reject_list`, by the check of the assignments it pays this recipient against the
/// reject list of its asset.
///
/// The consignment must be refused if an [`Error::InvalidConsignment`] or an
/// [`Error::ConsignmentRejected`] is returned.
pub(super) fn check_received_consignment(
    pending: PendingConsignment<true>,
    resolver: &impl ResolveWitness,
    asset_schema: AssetSchema,
    receiving: &HashMap<Opout, Assignment>,
    with_reject_list: bool,
    logger: &Logger,
    reject_list_resolver: &dyn ResolveRejectList,
) -> Result<ValidTransfer, Error> {
    // phase 2: resolve the witnesses and finalize, which requires all the claims
    // to be resolved by now
    let valid_consignment =
        resolve_witnesses(pending, resolver).map_err(|e| received_validation_error(e, logger))?;
    let validation_status = valid_consignment.validation_status();
    debug!(
        logger,
        "Consignment validity: {:?}",
        validation_status.validity()
    );

    if with_reject_list && asset_schema.supports_reject_list() {
        check_reject_list(
            asset_schema,
            valid_consignment.genesis(),
            validation_status.ops_dag.as_ref(),
            Some(reject_list_resolver),
            &receiving.keys().copied().collect(),
        )
        .inspect_err(|e| {
            if let Error::ConsignmentRejected { opouts } = e {
                error!(
                    logger,
                    "Found {} opout(s) that must be rejected",
                    opouts.len()
                );
            }
        })?;
        info!(logger, "Didn't find any opout(s) that should be rejected");
    }

    Ok(valid_consignment)
}
