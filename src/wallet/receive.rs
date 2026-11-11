//! Receive phases shared by the drivers that accept an incoming consignment.
//!
//! The native driver (`online`) keeps the consignment fetch and its retry/caching policy, then
//! runs the driver below. The driver holds the per-consignment orchestration - prepare, validate,
//! reject list, media, apply, ACK/NACK - and reaches the network only through
//! [`ReceiveTransport`], so the same sequence can run over the native blocking client and, next,
//! over the browser's async transport.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use super::*;

/// A decoded consignment plus the identifiers every receive phase needs.
///
/// The proxy response metadata (transfer ID, proxy URLs, invoice data) stays in
/// [`ProxyReceiveData`]/[`ReceivedConsignmentMeta`] in this commit: it is assembled by the native
/// driver next to the HTTP calls it comes from.
pub(super) struct PreparedConsignment {
    pub(super) consignment: RgbTransfer,
    pub(super) contract_id: ContractId,
    pub(super) asset_id: String,
    pub(super) asset_schema: AssetSchema,
}

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
pub(super) fn prepare_consignment(consignment: RgbTransfer) -> Result<PreparedConsignment, Error> {
    PreparedConsignment::new(consignment)
}

/// Outcome of the rgb-ops validation step.
pub(super) enum ConsignmentValidation {
    Valid(Box<ValidTransfer>),
    /// the consignment is invalid: the caller logs the details and refuses it
    Invalid(String),
}

/// Validate a consignment with the same rgb-ops call and error mapping the native receive uses.
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
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_received_consignment<W: WalletOnline + ?Sized>(
    wallet: &W,
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
                .import_contract(valid_contract.clone(), &wallet.blockchain_resolver())
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
    atomic_write_with(&valid_consignment_path, |tmp| {
        Ok(valid_consignment.save_file(tmp)?)
    })?;

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
}

/// [`ReceiveTransport`] over the existing blocking client.
///
/// Every operation is the native call it always was, performed inline: the future never suspends
/// and completes on its first poll.
pub(super) struct NativeReceiveTransport<'a, W: WalletOnline + ?Sized> {
    wallet: &'a W,
}

impl<'a, W: WalletOnline + ?Sized> NativeReceiveTransport<'a, W> {
    pub(super) fn new(wallet: &'a W) -> Self {
        Self { wallet }
    }
}

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
pub(super) trait ReceiveDriver: WalletOnline {
    /// Validate a consignment and apply it, ACKing it or refusing it.
    ///
    /// The caller has already fetched and decrypted the consignment to `consignment_path`, saved
    /// its metadata and marked the proxy endpoint used: those steps keep their retry/caching
    /// policy in the native caller. Everything from loading the file to posting the ACK or NACK
    /// is shared here.
    #[allow(clippy::too_many_arguments)]
    async fn drive_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
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

impl<W: WalletOnline + ?Sized> ReceiveDriver for W {
    async fn drive_receive<T: ReceiveTransport + ?Sized>(
        &self,
        transport: &T,
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
        let consignment = match RgbTransfer::load_file(consignment_path) {
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
        let safe_height = NonZeroU32::new(self.safe_height(batch_transfer.min_confirmations)?);
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            build_opouts_dag: Self::schema_supports_reject_list(asset_schema),
            safe_height,
        };
        let resolver = OffchainResolver {
            witness_id,
            consignment: &prepared.consignment,
            fallback: self.blockchain_resolver(),
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
            if grace < super::online::min_sender_retention_grace() {
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
                        self.broadcast_tx(donation_tx.expect("checked to be some"))?;
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
                    updated_batch_transfer.broadcast_deadline = ActiveValue::Set(
                        super::online::broadcast_deadline(res.expires_at.as_deref(), grace),
                    );
                }

                match (res.signed_tx, res.signed_tx_hash, res.sender_pk) {
                    (Some(signed_tx), Some(signed_tx_hash), Some(sender_pubkey)) => {
                        // the TX has been released: decrypt and broadcast it
                        self.broadcast_received_tx(
                            &recipient_id,
                            &signed_tx,
                            &signed_tx_hash,
                            &sender_pubkey,
                            recipient_seed,
                        )?;
                        updated_batch_transfer.status =
                            ActiveValue::Set(TransferStatus::WaitingConfirmations);
                    }
                    _ if donation_tx.is_some() => {
                        // donation: the signed TX travels inside the consignment, broadcast it
                        self.broadcast_tx(donation_tx.expect("checked to be some"))?;
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
                    self.broadcast_tx(tx)?;
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

#[cfg(test)]
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
        let outcome = drive_native(wallet.drive_receive(
            &transport,
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
}
