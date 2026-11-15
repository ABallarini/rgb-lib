//! Online functionality.
//!
//! This module defines the online wallet methods.

#[cfg(feature = "_online")]
use super::receive::{
    collect_unsafe_history_txids, donation_signed_tx, receive_mode_from_transfer,
};
use super::*;

/// Signed TX of an outgoing transfer, saved to broadcast it once the transfer is accepted
const SIGNED_TX_FILE: &str = "signed.tx";
/// Signed PSBT of an outgoing transfer, saved instead of its TX by previous versions
const SIGNED_PSBT_FILE: &str = "signed.psbt";

pub(crate) const UTXO_SIZE: u32 = 1000;
pub(crate) const UTXO_NUM: u8 = 5;

pub(crate) const MIN_BLOCK_ESTIMATION: u16 = 1;
pub(crate) const MAX_BLOCK_ESTIMATION: u16 = 1008;

/// Whether the proxy at `endpoint` speaks the protocol the wallet supports, for
/// [`WalletPrepare::check_recipients_transport_endpoints`].
fn check_proxy_usable(endpoint: &str) -> bool {
    check_proxy(endpoint).is_ok()
}

/// Return the indexer protocol for the provided URL.
/// An error is raised if the provided indexer URL is invalid or if the service is for the wrong
/// network or doesn't have the required functionality.
///
/// A Bitcoin Core node is only detected when `bitcoind_auth` is provided, otherwise the URL is
/// probed for an electrum server first and assumed to be an esplora one if that fails. See
/// [`IndexerConfig`] for the meaning of the returned protocol.
pub fn check_indexer_url(
    indexer_url: &str,
    bitcoind_auth: Option<&BitcoindAuth>,
    bitcoin_network: BitcoinNetwork,
) -> Result<IndexerProtocol, Error> {
    let indexer_config =
        detect_indexer(indexer_url, bitcoind_auth).ok_or_else(|| Error::InvalidIndexer {
            details: if bitcoind_auth.is_some() {
                s!("bitcoind support is not enabled (requires the `bitcoind` feature)")
            } else {
                s!("not a valid electrum nor esplora server")
            },
        })?;
    get_indexer_and_resolver(&indexer_config, bitcoin_network).map_err(|e| {
        // the esplora config is a blind fallback guess (see detect_indexer), so an unreachable
        // esplora server means neither probed protocol answered
        match (&indexer_config, &e) {
            (IndexerConfig::Esplora { .. }, Error::InvalidIndexer { details })
                if details == "not a valid esplora server" =>
            {
                Error::InvalidIndexer {
                    details: s!("not a valid electrum nor esplora server"),
                }
            }
            _ => e,
        }
    })?;

    Ok(indexer_config.protocol())
}

/// Parse and validate the [`OnlineOptions::proxy_auth_keys`], keying them by proxy URL.
fn parse_proxy_auth_keys(
    proxy_auth_keys: &HashMap<String, String>,
) -> Result<HashMap<String, ed25519_dalek::SigningKey>, Error> {
    let mut keys = HashMap::new();
    for (endpoint, seed) in proxy_auth_keys {
        let proxy_url = TransportEndpoint::new(endpoint.clone())?.endpoint;
        let seed: [u8; 32] = hex::decode(seed)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::InvalidProxyAuthKey {
                details: format!(
                    "expected a hex-encoded 32-byte Ed25519 seed for endpoint {endpoint}"
                ),
            })?;
        let signing_key = ed25519_from_seed(&seed);
        if keys.insert(proxy_url.clone(), signing_key).is_some() {
            return Err(Error::DuplicateProxyAuthKey {
                details: format!(
                    "endpoint {endpoint} resolves to a proxy URL ({proxy_url}) already covered by another entry"
                ),
            });
        }
    }
    Ok(keys)
}

/// Request the ACKs of the operation of `transfer_ids` from the sender proxy (`ack.get`), signing
/// the request with the operation (sender) key.
fn get_ack_signed(
    proxy_client: &ProxyClient,
    transfer_ids: &[String],
    sender_sk: &ed25519_dalek::SigningKey,
) -> Result<JsonRpcResponse<GetAckResponse>, Error> {
    let timestamp = now().unix_timestamp().to_string();
    let digest = sha256_digest(get_ack_message(transfer_ids, &timestamp).as_bytes());
    let signature = hex::encode(sign_ed25519(sender_sk, &digest));
    proxy_client.get_ack(transfer_ids, &signature, &timestamp)
}

/// List the transfers to an invoice on a recipient proxy (`transfer.list`), signing the request
/// with the recipient key.
fn list_invoice_transfers(
    proxy_url: &str,
    invoice_id: &str,
    recipient_seed: &[u8],
) -> Result<JsonRpcResponse<HashMap<String, ProxyTransferState>>, Error> {
    let seed: [u8; 32] = recipient_seed.try_into().map_err(|_| Error::Internal {
        details: s!("invalid recipient secret key"),
    })?;
    let sk = ed25519_from_seed(&seed);
    let timestamp = now().unix_timestamp().to_string();
    let digest = sha256_digest(list_transfers_message(invoice_id, &timestamp).as_bytes());
    let signature = hex::encode(sign_ed25519(&sk, &digest));
    ProxyClient::new(proxy_url)?.list_transfers(invoice_id, &signature, &timestamp)
}

/// Whether the sender proxy knows the operation of `transfer_ids`, registered with the operation
/// (sender) key, i.e. whether an earlier `ack.prepare` for it succeeded.
fn sender_proxy_knows_operation(
    proxy_client: &ProxyClient,
    transfer_ids: &[String],
    sender_sk: &ed25519_dalek::SigningKey,
) -> Result<bool, Error> {
    match get_ack_signed(proxy_client, transfer_ids, sender_sk)?.error {
        None => Ok(true),
        Some(err) => match map_proxy_error(err) {
            Error::OperationNotFound => Ok(false),
            e => Err(e),
        },
    }
}

/// Interpret the sender proxy's response to `ack.clean`, requested before deliberately failing
/// an outgoing operation.
///
/// Any proxy response other than the ones mapped to a [`CleanAckOutcome`] cannot be unambiguously
/// interpreted safely and is surfaced as an error.
fn clean_ack_outcome(error: Option<JsonRpcError>) -> Result<CleanAckOutcome, Error> {
    match error {
        None => Ok(CleanAckOutcome::Revoked),
        Some(err) => match map_proxy_error(err) {
            Error::ProxyTxAlreadyReleased => Ok(CleanAckOutcome::Released),
            Error::OperationNotFound => Ok(CleanAckOutcome::Unknown),
            e => Err(e),
        },
    }
}

fn clock_skew_margin() -> u32 {
    #[cfg(test)]
    if let Some(margin) = mock_clock_skew_margin() {
        return margin;
    }
    PROXY_CLOCK_SKEW_MARGIN_SECS
}

/// Whether the expiration of an outgoing operation has passed on the local clock by more than the
/// clock skew margin, so it has passed on the sender proxy's clock as well and the proxy can no
/// longer release the signed TX, whatever it knows about the operation.
fn expired_beyond_skew_margin(batch_transfer: &DbBatchTransfer) -> bool {
    batch_transfer.is_expired_with_margin(now().unix_timestamp(), clock_skew_margin())
}

/// Whether the broadcast deadline of an outgoing operation (its expiration plus the sender proxy
/// retention grace, or just its expiration if unknown) has passed on the local clock by more than
/// the clock skew margin, so the sender proxy can no longer hand out the signed TX, not even to
/// recipients that already obtained it, and recipients stopped broadcasting it
/// (`v1.0-changes-spec.md` 6.2).
fn broadcast_deadline_passed_beyond_skew_margin(batch_transfer: &DbBatchTransfer) -> bool {
    batch_transfer
        .broadcast_deadline
        .or(batch_transfer.expiration)
        .is_some_and(|deadline| {
            deadline.saturating_add(i64::from(clock_skew_margin())) < now().unix_timestamp()
        })
}

/// Whether the broadcast deadline of an incoming transfer plus the confirmation margin has passed,
/// after which a transfer whose TX is not confirmed is failed (`v1.0-changes-spec.md` 6.4). A
/// transfer with no known broadcast deadline is never considered past it.
fn confirmation_deadline_passed(batch_transfer: &DbBatchTransfer) -> bool {
    #[cfg(test)]
    let margin = mock_confirmation_margin().unwrap_or(CONFIRMATION_MARGIN_SECS);
    #[cfg(not(test))]
    let margin = CONFIRMATION_MARGIN_SECS;
    batch_transfer
        .broadcast_deadline
        .is_some_and(|deadline| deadline.saturating_add(i64::from(margin)) < now().unix_timestamp())
}

/// Whether an incoming transfer is expired, so it can be failed: a transfer waiting for the
/// broadcast of a TX the sender proxy may still release to it (it has a broadcast deadline) only
/// once past the broadcast deadline plus the confirmation margin, a blind receive reserved on
/// proxies (it has a retention deadline) still waiting for the counterparty only once the invoice
/// expiration has passed on the proxies' clocks too, as they accept transfers until then, any
/// other once past the invoice expiration.
fn incoming_expired(batch_transfer: &DbBatchTransfer, now: i64) -> bool {
    if batch_transfer.status == TransferStatus::WaitingBroadcast
        && batch_transfer.broadcast_deadline.is_some()
    {
        return confirmation_deadline_passed(batch_transfer);
    }
    if batch_transfer.status == TransferStatus::WaitingCounterparty
        && batch_transfer.retention_deadline.is_some()
    {
        return batch_transfer.is_expired_with_margin(now, clock_skew_margin());
    }
    batch_transfer.is_expired(now)
}

/// The retention grace advertised by a sender proxy (`retention_grace_secs`), i.e. how long
/// after an operation expiration it keeps a released signed TX available to the recipients. A
/// proxy not advertising it is considered to grant none.
pub(super) fn sender_proxy_retention_grace(proxy_url: &str) -> Result<u32, Error> {
    #[cfg(test)]
    if let Some(grace) = mock_retention_grace() {
        return Ok(grace);
    }
    let res = ProxyClient::new(proxy_url)?.get_info()?;
    if let Some(err) = res.error {
        return Err(map_proxy_error(err));
    }
    let info = res.result.ok_or_else(|| Error::Proxy {
        details: s!("missing server.info result"),
    })?;
    Ok(proxy_retention_grace(&info))
}

/// The minimum sender proxy retention grace a recipient requires to ACK a transfer.
pub(super) fn min_sender_retention_grace() -> u32 {
    #[cfg(test)]
    if let Some(grace) = mock_min_retention_grace() {
        return grace;
    }
    MIN_SENDER_RETENTION_GRACE_SECS
}

/// The broadcast deadline of an operation from the `expires_at` returned by `ack.post` and the
/// sender proxy retention grace, `None` if the proxy didn't return a usable expiration.
///
/// The sender picks its proxy, so the returned expiration is not to be trusted: one in the past,
/// or beyond the expiration of the invoice being paid (an operation has to expire before it, so
/// its TX can only be released while the recipient is still waiting for it, see
/// `v1.0-changes-spec.md` 6.1), is refused rather than turned into a deadline that has already
/// passed or is arbitrarily far in the future (which would also overflow the margins added to it
/// by the deadline checks). Such a transfer gets no broadcast deadline, like one ACKed via a proxy
/// not returning the expiration at all, so it expires with the invoice.
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

/// Minimum time between the expiration of an outgoing operation and the earliest invoice
/// expiration among its recipients (see [`INVOICE_EXPIRATION_MARGIN_SECS`]), following the clock
/// skew margin it accounts for.
fn invoice_expiration_margin() -> u32 {
    #[cfg(test)]
    if let Some(skew_margin) = mock_clock_skew_margin() {
        return 2 * skew_margin;
    }
    INVOICE_EXPIRATION_MARGIN_SECS
}

/// The RPC URLs of the given EVM chains, by chain ID.
fn evm_rpc_urls(evm_chains: &HashMap<u64, EvmChain>) -> HashMap<u64, String> {
    evm_chains
        .iter()
        .map(|(chain_id, evm_chain)| (*chain_id, evm_chain.rpc_url.clone()))
        .collect()
}

/// Check the expiration of an outgoing operation: it must be at least the clock skew margin in
/// the future, since one expiring sooner could already be expired on the sender proxy's clock,
/// and at most [`MAX_EXPIRATION_SECS`] in the future. For a proxy recipient the invoice
/// expiration bounds it further, but a donation has none.
fn check_operation_expiration(expiration_timestamp: i64) -> Result<(), Error> {
    let now_ts = now().unix_timestamp();
    if expiration_timestamp < now_ts + i64::from(clock_skew_margin())
        || expiration_timestamp > now_ts + i64::from(MAX_EXPIRATION_SECS)
    {
        return Err(Error::InvalidExpiration);
    }
    Ok(())
}

/// Interpret an error returned by the sender proxy to `ack.get`, requested while waiting for the
/// recipients' ACKs.
///
/// The only error with a safe interpretation is the proxy no longer knowing the operation (e.g.
/// it dropped its data): the ACKs cannot be retrieved anymore, so the caller falls back to
/// checking whether the TX was broadcast. That case returns `Ok(())`. Any other proxy response
/// cannot be unambiguously interpreted safely and is surfaced as an error.
fn check_get_ack_error(err: JsonRpcError) -> Result<(), Error> {
    match map_proxy_error(err) {
        Error::OperationNotFound => Ok(()),
        e => Err(e),
    }
}

/// The wallet's reject list resolver: the one of the standalone validation, logging what the
/// user may need to act on.
#[doc(hidden)]
pub struct WalletRejectListResolver<'a> {
    inner: RemoteRejectListResolver<'a>,
    logger: &'a Logger,
}

impl ResolveRejectList for WalletRejectListResolver<'_> {
    fn get_reject_list(&self, source: &RejectListSource) -> Result<RejectList, Error> {
        let (reject_list, invalid) =
            self.inner
                .get_reject_list_counting(source)
                .inspect_err(|e| {
                    if let Error::NoEvmRpcUrl { chain_id } = e {
                        error!(
                            self.logger,
                            "No EVM RPC URL configured for chain ID {chain_id}"
                        );
                    }
                })?;
        // invalid lines are counted and reported once, as a list can contain many
        if invalid > 0 {
            warn!(
                self.logger,
                "Ignoring {invalid} invalid opout(s) in reject list"
            );
        }
        Ok(reject_list)
    }
}

/// The online methods of the wallet: the ones talking to the indexer, the proxies and the hub.
///
/// The preparation of an outgoing operation is shared with the browser wallet (see
/// [`WalletPrepare`]), which this trait extends.
pub trait WalletOnline: WalletPrepare + receive::ReceiveWallet {
    fn blockchain_resolver(&self) -> ChainResolver<'_> {
        ChainResolver {
            inner: &self.online_data().as_ref().unwrap().resolver,
        }
    }

    fn sync_impl(&mut self, txn: &DbTxn, options: SyncOptions) -> Result<(), Error> {
        self.sync_bdk_and_db_txos(txn, options, false)
    }

    fn broadcast_tx(&self, tx: BdkTransaction) -> Result<BdkTransaction, Error> {
        let txid = tx.compute_txid().to_string();
        let indexer = self.indexer();
        match indexer.broadcast(&tx) {
            Ok(_) => {
                debug!(self.logger(), "Broadcasted TX with ID '{}'", txid);
                Ok(tx)
            }
            Err(e) => {
                match e {
                    #[cfg(feature = "bitcoind")]
                    IndexerError::Bitcoind(ref e) => {
                        let err_str = e.to_string();
                        if err_str.contains("min relay fee not met")
                            || err_str.contains("mempool min fee not met")
                        {
                            return Err(Error::MinFeeNotMet { txid: txid.clone() });
                        } else if err_str.contains("Fee exceeds maximum configured")
                            || err_str.contains("max-fee-exceeded")
                        {
                            return Err(Error::MaxFeeExceeded { txid: txid.clone() });
                        }
                    }
                    #[cfg(feature = "electrum")]
                    IndexerError::Electrum(ref e) => {
                        let err_str = e.to_string();
                        if err_str.contains("min relay fee not met")
                            || err_str.contains("mempool min fee not met")
                        {
                            return Err(Error::MinFeeNotMet { txid: txid.clone() });
                        } else if err_str.contains("Fee exceeds maximum configured") {
                            return Err(Error::MaxFeeExceeded { txid: txid.clone() });
                        }
                    }
                    #[cfg(feature = "esplora")]
                    IndexerError::Esplora(ref e) => {
                        if let EsploraError::HttpResponse { message, .. } = e {
                            if message.contains("min relay fee not met") {
                                return Err(Error::MinFeeNotMet { txid: txid.clone() });
                            } else if message.contains("Fee exceeds maximum configured") {
                                return Err(Error::MaxFeeExceeded { txid: txid.clone() });
                            }
                        }
                    }
                    IndexerError::Internal { .. } => {}
                }
                if indexer.get_tx_confirmations(&txid)?.is_none() {
                    return Err(Error::FailedBroadcast {
                        details: e.to_string(),
                    });
                }
                Ok(tx)
            }
        }
    }

    fn broadcast_psbt(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<BdkTransaction, Error> {
        let tx = signed_psbt
            .clone()
            .extract_tx()
            .map_err(InternalError::from)?;
        self.broadcast_signed_tx(txn, tx)
    }

    fn broadcast_signed_tx(
        &mut self,
        txn: &DbTxn,
        tx: BdkTransaction,
    ) -> Result<BdkTransaction, Error> {
        let tx = self.broadcast_tx(tx)?;

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

        Ok(tx)
    }

    fn reserve_vanilla_txos(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        r#type: WalletTransactionType,
    ) -> Result<(), Error> {
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let wt_idx = txn.set_wallet_transaction(DbWalletTransactionActMod {
            txid: ActiveValue::Set(txid),
            r#type: ActiveValue::Set(r#type),
            ..Default::default()
        })?;
        let reservations: Vec<DbReservedTxoActMod> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| DbReservedTxoActMod {
                txid: ActiveValue::Set(i.previous_output.txid.to_string()),
                vout: ActiveValue::Set(i.previous_output.vout),
                reserved_for_vanilla: ActiveValue::Set(Some(wt_idx)),
                ..Default::default()
            })
            .collect();
        txn.set_reserved_txos(reservations)?;
        Ok(())
    }

    /// Check that the PSBT being ended is of the given vanilla operation: an RGB operation (which
    /// has a transfer directory) or another vanilla one (as recorded by a non-dry-run begin) would
    /// be completed skipping its checks and steps.
    fn check_vanilla_end(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        r#type: WalletTransactionType,
    ) -> Result<(), Error> {
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        if self.files().exists(&self.transfer_key(&txid)?)? {
            return Err(Error::WrongOperation { txid });
        }
        if let Some((wallet_transaction, _)) =
            txn.get_wallet_transaction_with_reserved_txos_by_txid(&txid)?
            && wallet_transaction.r#type != r#type
        {
            return Err(Error::WrongOperation { txid });
        }
        Ok(())
    }

    fn finalize_vanilla_wallet_transaction(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        r#type: WalletTransactionType,
    ) -> Result<(), Error> {
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        match txn.get_wallet_transaction_with_reserved_txos_by_txid(&txid)? {
            Some((_wt, reservations)) => {
                txn.del_reserved_txos(&reservations)?;
            }
            None => {
                txn.set_wallet_transaction(DbWalletTransactionActMod {
                    txid: ActiveValue::Set(txid),
                    r#type: ActiveValue::Set(r#type),
                    ..Default::default()
                })?;
            }
        }
        Ok(())
    }

    fn broadcast_and_update_rgb(
        &mut self,
        txn: &DbTxn,
        stock: &mut RgbStock<'_>,
        signed_tx: BdkTransaction,
        fascia: Fascia,
    ) -> Result<BdkTransaction, Error> {
        let tx = self.broadcast_signed_tx(txn, signed_tx)?;
        stock.consume_fascia(fascia, None)?;
        Ok(tx)
    }

    fn create_split_tx(
        &mut self,
        inputs: &[BdkOutPoint],
        addresses: &Vec<ScriptBuf>,
        size: u32,
        fee_rate: FeeRate,
    ) -> Result<Psbt, bdk_wallet::error::CreateTxError> {
        let mut tx_builder = self.bdk_wallet_mut().build_tx();
        tx_builder
            .add_utxos(inputs)
            .map_err(|_| bdk_wallet::error::CreateTxError::UnknownUtxo)?
            .manually_selected_only()
            .fee_rate(fee_rate);
        for address in addresses {
            tx_builder.add_recipient(address.clone(), BdkAmount::from_sat(size as u64));
        }
        let mut psbt = tx_builder.finish()?;
        self.add_non_witness_utxos(&mut psbt);
        Ok(psbt)
    }

    fn create_utxos_begin_impl(
        &mut self,
        txn: &DbTxn,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_wallet(
                txn,
                SyncOptions {
                    keychain: SyncKeychain::Vanilla {
                        lookback: self.vanilla_sync_lookback(),
                    },
                    strategy: SyncStrategy::FastSync,
                },
                false,
            )?;
        }

        let unspent_txos = txn.get_unspent_txos(vec![])?;
        let unspents = txn.get_rgb_allocations(unspent_txos, None, None, None, None)?;

        let mut utxos_to_create = num.unwrap_or(UTXO_NUM);
        if up_to {
            let reserved = self.get_reserved_colored_outpoints(txn)?;
            let allocatable = self
                .get_available_allocations(unspents, &reserved, None)?
                .len();
            // compare in usize since the count of allocatable UTXOs can exceed u8::MAX
            if allocatable >= utxos_to_create as usize {
                return Err(Error::AllocationsAlreadyAvailable);
            }
            // allocatable < utxos_to_create <= u8::MAX, so the conversion cannot fail
            utxos_to_create -=
                u8::try_from(allocatable).expect("allocatable count cannot exceed u8::MAX");
        }
        debug!(
            self.logger(),
            "Will try to create {} UTXOs", utxos_to_create
        );

        let reserved: HashSet<BdkOutPoint> = self
            .get_reserved_vanilla_outpoints(txn)?
            .into_iter()
            .collect();
        let (inputs, usable_btc_amount) = self.internal_unspents().fold(
            (Vec::new(), 0u64),
            |(mut inputs, usable_btc_amount), u| {
                let outpoint = u.outpoint;
                let value = u.txout.value.to_sat();
                if reserved.contains(&outpoint) {
                    (inputs, usable_btc_amount)
                } else {
                    inputs.push(outpoint);
                    let usable_btc_amount = usable_btc_amount
                        .checked_add(value)
                        .expect("total UTXO value cannot exceed u64::MAX");
                    (inputs, usable_btc_amount)
                }
            },
        );
        let utxo_size = size.unwrap_or(UTXO_SIZE);
        if utxo_size == 0 {
            return Err(Error::InvalidAmountZero);
        }
        let possible_utxos = usable_btc_amount / utxo_size as u64;
        let max_possible_utxos: u8 = if possible_utxos > u8::MAX as u64 {
            u8::MAX
        } else {
            possible_utxos as u8
        };
        let mut btc_needed: u64 = (utxo_size as u64 * utxos_to_create as u64) + 1000;
        let mut btc_available: u64 = 0;
        let num_try_creating = min(utxos_to_create, max_possible_utxos);
        let mut addresses = vec![];
        for _i in 0..num_try_creating {
            addresses.push(self.get_new_address()?.script_pubkey());
        }
        while !addresses.is_empty() {
            match self.create_split_tx(&inputs, &addresses, utxo_size, fee_rate_checked) {
                Ok(psbt) => {
                    if !dry_run {
                        self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::CreateUtxos)?;
                    }
                    return Ok(psbt);
                }
                Err(e) => {
                    (btc_needed, btc_available) = match e {
                        bdk_wallet::error::CreateTxError::CoinSelection(InsufficientFunds {
                            needed,
                            available,
                        }) => (needed.to_sat(), available.to_sat()),
                        bdk_wallet::error::CreateTxError::OutputBelowDustLimit(_) => {
                            return Err(Error::OutputBelowDustLimit);
                        }
                        _ => {
                            return Err(Error::Internal {
                                details: e.to_string(),
                            });
                        }
                    };
                    addresses.pop()
                }
            };
        }
        Err(Error::InsufficientBitcoins {
            needed: btc_needed,
            available: btc_available,
        })
    }

    fn create_utxos_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<u8, Error> {
        self.check_vanilla_end(txn, signed_psbt, WalletTransactionType::CreateUtxos)?;
        self.finalize_vanilla_wallet_transaction(
            txn,
            signed_psbt,
            WalletTransactionType::CreateUtxos,
        )?;

        let tx = self.broadcast_psbt(txn, signed_psbt)?;

        let mut num_utxos_created = 0;
        let bdk_utxos: Vec<LocalOutput> = self.bdk_wallet().list_unspent().collect();
        let txid = tx.compute_txid();
        for utxo in bdk_utxos.into_iter() {
            if utxo.outpoint.txid == txid && utxo.keychain == KeychainKind::External {
                num_utxos_created += 1
            }
        }

        Ok(num_utxos_created)
    }

    fn drain_to_begin_impl(
        &mut self,
        txn: &DbTxn,
        address: String,
        fee_rate: u64,
        dry_run: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        self.sync_wallet(
            txn,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FastSync,
            },
            false,
        )?;
        self.sync_wallet(
            txn,
            SyncOptions {
                keychain: SyncKeychain::Vanilla {
                    lookback: self.vanilla_sync_lookback(),
                },
                strategy: SyncStrategy::FastSync,
            },
            false,
        )?;

        let script_pubkey = self.get_script_pubkey(&address)?;

        let mut tx_builder = self.bdk_wallet_mut().build_tx();
        tx_builder
            .drain_wallet()
            .drain_to(script_pubkey)
            .fee_rate(fee_rate_checked);

        let mut psbt = tx_builder.finish().map_err(|e| match e {
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

        if !dry_run {
            self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::Drain)?;
        }

        Ok(psbt)
    }

    fn drain_to_end_impl(
        &mut self,
        txn: &DbTxn,
        signed_psbt: &Psbt,
    ) -> Result<BdkTransaction, Error> {
        self.check_vanilla_end(txn, signed_psbt, WalletTransactionType::Drain)?;
        self.finalize_vanilla_wallet_transaction(txn, signed_psbt, WalletTransactionType::Drain)?;
        let tx = self.broadcast_psbt(txn, signed_psbt)?;
        Ok(tx)
    }

    /// Revoke the stored signed TXs for an outgoing operation on the sender proxy (`ack.clean`).
    /// An operation with nothing registered on a sender proxy (legacy, or whose recipients are
    /// all out-of-band) has nothing to revoke and is reported as [`CleanAckOutcome::Revoked`].
    fn clean_sender_ack(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<CleanAckOutcome, Error> {
        let Some(seed) = &batch_transfer.operation_secret_key else {
            // legacy: nothing to clean
            return Ok(CleanAckOutcome::Revoked);
        };
        let bt_data = batch_transfer.get_transfers(&db_data.asset_transfers, &db_data.transfers)?;
        // only the transfers registered on the sender proxy (out-of-band ones are not)
        let mut transfer_ids: Vec<String> = vec![];
        let mut sender_proxy = None;
        for atd in &bt_data.asset_transfers_data {
            for t in &atd.transfers {
                let transfer_sender_proxy = txn
                    .get_transfer_transport_endpoints_data(t.idx)?
                    .into_iter()
                    .find(|(tte, _)| tte.kind == TransportEndpointKind::SenderProxy)
                    .map(|(_, ce)| ce.endpoint);
                let Some(transfer_sender_proxy) = transfer_sender_proxy else {
                    continue;
                };
                if let Some(tid) = &t.proxy_transfer_id {
                    transfer_ids.push(tid.clone());
                }
                if sender_proxy.is_none() {
                    sender_proxy = Some(transfer_sender_proxy);
                }
            }
        }
        let Some(sender_proxy) = sender_proxy else {
            // no sender proxy (all recipients out-of-band): nothing to clean
            return Ok(CleanAckOutcome::Revoked);
        };
        transfer_ids.sort();
        let seed: [u8; 32] = seed.clone().try_into().map_err(|_| Error::Internal {
            details: s!("invalid operation secret key"),
        })?;
        let sk = ed25519_from_seed(&seed);
        let digest = sha256_digest(transfer_ids.concat().as_bytes());
        let sig = hex::encode(sign_ed25519(&sk, &digest));
        let proxy_client = ProxyClient::new(&sender_proxy)?;
        let res = proxy_client.clean_ack(&transfer_ids, &sig)?;
        clean_ack_outcome(res.error)
    }

    fn try_fail_batch_transfer(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
        revoke_released: bool,
    ) -> Result<TryFailBatchTransferOutcome, Error> {
        // an outgoing transfer is expired once its expiration has passed on the sender proxy's
        // clock too, as the proxy may release its TX until then
        let expired = if batch_transfer.incoming {
            incoming_expired(batch_transfer, now().unix_timestamp())
        } else {
            expired_beyond_skew_margin(batch_transfer)
        };
        let updated_batch_transfer = match self.refresh_transfer(
            txn,
            batch_transfer,
            db_data,
            &[],
            true,
        ) {
            Err(Error::MinFeeNotMet { txid: _ }) | Err(Error::MaxFeeExceeded { txid: _ }) => {
                Ok(None)
            }
            // the sender proxy lost the operation or serves an invalid ACK signature: the
            // refresh fails the transfer itself once its broadcast deadline has passed, until
            // then the signed TX may still be broadcast by a recipient, so the fail is denied
            Err(Error::OperationNotFound) | Err(Error::InvalidContentSignature)
                if !batch_transfer.incoming =>
            {
                info!(
                    self.logger(),
                    "Sender proxy cannot be relied upon, fail denied until the broadcast deadline"
                );
                return Ok(TryFailBatchTransferOutcome::Denied);
            }
            // a transfer that keeps failing to refresh (e.g. its ACK can't be posted or
            // retrieved) would otherwise never be failed; once expired its TX should no longer
            // be broadcast by the sender, so it's safe to fail it, while before that the
            // error could be transient and the transfer could still complete
            Err(e) if expired => {
                warn!(
                    self.logger(),
                    "Failing expired transfer that failed to refresh: {e}"
                );
                Ok(None)
            }
            Err(e) => Err(e),
            Ok(v) => Ok(v),
        }?;
        // if the status changed after the refresh, the transfer progressed
        if let Some(updated) = updated_batch_transfer {
            // the refresh may have failed the batch itself (e.g. it discovered a recipient NACK);
            // that is exactly the outcome a deliberate fail wanted, so report it as failed
            if updated.status == TransferStatus::Failed {
                return Ok(TryFailBatchTransferOutcome::Failed);
            }
            return Ok(TryFailBatchTransferOutcome::Refreshed);
        }
        // the refresh above may have been the first to check a received mint (see `is_mint`): the
        // fail is denied, as a mint expires only by its lock, which may have been made already, in
        // which case the mint completes whatever the recipient does, on an output the failed
        // receive would no longer track
        if batch_transfer.incoming && self.is_mint(batch_transfer, db_data)? {
            return Ok(TryFailBatchTransferOutcome::Denied);
        }
        // the status didn't change: before failing an outgoing transfer make sure its TX is not
        // on-chain already (a recipient holding the TX may have broadcast it), in which case the
        // transfer progresses instead
        if !batch_transfer.incoming
            && batch_transfer.status == TransferStatus::WaitingCounterparty
            && self
                .complete_batch_if_tx_on_chain(txn, batch_transfer)?
                .is_some()
        {
            return Ok(TryFailBatchTransferOutcome::Refreshed);
        }
        // an outgoing transfer every recipient ACKed has had its TX released: if it's still waiting
        // for the counterparty (e.g. its TX is not broadcast as an invoice has expired) it can only
        // be failed after spending one of the TX inputs (v1.0-changes-spec.md 6.1), which is not
        // supported, or once one of them has been spent by another confirmed transaction, which the
        // refresh above detects
        if !batch_transfer.incoming && batch_transfer.status == TransferStatus::WaitingCounterparty
        {
            // read from the DB, as the refresh above may have just stored the ACKs
            let transfers = txn.get_batch_transfer_transfers(batch_transfer.idx)?;
            if !transfers.is_empty() && transfers.iter().all(|t| t.ack == Some(true)) {
                info!(
                    self.logger(),
                    "Every recipient ACKed the transfer, fail denied"
                );
                return Ok(TryFailBatchTransferOutcome::Denied);
            }
        }
        // for a deliberate fail of an outgoing non-donation operation, revoke the released signed
        // TXs on the sender proxy first
        if revoke_released && !batch_transfer.incoming {
            match self.clean_sender_ack(txn, batch_transfer, db_data)? {
                CleanAckOutcome::Revoked => {}
                // the TX was already released to a recipient, who may still broadcast it: deny
                CleanAckOutcome::Released => return Ok(TryFailBatchTransferOutcome::Denied),
                // the proxy no longer knows the operation (e.g. it dropped its data), so whether
                // the TX was released cannot be known. Only an operation that completed send_end
                // had a signed TX registered: as recommended by v1.0-changes-spec.md 6.2, it is
                // failed only once its broadcast deadline (expiration plus the proxy retention
                // grace) has passed on the proxy's clock too, since until then the proxy may
                // recover the operation (e.g. from a backup) and hand out the TX, while recipients
                // that obtained the TX have time to broadcast it, which the chain check above
                // detects. The residual risk of a TX broadcast after that is accepted
                CleanAckOutcome::Unknown
                    if batch_transfer.status == TransferStatus::WaitingCounterparty =>
                {
                    if !broadcast_deadline_passed_beyond_skew_margin(batch_transfer) {
                        info!(
                            self.logger(),
                            "Operation unknown to the sender proxy, fail denied until its broadcast deadline"
                        );
                        return Ok(TryFailBatchTransferOutcome::Denied);
                    }
                    warn!(
                        self.logger(),
                        "Failing an operation unknown to the sender proxy past its broadcast deadline: its TX can still be broadcast if it was released before the proxy lost the operation"
                    );
                }
                // an operation that didn't complete send_end (still Initiated) never had a signed
                // TX registered, so the proxy is expected not to know it and nothing can have
                // been released
                CleanAckOutcome::Unknown => {}
            }
        }
        // a blind receive keeps its blinded UTXO reserved while a transfer to the invoice can
        // still be downloaded
        if batch_transfer.incoming
            && batch_transfer.status == TransferStatus::WaitingCounterparty
            && !self.blind_receive_may_be_failed(txn, batch_transfer, db_data)?
        {
            info!(
                self.logger(),
                "A transfer to the blind invoice may still be downloaded, fail denied"
            );
            return Ok(TryFailBatchTransferOutcome::Denied);
        }
        self.fail_batch_transfer(txn, batch_transfer)?;
        Ok(TryFailBatchTransferOutcome::Failed)
    }

    /// Whether the given batch transfer is a mint that has not reached mint_end yet.
    ///
    /// A mint batch carries a single main transition, the mint of one asset (the allocations of
    /// other assets moved along are not among its transfers), so a mint is never mixed with other
    /// transitions. Were it ever, the whole batch would still follow the mint flow (posted before
    /// signing, never registered on the sender proxy, broadcast by mint_end), so any mint
    /// transition makes the batch a mint.
    fn is_pending_mint(batch_transfer: &DbBatchTransfer, db_data: &DbData) -> bool {
        if batch_transfer.incoming
            || batch_transfer.status != TransferStatus::Initiated
            || batch_transfer.txid.is_none()
        {
            return false;
        }
        db_data.asset_transfers.iter().any(|at| {
            at.batch_transfer_idx == batch_transfer.idx
                && at.transition_type == Some(TypeOfTransition::Mint)
        })
    }

    fn fail_transfers_impl(
        &mut self,
        txn: &DbTxn,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
        skip_sync: bool,
    ) -> Result<FailTransfersOutcome, Error> {
        if !skip_sync {
            self.sync_wallet(
                txn,
                SyncOptions {
                    keychain: SyncKeychain::Colored,
                    strategy: SyncStrategy::FastSync,
                },
                false,
            )?;
        }

        let db_data = txn.get_db_data(false)?;
        let mut transfers_changed = false;
        let mut cannot_fail = false;

        if let Some(batch_transfer_idx) = batch_transfer_idx {
            let batch_transfer =
                txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;

            if !batch_transfer.is_fallible() {
                return Ok(FailTransfersOutcome {
                    transfers_changed: false,
                    cannot_fail: true,
                });
            }

            // a mint doesn't expire by a timestamp but by its lock
            if self.is_mint(&batch_transfer, &db_data)? {
                let failed = !batch_transfer.incoming
                    && !no_asset_only
                    && self.fail_expired_mint(txn, &batch_transfer)?;
                return Ok(FailTransfersOutcome {
                    transfers_changed: failed,
                    cannot_fail: !failed,
                });
            }

            // a transfer waiting for the counterparty's broadcast can only be failed once it has
            // expired, since the TX may still be broadcast before then
            if batch_transfer.status == TransferStatus::WaitingBroadcast {
                let expired = incoming_expired(&batch_transfer, now().unix_timestamp());
                if !expired {
                    return Ok(FailTransfersOutcome {
                        transfers_changed: false,
                        cannot_fail: true,
                    });
                }
            }

            if no_asset_only {
                let asset_transfers = batch_transfer.get_asset_transfers(&db_data.asset_transfers);
                let connected_assets = asset_transfers.iter().any(|t| t.asset_id.is_some());
                if connected_assets {
                    return Ok(FailTransfersOutcome {
                        transfers_changed: false,
                        cannot_fail: true,
                    });
                }
            }

            transfers_changed = true;
            // a deliberate fail (explicit batch idx) revokes any released signed TXs first
            if !matches!(
                self.try_fail_batch_transfer(txn, &batch_transfer, &db_data, true)?,
                TryFailBatchTransferOutcome::Failed
            ) {
                cannot_fail = true;
            }
        } else {
            // fail all expired transfers that are in a fallible status; an outgoing one is expired
            // once its expiration has passed on the sender proxy's clock too (ack.get reports no
            // expiration), as the proxy may release its TX until then. A mint never expires by a
            // timestamp: its recipient fails it at refresh once its lock has expired, its sender
            // once its lock is found expired below
            let now = now().unix_timestamp();
            let mut expired_transfers = vec![];
            let mut sent_mints = vec![];
            for t in db_data.batch_transfers.iter().filter(|t| t.is_fallible()) {
                if self.is_mint(t, &db_data)? {
                    if !t.incoming {
                        sent_mints.push(t);
                    }
                    continue;
                }
                let expired = if t.incoming {
                    incoming_expired(t, now)
                } else {
                    expired_beyond_skew_margin(t)
                };
                if expired {
                    expired_transfers.push(t);
                }
            }
            for batch_transfer in expired_transfers {
                if no_asset_only {
                    let connected_assets = batch_transfer
                        .get_asset_transfers(&db_data.asset_transfers)
                        .iter()
                        .any(|t| t.asset_id.is_some());
                    if connected_assets {
                        continue;
                    }
                }
                // expired transfers: the proxy operation has lapsed, no need to revoke released TXs
                if !matches!(
                    self.try_fail_batch_transfer(txn, batch_transfer, &db_data, false)?,
                    TryFailBatchTransferOutcome::Denied
                ) {
                    transfers_changed = true;
                }
            }
            // a mint whose lock can't be checked now (e.g. no EVM RPC URL is configured for its
            // chain) is left for a later call, not to block the others
            if !no_asset_only {
                for batch_transfer in sent_mints {
                    match self.fail_expired_mint(txn, batch_transfer) {
                        Ok(failed) => transfers_changed |= failed,
                        Err(e) => warn!(
                            self.logger(),
                            "Cannot check the lock of mint {}: {e}", batch_transfer.idx
                        ),
                    }
                }
            }
        }

        Ok(FailTransfersOutcome {
            transfers_changed,
            cannot_fail,
        })
    }

    fn wallet_specific_consistency_checks(&mut self, _txn: &DbTxn) -> Result<(), Error>;

    fn check_consistency(&mut self, txn: &DbTxn) -> Result<(), Error> {
        info!(self.logger(), "Doing a consistency check...");

        self.wallet_specific_consistency_checks(txn)?;

        let medias = txn.iter_media()?;
        for media in medias {
            if !self.files().exists(&self.media_key(&media.digest)?)? {
                return Err(Error::Inconsistency {
                    details: s!("DB media do not match with the ones stored in media directory"),
                });
            }
        }

        info!(self.logger(), "Consistency check completed");
        Ok(())
    }

    fn get_fee_estimation_impl(&self, blocks: u16) -> Result<f64, Error> {
        if !(MIN_BLOCK_ESTIMATION..=MAX_BLOCK_ESTIMATION).contains(&blocks) {
            return Err(Error::InvalidEstimationBlocks);
        }
        self.indexer().fee_estimation(blocks)
    }

    /// The EVM chains to go online with, by chain ID, if the wallet supports bridged assets.
    ///
    /// Each endpoint is checked to be a working EVM JSON-RPC server on the chain it is
    /// configured for: one on another chain would report meaningless block numbers and locks
    /// for the bridges living on the configured one. It is also checked to serve what confirming
    /// mint locks needs (see [`EvmClient::check_mint_support`]).
    fn check_evm_chains(
        &self,
        online_options: &OnlineOptions,
    ) -> Result<HashMap<u64, EvmChain>, Error> {
        if !self.supports_schema(&AssetSchema::Bfa) {
            return Ok(HashMap::new());
        }
        for (chain_id, evm_chain) in &online_options.evm_chains {
            // with a higher minimum than maximum, no block could be committed to when minting
            if evm_chain.min_mint_lock_blocks > evm_chain.max_mint_lock_blocks {
                return Err(Error::InvalidEvmChain {
                    details: format!(
                        "chain ID {chain_id}: min_mint_lock_blocks ({}) is greater than \
                         max_mint_lock_blocks ({})",
                        evm_chain.min_mint_lock_blocks, evm_chain.max_mint_lock_blocks
                    ),
                });
            }
            let evm_rpc_url = &evm_chain.rpc_url;
            let evm_client = EvmClient::new(evm_rpc_url)?;
            let actual = evm_client.chain_id().map_err(|e| Error::InvalidEvmRpcUrl {
                details: e.to_string(),
            })?;
            if actual != *chain_id {
                return Err(Error::EvmChainIdMismatch {
                    expected: *chain_id,
                    actual,
                });
            }
            evm_client.check_mint_support()?;
            debug!(
                self.logger(),
                "EVM RPC endpoint for chain ID {chain_id}: {}",
                evm_client.endpoint()
            );
        }
        Ok(online_options.evm_chains.clone())
    }

    fn get_online_data(
        &self,
        online_options: &OnlineOptions,
    ) -> Result<(Online, OnlineData), Error> {
        let id = now().unix_timestamp_nanos() as u64;
        let online = Online { id };
        let proxy_auth_keys = parse_proxy_auth_keys(&online_options.proxy_auth_keys)?;

        let (indexer, resolver) =
            get_indexer_and_resolver(&online_options.indexer_config, self.bitcoin_network())?;
        indexer.populate_tx_cache(self.bdk_wallet());

        let evm_chains = self.check_evm_chains(online_options)?;

        let online_data = OnlineData {
            id: online.id,
            indexer_config: online_options.indexer_config.clone(),
            indexer,
            resolver,
            evm_rpc_urls: evm_rpc_urls(&evm_chains),
            evm_chains,
            hub_client: None,
            user_role: None,
            vanilla_sync_lookback: online_options.vanilla_sync_lookback,
            failed_witness_receive_grace_secs: online_options.failed_witness_receive_grace_secs,
            proxy_auth_keys,
        };

        Ok((online, online_data))
    }

    fn go_online_impl(&mut self, online_options: &OnlineOptions) -> Result<Online, Error> {
        let online = if let Some(online_data) = self.online_data().as_ref() {
            let online = Online { id: online_data.id };
            if online_data.indexer_config != online_options.indexer_config {
                let (online, online_data) = self.get_online_data(online_options)?;
                *self.online_data_mut() = Some(online_data);
                info!(self.logger(), "Went online with new indexer");
                online
            } else {
                self.check_online(online)?;
                // the indexer is unchanged but the other options may have changed. No `..` on
                // purpose: a new option doesn't compile until it's handled here
                let OnlineOptions {
                    indexer_config: _,         // a new indexer goes online from scratch, see above
                    skip_consistency_check: _, // only used during this call, not stored
                    vanilla_sync_lookback,
                    failed_witness_receive_grace_secs,
                    proxy_auth_keys,
                    evm_chains: _, // checked and returned by check_evm_chains below
                } = online_options;
                let proxy_auth_keys = parse_proxy_auth_keys(proxy_auth_keys)?;
                let evm_chains = self.check_evm_chains(online_options)?;
                let online_data = self.online_data_mut().as_mut().unwrap();
                online_data.vanilla_sync_lookback = *vanilla_sync_lookback;
                online_data.failed_witness_receive_grace_secs = *failed_witness_receive_grace_secs;
                online_data.proxy_auth_keys = proxy_auth_keys;
                online_data.evm_rpc_urls = evm_rpc_urls(&evm_chains);
                online_data.evm_chains = evm_chains;
                online
            }
        } else {
            let (online, online_data) = self.get_online_data(online_options)?;
            *self.online_data_mut() = Some(online_data);
            online
        };

        if !online_options.skip_consistency_check {
            let txn = self.database().begin_transaction()?;
            self.check_consistency(&txn)?;
            self.persist_and_commit(txn)?;
        }

        Ok(online)
    }

    /// Whether one of the inputs of the TX of an outgoing transfer has been spent by another
    /// confirmed transaction, so that the TX can never confirm.
    fn tx_inputs_spent_elsewhere(&self, batch_transfer: &DbBatchTransfer) -> Result<bool, Error> {
        let Some(txid) = &batch_transfer.txid else {
            return Ok(false);
        };
        let tx = self.get_signed_tx(&self.get_transfer_dir(txid))?;
        let inputs: HashSet<BdkOutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        Ok(self.bdk_wallet().transactions().any(|wallet_tx| {
            wallet_tx.chain_position.is_confirmed()
                && wallet_tx.tx_node.txid.to_string() != *txid
                && wallet_tx
                    .tx_node
                    .tx
                    .input
                    .iter()
                    .any(|i| inputs.contains(&i.previous_output))
        }))
    }

    /// Whether one of the inputs of the TX of the mint received by the given transfer has been
    /// spent by another confirmed transaction, so that the TX can never confirm.
    fn received_mint_tx_inputs_spent_elsewhere(
        &self,
        batch_transfer: &DbBatchTransfer,
        recipient_id: &str,
    ) -> Result<bool, Error> {
        let txid = batch_transfer
            .txid
            .as_deref()
            .expect("an accepted receive has a TXID");
        let valid_consignment = self.load_received_valid_transfer(batch_transfer, recipient_id)?;
        let Some(witness_bundle) = valid_consignment
            .bundles
            .iter()
            .find(|wb| wb.witness_id().to_string() == txid)
        else {
            return Ok(false);
        };
        for input in &witness_bundle.tx.input {
            if self
                .indexer()
                .output_spent_on_chain(&input.previous_output)?
            {
                // the mint TX itself spends it if it has been confirmed meanwhile
                return Ok(self
                    .indexer()
                    .get_tx_confirmations(txid)?
                    .is_none_or(|confirmations| confirmations == 0));
            }
        }
        Ok(false)
    }

    /// The signed TX of an outgoing transfer, read from its signed PSBT for a transfer created by
    /// a previous version.
    fn get_signed_tx(&self, transfer_dir: &Path) -> Result<BdkTransaction, Error> {
        let tx_file = transfer_dir.join(SIGNED_TX_FILE);
        if tx_file.exists() {
            let invalid = |e: String| Error::Internal {
                details: format!("invalid signed TX: {e}"),
            };
            let tx_bytes = hex::decode(fs::read_to_string(tx_file)?.trim())
                .map_err(|e| invalid(e.to_string()))?;
            return bdk_wallet::bitcoin::consensus::encode::deserialize(&tx_bytes)
                .map_err(|e| invalid(e.to_string()));
        }
        let psbt_str = fs::read_to_string(transfer_dir.join(SIGNED_PSBT_FILE))?;
        Ok(Psbt::from_str(&psbt_str)?
            .extract_tx()
            .map_err(InternalError::from)?)
    }

    fn get_signed_psbt(&self, transfer_dir: &Path) -> Result<Psbt, Error> {
        let psbt_file = transfer_dir.join(SIGNED_PSBT_FILE);
        let psbt_str = String::from_utf8(self.files().read(&self.wallet_key(&psbt_file)?)?)
            .map_err(|e| Error::Internal {
                details: format!("cannot read {}: {e}", psbt_file.display()),
            })?;
        Ok(Psbt::from_str(&psbt_str)?)
    }

    /// Symmetric key shared with the counterparty (from the own operation seed and the
    /// counterparty's hex-encoded Ed25519 pubkey) and the raw bytes of the expected plaintext hash,
    /// as the encryption primitives take them.
    fn shared_key_and_hash(
        own_seed: &[u8],
        counterparty_pubkey_hex: &str,
        hash_hex: &str,
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        let seed: [u8; 32] = own_seed.try_into().map_err(|_| Error::Internal {
            details: s!("invalid own secret key"),
        })?;
        let own_sk = ed25519_from_seed(&seed);
        let counterparty_vk =
            verifying_key_from_bytes(&hex::decode(counterparty_pubkey_hex).map_err(|_| {
                Error::Internal {
                    details: s!("invalid counterparty pubkey"),
                }
            })?)?;
        let derived = derive_shared(&own_sk, &counterparty_vk)?;
        let hash_raw = decode_hash_hex(hash_hex)?;
        Ok((derived.sym_key, hash_raw))
    }

    /// File counterpart of [`decrypt_blob_with_shared_key`](Self::decrypt_blob_with_shared_key)
    /// for the (potentially big) consignment and media, taking the payload as the proxy delivers
    /// it: base64-encoded in its JSON-RPC response, so the ciphertext is already in memory and
    /// will stay that way until the proxy supports streaming it. The payload is decoded and
    /// decrypted on the fly, the plaintext is streamed into `dest` one chunk at a time and written
    /// atomically, then the file is verified against the expected plaintext hash before being
    /// made visible.
    ///
    /// This is the one wallet write that does not go through the wallet adapter: the payload is
    /// streamed into a temporary file and verified by reading that file back, so it needs a real
    /// filesystem path rather than a byte buffer.
    fn decrypt_blob_with_shared_key_to_file(
        &self,
        payload_b64: &str,
        encryption: Encryption,
        own_seed: &[u8],
        counterparty_pubkey_hex: &str,
        hash_hex: &str,
        dest: &Path,
    ) -> Result<(), Error> {
        let (sym_key, hash_raw) =
            Self::shared_key_and_hash(own_seed, counterparty_pubkey_hex, hash_hex)?;
        let decoded =
            || base64::read::DecoderReader::new(payload_b64.as_bytes(), &general_purpose::STANDARD);
        atomic_write_with(dest, |tmp| {
            let decrypt_to = |tmp: &Path| -> Result<(), Error> {
                let mut file = fs::File::create(tmp)?;
                decrypt_stream(decoded(), &mut file, &sym_key, &hash_raw)
            };
            let copy_to = |tmp: &Path| -> Result<(), Error> {
                let mut file = fs::File::create(tmp)?;
                io::copy(&mut decoded(), &mut file).map_err(|e| match e.kind() {
                    // malformed base64 is a malformed payload, not an I/O failure
                    io::ErrorKind::InvalidData => Error::InvalidEncryptedBlob {
                        details: e.to_string(),
                    },
                    _ => e.into(),
                })?;
                Ok(())
            };
            // When the payload is written unmodified it might still be encrypted.
            // The plaintext hash check below catches these cases as well.
            match encryption {
                Encryption::Unsupported => copy_to(tmp)?,
                Encryption::Required => decrypt_to(tmp)?,
                Encryption::Optional => {
                    if decrypt_to(tmp).is_err() {
                        copy_to(tmp)?;
                    }
                }
            }
            if hash_file(tmp)? != hash_hex {
                return Err(Error::HashMismatch);
            }
            Ok(())
        })
    }

    /// Sign an ACK/NACK with the recipient's operation key and post it to the sender's proxy.
    fn sign_and_post_ack(
        &self,
        sender_proxy: &str,
        transfer_id: &str,
        ack: bool,
        consignment_hash: &str,
        recipient_seed: &[u8],
    ) -> Result<PostAckResponse, Error> {
        let seed: [u8; 32] = recipient_seed.try_into().map_err(|_| Error::Internal {
            details: s!("invalid recipient secret key"),
        })?;
        let sk = ed25519_from_seed(&seed);
        let digest = Self::ack_digest(transfer_id, ack, consignment_hash);
        let sig = hex::encode(sign_ed25519(&sk, &digest));
        let proxy_client = ProxyClient::new(sender_proxy)?;
        let res = proxy_client.post_ack(transfer_id, ack, &sig)?;
        if let Some(err) = res.error {
            return Err(map_proxy_error(err));
        }
        res.result.ok_or_else(|| Error::Proxy {
            details: s!("missing ack.post result"),
        })
    }

    /// Decrypt the released signed TX, verify it, save it so it can be broadcast again until the
    /// broadcast deadline (v1.0-changes-spec.md 6.4) and broadcast it.
    fn broadcast_received_tx(
        &self,
        recipient_id: &str,
        signed_tx_b64: &str,
        signed_tx_hash: &str,
        sender_pubkey_hex: &str,
        recipient_seed: &[u8],
    ) -> Result<(), Error> {
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
        self.broadcast_tx(tx)?;
        Ok(())
    }

    /// Broadcast again the signed TX released to a recipient, if saved, e.g. after it was evicted
    /// from the mempool. Failures are only logged, as the TX may e.g. have been replaced.
    fn rebroadcast_received_tx(&self, recipient_id: &str) {
        let path = self.get_received_signed_tx_path(recipient_id);
        let Ok(tx_bytes) = self
            .wallet_key(&path)
            .and_then(|key| self.files().read(&key))
        else {
            return;
        };
        let tx: BdkTransaction =
            match bdk_wallet::bitcoin::consensus::encode::deserialize(&tx_bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    warn!(self.logger(), "Cannot load saved signed TX: {e}");
                    return;
                }
            };
        debug!(self.logger(), "Broadcasting the saved signed TX again");
        if let Err(e) = self.broadcast_tx(tx) {
            warn!(
                self.logger(),
                "Failed to broadcast the saved signed TX again: {e}"
            );
        }
    }

    fn fetch_and_save_attachments(
        &self,
        attachments: Vec<Attachment>,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
    ) -> Result<bool, Error> {
        let provided_map: HashMap<String, String> = match mode {
            ReceiveMode::OutOfBand { media_file_paths } => {
                let mut map = HashMap::new();
                for path in media_file_paths {
                    map.insert(hash_file(Path::new(path))?, path.clone());
                }
                map
            }
            ReceiveMode::Proxy { .. } => HashMap::new(),
        };

        // for the proxy exchange the media is stored under an id derived from the shared secret (not
        // the plaintext digest); derive the secret once so we can locate each attachment
        let proxy_derived = if let ReceiveMode::Proxy(data) = mode {
            let seed: [u8; 32] = recipient_seed.try_into().map_err(|_| Error::Internal {
                details: s!("invalid recipient secret key"),
            })?;
            let recipient_sk = ed25519_from_seed(&seed);
            let sender_vk =
                verifying_key_from_bytes(&hex::decode(&data.sender_pubkey).map_err(|_| {
                    Error::Internal {
                        details: s!("invalid sender pubkey"),
                    }
                })?)?;
            Some(derive_shared(&recipient_sk, &sender_vk)?)
        } else {
            None
        };

        let mut saved_media = vec![];
        for attachment in attachments {
            let digest = hex::encode(attachment.digest);
            let media_path = self.media_dir().join(&digest);
            let media_key = self.media_key(&digest)?;
            // resolve media only if the file is not already present
            if self.files().exists(&media_key)? {
                continue;
            }
            match mode {
                ReceiveMode::Proxy(data) => {
                    let proxy_client = ProxyClient::new(&data.proxy_url)?;
                    let media_id = proxy_derived
                        .as_ref()
                        .expect("proxy mode always derives the shared secret")
                        .media_id(&digest);
                    let media_res = proxy_client.get_media(&data.transfer_id, &media_id)?;
                    #[cfg(test)]
                    debug!(self.logger(), "Media GET response: {:?}", media_res);
                    match media_res.result {
                        Some(media_res) => {
                            // also checks the plaintext against the digest in the contract. The
                            // payload is streamed through a temporary file and verified by
                            // reading it back, so this one write stays on the native path.
                            self.decrypt_blob_with_shared_key_to_file(
                                &media_res,
                                data.recipient_encryption,
                                recipient_seed,
                                &data.sender_pubkey,
                                &digest,
                                &media_path,
                            )?;
                        }
                        None => {
                            error!(
                                self.logger(),
                                "Cannot find the media file but the contract defines one"
                            );
                            WalletOffline::cleanup_media_files(self, &saved_media)?;
                            return Ok(false);
                        }
                    }
                }
                ReceiveMode::OutOfBand { .. } => match provided_map.get(&digest) {
                    Some(path) => {
                        // the provided file is a host path, the wallet copy is a wallet blob
                        let bytes = fs::read(path)?;
                        self.files().atomic_write(&media_key, &bytes)?;
                    }
                    None => {
                        error!(
                            self.logger(),
                            "Media for digest {digest} was not provided for the out-of-band receive"
                        );
                        WalletOffline::cleanup_media_files(self, &saved_media)?;
                        return Ok(false);
                    }
                },
            }
            saved_media.push(media_key);
        }

        Ok(true)
    }

    fn cleanup_media_files(&self, keys: &[WalletPath]) -> Result<(), Error> {
        for key in keys {
            self.files().remove(key)?;
        }
        Ok(())
    }

    fn get_consignment(
        &self,
        proxy_url: &str,
        transfer_id: String,
    ) -> Result<GetConsignmentResponse, Error> {
        let proxy_client = ProxyClient::new(proxy_url)?;
        let consignment_res = proxy_client.get_consignment(&transfer_id);
        if consignment_res.is_err() || consignment_res.as_ref().unwrap().result.as_ref().is_none() {
            debug!(
                self.logger(),
                "Consignment GET response error: {:?}", &consignment_res
            );
            return Err(Error::NoConsignment);
        }

        let consignment_res = consignment_res.unwrap().result.unwrap();
        #[cfg(test)]
        debug!(
            self.logger(),
            "Consignment GET response: {:?}", consignment_res
        );

        Ok(consignment_res)
    }

    fn extract_received_assignments(
        &self,
        consignment: &RgbTransfer,
        witness_id: RgbTxid,
        payment_seal: PaymentSeal,
    ) -> HashMap<Opout, Assignment> {
        match consignment
            .bundles
            .iter()
            .find(|bundle| bundle.witness_id() == witness_id)
        {
            Some(bundle) => self.assignments_for_bundle(bundle, payment_seal),
            None => HashMap::new(),
        }
    }

    /// The outputs spent within the consignment by its known transitions (see
    /// [`receive_checks::known_spent_opouts`]).
    fn known_spent_opouts(consignment: &RgbTransfer) -> BTreeSet<Opout> {
        receive_checks::known_spent_opouts(consignment)
    }

    /// Locate the destinations at which the consignment pays this recipient (see
    /// [`receive_checks::find_payments`]).
    ///
    /// The spent outputs are the inputs of the known transitions (see `known_spent_opouts`), which
    /// only the deterministic validation checks, so the result can be trusted only for a
    /// consignment that went through it.
    ///
    /// `spent` are the consignment's spent outputs (see `known_spent_opouts`), which callers
    /// matching several transfers against a consignment compute once.
    fn find_payments<'c, 'a>(
        &'a self,
        consignment: &'c RgbTransfer,
        matcher: &'a ReceiveMatcher,
        spent: &'a BTreeSet<Opout>,
    ) -> impl Iterator<Item = ConsignmentPayment<'c>> + 'a
    where
        'c: 'a,
    {
        receive_checks::find_payments(consignment, matcher, spent)
    }

    /// The slots taken on the TXO at `outpoint`, if known and unspent (see
    /// [`receive_checks::count_utxo_taken_slots`]).
    fn count_utxo_taken_slots(
        &self,
        txn: &DbTxn,
        outpoint: &Outpoint,
        asset_id: &str,
        transfer_idx: i32,
        asset_transfer_idx: i32,
    ) -> Result<TakenSlots, Error> {
        receive_checks::count_utxo_taken_slots(
            txn,
            outpoint,
            asset_id,
            transfer_idx,
            asset_transfer_idx,
        )
    }

    // extract the assignments in a single bundle that pay the recipient at `payment_seal`
    fn assignments_for_bundle(
        &self,
        bundle: &WitnessBundle,
        payment_seal: PaymentSeal,
    ) -> HashMap<Opout, Assignment> {
        receive_checks::assignments_for_bundle(bundle, payment_seal)
    }

    fn reject_list_resolver(&self) -> WalletRejectListResolver<'_> {
        WalletRejectListResolver {
            // going online checks the chain of every configured EVM RPC endpoint
            inner: RemoteRejectListResolver {
                evm_rpc_urls: self.evm_rpc_urls(),
                evm_chains_checked: true,
            },
            logger: self.logger(),
        }
    }

    fn extract_attachments(
        &self,
        stock: &RgbStock<'_>,
        valid_contract: &ValidContract,
        asset_schema: AssetSchema,
    ) -> Result<Vec<Attachment>, Error> {
        receive_checks::extract_attachments(stock, valid_contract, asset_schema)
    }

    fn safe_height(&self, min_confirmations: u8) -> Result<u32, Error> {
        Ok(self
            .indexer()
            .get_latest_block_height()?
            .saturating_sub(min_confirmations as u32)
            + 1)
    }

    /// Load the validated consignment of a received transfer.
    ///
    /// The validated copy is kept while the transfer is pending, to avoid validating again on
    /// every refresh. When missing (e.g. a transfer migrated from the legacy format, whose
    /// validated copy cannot be carried over), the consignment is validated again and the copy
    /// saved.
    fn load_received_valid_transfer(
        &self,
        batch_transfer: &DbBatchTransfer,
        recipient_id: &str,
    ) -> Result<ValidTransfer, Error> {
        let consignment_path = self.get_receive_consignment_path(recipient_id);
        let valid_consignment_path = self.get_receive_valid_consignment_path(&consignment_path);
        if self
            .files()
            .exists(&self.wallet_key(&valid_consignment_path)?)?
        {
            // rgb-ops only exposes a path-based loader for a validated consignment
            return ValidTransfer::load_file(&valid_consignment_path)
                .map_err(|e| InternalError::from(e).into());
        }

        debug!(
            self.logger(),
            "No validated consignment for {recipient_id}, validating consignment"
        );
        let consignment_key = self.wallet_key(&consignment_path)?;
        let consignment = RgbTransfer::load(&self.files().read(&consignment_key)?[..])
            .map_err(InternalError::from)?;
        let txid = batch_transfer
            .txid
            .as_deref()
            .expect("received batch_transfer with a consignment must have a txid");
        let witness_id = RgbTxid::from_str(txid).map_err(InternalError::from)?;
        let safe_height = NonZeroU32::new(self.safe_height(batch_transfer.min_confirmations)?);
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            // the reject list has already been checked when the consignment was received, so no
            // caller of this method needs the operations DAG, which would only bloat the saved file
            build_ops_dag: false,
            safe_height,
        };
        let valid_consignment = validate_consignment_internal(
            &consignment,
            Some(witness_id),
            &self.blockchain_resolver(),
            ClaimResolution::Evm(self.evm_rpc_urls()),
            &validation_config,
        )
        .map_err(|e| match e {
            Error::ConsignmentValidationFailed { details } => Error::Internal {
                details: format!("received consignment failed re-validation: {details}"),
            },
            e => e,
        })?;
        atomic_write_with(&valid_consignment_path, |tmp| {
            Ok(valid_consignment.save_file(tmp)?)
        })?;
        Ok(valid_consignment)
    }

    /// the canonical ACK/NACK content message digest used both when signing (recipient) and
    /// verifying (sender) an ACK (SHA-256 of `recipient_id || true|false || consignment_hash`)
    fn ack_digest(transfer_id: &str, ack: bool, consignment_hash: &str) -> [u8; 32] {
        let msg = format!(
            "{transfer_id}{}{consignment_hash}",
            if ack { "true" } else { "false" }
        );
        sha256_digest(msg.as_bytes())
    }

    fn wait_consignment(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Waiting consignment...");

        let (asset_transfer, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
        let recipient_id = transfer
            .recipient_id
            .clone()
            .expect("transfer should have a recipient ID");
        debug!(self.logger(), "Recipient ID: {recipient_id}");

        if transfer.uses_out_of_band_exchange() {
            debug!(self.logger(), "Skipping consignment exchange out-of-band");
            return Ok(None);
        }

        let tte_data = txn.get_transfer_transport_endpoints_data(transfer.idx)?;

        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();

        // the recipient's per-operation Ed25519 secret seed (used to derive the shared secret)
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();

        // if we already downloaded the consignment and its metadata in a previous attempt that
        // failed for a transient reason (e.g. network error), reuse them instead of hitting the
        // proxy again; the endpoint we used is recorded in the metadata, since a failed refresh
        // rolls back the `used` flag on the transfer transport endpoint
        let consignment_path = self.get_receive_consignment_path(&recipient_id);
        let consignment_meta_path = self.get_receive_consignment_meta_path(&recipient_id);
        let consignment_key = self.wallet_key(&consignment_path)?;
        let consignment_meta_key = self.wallet_key(&consignment_meta_path)?;
        // a consignment or metadata file that cannot be read is treated as missing, as before
        let cached_meta = if self.files().exists(&consignment_key)?
            && self.files().exists(&consignment_meta_key)?
        {
            self.files()
                .read(&consignment_meta_key)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<ReceivedConsignmentMeta>(&bytes).ok())
        } else {
            None
        };
        let data = if let Some(meta) = cached_meta
            && let Some(cached_transfer_id) = meta.transfer_id.clone()
            && let Some((cached_tte, cached_te)) = tte_data.iter().find(|(tte, te)| {
                tte.kind == TransportEndpointKind::RecipientProxy
                    && meta
                        .proxy_url
                        .as_ref()
                        .map_or(tte.used, |url| url == &te.endpoint)
            }) {
            debug!(
                self.logger(),
                "Reusing previously-downloaded consignment for {recipient_id}"
            );
            let data = ProxyReceiveData {
                proxy_url: cached_te.endpoint.clone(),
                transfer_id: cached_transfer_id,
                sender_proxy: meta.sender_transport_endpoint,
                sender_pubkey: meta.sender_pubkey,
                consignment_hash: meta.consignment_hash,
                recipient_encryption: transfer.recipient_encryption,
                batch: meta.batch,
            };
            // a failed refresh also rolls back what was saved along with the download
            if !cached_tte.used {
                let mut updated_transfer_transport_endpoint: DbTransferTransportEndpointActMod =
                    cached_tte.clone().into();
                updated_transfer_transport_endpoint.used = ActiveValue::Set(true);
                txn.update_transfer_transport_endpoint(&mut updated_transfer_transport_endpoint)?;
            }
            if transfer.consignment_hash.is_none() || transfer.proxy_transfer_id.is_none() {
                let mut ut: DbTransferActMod = transfer.clone().into();
                ut.consignment_hash = ActiveValue::Set(Some(data.consignment_hash.clone()));
                ut.proxy_transfer_id = ActiveValue::Set(Some(data.transfer_id.clone()));
                txn.update_transfer(&mut ut)?;
            }
            if !tte_data
                .iter()
                .any(|(tte, _)| tte.kind == TransportEndpointKind::SenderProxy)
            {
                self.save_sender_transport_endpoint(txn, transfer.idx, &data.sender_proxy)?;
            }
            data
        } else {
            // discover the transfer to the invoice and download its consignment
            let recipient_pk = hex::encode(transfer.recipient_pubkey.as_ref().ok_or_else(
                || Error::Internal {
                    details: s!("missing recipient pubkey"),
                },
            )?);
            let invoice_id = invoice_id(&recipient_id, &recipient_pk);
            let mut proxy_res = None;
            for (transfer_transport_endpoint, transport_endpoint) in tte_data {
                if transfer_transport_endpoint.kind != TransportEndpointKind::RecipientProxy {
                    continue;
                }
                let Some(found) = self.find_invoice_transfer(
                    &transport_endpoint.endpoint,
                    &invoice_id,
                    &recipient_seed,
                )?
                else {
                    info!(
                        self.logger(),
                        "Skipping transport endpoint: {:?}", &transport_endpoint
                    );
                    continue;
                };

                proxy_res = Some((transport_endpoint.endpoint, found));
                let mut updated_transfer_transport_endpoint: DbTransferTransportEndpointActMod =
                    transfer_transport_endpoint.into();
                updated_transfer_transport_endpoint.used = ActiveValue::Set(true);
                txn.update_transfer_transport_endpoint(&mut updated_transfer_transport_endpoint)?;
                break;
            }
            let Some((proxy_url, (transfer_id, result))) = proxy_res else {
                return Ok(None);
            };
            // the sender endpoint arrives in RgbTransport (rpc://) format; convert to an HTTP URL
            let sender_proxy =
                self.convert_transport_endpoint_url(&result.sender_transport_endpoint)?;
            let data = ProxyReceiveData {
                proxy_url,
                transfer_id,
                sender_proxy,
                sender_pubkey: result.sender_pk.clone(),
                consignment_hash: result.consignment_hash.clone(),
                recipient_encryption: transfer.recipient_encryption,
                batch: result.batch,
            };

            // decode and (if needed) decrypt the consignment; a malformed payload is refused like
            // one that fails decryption or verification
            match self.decrypt_blob_with_shared_key_to_file(
                &result.consignment,
                data.recipient_encryption,
                &recipient_seed,
                &data.sender_pubkey,
                &data.consignment_hash,
                &consignment_path,
            ) {
                Ok(()) => {}
                Err(e @ Error::IO { .. }) => return Err(e),
                Err(_) => {
                    error!(self.logger(), "Failed to decrypt/verify consignment");
                    // a consignment that can't be read isn't known to be a mint: if it is one, it
                    // hasn't been checked, so its transfer still expires with the invoice even if
                    // the NACK keeps failing
                    let mode = ReceiveMode::Proxy(ProxyReceiveData {
                        proxy_url: data.proxy_url.clone(),
                        transfer_id: data.transfer_id.clone(),
                        sender_proxy: data.sender_proxy.clone(),
                        sender_pubkey: data.sender_pubkey.clone(),
                        consignment_hash: data.consignment_hash.clone(),
                        recipient_encryption: data.recipient_encryption,
                        batch: data.batch,
                    });
                    let transport = NativeReceiveTransport::new(self);
                    return drive_native(self.refuse_consignment_via(
                        &transport,
                        txn,
                        &mode,
                        &recipient_id,
                        &recipient_seed,
                        &mut updated_batch_transfer,
                        false,
                    ));
                }
            }
            let meta = ReceivedConsignmentMeta {
                proxy_url: Some(data.proxy_url.clone()),
                transfer_id: Some(data.transfer_id.clone()),
                sender_transport_endpoint: data.sender_proxy.clone(),
                sender_pubkey: data.sender_pubkey.clone(),
                consignment_hash: data.consignment_hash.clone(),
                batch: data.batch,
            };
            let meta_str = serde_json::to_string(&meta).map_err(InternalError::from)?;
            self.files()
                .atomic_write(&consignment_meta_key, meta_str.as_bytes())?;

            // persist the transfer ID, the consignment hash and the sender proxy endpoint (for the
            // ACK)
            let mut ut: DbTransferActMod = transfer.clone().into();
            ut.consignment_hash = ActiveValue::Set(Some(data.consignment_hash.clone()));
            ut.proxy_transfer_id = ActiveValue::Set(Some(data.transfer_id.clone()));
            txn.update_transfer(&mut ut)?;
            self.save_sender_transport_endpoint(txn, transfer.idx, &data.sender_proxy)?;

            data
        };

        let proxy_url = data.proxy_url.clone();
        let transfer_id = data.transfer_id.clone();
        let mode = ReceiveMode::Proxy(data);
        let res = self.process_received_consignment(
            txn,
            batch_transfer,
            &asset_transfer,
            &transfer,
            recipient_id,
            &consignment_path,
            mode,
            &mut updated_batch_transfer,
        )?;
        // once the consignment has been handled (ACKed or refused), its data is saved locally and
        // the proxy can delete it, while the transfer keeps counting towards the invoice quota
        if res.is_some() && self.releases_received_transfer_data() {
            self.mark_transfer_retrieved(&proxy_url, &transfer_id, &recipient_seed);
        }
        Ok(res)
    }

    /// Find the transfer to an invoice on a recipient proxy and download its consignment.
    ///
    /// The proxy is asked for the pending transfers of the invoice, the first one whose transfer
    /// ID matches the one derived from the invoice ID and the sender pubkey is returned. Invoices
    /// are single-use, so at most one transfer is expected. Proxy errors (e.g. an unreachable
    /// proxy or an invoice it doesn't know) make it skip the proxy.
    fn find_invoice_transfer(
        &self,
        proxy_url: &str,
        invoice_id: &str,
        recipient_seed: &[u8],
    ) -> Result<Option<(String, GetConsignmentResponse)>, Error> {
        let transfers = match list_invoice_transfers(proxy_url, invoice_id, recipient_seed) {
            Ok(res) => match (res.result, res.error) {
                (Some(transfers), None) => transfers,
                (_, err) => {
                    debug!(self.logger(), "Transfer list error: {:?}", err);
                    return Ok(None);
                }
            },
            Err(e) => {
                debug!(self.logger(), "Transfer list error: {e}");
                return Ok(None);
            }
        };
        let mut pending: Vec<String> = transfers
            .into_iter()
            .filter(|(_, state)| *state == ProxyTransferState::Pending)
            .map(|(tid, _)| tid)
            .collect();
        pending.sort();
        for transfer_id in pending {
            let result = match self.get_consignment(proxy_url, transfer_id.clone()) {
                Err(Error::NoConsignment) => continue,
                Err(e) => return Err(e),
                Ok(r) => r,
            };
            // a transfer whose ID doesn't match the sender pubkey was not posted by its sender
            if self::transfer_id(invoice_id, &result.sender_pk) != transfer_id {
                warn!(
                    self.logger(),
                    "Ignoring transfer {transfer_id}, which doesn't match its sender pubkey"
                );
                continue;
            }
            return Ok(Some((transfer_id, result)));
        }
        Ok(None)
    }

    /// Whether a blind receive still waiting for the counterparty may be failed, which releases its
    /// blinded UTXO (`v1.0-changes-spec.md` 6.1). Before the invoice expiration the receive can be
    /// cancelled. After it, the blinded UTXO stays reserved until the invoice expiration has passed
    /// on the proxies' clocks too and then, on each recipient proxy, either a `transfer.list` shows
    /// no pending transfer or the proxy retention grace has passed, since a transfer created before
    /// the expiration (e.g. a donation, whose TX is broadcast already) can be downloaded until then
    /// and would otherwise assign its assets to a spent UTXO. An "invoice not reserved" answer is
    /// taken as no pending transfer, as the proxy can delete the invoice data once nothing is
    /// pending, accepting that it can't be told apart from a data wipe.
    fn blind_receive_may_be_failed(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<bool, Error> {
        let Some(retention_deadline) = batch_transfer.retention_deadline else {
            return Ok(true);
        };
        let now = now().unix_timestamp();
        if !batch_transfer.is_expired(now) {
            return Ok(true);
        }
        let skew_margin = i64::from(clock_skew_margin());
        if !batch_transfer.is_expired_with_margin(now, clock_skew_margin()) {
            return Ok(false);
        }
        if retention_deadline.saturating_add(skew_margin) < now {
            return Ok(true);
        }
        let (_, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
        let (Some(recipient_id), Some(recipient_pubkey), Some(recipient_seed)) = (
            &transfer.recipient_id,
            &transfer.recipient_pubkey,
            &batch_transfer.operation_secret_key,
        ) else {
            return Ok(true);
        };
        let invoice_id = invoice_id(recipient_id, &hex::encode(recipient_pubkey));
        for (tte, te) in txn.get_transfer_transport_endpoints_data(transfer.idx)? {
            if tte.kind != TransportEndpointKind::RecipientProxy {
                continue;
            }
            let res = list_invoice_transfers(&te.endpoint, &invoice_id, recipient_seed);
            let nothing_pending = match res {
                Ok(res) => match (res.result, res.error) {
                    (Some(transfers), None) => transfers
                        .values()
                        .all(|state| *state != ProxyTransferState::Pending),
                    (_, Some(err)) => matches!(map_proxy_error(err), Error::InvoiceNotReserved),
                    (None, None) => false,
                },
                Err(_) => false,
            };
            if !nothing_pending {
                debug!(
                    self.logger(),
                    "Recipient proxy {} may still hold a transfer to the invoice", te.endpoint
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Let the recipient proxy delete the data of a transfer that has been handled. Failures are
    /// only logged, as the proxy deletes the data anyway once the invoice expires.
    fn mark_transfer_retrieved(&self, proxy_url: &str, transfer_id: &str, recipient_seed: &[u8]) {
        let Ok(seed) = <[u8; 32]>::try_from(recipient_seed) else {
            return;
        };
        let sk = ed25519_from_seed(&seed);
        let digest = sha256_digest(transfer_retrieved_message(transfer_id).as_bytes());
        let signature = hex::encode(sign_ed25519(&sk, &digest));
        let res = ProxyClient::new(proxy_url)
            .and_then(|client| client.transfer_retrieved(transfer_id, &signature));
        match res {
            Ok(r) if r.error.is_none() => {}
            Ok(r) => warn!(
                self.logger(),
                "Failed to mark transfer as retrieved: {:?}", r.error
            ),
            Err(e) => warn!(self.logger(), "Failed to mark transfer as retrieved: {e}"),
        }
    }

    /// The config to validate a consignment received by this wallet, of an asset with the given
    /// schema, reporting the witnesses mined above `safe_height` (if any) in a warning: the
    /// operations DAG is built if the schema supports a reject list, to check the assignments
    /// received against it (see `check_received_consignment`).
    fn received_validation_config(
        &self,
        asset_schema: AssetSchema,
        safe_height: Option<NonZeroU32>,
    ) -> ValidationConfig {
        ValidationConfig {
            chain_net: self.chain_net(),
            build_ops_dag: asset_schema.supports_reject_list(),
            safe_height,
        }
    }

    /// Map an error validating a consignment received by this wallet, logging it: an invalid
    /// consignment is reported as an [`Error::InvalidConsignment`], to be refused.
    fn received_validation_error(&self, e: Error) -> Error {
        receive_checks::received_validation_error(e, self.logger())
    }

    /// Phase 2 of the validation of a consignment received by this wallet (validated with the
    /// config given by `received_validation_config`), followed, if `with_reject_list`, by the
    /// check of the assignments it pays this recipient against the reject list of its asset.
    ///
    /// The consignment must be refused if an [`Error::InvalidConsignment`] or an
    /// [`Error::ConsignmentRejected`] is returned.
    fn check_received_consignment<R: ResolveWitness>(
        &self,
        pending: PendingConsignment<true>,
        resolver: &R,
        asset_schema: AssetSchema,
        receiving: &HashMap<Opout, Assignment>,
        with_reject_list: bool,
    ) -> Result<ValidTransfer, Error> {
        receive_checks::check_received_consignment(
            pending,
            resolver,
            asset_schema,
            receiving,
            with_reject_list,
            self.logger(),
            &self.reject_list_resolver(),
        )
    }

    /// Whether a received mint pays what the invoice requests (see
    /// [`receive_checks::mint_pays_requested`]).
    fn mint_pays_requested(transfer: &DbTransfer, receiving: &HashMap<Opout, Assignment>) -> bool {
        receive_checks::mint_pays_requested(transfer, receiving)
    }

    // validate a received consignment, if valid import any unknown asset (and its media), persist
    // the receive colorings, then update the transfer status (ACKing the consignment when possible)
    fn process_received_consignment(
        &self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        asset_transfer: &DbAssetTransfer,
        transfer: &DbTransfer,
        recipient_id: String,
        consignment_path: &Path,
        mode: ReceiveMode,
        updated_batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        let transport = NativeReceiveTransport::new(self);
        let chain = self.blockchain_resolver();
        let (outcome, _) = drive_native(self.drive_receive(
            &transport,
            &chain,
            txn,
            batch_transfer,
            asset_transfer,
            transfer,
            recipient_id,
            consignment_path,
            mode,
            updated_batch_transfer,
            None,
        ))?;
        Ok(outcome)
    }

    fn provide_out_of_band_consignment_impl(
        &self,
        txn: &DbTxn,
        consignment_path_in: &str,
        media_file_paths: Vec<String>,
    ) -> Result<RefreshResult, Error> {
        let consignment =
            RgbTransfer::load_file(consignment_path_in).map_err(|_| Error::InvalidFilePath {
                file_path: consignment_path_in.to_string(),
            })?;

        let db_data = txn.get_db_data(false)?;

        let asset_id = consignment.contract_id().to_string();

        let spent = Self::known_spent_opouts(&consignment);
        let mut matches = vec![];
        for batch_transfer in &db_data.batch_transfers {
            // skip non-incoming transfers and transfers that are not waiting for a counterparty
            if !batch_transfer.incoming
                || batch_transfer.status != TransferStatus::WaitingCounterparty
            {
                continue;
            }
            let (asset_transfer, transfer) = batch_transfer
                .get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
            // skip transfers bound to a different asset
            if asset_transfer
                .asset_id
                .as_ref()
                .is_some_and(|aid| aid != &asset_id)
            {
                continue;
            }
            // skip transfers that are not set up for out-of-band exchange
            if !transfer.uses_out_of_band_exchange() {
                continue;
            }

            // check if a consignment bundle pays this transfer: this only selects the transfers
            // the consignment may be for, any payment is enough, as each one selected is then
            // processed by process_received_consignment, which refuses the consignment unless it
            // pays the transfer at exactly one destination
            let matcher = transfer.receive_matcher(None)?;
            if self
                .find_payments(&consignment, &matcher, &spent)
                .next()
                .is_some()
            {
                matches.push((
                    batch_transfer.clone(),
                    asset_transfer.clone(),
                    transfer.clone(),
                ));
            }
        }
        if matches.is_empty() {
            return Err(Error::CannotProvideOutOfBandConsignment {
                details: s!("no pending receive transfer matches the provided consignment"),
            });
        }

        // a single consignment (for one asset) can pay more than one of this wallet's pending
        // invoices (e.g. a sender batched a send to two of them), so process every matched receive
        let mut results: RefreshResult = HashMap::new();
        for (batch_transfer, asset_transfer, transfer) in matches {
            let recipient_id = transfer
                .recipient_id
                .clone()
                .expect("matched transfer should have a recipient ID");
            debug!(
                self.logger(),
                "Providing out-of-band consignment for recipient ID: {recipient_id}"
            );

            // copy the provided consignment to the canonical receive path, so later refresh stages
            // (safe height, confirmations) find it where they expect it. The source is a host
            // path, the destination is a wallet file.
            let consignment_path = self.get_receive_consignment_path(&recipient_id);
            let bytes = fs::read(consignment_path_in)?;
            self.files()
                .atomic_write(&self.wallet_key(&consignment_path)?, &bytes)?;

            let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
            let mode = ReceiveMode::OutOfBand {
                media_file_paths: media_file_paths.clone(),
            };
            let updated = self.process_received_consignment(
                txn,
                &batch_transfer,
                &asset_transfer,
                &transfer,
                recipient_id,
                &consignment_path,
                mode,
                &mut updated_batch_transfer,
            )?;

            results.insert(
                batch_transfer.idx,
                RefreshedTransfer {
                    updated_status: updated.map(|t| t.status),
                    failure: None,
                },
            );
        }

        Ok(results)
    }

    fn wait_safe_height(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Waiting safe height...");

        let (_, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
        let recipient_id = transfer
            .recipient_id
            .clone()
            .expect("transfer should have a recipient ID");
        let txid = batch_transfer
            .txid
            .as_deref()
            .expect("batch_transfer in WaitingSafeHeight must have a txid");

        // a transfer from the previous proxy protocol cannot be ACKed anymore, so waiting for a
        // safe height is pointless. Failing it right away, without waiting for the expiration, is
        // safe: in that protocol the recipient only ACKed after this wait, so no ACK was ever
        // posted and a non-donation sender never broadcasts without it; a donation was broadcast
        // at send time, which the chain check below (mempool included) catches
        if batch_transfer.is_legacy() {
            let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
            if self.indexer().get_tx_confirmations(txid)?.is_some() {
                info!(
                    self.logger(),
                    "TX of a transfer from the previous proxy protocol found on-chain"
                );
                updated_batch_transfer.status =
                    ActiveValue::Set(TransferStatus::WaitingConfirmations);
                return Ok(Some(
                    txn.update_batch_transfer(&mut updated_batch_transfer)?,
                ));
            }
            info!(
                self.logger(),
                "Transfer from the previous proxy protocol cannot be completed, failing it"
            );
            return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
        }

        let valid_consignment = self.load_received_valid_transfer(batch_transfer, &recipient_id)?;
        let validation_status = valid_consignment.validation_status();
        let unsafe_txids = collect_unsafe_history_txids(&validation_status.warnings, txid);

        if !unsafe_txids.is_empty() {
            let safe_height = self.safe_height(batch_transfer.min_confirmations)?;
            for txid in unsafe_txids {
                let Some(tx_height) = self.tx_height(txid)? else {
                    return Ok(None);
                };
                if tx_height > safe_height {
                    return Ok(None);
                }
            }
        }

        // the paying bundle is the one committed by the witness TX saved when the consignment was
        // accepted: matching the consignment again could yield another one, as the seal blinding
        // a proxy witness receive was matched with isn't known here
        let paying_bundle = valid_consignment
            .bundles
            .iter()
            .find(|bundle| bundle.witness_id().to_string() == txid);
        let signed_tx =
            paying_bundle.and_then(|paying_bundle| donation_signed_tx(&paying_bundle.tx));
        // the mint paying the recipient was saved when the consignment was accepted
        let mint_consignment = self.has_received_mint(&recipient_id);

        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        let mode = receive_mode_from_transfer(self, txn, &transfer)?;
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        let transport = NativeReceiveTransport::new(self);
        drive_native(self.ack_consignment_via(
            &transport,
            txn,
            batch_transfer,
            &transfer,
            &mut updated_batch_transfer,
            &mode,
            &recipient_seed,
            signed_tx,
            mint_consignment,
        ))
    }

    fn wait_ack(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Waiting ACK...");

        let mut batch_transfer_data =
            batch_transfer.get_transfers(&db_data.asset_transfers, &db_data.transfers)?;

        // collect the (shared) sender proxy endpoint and the IDs of the transfers registered on
        // it; out-of-band recipients have no sender proxy endpoint, as they are not registered
        // there (naming them in ack.get would make the proxy reject the whole request)
        let mut transfer_ids: Vec<String> = vec![];
        let mut sender_proxy: Option<String> = None;
        for asset_transfer_data in &batch_transfer_data.asset_transfers_data {
            for transfer in &asset_transfer_data.transfers {
                let transfer_sender_proxy = txn
                    .get_transfer_transport_endpoints_data(transfer.idx)?
                    .into_iter()
                    .find(|(tte, _)| tte.kind == TransportEndpointKind::SenderProxy)
                    .map(|(_, ce)| ce.endpoint);
                let Some(transfer_sender_proxy) = transfer_sender_proxy else {
                    continue;
                };
                // a SenderProxy endpoint is only ever saved for a proxy recipient transfer, which
                // always has a transfer ID: a missing one is corrupted data, and skipping it would
                // just leave the batch waiting until its expiration, so surface it instead
                let tid = transfer
                    .proxy_transfer_id
                    .clone()
                    .ok_or_else(|| Error::Internal {
                        details: format!(
                            "transfer {} has a sender proxy endpoint but no transfer ID",
                            transfer.idx
                        ),
                    })?;
                transfer_ids.push(tid);
                if sender_proxy.is_none() {
                    sender_proxy = Some(transfer_sender_proxy);
                }
            }
        }
        let Some(sender_proxy) = sender_proxy else {
            // no sender proxy registered (e.g. donation): nothing to wait for here
            return Ok(None);
        };

        // ack.get is authenticated: sign SHA-256(sorted recipient IDs ‖ timestamp) with the
        // operation (sender) key; the proxy verifies it against the registered sender_pk and
        // rejects timestamps outside its tolerance window
        let seed: [u8; 32] = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default()
            .try_into()
            .map_err(|_| Error::Internal {
                details: s!("invalid operation secret key"),
            })?;
        let sk = ed25519_from_seed(&seed);
        let proxy_client = ProxyClient::new(&sender_proxy)?;
        let ack_res = get_ack_signed(&proxy_client, &transfer_ids, &sk)?;
        debug!(self.logger(), "ACK get response: {:?}", ack_res);
        if let Some(err) = ack_res.error {
            // the sender proxy no longer knows the operation (e.g. it dropped its data): the ACKs
            // cannot be retrieved anymore and whether the TX was released cannot be known, so
            // settle via the chain if a recipient broadcast it, otherwise keep waiting until the
            // broadcast deadline has passed on the proxy's clock too, past which the proxy never
            // hands out a TX even if it recovers the operation and recipients stop broadcasting
            // it (v1.0-changes-spec.md 6.2)
            check_get_ack_error(err)?;
            return self
                .settle_untrusted_batch(
                    txn,
                    batch_transfer,
                    "the sender proxy no longer knows the operation",
                    Error::OperationNotFound,
                )
                .map(Some);
        }
        let ack_data = ack_res.result.ok_or_else(|| Error::Proxy {
            details: s!("missing ack.get result"),
        })?;

        for asset_transfer_data in batch_transfer_data.asset_transfers_data.iter_mut() {
            for transfer in asset_transfer_data.transfers.iter_mut() {
                if transfer.ack.is_some() {
                    continue;
                }
                let tte_data = txn.get_transfer_transport_endpoints_data(transfer.idx)?;
                // a transfer with no transport endpoints at all has nothing to poll; recipients that
                // never responded on the proxy are filtered out below by the missing ACK/signature
                if tte_data.is_empty() {
                    continue;
                }
                // transport endpoints are only saved for a proxy recipient transfer, which always
                // has a transfer ID: a missing one is corrupted data, and skipping it would just
                // leave the batch waiting until its expiration, so surface it instead
                let transfer_id =
                    transfer
                        .proxy_transfer_id
                        .clone()
                        .ok_or_else(|| Error::Internal {
                            details: format!(
                                "transfer {} has transport endpoints but no transfer ID",
                                transfer.idx
                            ),
                        })?;
                debug!(self.logger(), "Transfer ID: {transfer_id}");
                // a transfer absent from the response has not been responded to yet (its ACK/NACK
                // data was already fetched in bulk above)
                let ack = ack_data.acks.get(&transfer_id).copied();
                let sig = ack_data.signatures.get(&transfer_id).cloned();
                let (Some(ack), Some(sig_hex)) = (ack, sig) else {
                    continue;
                };

                // verify the recipient's ACK signature
                let pubkey = transfer
                    .recipient_pubkey
                    .as_ref()
                    .ok_or_else(|| Error::Internal {
                        details: s!("missing recipient pubkey"),
                    })?;
                let vk = verifying_key_from_bytes(pubkey)?;
                let consignment_hash =
                    transfer
                        .consignment_hash
                        .clone()
                        .ok_or_else(|| Error::Internal {
                            details: s!("missing consignment hash"),
                        })?;
                let digest = Self::ack_digest(&transfer_id, ack, &consignment_hash);
                let sig_bytes =
                    hex::decode(&sig_hex).map_err(|_| Error::InvalidContentSignature)?;
                if !verify_ed25519(&vk, &digest, &sig_bytes) {
                    // the proxy served an ACK the recipient never signed, so it is corrupt or
                    // forging ACKs and nothing it says can be trusted. The batch cannot be failed
                    // right away either, as the proxy may have released the TX and ack.clean would
                    // be refused (due to the stored ACK), so, as v1.0-changes-spec.md 6.3
                    // prescribes, it is settled like one the proxy lost (6.2), surfacing the error
                    // while waiting
                    return self
                        .settle_untrusted_batch(
                            txn,
                            batch_transfer,
                            "the sender proxy serves an invalid ACK signature",
                            Error::InvalidContentSignature,
                        )
                        .map(Some);
                }

                let mut updated_transfer: DbTransferActMod = transfer.clone().into();
                updated_transfer.ack = ActiveValue::Set(Some(ack));
                updated_transfer.ack_signature = ActiveValue::Set(Some(sig_bytes.clone()));
                txn.update_transfer(&mut updated_transfer)?;
                transfer.ack = Some(ack);
                transfer.ack_signature = Some(sig_bytes);
            }
        }

        let mut batch_transfer_transfers: Vec<DbTransfer> = vec![];
        batch_transfer_data
            .asset_transfers_data
            .iter()
            .for_each(|atd| batch_transfer_transfers.extend(atd.transfers.clone()));
        self.try_complete_batch(txn, batch_transfer, &batch_transfer_transfers)
    }

    fn try_complete_batch(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        transfers: &[DbTransfer],
    ) -> Result<Option<DbBatchTransfer>, Error> {
        if transfers.iter().any(|t| t.ack == Some(false)) {
            return Ok(Some(
                self.fail_batch_transfer(txn, batch_transfer)
                    .map_err(|e| match e {
                        Error::MultisigTransferStatusMismatch => Error::MultisigUnexpectedData {
                            details: s!("hub reports accepted=true but recipient sent a NACK"),
                        },
                        other => other,
                    })?,
            ));
        }
        if !transfers.iter().all(|t| t.ack == Some(true)) {
            return Ok(None);
        }

        // every recipient has ACKed: broadcast the transaction if transfer hasn't expired

        // don't broadcast a transfer that has expired: past its expiration the recipient is allowed
        // to fail it, so broadcasting now could complete a transfer the recipient has already given
        // up on. When every ACK came (signed) from the sender proxy, the proxy released the TX to
        // the recipients, so the transfer cannot simply be failed anymore: the TX is broadcast
        // while no invoice has expired, while past that a recipient that didn't obtain the TX
        // (v1.0-changes-spec.md 6.3) may have failed the transfer, so the transfer only progresses
        // if the TX is found on-chain and can otherwise only be failed after spending one of its
        // inputs (v1.0-changes-spec.md 6.1)
        let released = transfers.iter().all(|t| t.ack_signature.is_some());
        let now = now().unix_timestamp();
        if !released && batch_transfer.is_expired(now) {
            debug!(
                self.logger(),
                "Transfer expired before broadcast, failing it instead of broadcasting"
            );
            return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
        }
        if released && Self::any_invoice_expired(transfers, now) {
            if let Some(updated) = self.complete_batch_if_tx_on_chain(txn, batch_transfer)? {
                return Ok(Some(updated));
            }
            // the TX can never confirm once one of its inputs has been spent by another confirmed
            // transaction, which is the only way such an operation can fail
            if self.tx_inputs_spent_elsewhere(batch_transfer)? {
                info!(
                    self.logger(),
                    "An input of the TX has been spent by another confirmed transaction, failing the transfer"
                );
                return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
            }
            warn!(
                self.logger(),
                "Every recipient ACKed but an invoice has expired: not broadcasting the TX"
            );
            return Ok(None);
        }
        match self.set_hub_accept_status(batch_transfer.idx)? {
            Some(true) => {}
            Some(false) => return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?)),
            None => return Ok(None),
        }
        Ok(Some(self.broadcast_batch(txn, batch_transfer)?))
    }

    /// Whether the invoice expiration of any recipient has passed, accounting for the clock skew
    /// with the recipient.
    fn any_invoice_expired(transfers: &[DbTransfer], now: i64) -> bool {
        transfers
            .iter()
            .filter_map(|t| t.invoice_expiration)
            .any(|exp| now + PROXY_CLOCK_SKEW_MARGIN_SECS as i64 >= exp)
    }

    /// Broadcast the TX of an outgoing batch transfer (a no-op on the network if a recipient
    /// already did), update the RGB state and move the transfer to `WaitingConfirmations`.
    fn broadcast_batch(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<DbBatchTransfer, Error> {
        let txid = batch_transfer
            .txid
            .as_ref()
            .expect("batch transfer should have a TXID");
        let transfer_dir = self.get_transfers_dir().join(txid);
        let signed_tx = self.get_signed_tx(&transfer_dir)?;
        let mut stock = self.rgb_stock(txn)?;
        let fascia = self.read_fascia_at(&self.wallet_key(&transfer_dir.join(FASCIA_FILE))?)?;
        self.broadcast_and_update_rgb(txn, &mut stock, signed_tx, fascia)?;
        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        updated_batch_transfer.status = ActiveValue::Set(TransferStatus::WaitingConfirmations);

        txn.update_batch_transfer(&mut updated_batch_transfer)
    }

    /// Settle an outgoing batch transfer whose sender proxy can no longer be relied upon to tell
    /// whether the signed TX was released (it lost the operation, or serves an ACK with an invalid
    /// signature), as `v1.0-changes-spec.md` 6.2 and 6.3 prescribe: complete it if its TX is
    /// on-chain, otherwise fail it once its broadcast deadline (expiration plus the sender proxy
    /// retention grace) has passed on the proxy's clock too, past which the proxy never hands out
    /// a TX and recipients that obtained it stop broadcasting it, accepting the residual risk of a
    /// TX broadcast later anyway.
    ///
    /// While the transfer has to keep waiting, `waiting_error` is returned, so that the refresh
    /// reports why the transfer cannot progress and a fail attempt is denied.
    ///
    /// `reason` describes why the proxy cannot be relied upon, for the logs.
    fn settle_untrusted_batch(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        reason: &str,
        waiting_error: Error,
    ) -> Result<DbBatchTransfer, Error> {
        if let Some(updated) = self.complete_batch_if_tx_on_chain(txn, batch_transfer)? {
            return Ok(updated);
        }
        if !broadcast_deadline_passed_beyond_skew_margin(batch_transfer) {
            return Err(waiting_error);
        }
        warn!(
            self.logger(),
            "Failing a transfer past its broadcast deadline as {reason}: its TX can still be broadcast if it was released"
        );
        self.fail_batch_transfer(txn, batch_transfer)
    }

    /// Complete an outgoing batch transfer waiting for its counterparty if its TX is on-chain
    /// (mempool included), which happens when a recipient obtained the TX from the sender proxy
    /// and broadcast it without the sender learning about the ACKs.
    ///
    /// Finding the TX guarantees the transfer cannot be failed. Not finding it gives no
    /// guarantee: a recipient may still hold the TX and broadcast it later.
    fn complete_batch_if_tx_on_chain(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        let Some(txid) = &batch_transfer.txid else {
            return Ok(None);
        };
        if self.indexer().get_tx_confirmations(txid)?.is_none() {
            return Ok(None);
        }
        info!(
            self.logger(),
            "TX of a transfer waiting for the counterparty found on-chain"
        );
        Ok(Some(self.broadcast_batch(txn, batch_transfer)?))
    }

    fn provide_out_of_band_ack_impl(
        &mut self,
        txn: &DbTxn,
        recipient_id: String,
    ) -> Result<Option<OperationResult>, Error> {
        let db_data = txn.get_db_data(false)?;

        // recipient IDs are unique per transfer, so this identifies a single recipient transfer
        let transfer = db_data
            .transfers
            .iter()
            .find(|t| t.recipient_id.as_deref() == Some(recipient_id.as_str()))
            .cloned()
            .ok_or(Error::CannotProvideOutOfBandAck {
                details: s!("no transfer found for the provided recipient ID"),
            })?;
        let asset_transfer = db_data
            .asset_transfers
            .iter()
            .find(|at| at.idx == transfer.asset_transfer_idx)
            .cloned()
            .expect("transfer should have an asset transfer");
        let batch_transfer = db_data
            .batch_transfers
            .iter()
            .find(|bt| bt.idx == asset_transfer.batch_transfer_idx)
            .cloned()
            .expect("asset transfer should have a batch transfer");

        // check if the transfer can receive an out-of-band ACK
        if batch_transfer.incoming {
            return Err(Error::CannotProvideOutOfBandAck {
                details: s!("only outgoing transfers can be ACKed"),
            });
        }
        if batch_transfer.status != TransferStatus::WaitingCounterparty {
            return Err(Error::CannotProvideOutOfBandAck {
                details: s!("only WaitingCounterparty transfers can be ACKed"),
            });
        }
        // a RECIPIENT-facing proxy endpoint means the consignment/ACK are exchanged automatically
        // (via refresh); the sender's own SenderProxy endpoint (v1.0, for ACK retrieval) doesn't
        // make the recipient automated, so it must not block an out-of-band ACK
        let tte_data = txn.get_transfer_transport_endpoints_data(transfer.idx)?;
        if tte_data
            .iter()
            .any(|(tte, _)| tte.kind == TransportEndpointKind::RecipientProxy)
        {
            return Err(Error::CannotProvideOutOfBandAck {
                details: s!(
                    "recipient uses an automated transport; use refresh() to complete it instead"
                ),
            });
        }

        // record the out-of-band ACK (if not there already)
        if transfer.ack != Some(true) {
            let mut updated_transfer: DbTransferActMod = transfer.clone().into();
            updated_transfer.ack = ActiveValue::Set(Some(true));
            txn.update_transfer(&mut updated_transfer)?;
        }

        // gather the batch's transfers, reflecting the ACK just recorded, and try to complete the
        // batch (broadcasting only once every recipient, out-of-band or automated transport, has
        // ACKed)
        let batch_transfer_data =
            batch_transfer.get_transfers(&db_data.asset_transfers, &db_data.transfers)?;
        let mut transfers: Vec<DbTransfer> = vec![];
        batch_transfer_data
            .asset_transfers_data
            .iter()
            .for_each(|atd| transfers.extend(atd.transfers.clone()));
        // reflect the ACK in-memory, since `db_data` was loaded before the ACK was written to the
        // DB and `get_transfers` thus returns stale copies
        for t in transfers.iter_mut() {
            if t.idx == transfer.idx {
                t.ack = Some(true);
            }
        }

        let Some(updated) = self.try_complete_batch(txn, &batch_transfer, &transfers)? else {
            // other recipients still need to ACK: leave the batch WaitingCounterparty
            return Ok(None);
        };
        if updated.status != TransferStatus::WaitingConfirmations {
            // the batch was failed instead of broadcast (e.g. it expired)
            return Err(Error::CannotProvideOutOfBandAck {
                details: s!("transfer could not be completed"),
            });
        }

        let txid = updated
            .txid
            .clone()
            .expect("broadcast batch transfer should have a TXID");

        // recover the entropy used at send time for the operation result
        let transfer_dir = self.get_transfers_dir().join(&txid);
        let info_file = transfer_dir.join(TRANSFER_DATA_FILE);
        let serialized_info = String::from_utf8(self.files().read(&self.wallet_key(&info_file)?)?)
            .map_err(|e| Error::Internal {
                details: format!("cannot read {}: {e}", info_file.display()),
            })?;
        let info_contents: InfoBatchTransfer =
            serde_json::from_str(&serialized_info).map_err(InternalError::from)?;

        Ok(Some(OperationResult {
            txid,
            batch_transfer_idx: updated.idx,
            entropy: info_contents.entropy,
        }))
    }

    fn tx_height(&self, txid: String) -> Result<Option<u32>, Error> {
        let txid = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        Ok(
            match self
                .blockchain_resolver()
                .resolve_witness(txid)
                .map_err(|e| Error::Network {
                    details: e.to_string(),
                })? {
                WitnessStatus::Resolved(_, WitnessOrd::Mined(witness_pos)) => {
                    Some(witness_pos.height().get())
                }
                _ => None,
            },
        )
    }

    fn wait_confirmations(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
        incoming: bool,
        skip_sync: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Waiting confirmations...");
        let txid = batch_transfer
            .txid
            .clone()
            .expect("batch transfer should have a TXID");
        debug!(
            self.logger(),
            "Getting details of transaction with ID '{}'...", txid
        );
        let confirmations = self.indexer().get_tx_confirmations(&txid)?;
        debug!(self.logger(), "Confirmations: {:?}", confirmations);

        // an incoming transfer with a broadcast deadline (released via the sender proxy) whose TX
        // is not confirmed is failed once past the deadline plus the confirmation margin, while
        // until the deadline its TX is broadcast again if missing (v1.0-changes-spec.md 6.4)
        if incoming
            && batch_transfer.broadcast_deadline.is_some()
            && confirmations.unwrap_or(0) == 0
        {
            if confirmation_deadline_passed(batch_transfer) {
                info!(
                    self.logger(),
                    "TX not confirmed past the broadcast deadline, failing the transfer"
                );
                return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
            }
            if confirmations.is_none()
                && batch_transfer
                    .broadcast_deadline
                    .is_some_and(|deadline| now().unix_timestamp() <= deadline)
            {
                let (_, transfer) = batch_transfer
                    .get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
                if let Some(recipient_id) = &transfer.recipient_id {
                    self.rebroadcast_received_tx(recipient_id);
                }
            }
        }

        let Some(confirmations) = confirmations else {
            return Ok(None);
        };

        if confirmations < batch_transfer.min_confirmations as u64 {
            if batch_transfer.status == TransferStatus::WaitingBroadcast {
                let mut updated_batch_transfer: DbBatchTransferActMod =
                    batch_transfer.clone().into();
                updated_batch_transfer.status =
                    ActiveValue::Set(TransferStatus::WaitingConfirmations);
                return Ok(Some(
                    txn.update_batch_transfer(&mut updated_batch_transfer)?,
                ));
            }
            return Ok(None);
        }

        if incoming {
            let (asset_transfer, transfer) = batch_transfer
                .get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
            let recipient_id = transfer
                .clone()
                .recipient_id
                .expect("transfer should have a recipient ID");
            debug!(self.logger(), "Recipient ID: {recipient_id}");

            if let Some(RecipientTypeFull::Witness { vout }) = transfer.recipient_type {
                if !skip_sync {
                    self.sync_wallet(
                        txn,
                        SyncOptions {
                            keychain: SyncKeychain::Colored,
                            strategy: SyncStrategy::FastSync,
                        },
                        false,
                    )?;
                }
                let outpoint = Outpoint {
                    txid: txid.clone(),
                    vout: vout.unwrap(),
                };
                let txo = txn.get_txo(&outpoint)?.expect("txo must exist");
                let mut txo: DbTxoActMod = txo.into();
                txo.pending_witness = ActiveValue::Set(false);
                txn.update_txo(txo)?;
            }

            // accept consignment
            let valid_consignment =
                self.load_received_valid_transfer(batch_transfer, &recipient_id)?;
            let mut stock = self.rgb_stock(txn)?;
            stock.accept_transfer(valid_consignment.clone(), &self.blockchain_resolver())?;
            self.delete_valid_consignment(&recipient_id)?;
            let asset_schema: AssetSchema = valid_consignment.schema_id().try_into()?;
            match asset_schema {
                AssetSchema::Ifa => {
                    let contract_id = valid_consignment.contract_id();
                    let contract_wrapper =
                        stock.contract_wrapper::<InflatableFungibleAsset>(contract_id)?;
                    let known_circulating_supply = contract_wrapper.total_issued_supply().into();
                    let asset_id = asset_transfer.asset_id.unwrap();
                    let db_asset = txn.get_asset(asset_id).unwrap().unwrap();
                    let db_known_circulating_supply = db_asset
                        .known_circulating_supply
                        .as_ref()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    if db_known_circulating_supply < known_circulating_supply {
                        let mut updated_asset: DbAssetActMod = db_asset.into();
                        updated_asset.known_circulating_supply =
                            ActiveValue::Set(Some(known_circulating_supply.to_string()));
                        txn.update_asset(&mut updated_asset)?;
                    }
                }
                AssetSchema::Nia | AssetSchema::Uda | AssetSchema::Cfa | AssetSchema::Bfa => {}
            }
        }

        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        updated_batch_transfer.status = ActiveValue::Set(TransferStatus::Settled);
        Ok(Some(
            txn.update_batch_transfer(&mut updated_batch_transfer)?,
        ))
    }

    fn wait_counterparty(
        &mut self,
        txn: &DbTxn,
        transfer: &DbBatchTransfer,
        db_data: &DbData,
        incoming: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        // a transfer from the previous proxy protocol can neither be received nor ACKed anymore,
        // and failing it right away, without waiting for the expiration, is safe: an incoming one
        // was never ACKed, so its sender never broadcasts; an outgoing one is only ever broadcast
        // by this wallet, which won't happen anymore
        if transfer.is_legacy() {
            info!(
                self.logger(),
                "Transfer from the previous proxy protocol cannot be completed, failing it"
            );
            return Ok(Some(self.fail_batch_transfer(txn, transfer)?));
        }
        if incoming {
            self.wait_consignment(txn, transfer, db_data)
        } else {
            self.wait_ack(txn, transfer, db_data)
        }
    }

    fn refresh_transfer(
        &mut self,
        txn: &DbTxn,
        transfer: &DbBatchTransfer,
        db_data: &DbData,
        filter: &[RefreshFilter],
        skip_sync: bool,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Refreshing transfer: {:?}", transfer);
        let incoming = transfer.incoming;
        if !filter.is_empty() {
            let requested = RefreshFilter {
                status: RefreshTransferStatus::try_from(transfer.status).expect("pending status"),
                incoming,
            };
            if !filter.contains(&requested) {
                return Ok(None);
            }
        }
        match transfer.status {
            TransferStatus::WaitingCounterparty => {
                if self.get_hub_fail_status(transfer.idx)? {
                    return Ok(Some(self.fail_batch_transfer(txn, transfer)?));
                }
                self.wait_counterparty(txn, transfer, db_data, incoming)
            }
            TransferStatus::WaitingSafeHeight => self.wait_safe_height(txn, transfer, db_data),
            // a proxy recipient that ACKed polls the sender proxy for the TX (or expiration); an
            // out-of-band recipient instead waits for the sender to broadcast and watches the chain
            // (as WaitingConfirmations does), since it has no sender proxy to poll
            TransferStatus::WaitingBroadcast => {
                let (_, incoming_transfer) =
                    transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
                if incoming_transfer.uses_out_of_band_exchange() {
                    // out-of-band: the sender broadcasts once every recipient ACKs; watch the chain
                    self.wait_confirmations(txn, transfer, db_data, incoming, skip_sync)
                } else {
                    // proxy recipient: if the TX is already on-chain (broadcast by the sender when the
                    // batch completed, or by an earlier poll) settle via the chain; otherwise poll the
                    // sender proxy for the TX (or expiration)
                    match self.wait_confirmations(txn, transfer, db_data, incoming, skip_sync)? {
                        Some(updated) => Ok(Some(updated)),
                        None => self.wait_broadcast(txn, transfer, db_data),
                    }
                }
            }
            TransferStatus::WaitingConfirmations => {
                self.wait_confirmations(txn, transfer, db_data, incoming, skip_sync)
            }
            _ => Ok(None),
        }
    }

    /// A proxy recipient that has ACKed polls the sender proxy until the signed TX is
    /// released, then decrypts and broadcasts it.
    fn wait_broadcast(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
        db_data: &DbData,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        debug!(self.logger(), "Waiting broadcast...");

        let (_, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;

        // a legacy transfer was ACKed on the recipient proxy, so the sender may still broadcast the
        // TX (which can be detected on-chain) until the expiration, after which the transfer is
        // failed
        if batch_transfer.is_legacy() {
            let now = now().unix_timestamp();
            if batch_transfer.is_expired(now) {
                info!(
                    self.logger(),
                    "Expired transfer from the previous proxy protocol, failing it"
                );
                return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
            }
            debug!(self.logger(), "Waiting for the sender to broadcast");
            return Ok(None);
        }

        // a received mint has no broadcast deadline, as it's not registered on the sender proxy
        // (see ack_consignment), and can no longer expire, its lock being finalized: it's waited
        // for until its TX is broadcast (detected by wait_confirmations, tried before this on
        // every refresh), or failed once the TX can never confirm
        if self.is_mint(batch_transfer, db_data)? {
            let recipient_id = transfer
                .recipient_id
                .as_deref()
                .expect("transfer should have a recipient ID");
            if self.received_mint_tx_inputs_spent_elsewhere(batch_transfer, recipient_id)? {
                info!(
                    self.logger(),
                    "An input of the mint TX has been spent by another confirmed transaction, \
                     failing the transfer"
                );
                return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
            }
            debug!(self.logger(), "Waiting for the minter to broadcast");
            return Ok(None);
        }

        // sender proxy endpoint (where the signed TX is released); without one there is nothing
        // to ask for the TX, the sender broadcasts it and wait_confirmations detects it on-chain
        let mut sender_proxy = None;
        for (tte, ce) in txn.get_transfer_transport_endpoints_data(transfer.idx)? {
            if tte.kind == TransportEndpointKind::SenderProxy {
                sender_proxy = Some(ce.endpoint);
                break;
            }
        }
        let Some(sender_proxy) = sender_proxy else {
            debug!(
                self.logger(),
                "No sender proxy, waiting for the sender to broadcast"
            );
            return Ok(None);
        };

        let consignment_hash =
            transfer
                .consignment_hash
                .clone()
                .ok_or_else(|| Error::Internal {
                    details: s!("missing consignment hash"),
                })?;
        let recipient_seed = batch_transfer
            .operation_secret_key
            .clone()
            .unwrap_or_default();

        let transfer_id = transfer
            .proxy_transfer_id
            .clone()
            .ok_or_else(|| Error::Internal {
                details: s!("missing transfer ID"),
            })?;
        // the TX is not on-chain (wait_confirmations is tried before this on every refresh):
        // past the broadcast deadline plus the confirmation margin the transfer is failed, unless
        // the proxy still releases the TX (v1.0-changes-spec.md 6.4)
        let fail_if_past_deadline = |wallet: &mut Self| -> Result<Option<DbBatchTransfer>, Error> {
            if confirmation_deadline_passed(batch_transfer) {
                info!(
                    wallet.logger(),
                    "TX not confirmed past the broadcast deadline, failing the transfer"
                );
                return Ok(Some(wallet.fail_batch_transfer(txn, batch_transfer)?));
            }
            Ok(None)
        };
        let res = match self.sign_and_post_ack(
            &sender_proxy,
            &transfer_id,
            true,
            &consignment_hash,
            &recipient_seed,
        ) {
            Ok(r) => r,
            // the operation expired without releasing the TX, which never will be: fail the
            // transfer
            Err(Error::OperationExpired) => {
                return Ok(Some(self.fail_batch_transfer(txn, batch_transfer)?));
            }
            // the sender proxy no longer knows the operation: a TX released before can still be
            // broadcast (and detected on-chain) until the broadcast deadline. An operation never
            // registered there (e.g. mint) has no broadcast deadline: the TX is broadcast by the
            // sender and wait_confirmations (tried before this on every refresh) detects it
            Err(Error::OperationNotFound) => return fail_if_past_deadline(self),
            // no definite answer: fail the transfer once past the broadcast deadline
            Err(e) => {
                if let Some(updated) = fail_if_past_deadline(self)? {
                    return Ok(Some(updated));
                }
                return Err(e);
            }
        };

        let mut updated_batch_transfer: DbBatchTransferActMod = batch_transfer.clone().into();
        // a transfer ACKed via a proxy not returning the operation expiration yet has no broadcast
        // deadline, set it as soon as it's known
        let mut deadline_changed = false;
        if batch_transfer.broadcast_deadline.is_none()
            && let Some(deadline) = broadcast_deadline(
                res.expires_at.as_deref(),
                sender_proxy_retention_grace(&sender_proxy)?,
                batch_transfer.expiration,
            )
        {
            updated_batch_transfer.broadcast_deadline = ActiveValue::Set(Some(deadline));
            deadline_changed = true;
        }

        match (res.signed_tx, res.signed_tx_hash, res.sender_pk) {
            (Some(signed_tx), Some(signed_tx_hash), Some(sender_pubkey)) => {
                let recipient_id = transfer
                    .recipient_id
                    .clone()
                    .expect("transfer should have a recipient ID");
                self.broadcast_received_tx(
                    &recipient_id,
                    &signed_tx,
                    &signed_tx_hash,
                    &sender_pubkey,
                    &recipient_seed,
                )?;
                updated_batch_transfer.status =
                    ActiveValue::Set(TransferStatus::WaitingConfirmations);
                Ok(Some(
                    txn.update_batch_transfer(&mut updated_batch_transfer)?,
                ))
            }
            // still waiting on the other recipients (or a non-compliant proxy)
            _ => {
                if deadline_changed {
                    // the status is unchanged, the deadline is checked on the next refresh
                    txn.update_batch_transfer(&mut updated_batch_transfer)?;
                    return Ok(None);
                }
                fail_if_past_deadline(self)
            }
        }
    }

    fn refresh_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: Option<String>,
        filter: Vec<RefreshFilter>,
        skip_sync: bool,
    ) -> Result<RefreshResult, Error> {
        let mut db_data = txn.get_db_data(false)?;

        if asset_id.is_some() {
            let batch_transfers_ids: Vec<i32> = db_data
                .asset_transfers
                .iter()
                .filter(|t| t.asset_id == asset_id)
                .map(|t| t.batch_transfer_idx)
                .collect();
            db_data
                .batch_transfers
                .retain(|t| batch_transfers_ids.contains(&t.idx));
        };
        db_data.batch_transfers.retain(|t| t.waiting());

        let mut refresh_result = HashMap::new();
        for transfer in &db_data.batch_transfers {
            let mut failure = None;
            let mut updated_status = None;
            // a failed refresh must not leave its partial changes behind (e.g. the colorings of a
            // consignment validated before its ACK failed), as the next one would redo them
            match txn.with_savepoint(|txn| {
                self.refresh_transfer(txn, transfer, &db_data, &filter, skip_sync)
            }) {
                Ok(Some(updated_transfer)) => updated_status = Some(updated_transfer.status),
                Err(e) => failure = Some(e),
                _ => {}
            }
            refresh_result.insert(
                transfer.idx,
                RefreshedTransfer {
                    updated_status,
                    failure,
                },
            );
        }

        Ok(refresh_result)
    }

    fn finalize_transfer_end(
        &mut self,
        txn: &DbTxn,
        txid: String,
        psbt: &Psbt,
        info_contents: &InfoBatchTransfer,
        status: TransferStatus,
        consignment_hashes: &HashMap<String, String>,
        fascia: Fascia,
        sync_tte_used: bool,
    ) -> Result<i32, Error> {
        let mut stock = self.rgb_stock(txn)?;
        let signed_tx = psbt.clone().extract_tx().map_err(InternalError::from)?;
        self.broadcast_and_update_rgb(txn, &mut stock, signed_tx, fascia)?;
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

    #[allow(clippy::too_many_arguments)]
    fn send_begin_impl(
        &mut self,
        txn: &DbTxn,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: Option<i64>,
        sender_transport_endpoint: Option<String>,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        if recipient_map.is_empty() || recipient_map.values().any(|v| v.is_empty()) {
            return Err(Error::InvalidRecipientMap);
        }
        if let Some(expiration_timestamp) = expiration_timestamp {
            check_operation_expiration(expiration_timestamp)?;
        }
        if let Some(endpoint) = &sender_transport_endpoint {
            self.convert_transport_endpoint_url(endpoint)?;
        }

        let operation_sk = gen_ed25519();
        let operation_secret_key = operation_sk.to_bytes().to_vec();
        let now_ts = now().unix_timestamp();
        // earliest invoice expiration among the proxy recipients, bounding the operation one
        let mut min_invoice_expiration: Option<i64> = None;

        let (fee_rate_checked, unspents, input_unspents, mut stock) =
            self.get_transfer_begin_data(txn, fee_rate)?;

        let chainnet: ChainNet = self.bitcoin_network().into();
        let mut witness_recipients: Vec<(ScriptBuf, u64)> = vec![];
        let mut recipient_vout = 1;
        let main_transition = MainTransition::Transfer;
        let mut assets_data: BTreeMap<String, (AssetInfo, AssignmentsCollection)> = BTreeMap::new();
        let mut local_recipients: BTreeMap<String, Vec<LocalRecipient>> = BTreeMap::new();
        for (asset_id, recipients) in &recipient_map {
            let asset = txn.check_asset_exists(asset_id.clone())?;
            let schema = asset.schema;
            self.check_schema_support(&schema)?;

            let mut original_assignments_needed = AssignmentsCollection::default();
            for recipient in recipients {
                // a proxy recipient posts its ACK to (and gets the signed TX from) the sender
                // proxy, so one is needed
                if !recipient.transport_endpoints.is_empty() && sender_transport_endpoint.is_none()
                {
                    return Err(Error::InvalidTransportEndpoint {
                        details: s!("missing sender transport endpoint"),
                    });
                }
                let (local_recipient, witness_output) = self.parse_recipient(
                    recipient,
                    schema,
                    chainnet,
                    recipient_vout,
                    &operation_sk,
                    now_ts,
                    false,
                )?;
                if let Some(witness_output) = witness_output {
                    witness_recipients.push(witness_output);
                    recipient_vout += 1;
                }
                if let Some(invoice_expiration) = local_recipient.invoice_expiration {
                    min_invoice_expiration = Some(
                        min_invoice_expiration
                            .map_or(invoice_expiration, |m| std::cmp::min(m, invoice_expiration)),
                    );
                }
                local_recipients
                    .entry(asset_id.clone())
                    .or_default()
                    .push(local_recipient);

                // an asset has at most one link right
                if recipient.assignment == Assignment::LinkRight && original_assignments_needed.link
                {
                    return Err(Error::InvalidRecipientData {
                        details: s!("the link right can only be sent to a single recipient"),
                    });
                }
                recipient
                    .assignment
                    .add_to_assignments(&mut original_assignments_needed);
            }
            // a single mint right is enough to send any number of them, as the schema allows
            // mint rights to be duplicated (a transfer needs at least as many outputs as inputs)
            original_assignments_needed.mint = min(original_assignments_needed.mint, 1);
            let contract_id = ContractId::from_str(asset_id).expect("invalid contract ID");
            assets_data.insert(
                asset_id.clone(),
                (
                    AssetInfo {
                        contract_id,
                        schema,
                        reject_list_url: asset.reject_list_url,
                    },
                    original_assignments_needed,
                ),
            );
        }

        // the operation must expire sufficiently before every invoice, so its TX can only be
        // released while the recipients are still waiting for it (v1.0-changes-spec.md 6.1)
        if !donation
            && let (Some(expiration), Some(min_invoice_expiration)) =
                (expiration_timestamp, min_invoice_expiration)
            && expiration > min_invoice_expiration - invoice_expiration_margin() as i64
        {
            return Err(Error::InvalidExpiration);
        }

        // whether the transport endpoints are usable is checked once all the recipients have
        // passed the checks that need no network
        Self::check_recipients_transport_endpoints(
            local_recipients.values_mut().flatten(),
            check_proxy_usable,
        )?;

        let receive_ids: Vec<String> = recipient_map
            .values()
            .flatten()
            .map(|r| r.recipient_id.clone())
            .collect();
        let transfer_dir = self.setup_transfer_directory(receive_ids)?;

        let mut rejected = HashSet::new();
        let mut reject_lists = HashMap::new();
        let mut transfer_info_map: BTreeMap<String, InfoAssetTransfer> = BTreeMap::new();
        let mut invoices_checked = false;

        Ok(loop {
            // the inputs selected for all the assets, which are spent together, selected for one
            // asset after the other in a stable order (by asset ID), as the selection for an asset
            // depends on the UTXOs selected for the ones before
            let mut selected = SelectedInputs::default();
            for asset_id in assets_data.keys() {
                let (asset_info, original_assignments_needed) =
                    assets_data.get(asset_id).unwrap().clone();
                let assignments_needed =
                    if let Some(existing_info) = transfer_info_map.get(asset_id) {
                        existing_info.assignments_needed.clone()
                    } else {
                        original_assignments_needed.clone()
                    };

                // if no more assignments this returns an error that makes the loop stop
                let asset_spend = self.select_rgb_inputs(
                    asset_id.clone(),
                    &assignments_needed,
                    input_unspents.clone(),
                    &mut selected,
                    Self::max_input_allocations(&TypeOfTransition::Transfer),
                )?;

                let transfer_info = InfoAssetTransfer {
                    asset_info,
                    recipients: local_recipients[asset_id].clone(),
                    asset_spend,
                    change: AssignmentsCollection::default(),
                    original_assignments_needed,
                    assignments_needed,
                    assignments_spent: HashMap::new(),
                    change_destinations: vec![],
                    main_transition,
                    beneficiaries_blinded: vec![],
                    beneficiaries_witness: vec![],
                };
                transfer_info_map.insert(asset_id.clone(), transfer_info);
            }

            // now that the assignments are confirmed available (select_rgb_inputs succeeded), ensure
            // each invoice can still accept a transfer on (one of) its proxies, proceeding only if
            // a proxy reports it as available. Done here (not earlier) so an InsufficientAssignments
            // error takes precedence
            if !invoices_checked {
                invoices_checked = true;
                for recipients in local_recipients.values() {
                    // out-of-band recipients have no proxy to check
                    for lr in recipients
                        .iter()
                        .filter(|lr| !lr.transport_endpoints.is_empty())
                    {
                        let (invoice_id, _) = lr.proxy_ids("");
                        let mut full = false;
                        let mut unknown = false;
                        let mut available = false;
                        for lte in lr.transport_endpoints.iter().filter(|e| e.usable) {
                            // a proxy that cannot be asked is skipped, as another one may still
                            // have the invoice available
                            let result = match ProxyClient::new(&lte.endpoint)
                                .and_then(|c| c.check_invoices(std::slice::from_ref(&invoice_id)))
                            {
                                Ok(res) => res.result,
                                Err(e) => {
                                    debug!(self.logger(), "Invoice check error: {e}");
                                    continue;
                                }
                            };
                            match result.and_then(|r| r.get(&invoice_id).map(|r| r.status)) {
                                Some(InvoiceStatus::Available) => {
                                    available = true;
                                    break;
                                }
                                Some(InvoiceStatus::Full) => full = true,
                                Some(InvoiceStatus::Unknown) => unknown = true,
                                None => {}
                            }
                        }
                        if !available {
                            return Err(if full {
                                Error::InvoiceQuotaExceeded
                            } else if unknown {
                                Error::InvoiceNotReserved
                            } else {
                                Error::NoValidTransportEndpoint
                            });
                        }
                    }
                }
            }

            match self.prepare_transfer_psbt(
                txn,
                &mut transfer_info_map,
                transfer_dir.clone(),
                donation,
                unspents.clone(),
                &input_unspents,
                &witness_recipients,
                fee_rate_checked,
                min_confirmations,
                expiration_timestamp,
                sender_transport_endpoint.clone(),
                Some(operation_secret_key.clone()),
                &mut stock,
                &mut rejected,
                &mut reject_lists,
                dry_run,
            )? {
                PrepareTransferPsbtResult::Retry => continue,
                PrepareTransferPsbtResult::Success(begin_operation_data) => {
                    break *begin_operation_data;
                }
            }
        })
    }

    fn send_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<OperationResult, Error> {
        // a send ended again (e.g. retried after a crash) is completed only while it's still in
        // progress: one that has failed (which revoked its signed TX on the sender proxy) or
        // progressed must not be brought back to waiting for the counterparty. This is checked
        // before reading the transfer data, which doesn't parse for a send from before the proxy
        // protocol update (failed by the upgrade)
        let txid = signed_psbt.unsigned_tx.compute_txid().to_string();
        if let Some(existing) = txn
            .get_batch_transfers_by_txid(&txid)?
            .into_iter()
            .find(|batch_transfer| !batch_transfer.incoming)
            && !matches!(
                existing.status,
                TransferStatus::Initiated | TransferStatus::WaitingCounterparty
            )
        {
            return Err(Error::CannotEndTransfer { txid });
        }

        let (_, transfer_dir, mut info_contents, mut fascia) =
            self.get_transfer_end_data(signed_psbt)?;

        // the data must be of this operation: another one would be completed skipping its checks
        // and steps
        if !info_contents.is_operation(&TypeOfTransition::Transfer) {
            return Err(Error::WrongOperation { txid });
        }

        // extract the signed transaction (needed for its hash and, for donations, to embed it)
        let tx = signed_psbt
            .clone()
            .extract_tx()
            .map_err(InternalError::from)?;
        let tx_bytes = bdk_wallet::bitcoin::consensus::encode::serialize(&tx);
        let signed_tx_hash_raw = sha256_digest(&tx_bytes);
        let signed_tx_hash = hex::encode(signed_tx_hash_raw);

        // for donations, embed the signed transaction in the consignment so also the recipient can
        // broadcast it
        if info_contents.donation {
            fascia.update_witness_tx(tx.clone());
        }

        self.gen_consignments(txn, &fascia, &info_contents.transfers, &transfer_dir)?;

        // only the TX is needed to broadcast it
        let signed_tx_key = self.wallet_key(&transfer_dir.join(SIGNED_TX_FILE))?;
        self.files()
            .atomic_write(&signed_tx_key, hex::encode(&tx_bytes).as_bytes())?;

        // sender operation key (one per operation, shared across all recipients)
        let seed: [u8; 32] = info_contents
            .operation_secret_key
            .clone()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Internal {
                details: s!("missing operation secret key"),
            })?;
        let sender_sk = ed25519_from_seed(&seed);
        let sender_pubkey_hex = hex::encode(sender_sk.verifying_key().to_bytes());
        // only needed by proxy recipients (checked by send_begin), absent for an all-out-of-band send
        let sender_transport_endpoint = info_contents.sender_transport_endpoint.clone();

        let total_recipients: usize = info_contents
            .transfers
            .values()
            .map(|t| t.recipients.len())
            .sum();
        let batch = total_recipients > 1;

        let consignment_hashes = self.consignment_hashes(&transfer_dir, &info_contents)?;

        // ACK preparation on the sender's own proxy (non-donation only, and only when at least one
        // recipient uses a proxy), before posting consignments
        let has_proxy_recipients = info_contents.transfers.values().any(|t| {
            t.recipients
                .iter()
                .any(|r| !r.transport_endpoints.is_empty())
        });
        // expiration plus the sender proxy retention grace, until which recipients may still
        // obtain and broadcast the signed TX (v1.0-changes-spec.md 6.2)
        let mut broadcast_deadline = None;
        // whether the operation was registered earlier and has expired since, so there is nothing
        // left to post
        let mut operation_expired = false;
        if !info_contents.donation && has_proxy_recipients {
            let mut transfer_data: HashMap<String, AckTransferData> = HashMap::new();
            for (asset_id, info_asset) in &info_contents.transfers {
                let consignment_hash = consignment_hashes[asset_id].clone();
                for recipient in &info_asset.recipients {
                    // out-of-band recipients never contact the sender proxy (their ACK and the
                    // signed TX are exchanged out-of-band), so they are not registered there
                    if recipient.transport_endpoints.is_empty() {
                        continue;
                    }
                    let vk = verifying_key_from_bytes(&recipient.public_key)?;
                    let derived = derive_shared(&sender_sk, &vk)?;
                    let enc_tx = encrypt_blob(&tx_bytes, &derived.sym_key, &signed_tx_hash_raw)?;
                    let (_, transfer_id) = recipient.proxy_ids(&sender_pubkey_hex);
                    transfer_data.insert(
                        transfer_id,
                        AckTransferData {
                            recipient_pk: hex::encode(&recipient.public_key),
                            consignment_hash: consignment_hash.clone(),
                            signed_tx: general_purpose::STANDARD.encode(&enc_tx),
                        },
                    );
                }
            }
            // a send with a counterparty always has an expiration (required by the public API)
            let expiration = info_contents
                .expiration_timestamp
                .ok_or_else(|| Error::Internal {
                    details: s!("missing expiration"),
                })?;
            let sender_transport_endpoint =
                sender_transport_endpoint
                    .as_deref()
                    .ok_or_else(|| Error::Internal {
                        details: s!("missing sender transport endpoint"),
                    })?;
            let sender_proxy_url =
                self.convert_transport_endpoint_url(sender_transport_endpoint)?;
            let retention_grace = sender_proxy_retention_grace(&sender_proxy_url)?;
            broadcast_deadline = Some(expiration.saturating_add(i64::from(retention_grace)));
            let proxy_client = ProxyClient::new(&sender_proxy_url)?;
            let transfer_ids: Vec<String> = transfer_data.keys().cloned().collect();
            let expiration = expiration.to_string();
            // only needed by proxies with proxy-level authentication enabled
            let signature = self.online_data().as_ref().and_then(|online_data| {
                online_data.proxy_auth_signature(
                    &sender_proxy_url,
                    &prepare_ack_auth_message(
                        &sender_pubkey_hex,
                        &expiration,
                        &signed_tx_hash,
                        &transfer_data,
                    ),
                )
            });
            let res = proxy_client.prepare_ack(
                transfer_data,
                &expiration,
                &signed_tx_hash,
                &sender_pubkey_hex,
                signature,
            )?;
            if let Some(err) = res.error {
                match map_proxy_error(err) {
                    // a prior ACK clean (e.g. by another multisig cosigner) nulled the signed TX
                    // for this operation; a cosigner now completing it tries to re-supply the
                    // signed TX, which is expected and should be ignored
                    //
                    // signed_tx is deterministic (given the same tx bytes and keys) and every other
                    // field still matches what's registered, meaning this error can only happen in
                    // the described case (nulled) and is not a real conflict, so continue posting
                    // the consignment(s) and updating local state
                    Error::SignedTxCleared => {}
                    // the operation has expired: if it was registered earlier (by this wallet
                    // before a crash, or by another multisig cosigner) only the local state is
                    // left to update, from which the refresh settles or fails the operation,
                    // otherwise it can no longer be started
                    e @ Error::ExpirationInvalid => {
                        if !sender_proxy_knows_operation(&proxy_client, &transfer_ids, &sender_sk)?
                        {
                            return Err(e);
                        }
                        operation_expired = true;
                    }
                    e => return Err(e),
                }
            }
        }

        // an expired operation can no longer progress, so its consignments are not posted
        if !operation_expired {
            let mut medias = None;
            let mut tokens = None;
            let mut token_medias = None;
            for (asset_id, info_contents_asset) in info_contents.transfers.iter_mut() {
                let asset = txn.get_asset(asset_id.clone())?.unwrap();
                let token = match asset.schema {
                    AssetSchema::Uda => {
                        if medias.clone().is_none() {
                            medias = Some(txn.iter_media()?);
                            tokens = Some(txn.iter_tokens()?);
                            token_medias = Some(txn.iter_token_medias()?);
                        }
                        self.get_asset_token(
                            asset.idx,
                            medias.as_ref().unwrap(),
                            tokens.as_ref().unwrap(),
                            token_medias.as_ref().unwrap(),
                        )
                    }
                    AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa | AssetSchema::Bfa => {
                        None
                    }
                };

                // post consignment(s) and optional media(s)
                let asset_transfer_dir = self.get_asset_transfer_dir(&transfer_dir, asset_id);
                let consignment_hash = consignment_hashes[asset_id].clone();
                self.post_transfer_data(
                    &mut info_contents_asset.recipients,
                    asset_transfer_dir,
                    self.get_asset_medias(txn, asset.media_idx, token)?,
                    &sender_sk,
                    &sender_pubkey_hex,
                    sender_transport_endpoint.as_deref(),
                    &consignment_hash,
                    batch,
                )?;
            }
        }

        let sync_tte_used = true;
        let batch_transfer_idx = if info_contents.donation {
            self.finalize_transfer_end(
                txn,
                txid.clone(),
                signed_psbt,
                &info_contents,
                TransferStatus::WaitingConfirmations,
                &consignment_hashes,
                fascia,
                sync_tte_used,
            )?
        } else {
            let batch_transfer_idx = self.update_or_save_transfers(
                txn,
                txid.clone(),
                &info_contents,
                TransferStatus::WaitingCounterparty,
                &consignment_hashes,
                sync_tte_used,
                signed_psbt,
            )?;
            if broadcast_deadline.is_some() {
                let batch_transfer = txn
                    .get_batch_transfers_by_txid(&txid)?
                    .into_iter()
                    .find(|bt| bt.idx == batch_transfer_idx)
                    .expect("batch transfer has just been saved");
                let mut updated: DbBatchTransferActMod = batch_transfer.into();
                updated.broadcast_deadline = ActiveValue::Set(broadcast_deadline);
                txn.update_batch_transfer(&mut updated)?;
            }
            batch_transfer_idx
        };

        // test-only: simulate a wallet crash after the consignment has been posted to
        // the proxy and the transfer has been saved, but before the enclosing DB transaction
        // is committed, so the save is rolled back while the proxy keeps the consignment.
        #[cfg(test)]
        if mock_send_end_crash() {
            return Err(Error::Internal {
                details: s!("simulated wallet crash in send_end"),
            });
        }

        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }

    fn send_btc_begin_impl(
        &mut self,
        txn: &DbTxn,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_wallet(
                txn,
                SyncOptions {
                    keychain: SyncKeychain::Vanilla {
                        lookback: self.vanilla_sync_lookback(),
                    },
                    strategy: SyncStrategy::FastSync,
                },
                false,
            )?;
        }

        let script_pubkey = self.get_script_pubkey(&address)?;

        let unspendable = self.get_unspendable_bdk_outpoints(txn)?;

        let mut tx_builder = self.bdk_wallet_mut().build_tx();
        tx_builder
            .unspendable(unspendable)
            .add_recipient(script_pubkey, BdkAmount::from_sat(amount))
            .fee_rate(fee_rate_checked);
        let mut psbt = tx_builder.finish().map_err(|e| match e {
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

        if !dry_run {
            self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::SendBtc)?;
        }

        Ok(psbt)
    }

    fn send_btc_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<String, Error> {
        self.check_vanilla_end(txn, signed_psbt, WalletTransactionType::SendBtc)?;
        let tx = self.broadcast_psbt(txn, signed_psbt)?;
        self.finalize_vanilla_wallet_transaction(txn, signed_psbt, WalletTransactionType::SendBtc)?;
        Ok(tx.compute_txid().to_string())
    }

    fn inflate_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        inflation_amounts: Vec<u64>,
        fee_rate: u64,
        min_confirmations: u8,
        dry_run: bool,
    ) -> Result<BeginOperationData, Error> {
        let asset = txn.check_asset_exists(asset_id.clone())?;
        let schema = asset.schema;
        self.check_schema_support(&schema)?;
        if !schema.supports_inflation() {
            return Err(Error::UnsupportedInflation {
                asset_schema: schema,
            });
        }

        let known_circulating_supply = asset
            .known_circulating_supply
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let inflation =
            self.get_total_inflation_amount(&inflation_amounts, known_circulating_supply)?;
        if inflation == 0 {
            return Err(Error::NoInflationAmounts);
        }

        let (fee_rate_checked, unspents, input_unspents, mut stock) =
            self.get_transfer_begin_data(txn, fee_rate)?;

        let assignments_needed = AssignmentsCollection {
            inflation,
            ..Default::default()
        };
        let asset_spend = self.select_rgb_inputs(
            asset_id.clone(),
            &assignments_needed,
            input_unspents.clone(),
            &mut SelectedInputs::default(),
            Self::max_input_allocations(&TypeOfTransition::Inflate),
        )?;

        let chainnet: ChainNet = self.bitcoin_network().into();
        let amount_sat = asset_spend.input_btc_amt / inflation_amounts.len() as u64;
        let dust = self
            .bdk_wallet()
            .public_descriptor(KeychainKind::External)
            .dust_value()
            .to_sat();
        let amount_sat = max(amount_sat, dust);
        let mut local_recipients = vec![];
        let mut witness_recipients: Vec<(ScriptBuf, u64)> = vec![];
        for (idx, amt) in inflation_amounts.iter().enumerate() {
            let script_pubkey = self
                .get_new_addresses(KeychainKind::External, 1)?
                .script_pubkey();
            let beneficiary = beneficiary_from_script_buf(script_pubkey.clone());
            let beneficiary = XChainNet::with(chainnet, beneficiary);
            let recipient_id = beneficiary.to_string();
            witness_recipients.push((script_pubkey, amount_sat));
            let vout = idx as u32 + 1; // start from 1 because of OP_RETURN
            local_recipients.push(LocalRecipient {
                recipient_id,
                local_recipient_data: LocalRecipientData::Witness(LocalWitnessData {
                    amount_sat,
                    blinding: None,
                    vout,
                }),
                assignment: Assignment::Fungible(*amt),
                transport_endpoints: vec![],
                public_key: vec![],
                encryption: Encryption::Unsupported,
                invoice_expiration: None,
            })
        }

        let contract_id = ContractId::from_str(&asset_id).expect("invalid contract ID");
        let asset_info = AssetInfo {
            contract_id,
            schema,
            reject_list_url: asset.reject_list_url,
        };
        let transfer_info = InfoAssetTransfer {
            asset_info,
            recipients: local_recipients.clone(),
            asset_spend: asset_spend.clone(),
            change: AssignmentsCollection::default(),
            original_assignments_needed: assignments_needed.clone(),
            assignments_needed,
            assignments_spent: HashMap::new(),
            change_destinations: vec![],
            main_transition: MainTransition::Inflate,
            beneficiaries_blinded: vec![],
            beneficiaries_witness: vec![],
        };
        let receive_ids: Vec<String> = local_recipients
            .iter()
            .map(|lr| lr.recipient_id.clone())
            .collect();
        let transfer_dir = self.setup_transfer_directory(receive_ids)?;

        self.prepare_single_asset_psbt(
            txn,
            transfer_info,
            transfer_dir,
            unspents,
            &input_unspents,
            &witness_recipients,
            fee_rate_checked,
            min_confirmations,
            None,
            None,
            &mut stock,
            dry_run,
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

    fn inflate_end_impl(
        &mut self,
        txn: &DbTxn,
        signed_psbt: &Psbt,
    ) -> Result<OperationResult, Error> {
        self.check_end_initiated(txn, signed_psbt)?;
        let (txid, _transfer_dir, info_contents, fascia) =
            self.get_transfer_end_data(signed_psbt)?;

        // the data must be of this operation: another one would be completed skipping its checks
        // and steps
        if !info_contents.is_operation(&TypeOfTransition::Inflate) {
            return Err(Error::WrongOperation { txid });
        }

        // an inflation produces no consignment
        let batch_transfer_idx = self.finalize_transfer_end(
            txn,
            txid.clone(),
            signed_psbt,
            &info_contents,
            TransferStatus::WaitingConfirmations,
            &HashMap::new(),
            fascia,
            false,
        )?;

        let (asset_id, transfer_info) = info_contents.transfers.into_iter().next().unwrap();
        let inflation = transfer_info.original_assignments_needed.inflation;
        let db_asset = txn.get_asset(asset_id).unwrap().unwrap();
        let known_circulating_supply = db_asset
            .known_circulating_supply
            .as_ref()
            .unwrap()
            .parse::<u64>()
            .expect("DB should contain a valid known circulating supply");
        let updated_known_circulating_supply = known_circulating_supply
            .checked_add(inflation)
            .expect("known circulating supply plus inflation cannot exceed u64::MAX");
        let mut updated_asset: DbAssetActMod = db_asset.into();
        updated_asset.known_circulating_supply =
            ActiveValue::Set(Some(updated_known_circulating_supply.to_string()));
        txn.update_asset(&mut updated_asset)?;

        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }

    /// Prepare the PSBT of an operation that pays no one (a burn or a link), spending the
    /// `assignments_needed` of `asset` with the `main_transition`.
    ///
    /// The operation assigns nothing to anyone, so it gets no recipient output and records no
    /// recipient: a random ID names its transfer directory until the TXID replaces it, and the
    /// transfer row recording the operation is saved on its own.
    #[allow(clippy::too_many_arguments)]
    fn begin_without_recipient_impl(
        &mut self,
        txn: &DbTxn,
        asset: DbAsset,
        assignments_needed: AssignmentsCollection,
        main_transition: MainTransition,
        fee_rate: u64,
        min_confirmations: u8,
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
            dry_run,
        )
    }

    /// Complete an operation that pays no one (a burn or a link) with the `main_transition`,
    /// broadcasting the `signed_psbt`.
    ///
    /// The consignment proving the operation is not posted anywhere, as there's no recipient, and
    /// is only made available on disk (see the `consignment_path` of the operation).
    fn end_without_recipient_impl(
        &mut self,
        txn: &DbTxn,
        signed_psbt: &Psbt,
        main_transition: TypeOfTransition,
    ) -> Result<(OperationResult, InfoBatchTransfer), Error> {
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

        let batch_transfer_idx = self.finalize_transfer_end(
            txn,
            txid.clone(),
            signed_psbt,
            &info_contents,
            TransferStatus::WaitingConfirmations,
            &consignment_hashes,
            fascia,
            false,
        )?;

        let res = OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        };
        Ok((res, info_contents))
    }

    fn burn_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        amount: u64,
        burn_reason: Option<String>,
        fee_rate: u64,
        min_confirmations: u8,
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
            dry_run,
        )
    }

    fn burn_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<OperationResult, Error> {
        let (res, _) = self.end_without_recipient_impl(txn, signed_psbt, TypeOfTransition::Burn)?;
        Ok(res)
    }

    fn link_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        linked_to_contract: String,
        fee_rate: u64,
        min_confirmations: u8,
        skip_contract_checks: bool,
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
            dry_run,
        )
    }

    fn link_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<OperationResult, Error> {
        let (res, info_contents) =
            self.end_without_recipient_impl(txn, signed_psbt, TypeOfTransition::Link)?;

        // the link transition assigns nothing, so no consignment of a later operation carries
        // it: the link is known only to this wallet, which records it once broadcast
        for (asset_id, transfer_info) in &info_contents.transfers {
            if let MainTransition::Link { linked_to_contract } = transfer_info.main_transition {
                let mut asset: DbAssetActMod = txn.check_asset_exists(asset_id.clone())?.into();
                asset.linked_to_contract = ActiveValue::Set(Some(linked_to_contract.to_string()));
                txn.update_asset(&mut asset)?;
            }
        }

        Ok(res)
    }

    /// The EVM RPC client for the chain the bridge of the given BFA contract lives on, along with
    /// the contract's bridge location.
    fn evm_client_for_contract(
        &self,
        stock: &RgbStock<'_>,
        contract_id: ContractId,
    ) -> Result<(EvmClient, BridgeLocation), Error> {
        let bridge_location = stock
            .contract_wrapper::<BridgedFungibleAsset>(contract_id)?
            .bridge_location();
        let BridgeLocation::Evm(EvmContract { chain_id, .. }) = &bridge_location;
        let evm_client = self.evm_client_for_chain(*chain_id)?;
        Ok((evm_client, bridge_location))
    }

    /// The EVM RPC client configured for the chain with the given `chain_id`.
    ///
    /// The endpoint is not asked which chain it is on here: going online checks that for every
    /// configured endpoint (see `check_evm_chains`), and the configuration can only be changed by
    /// going online again, so a client is only built for an endpoint that answered with this
    /// chain ID. An endpoint that starts serving another chain while the wallet is online needs
    /// the wallet to go online again, as a check before each call wouldn't catch it either: the
    /// check and the call it guards are separate requests.
    fn evm_client_for_chain(&self, chain_id: u64) -> Result<EvmClient, Error> {
        let Some(evm_rpc_url) = self.evm_rpc_url(chain_id) else {
            error!(
                self.logger(),
                "No EVM RPC URL configured for chain ID {chain_id}"
            );
            return Err(Error::NoEvmRpcUrl { chain_id });
        };
        EvmClient::new(evm_rpc_url)
    }

    fn mint_begin_impl(
        &mut self,
        txn: &DbTxn,
        asset_id: String,
        recipient: Recipient,
        before_block: u64,
        fee_rate: u64,
        min_confirmations: u8,
        sender_transport_endpoint: String,
    ) -> Result<BeginOperationData, Error> {
        let asset = txn.check_asset_exists(asset_id.clone())?;
        let schema = asset.schema;
        self.check_schema_support(&schema)?;
        if !schema.supports_mint() {
            return Err(Error::UnsupportedMint {
                asset_schema: schema,
            });
        }

        match recipient.assignment {
            Assignment::Fungible(_) => {}
            _ => return Err(Error::InvalidAssignment),
        };

        let operation_sk = gen_ed25519();
        let operation_secret_key = operation_sk.to_bytes().to_vec();

        let (fee_rate_checked, unspents, input_unspents, mut stock) =
            self.get_transfer_begin_data(txn, fee_rate)?;

        // refuse to spend the last mint right to avoid leaving the wallet unable to mint
        let mint_rights = input_unspents
            .iter()
            .flat_map(|u| &u.rgb_allocations)
            .filter(|a| {
                a.asset_id.as_ref() == Some(&asset_id)
                    && a.status.settled()
                    && a.assignment == Assignment::MintRight
            })
            .count();
        if mint_rights == 1 {
            return Err(Error::LastMintRight);
        }

        let assignments_needed = AssignmentsCollection {
            mint: 1,
            ..Default::default()
        };
        let asset_spend = self.select_rgb_inputs(
            asset_id.clone(),
            &assignments_needed,
            input_unspents.clone(),
            &mut SelectedInputs::default(),
            Self::max_input_allocations(&TypeOfTransition::Mint),
        )?;

        let mut local_recipients = vec![];

        let chainnet: ChainNet = self.bitcoin_network().into();
        let mut witness_recipients: Vec<(ScriptBuf, u64)> = vec![];
        // a mint recipient is always a proxy one
        if recipient.transport_endpoints.is_empty() {
            return Err(Error::InvalidTransportEndpoints {
                details: s!("no valid transport endpoints"),
            });
        }
        let now_ts = now().unix_timestamp();
        let (local_recipient, witness_output) =
            self.parse_recipient(&recipient, schema, chainnet, 1, &operation_sk, now_ts, true)?;
        witness_recipients.extend(witness_output);
        local_recipients.push(local_recipient);
        Self::check_recipients_transport_endpoints(&mut local_recipients, check_proxy_usable)?;

        // the lock commits to this operation's ID, so it can only be included after the latest
        // external chain block: refuse a block to commit to (see RGB_METADATA_BEFORE_BLOCK)
        // leaving no block before it for the lock, closer than configured (leaving the lock too
        // little time, see EvmChain::min_mint_lock_blocks) or further (as recipients refuse such
        // mints, see EvmChain::max_mint_lock_blocks). This block is the mint's only
        // expiration: no timestamp is involved, as the recipient has no expiration and a mint is
        // never registered on the sender proxy. The latest block is taken from an RPC endpoint
        // checked to be on the bridge's chain, the block numbers of another chain being unrelated
        let contract_id = ContractId::from_str(&asset_id).expect("invalid contract ID");
        let (evm_client, bridge_location) = self.evm_client_for_contract(&stock, contract_id)?;
        let BridgeLocation::Evm(EvmContract { chain_id, .. }) = &bridge_location;
        let EvmChain {
            min_mint_lock_blocks,
            max_mint_lock_blocks,
            ..
        } = *self
            .evm_chain(*chain_id)
            .expect("configured along with the EVM RPC URL");
        let latest_block = evm_client.block_number()?;
        if before_block <= latest_block.saturating_add(1) {
            return Err(Error::InvalidBeforeBlock {
                details: format!(
                    "the lock cannot be included before block {before_block}, the latest \
                     external chain block being {latest_block}"
                ),
            });
        }
        if before_block < latest_block.saturating_add(min_mint_lock_blocks) {
            return Err(Error::InvalidBeforeBlock {
                details: format!(
                    "block {before_block} is less than {min_mint_lock_blocks} blocks after the \
                     latest external chain block {latest_block}"
                ),
            });
        }
        if before_block > latest_block.saturating_add(max_mint_lock_blocks) {
            return Err(Error::InvalidBeforeBlock {
                details: format!(
                    "block {before_block} is more than {max_mint_lock_blocks} blocks after the \
                     latest external chain block {latest_block}"
                ),
            });
        }
        debug!(self.logger(), "External chain block bound: {before_block}");

        let asset_info = AssetInfo {
            contract_id,
            schema,
            reject_list_url: asset.reject_list_url,
        };
        let transfer_info = InfoAssetTransfer {
            asset_info,
            recipients: local_recipients.clone(),
            asset_spend: asset_spend.clone(),
            change: AssignmentsCollection::default(),
            original_assignments_needed: assignments_needed.clone(),
            assignments_needed,
            assignments_spent: HashMap::new(),
            change_destinations: vec![],
            main_transition: MainTransition::Mint { before_block },
            beneficiaries_blinded: vec![],
            beneficiaries_witness: vec![],
        };
        let receive_ids: Vec<String> = local_recipients
            .iter()
            .map(|lr| lr.recipient_id.clone())
            .collect();
        let transfer_dir = self.setup_transfer_directory(receive_ids)?;

        let begin_operation_data = self.prepare_single_asset_psbt(
            txn,
            transfer_info.clone(),
            transfer_dir,
            unspents,
            &input_unspents,
            &witness_recipients,
            fee_rate_checked,
            min_confirmations,
            Some(sender_transport_endpoint.clone()),
            Some(operation_secret_key.clone()),
            &mut stock,
            false,
        )?;

        let (_txid, transfer_dir, info_contents, fascia) =
            self.get_transfer_end_data(&begin_operation_data.psbt)?;

        self.gen_consignments(txn, &fascia, &info_contents.transfers, &transfer_dir)?;

        // post consignment(s) and optional media(s)
        let mut post_recipients = transfer_info.recipients.clone();
        let asset_transfer_dir = self.get_asset_transfer_dir(&transfer_dir, &asset_id);
        // The consignment is posted now, before the TX is signed, so the recipient can verify the
        // mint operation (its OpId, seal and amount) before locking funds on the external chain.
        // Since the signed TX doesn't exist yet, the operation cannot be registered on the sender
        // proxy (ack.prepare): a mint recipient doesn't ACK, and the TX is broadcast by
        // mint_end. Once the PSBT is signed before the lock (bridge v2), this can register the
        // operation and follow the regular ACK flow, as send does.
        let sender_pubkey_hex = hex::encode(operation_sk.verifying_key().to_bytes());
        let consignment_hash =
            hash_file(&self.get_send_consignment_path_impl(&asset_transfer_dir))?;
        self.post_transfer_data(
            &mut post_recipients,
            asset_transfer_dir,
            self.get_asset_medias(txn, asset.media_idx, None)?,
            &operation_sk,
            &sender_pubkey_hex,
            Some(&sender_transport_endpoint),
            &consignment_hash,
            false,
        )?;

        Ok(begin_operation_data)
    }

    /// The details of the mint the given batch transfer data and fascia carry, as its sender:
    /// what its lock on the external chain has to match.
    fn sent_mint(
        &self,
        stock: &RgbStock<'_>,
        info_contents: &InfoBatchTransfer,
        fascia: &Fascia,
    ) -> Result<SentMint, Error> {
        let (transfer_info, before_block) = info_contents
            .transfers
            .values()
            .find_map(|t| match t.main_transition {
                MainTransition::Mint { before_block } => Some((t, before_block)),
                _ => None,
            })
            .ok_or_else(|| Error::Internal {
                details: s!("not a mint transfer"),
            })?;
        let amount = transfer_info
            .recipients
            .iter()
            .map(|r| r.assignment.main_amount())
            .sum::<u64>();
        let contract_id = transfer_info.asset_info.contract_id;
        let opid = fascia
            .bundles()
            .iter()
            .filter(|(id, _)| **id == contract_id)
            .flat_map(|(_, bundle)| bundle.known_transitions.iter())
            .find(|kt| kt.transition.transition_type == TS_MINT)
            .map(|kt| kt.opid)
            .ok_or_else(|| Error::Internal {
                details: s!("mint transition missing from fascia"),
            })?;
        let bridge_location = stock
            .contract_wrapper::<BridgedFungibleAsset>(contract_id)?
            .bridge_location();
        Ok(SentMint {
            contract_id,
            opid,
            lock_id: LockId::with(opid, fascia.witness_id()),
            amount,
            before_block,
            bridge_location,
        })
    }

    /// Whether the given batch transfer is a mint, as its sender until mint_end or as its
    /// recipient once the mint has been checked (and its details saved, see
    /// [`Self::read_received_mint`]), which `fail_transfers` never fails.
    fn is_mint(&self, batch_transfer: &DbBatchTransfer, db_data: &DbData) -> Result<bool, Error> {
        if !batch_transfer.incoming {
            return Ok(Self::is_pending_mint(batch_transfer, db_data));
        }
        let (_, transfer) =
            batch_transfer.get_incoming_transfer(&db_data.asset_transfers, &db_data.transfers)?;
        Ok(transfer
            .recipient_id
            .as_ref()
            .is_some_and(|recipient_id| self.has_received_mint(recipient_id)))
    }

    /// Set the known circulating supply of the BFA asset with ID `asset_id` to the one read from
    /// its bridge contract (see [`ReceiveWallet::read_bridge_circulating_supply`]), if any.
    ///
    /// The supply read is the latest one, as of a later finalized block, so it replaces the known
    /// one whether higher or lower (tokens being released from the bridge).
    fn update_bfa_known_circulating_supply(
        &self,
        txn: &DbTxn,
        asset_id: String,
        supply: Option<u64>,
    ) -> Result<(), Error> {
        receive_checks::update_bfa_known_circulating_supply(txn, asset_id, supply)
    }

    /// Check the bridge contract records a finalized lock matching the mint in the given fascia,
    /// included before the block the mint commits to, erroring with MintLockNotFound if there's
    /// none yet and with MintLockExpired if there never will be. Returns the EVM client used and
    /// the mint.
    fn check_mint_lock(
        &self,
        txn: &DbTxn,
        info_contents: &InfoBatchTransfer,
        fascia: &Fascia,
    ) -> Result<(EvmClient, SentMint), Error> {
        let mint = self.sent_mint(&self.rgb_stock(txn)?, info_contents, fascia)?;
        let BridgeLocation::Evm(EvmContract { chain_id, address }) = &mint.bridge_location;
        let evm_client = self.evm_client_for_chain(*chain_id)?;
        debug!(
            self.logger(),
            "Checking for the lock {} of the mint operation {} at bridge location {:?}",
            mint.lock_id,
            mint.opid,
            mint.bridge_location
        );
        let finalized_block = evm_client.finalized_block_number()?;
        match evm_client.mint_lock_status(
            address,
            &mint.lock_id,
            mint.amount,
            mint.before_block,
            finalized_block,
        )? {
            MintLockStatus::Confirmed => Ok((evm_client, mint)),
            MintLockStatus::Pending => Err(Error::MintLockNotFound {
                opid: mint.opid.to_string(),
            }),
            MintLockStatus::Expired => Err(Error::MintLockExpired {
                opid: mint.opid.to_string(),
                before_block: mint.before_block,
            }),
        }
    }

    /// Fail the given sent mint, not ended yet, if its lock has expired (see check_mint_lock),
    /// releasing its inputs. Returns whether it has been failed.
    fn fail_expired_mint(
        &mut self,
        txn: &DbTxn,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<bool, Error> {
        let txid = batch_transfer
            .txid
            .clone()
            .expect("a pending mint has a TXID");
        let (_, _, info_contents, fascia) = self.get_transfer_end_data_by_txid(txid)?;
        match self.check_mint_lock(txn, &info_contents, &fascia) {
            Err(Error::MintLockExpired { .. }) => {
                info!(self.logger(), "Mint lock expired, failing the transfer");
                self.fail_batch_transfer(txn, batch_transfer)?;
                Ok(true)
            }
            // a lock that's confirmed completes the mint at mint_end, one that's pending may still
            Ok(_) | Err(Error::MintLockNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn mint_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<OperationResult, Error> {
        // a mint ended again (e.g. retried after a crash) is completed only while it's still
        // initiated: one that has failed (which released its inputs) or progressed must not be
        // broadcast or brought back to waiting for confirmations
        self.check_end_initiated(txn, signed_psbt)?;
        let (txid, transfer_dir, info_contents, fascia) =
            self.get_transfer_end_data(signed_psbt)?;

        // the data must be of this operation: another one would be completed skipping its checks
        // and steps
        if !info_contents.is_operation(&TypeOfTransition::Mint) {
            return Err(Error::WrongOperation { txid });
        }

        // a mint expires only once its lock can no longer be included before the block it commits
        // to (no timestamp is involved): an expired one never confirms, so fail it, releasing its
        // inputs (the caller commits the fail along with the error)
        let (evm_client, mint) = match self.check_mint_lock(txn, &info_contents, &fascia) {
            Ok(checked) => checked,
            Err(e) => {
                if let Error::MintLockExpired { .. } = e
                    && let Some(batch_transfer) = txn
                        .get_batch_transfers_by_txid(&txid)?
                        .into_iter()
                        .find(|batch_transfer| !batch_transfer.incoming)
                {
                    info!(self.logger(), "Mint lock expired, failing the transfer");
                    self.fail_batch_transfer(txn, &batch_transfer)?;
                }
                return Err(e);
            }
        };

        // the bridge now accounts the minted amount too
        let BridgeLocation::Evm(EvmContract { address, .. }) = &mint.bridge_location;
        let supply = self.read_bridge_circulating_supply(&evm_client, address);
        self.update_bfa_known_circulating_supply(txn, mint.contract_id.to_string(), supply)?;

        // the consignments were generated (and posted) by mint_begin
        let consignment_hashes = self.consignment_hashes(&transfer_dir, &info_contents)?;
        let batch_transfer_idx = self.finalize_transfer_end(
            txn,
            txid.clone(),
            signed_psbt,
            &info_contents,
            TransferStatus::WaitingConfirmations,
            &consignment_hashes,
            fascia,
            false,
        )?;

        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }
}

/// Online operations for a wallet.
#[cfg(feature = "_online")]
pub trait RgbWalletOpsOnline: RgbWalletOpsOffline + WalletOnline {
    /// Set the status for eligible transfers to [`TransferStatus::Failed`] and return true if any
    /// transfer has changed.
    ///
    /// An optional `batch_transfer_idx` can be provided to operate on a single batch transfer.
    ///
    /// If a `batch_transfer_idx` is provided and `no_asset_only` is true, transfers with an
    /// associated asset ID will not be failed and instead return an error.
    ///
    /// If no `batch_transfer_idx` is provided, only expired transfers will be failed,
    /// and if `no_asset_only` is true transfers with an associated asset ID will be skipped.
    ///
    /// Transfers are eligible if they remain in a fallible status after a `refresh` has been
    /// performed. A transfer in status [`TransferStatus::WaitingBroadcast`] is an exception: it can
    /// only be failed once it has expired, since the TX may still be broadcast before then. For a
    /// transfer ACKed via the sender proxy this is once its broadcast deadline (the operation
    /// expiration plus the sender proxy retention grace) and a further confirmation margin have
    /// passed.
    ///
    /// An outgoing transfer is considered expired only once its expiration has passed on the
    /// sender proxy's clock as well (a fixed clock skew margin is added), as the proxy may release
    /// its TX until then.
    ///
    /// A mint, either sent and not ended yet or received and checked (see
    /// [`get_received_mint`](RgbWalletOpsOffline::get_received_mint)), doesn't expire by a
    /// timestamp but by the external chain block its lock has to be included before: the
    /// recipient fails it at refresh once its lock has expired, while a sent one is failed by this
    /// method (or by `mint_end`) once its lock is found expired, releasing its inputs, and is
    /// never failed before. Without a `batch_transfer_idx`, a sent mint whose lock can't be
    /// checked (e.g. no EVM RPC URL is configured for its chain) is skipped. When a
    /// `batch_transfer_idx` is provided, the signed TX of an outgoing transfer is revoked on the
    /// sender proxy before failing it: if a recipient already obtained it, the transfer cannot be
    /// failed. If the sender proxy no longer knows the operation (e.g.
    /// it lost its data), the transfer can only be failed once its broadcast deadline (its
    /// expiration plus the sender proxy retention grace) has passed on the proxy's clock too, and
    /// only if its TX is not found on-chain: this accepts the residual risk of a recipient that
    /// obtained the TX before the data loss broadcasting it later, which would spend the inputs of
    /// the failed transfer. Ruling that out requires invalidating the TX by spending one of its
    /// inputs, which this method does not do.
    fn fail_transfers(
        &mut self,
        online: Online,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
        skip_sync: bool,
    ) -> Result<bool, Error> {
        info!(
            self.logger(),
            "Failing batch transfer with idx {:?}...", batch_transfer_idx
        );
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let outcome =
            self.fail_transfers_impl(&txn, batch_transfer_idx, no_asset_only, skip_sync)?;
        if outcome.transfers_changed {
            self.update_backup_info(&txn, false)?;
        }
        self.persist_and_commit(txn)?;
        info!(self.logger(), "Fail transfers completed");
        if outcome.cannot_fail {
            return Err(Error::CannotFailBatchTransfer);
        }
        Ok(outcome.transfers_changed)
    }

    /// Sync the wallet and save new colored UTXOs to the DB.
    ///
    /// Gets [`SyncOptions`] to configure the sync strategy and keychain.
    ///
    /// Callers that want both keychains synced must invoke this method once per keychain.
    fn sync(&mut self, online: Online, options: SyncOptions) -> Result<(), Error> {
        info!(self.logger(), "Syncing...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        self.sync_impl(&txn, options)?;
        self.persist_and_commit(txn)?;
        info!(self.logger(), "Sync completed");
        Ok(())
    }

    /// Return the fee estimation in sat/vB for the requested number of `blocks`.
    ///
    /// The `blocks` parameter must be between 1 and 1008.
    fn get_fee_estimation(&self, online: Online, blocks: u16) -> Result<f64, Error> {
        info!(self.logger(), "Getting fee estimation...");
        self.check_online(online)?;
        let estimation = self.get_fee_estimation_impl(blocks)?;
        info!(self.logger(), "Get fee estimation completed");
        Ok(estimation)
    }

    /// Update pending RGB transfers, based on their current status, and return a
    /// [`RefreshResult`].
    ///
    /// An optional `asset_id` can be provided to refresh transfers related to a specific asset.
    ///
    /// Each item in the [`RefreshFilter`] vector defines transfers to be refreshed. Transfers not
    /// matching any provided filter are skipped. If the vector is empty, all transfers are
    /// refreshed.
    ///
    /// Transfers created with the previous proxy protocol, which is not backward compatible, are
    /// failed since they can no longer be completed, unless their TX is found on-chain (in which
    /// case they proceed to wait for confirmations). A transfer waiting for the counterparty's
    /// broadcast is only failed once expired, as the counterparty may still broadcast until then.
    ///
    /// An outgoing transfer whose sender proxy no longer knows the operation, or serves an ACK
    /// with an invalid signature (the refresh then reports [`Error::InvalidContentSignature`] for
    /// it), is failed once its broadcast deadline (its expiration plus the sender proxy retention
    /// grace) has passed on the proxy's clock as well (a fixed clock skew margin is added), unless
    /// its TX is found on-chain first, in which case it proceeds to wait for confirmations. While
    /// waiting, the refresh reports [`Error::OperationNotFound`] for a transfer the proxy no longer
    /// knows. This accepts the residual risk of a recipient that obtained the TX broadcasting it
    /// later.
    ///
    /// An incoming transfer whose signed TX is released via the sender proxy is NACKed if the
    /// sender proxy retention grace is shorter than a minimum (1 day). Its TX is broadcast as soon
    /// as it's obtained and again, if missing, until the broadcast deadline; if the TX is not
    /// confirmed once the broadcast deadline and a further confirmation margin (1 day) have passed,
    /// the transfer is failed.
    fn refresh(
        &mut self,
        online: Online,
        asset_id: Option<String>,
        filter: Vec<RefreshFilter>,
        skip_sync: bool,
    ) -> Result<RefreshResult, Error> {
        info!(self.logger(), "Refreshing asset {:?}...", asset_id);
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        if let Some(aid) = &asset_id {
            txn.check_asset_exists(aid.clone())?;
        }
        let res = self.refresh_impl(&txn, asset_id, filter, skip_sync)?;
        if res.transfers_changed() {
            self.update_backup_info(&txn, false)?;
        }
        self.persist_and_commit(txn)?;
        info!(self.logger(), "Refresh completed");
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_error(code: i64) -> JsonRpcError {
        JsonRpcError {
            code,
            message: s!("msg"),
            data: None,
        }
    }

    // the sender proxy's ack.clean response decides whether a deliberate fail can proceed
    #[test]
    fn clean_ack_outcome_decisions() {
        // the signed TXs were revoked
        assert_matches!(clean_ack_outcome(None).unwrap(), CleanAckOutcome::Revoked);
        // the proxy never had or no longer has the operation
        assert_matches!(
            clean_ack_outcome(Some(proxy_error(-104))).unwrap(),
            CleanAckOutcome::Unknown
        );
        // all the recipients already ACKed (-107): the TX may be in a recipient's hands
        assert_matches!(
            clean_ack_outcome(Some(proxy_error(-107))).unwrap(),
            CleanAckOutcome::Released
        );
        // any other response is surfaced rather than read as "nothing to revoke": a rejected
        // signature, or an error this version doesn't know (e.g. -500 from a proxy with a
        // different error set)
        assert_matches!(
            clean_ack_outcome(Some(proxy_error(-502))).unwrap_err(),
            Error::InvalidEndpointAuthSignature
        );
        assert_matches!(
            clean_ack_outcome(Some(proxy_error(-500))).unwrap_err(),
            Error::Proxy { .. }
        );
    }

    // only a lost operation is tolerated when polling ack.get
    #[test]
    fn check_get_ack_error_decisions() {
        assert!(check_get_ack_error(proxy_error(-104)).is_ok());
        assert_matches!(
            check_get_ack_error(proxy_error(-502)).unwrap_err(),
            Error::InvalidEndpointAuthSignature
        );
        assert_matches!(
            check_get_ack_error(proxy_error(-500)).unwrap_err(),
            Error::Proxy { .. }
        );
    }

    fn batch_transfer(
        status: TransferStatus,
        expiration: Option<i64>,
        broadcast_deadline: Option<i64>,
    ) -> DbBatchTransfer {
        DbBatchTransfer {
            idx: 1,
            txid: None,
            status,
            created_at: 0,
            updated_at: 0,
            expiration,
            min_confirmations: 1,
            incoming: true,
            operation_secret_key: None,
            broadcast_deadline,
            retention_deadline: None,
        }
    }

    // the `expires_at` of an `ack.post` response comes from the sender proxy, which the sender
    // picks, so the deadline computed from it must not depend on the proxy being honest
    #[test]
    fn broadcast_deadline_refuses_untrusted_expirations() {
        let grace = MIN_SENDER_RETENTION_GRACE_SECS;
        let invoice_expiration = now().unix_timestamp() + 86400;
        let deadline = |expires_at: Option<&str>| {
            broadcast_deadline(expires_at, grace, Some(invoice_expiration))
        };

        // an expiration compliant with the invoice gives the deadline
        let expiration = invoice_expiration - i64::from(invoice_expiration_margin());
        assert_eq!(
            deadline(Some(&expiration.to_string())),
            Some(expiration + i64::from(grace))
        );

        // an expiration beyond the invoice one gives none: a far future deadline would make the
        // margins added to it by the deadline checks overflow, panicking on every refresh, and
        // the transfer could never be failed
        for expiration in [
            i64::MAX,
            i64::MAX - i64::from(grace),
            i64::MAX - i64::from(grace) - i64::from(CONFIRMATION_MARGIN_SECS),
            invoice_expiration + 1,
        ] {
            let refused = deadline(Some(&expiration.to_string()));
            assert_eq!(refused, None, "expiration {expiration} was not refused");
        }

        // an expiration already passed gives none as well, instead of a deadline that would fail
        // the transfer before its TX can be broadcast, and so do a missing or unparsable one
        for expires_at in [Some("-1"), Some("0"), Some("sooner or later"), None] {
            assert_eq!(deadline(expires_at), None, "{expires_at:?} was not refused");
        }

        // with no invoice expiration to bound it (e.g. a mint, whose TX the sender broadcasts)
        // there is no deadline either
        let expiration = (now().unix_timestamp() + 1).to_string();
        assert_eq!(broadcast_deadline(Some(&expiration), grace, None), None);
    }

    // a deadline saved by an older version from a hostile `expires_at` must not panic the checks
    // adding their margins to it, which would leave the transfer impossible to refresh or fail
    #[test]
    fn deadline_checks_tolerate_a_saved_hostile_deadline() {
        let now = now().unix_timestamp();
        let transfer = batch_transfer(
            TransferStatus::WaitingBroadcast,
            Some(now + 86400),
            Some(i64::MAX),
        );
        assert!(!broadcast_deadline_passed_beyond_skew_margin(&transfer));
        assert!(!confirmation_deadline_passed(&transfer));
        assert!(!incoming_expired(&transfer, now));

        // same for the expiration, which the skew margin is added to
        let transfer = batch_transfer(TransferStatus::WaitingCounterparty, Some(i64::MAX), None);
        assert!(!broadcast_deadline_passed_beyond_skew_margin(&transfer));
        assert!(!expired_beyond_skew_margin(&transfer));
        assert!(!incoming_expired(&transfer, now));
    }
}
