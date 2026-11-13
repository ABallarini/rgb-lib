//! Browser receive transport.
//!
//! [`WasmReceiveTransport`] implements the shared [`ReceiveTransport`] trait over the async proxy
//! client, so the same receive driver can run on wasm32 without touching the native blocking
//! client. Every operation reuses the helpers the native transport uses: the ACK and retrieved
//! signatures, the reject-list parsing, the retention-grace mapping and the encryption/media
//! helpers. Only the HTTP call itself differs, and the media blobs are written through
//! [`WalletFiles`] keys instead of filesystem paths.
//!
//! The orchestration around the driver - discover the proxy transfer, decrypt it into the wallet
//! files, prefetch the chain questions and run the shared driver inside one database transaction -
//! also lives here. It is the browser counterpart of the native `wait_consignment`, not a second
//! copy of the receive phases: load, validate, reject list, media, apply and ACK/NACK stay in
//! `receive.rs`.

use super::indexer_async::{EsploraResolver, EsploraTransport};
use super::receive::{
    PendingReceive, PrefetchQuestions, ReceiveDriver, ReceiveTransport, ReceiveWallet,
    ack_signature, already_handled, broadcast_error, pending_receives, receive_transfer_idx,
    transfer_retrieved_signature,
};
use super::resolver_async::PrefetchedChain;
use super::*;
use crate::api::fetch::ProxyFetchClient;
use crate::api::jsonrpc::{
    PostAckResponse, ProxyTransferState, list_transfers_message, map_proxy_error,
};
use crate::encryption::sha256_digest;
use crate::no_wallet::validation::{
    RejectList, RejectListSource, ResolveRejectList, genesis_reject_list_source,
};
use base64::{Engine as _, engine::general_purpose};

/// Marker of a `transfer.retrieved` the durable snapshot still owes the recipient proxy.
const RETRIEVED_MARKER_FILE: &str = "retrieved.pending.json";

/// The reject lists a consignment's assets declare, read before the database transaction opens.
///
/// The browser cannot fetch while a transaction is open, so the receive prefetches the lists the
/// validation will ask for and hands them to the driver through [`ResolveRejectList`].
#[derive(Default)]
pub(super) struct PrefetchedRejectLists {
    lists: HashMap<RejectListSource, RejectList>,
}

impl ResolveRejectList for PrefetchedRejectLists {
    fn get_reject_list(&self, source: &RejectListSource) -> Result<RejectList, Error> {
        self.lists
            .get(source)
            .cloned()
            .ok_or_else(|| Error::Internal {
                details: format!("no prefetched reject list for {source:?}"),
            })
    }
}

/// Read the reject lists the consignment's assets declare, failing closed on the ones kept by an
/// EVM contract, which the browser cannot query.
async fn prefetch_reject_lists(
    wallet: &Wallet,
    consignment: Option<&RgbTransfer>,
) -> Result<PrefetchedRejectLists, Error> {
    let mut lists = HashMap::new();
    let Some(consignment) = consignment else {
        return Ok(PrefetchedRejectLists { lists });
    };
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let Some(source) = genesis_reject_list_source(asset_schema, consignment.genesis())? else {
        return Ok(PrefetchedRejectLists { lists });
    };
    match &source {
        RejectListSource::Url(url) => {
            let client = ProxyFetchClient::new(url)?;
            let list = client.get_reject_list().await?;
            let (reject_list, invalid) = RejectList::parse(&list);
            if invalid > 0 {
                warn!(
                    wallet.logger(),
                    "Ignoring {invalid} invalid opout(s) in reject list"
                );
            }
            lists.insert(source, reject_list);
        }
        RejectListSource::Evm(_) => {
            return Err(Error::Internal {
                details: s!("EVM reject lists are not supported in the browser"),
            });
        }
    }
    Ok(PrefetchedRejectLists { lists })
}

/// [`ReceiveTransport`] over the browser's `fetch` client.
struct WasmReceiveTransport<'a, W: WalletOffline + ?Sized> {
    wallet: &'a W,
    /// Esplora endpoint that answers the chain queries (tip height, broadcast).
    indexer_url: &'a str,
    /// Reject lists prefetched before the transaction opened.
    reject_lists: &'a PrefetchedRejectLists,
}

#[allow(dead_code)]
impl<'a, W: WalletOffline + ?Sized> WasmReceiveTransport<'a, W> {
    fn new(wallet: &'a W, indexer_url: &'a str, reject_lists: &'a PrefetchedRejectLists) -> Self {
        Self {
            wallet,
            indexer_url,
            reject_lists,
        }
    }
}

impl<W: WalletOffline + ?Sized> ReceiveTransport for WasmReceiveTransport<'_, W> {
    fn reject_list_resolver(&self) -> &dyn ResolveRejectList {
        self.reject_lists
    }

    async fn fetch_and_save_attachments(
        &self,
        attachments: Vec<Attachment>,
        mode: &ReceiveMode,
        recipient_seed: &[u8],
    ) -> Result<bool, Error> {
        if attachments.is_empty() {
            return Ok(true);
        }
        // Out-of-band media arrives as host filesystem paths, which a browser wallet cannot read.
        // The proxy exchange is the browser receive flow; an out-of-band receive with media is not
        // supported here.
        let ReceiveMode::Proxy(data) = mode else {
            return Err(Error::Internal {
                details: s!("out-of-band media files are not available in the browser"),
            });
        };

        // the media are stored under an id derived from the shared secret, not the plaintext digest
        let derived = crate::encryption::shared_keys(recipient_seed, &data.sender_pubkey)?;
        let client = ProxyFetchClient::new(&data.proxy_url)?;
        let mut saved_media = vec![];
        for attachment in attachments {
            let digest = hex::encode(attachment.digest);
            let media_key = self.wallet.media_key(&digest)?;
            // resolve media only if the blob is not already present
            if self.wallet.files().exists(&media_key)? {
                continue;
            }
            let media_id = derived.media_id(&digest);
            let media_res = client.get_media(&data.transfer_id, &media_id).await?;
            match media_res.result {
                Some(payload) => {
                    // also checks the plaintext against the digest in the contract
                    let bytes = crate::encryption::decrypt_b64_blob_with_shared_key(
                        &payload,
                        data.recipient_encryption,
                        recipient_seed,
                        &data.sender_pubkey,
                        &digest,
                    )?;
                    self.wallet.files().atomic_write(&media_key, &bytes)?;
                }
                None => {
                    error!(
                        self.wallet.logger(),
                        "Cannot find the media file but the contract defines one"
                    );
                    self.wallet.cleanup_media_files(&saved_media)?;
                    return Ok(false);
                }
            }
            saved_media.push(media_key);
        }

        Ok(true)
    }

    async fn sender_retention_grace(&self, sender_proxy: &str) -> Result<u32, Error> {
        let client = ProxyFetchClient::new(sender_proxy)?;
        let res = client.get_info().await?;
        if let Some(err) = res.error {
            return Err(map_proxy_error(err));
        }
        let info = res.result.ok_or_else(|| Error::Proxy {
            details: s!("missing server.info result"),
        })?;
        Ok(crate::utils::proxy_retention_grace(&info))
    }

    async fn post_ack(
        &self,
        sender_proxy: &str,
        transfer_id: &str,
        ack: bool,
        consignment_hash: &str,
        recipient_seed: &[u8],
    ) -> Result<PostAckResponse, Error> {
        let sig = ack_signature(transfer_id, ack, consignment_hash, recipient_seed)?;
        let client = ProxyFetchClient::new(sender_proxy)?;
        let res = client.post_ack(transfer_id, ack, &sig).await?;
        if let Some(err) = res.error {
            return Err(map_proxy_error(err));
        }
        res.result.ok_or_else(|| Error::Proxy {
            details: s!("missing ack.post result"),
        })
    }

    async fn mark_transfer_retrieved(
        &self,
        proxy_url: &str,
        transfer_id: &str,
        recipient_seed: &[u8],
    ) -> bool {
        let Some(signature) = transfer_retrieved_signature(transfer_id, recipient_seed) else {
            return false;
        };
        let res = match ProxyFetchClient::new(proxy_url) {
            Ok(client) => client.transfer_retrieved(transfer_id, &signature).await,
            Err(e) => {
                warn!(
                    self.wallet.logger(),
                    "Failed to mark transfer as retrieved: {e}"
                );
                return false;
            }
        };
        match res {
            Ok(r) if r.error.is_none() => true,
            Ok(r) => {
                warn!(
                    self.wallet.logger(),
                    "Failed to mark transfer as retrieved: {:?}", r.error
                );
                false
            }
            Err(e) => {
                warn!(
                    self.wallet.logger(),
                    "Failed to mark transfer as retrieved: {e}"
                );
                false
            }
        }
    }

    async fn tip_height(&self) -> Result<u32, Error> {
        EsploraTransport::new(self.indexer_url)?
            .get_latest_block_height()
            .await
    }

    async fn broadcast(&self, tx: BdkTransaction) -> Result<(), Error> {
        let txid = tx.compute_txid().to_string();
        let indexer = EsploraTransport::new(self.indexer_url)?;
        match indexer.broadcast(&tx).await {
            Ok(()) => {
                debug!(self.wallet.logger(), "Broadcasted TX with ID '{}'", txid);
                Ok(())
            }
            Err(e) => {
                if let Some(err) = broadcast_error(&txid, &e) {
                    return Err(err);
                }
                if indexer.get_tx_confirmations(&txid).await?.is_none() {
                    return Err(Error::FailedBroadcast {
                        details: e.to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

// Test-only hook: make the fetch path fail after the consignment and its metadata were cached, so a
// second attempt can prove it reuses them instead of contacting the proxy again.
#[cfg(test)]
thread_local! {
    static FAIL_AFTER_CACHE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn set_fail_after_cache(fail: bool) {
    FAIL_AFTER_CACHE.with(|cell| cell.set(fail));
}

#[cfg(test)]
fn fail_after_cache() -> bool {
    FAIL_AFTER_CACHE.with(|cell| cell.get())
}

#[cfg(not(test))]
fn fail_after_cache() -> bool {
    false
}

/// A receive an earlier attempt already downloaded, decrypted and saved.
///
/// The consignment bytes are the cached plaintext, so the reuse path never decodes, decrypts or
/// validates them a second time: it feeds the same prefetch and driver path as a fresh download.
pub(super) struct CachedReceive {
    candidate: super::receive::PendingReceive,
    data: ProxyReceiveData,
    consignment_bytes: Vec<u8>,
    consignment_path: PathBuf,
}

/// The outcome of handling one proxy transfer, before it is turned into a result for the host.
enum ReceiveOutcome {
    /// the shared driver handled it, committing the new state
    Handled,
    /// the transfer was already handled by an earlier run: nothing to do
    AlreadyHandled,
    /// the transfer is applied and only the native refresh can move it further (confirmations)
    Waiting,
    /// the transfer was not posted to any pending invoice of this wallet
    NotOurs,
}

/// `transfer.list` signed with the recipient's operation key, as the native client does it.
fn list_transfers_signature(
    invoice_id: &str,
    recipient_seed: &[u8],
) -> Result<(String, String), Error> {
    let seed: [u8; 32] = recipient_seed.try_into().map_err(|_| Error::Internal {
        details: s!("invalid recipient secret key"),
    })?;
    let sk = ed25519_from_seed(&seed);
    let timestamp = now().unix_timestamp().to_string();
    let digest = sha256_digest(list_transfers_message(invoice_id, &timestamp).as_bytes());
    Ok((hex::encode(sign_ed25519(&sk, &digest)), timestamp))
}

/// The chain answers the upcoming validation and consumption may ask for.
///
/// Every bundled witness TX is fetched, as validation resolves each one unless a valid SPV proof
/// answers it, and consumption resolves them again. The alternative witnesses the stock already
/// knows for the same bundles are included because consumption re-resolves them when a bundle's
/// witness ord is invalid (e.g. after a reorg). Headers cover every SPV proof the bundles carry.
async fn prefetch_chain_answers(
    wallet: &Wallet,
    indexer_url: &str,
    consignment: Option<&RgbTransfer>,
) -> Result<PrefetchedChain, Error> {
    let mut questions = match consignment {
        Some(consignment) => PrefetchQuestions::for_consignment(consignment),
        None => PrefetchQuestions::default(),
    };
    let txn = wallet.database().begin_transaction()?;
    if let Some(consignment) = consignment {
        let stock = wallet.rgb_stock(&txn)?;
        questions.add_known_alternatives(&stock, consignment)?;
    }
    // the read transaction is closed before the prefetch: no DB transaction stays open across the
    // network wait, which a single-threaded browser cannot afford
    drop(txn);

    let resolver = EsploraResolver::new(EsploraTransport::new(indexer_url)?);
    PrefetchedChain::fetch(
        &resolver,
        wallet.chain_net(),
        questions.witness_ids,
        questions.heights,
    )
    .await
    .map_err(|e| Error::Network {
        details: e.to_string(),
    })
}

/// The operation seed of a receive, looked up by the proxy transfer ID stored with it.
fn recipient_seed_for(db_data: &DbData, transfer_id: &str) -> Option<Vec<u8>> {
    let transfer = db_data
        .transfers
        .iter()
        .find(|transfer| transfer.proxy_transfer_id.as_deref() == Some(transfer_id))?;
    let asset_transfer = db_data
        .asset_transfers
        .iter()
        .find(|asset_transfer| asset_transfer.idx == transfer.asset_transfer_idx)?;
    db_data
        .batch_transfers
        .iter()
        .find(|batch_transfer| batch_transfer.idx == asset_transfer.batch_transfer_idx)?
        .operation_secret_key
        .clone()
}

impl Wallet {
    /// The cached consignment of an earlier, failed receive attempt for this proxy transfer ID.
    ///
    /// The download path writes the decrypted consignment and its [`ReceivedConsignmentMeta`] before
    /// the database transaction runs, so a failure in the prefetch or in the driver leaves a cache
    /// the next attempt can use. A cache is reused only when the metadata names this transfer ID and
    /// the pending receive it belongs to derives the same ID from the cached sender key. A missing
    /// or unreadable cache is treated as absent, so the caller falls back to the proxy.
    pub(super) fn cached_receive(
        &self,
        db_data: &DbData,
        proxy_url: &str,
        transfer_id: &str,
    ) -> Result<Option<CachedReceive>, Error> {
        for candidate in pending_receives(db_data)? {
            let Some(recipient_id) = candidate.transfer.recipient_id.clone() else {
                continue;
            };
            let consignment_path = self.get_receive_consignment_path(&recipient_id);
            let consignment_key = self.wallet_key(&consignment_path)?;
            let meta_key =
                self.wallet_key(&self.get_receive_consignment_meta_path(&recipient_id))?;
            if !self.files().exists(&consignment_key)? || !self.files().exists(&meta_key)? {
                continue;
            }
            let Ok(meta_bytes) = self.files().read(&meta_key) else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<ReceivedConsignmentMeta>(&meta_bytes) else {
                continue;
            };
            if meta.transfer_id.as_deref() != Some(transfer_id)
                || candidate
                    .expected_transfer_id(&meta.sender_pubkey)
                    .as_deref()
                    != Some(transfer_id)
            {
                continue;
            }
            let Ok(consignment_bytes) = self.files().read(&consignment_key) else {
                continue;
            };
            let Ok(sender_proxy) =
                self.convert_transport_endpoint_url(&meta.sender_transport_endpoint)
            else {
                continue;
            };
            let data = ProxyReceiveData {
                proxy_url: proxy_url.to_string(),
                transfer_id: transfer_id.to_string(),
                sender_proxy,
                sender_pubkey: meta.sender_pubkey,
                consignment_hash: meta.consignment_hash,
                recipient_encryption: candidate.transfer.recipient_encryption,
                batch: meta.batch,
            };
            return Ok(Some(CachedReceive {
                candidate,
                data,
                consignment_bytes,
                consignment_path,
            }));
        }
        Ok(None)
    }

    /// Receive one proxy transfer by its ID, decrypting it, validating it and ACKing it.
    ///
    /// The caller supplies the recipient proxy URL (where the consignment lives) and the Esplora
    /// URL (for chain answers and the broadcast of a released signed TX). The transfer must belong
    /// to a pending incoming invoice of this wallet; a transfer already handled is a no-op, and a
    /// transfer not addressed to this wallet is an error.
    ///
    /// Everything the shared driver changes - transfer status, colorings, asset rows, pending
    /// witness flags, the ACK flag and the broadcast deadline - is committed in one database
    /// transaction. A failure drops it and leaves the wallet as it was, while the proxy call and
    /// the files written before it keep the native contract (the consignment and its metadata are
    /// reusable on the next attempt).
    pub async fn receive_transfer_async(
        &mut self,
        proxy_url: &str,
        indexer_url: &str,
        transfer_id: &str,
    ) -> Result<Option<i32>, Error> {
        match self
            .receive_proxy_transfer(proxy_url, indexer_url, transfer_id)
            .await?
        {
            ReceiveOutcome::Handled | ReceiveOutcome::AlreadyHandled | ReceiveOutcome::Waiting => {
                let db_data = self.db_data()?;
                Ok(receive_transfer_idx(&db_data, transfer_id))
            }
            ReceiveOutcome::NotOurs => Err(Error::Internal {
                details: format!(
                    "no pending receive transfer of this wallet matches proxy transfer \
                     '{transfer_id}'"
                ),
            }),
        }
    }

    /// Sync the BDK wallet and receive every pending proxy transfer of this wallet.
    ///
    /// The BDK part is the same read-only full scan [`Self::sync_async`] runs, including its
    /// pending-witness reconciliation and colored-TXO registration. The receive part lists the
    /// transfers of each pending incoming invoice on `proxy_url` - the native selection: only
    /// `Pending` transfers are considered, sorted by ID - and runs the shared driver on each.
    /// Transfers not addressed to this wallet are skipped, a terminal one is left untouched, and a
    /// receive left in `WaitingSafeHeight` or `WaitingBroadcast` is resumed instead of being
    /// treated as complete, so a repeated call is idempotent.
    ///
    /// Returns the batch transfer indices handled by this call, in processing order. A failure
    /// rolls back only the transfer it happened on and stops the loop.
    pub async fn sync_online_async(
        &mut self,
        proxy_url: &str,
        indexer_url: &str,
        stop_gap: Option<usize>,
    ) -> Result<Vec<i32>, Error> {
        self.sync_async(indexer_url, stop_gap).await?;
        self.receive_pending_proxy_transfers(proxy_url, indexer_url)
            .await
    }

    /// The receive half of [`Self::sync_online_async`], over the pending invoices in the DB.
    ///
    /// Kept separate from the BDK scan so the receive loop can be exercised without an indexer.
    pub(super) async fn receive_pending_proxy_transfers(
        &mut self,
        proxy_url: &str,
        indexer_url: &str,
    ) -> Result<Vec<i32>, Error> {
        let pending = pending_receives(&self.db_data()?)?;
        let client = ProxyFetchClient::new(proxy_url)?;
        let mut handled = vec![];
        for candidate in pending {
            let recipient_id = candidate
                .transfer
                .recipient_id
                .clone()
                .expect("pending receives have a recipient ID");
            let recipient_pk = hex::encode(
                candidate
                    .transfer
                    .recipient_pubkey
                    .as_ref()
                    .expect("pending receives have a recipient pubkey"),
            );
            let seed = candidate
                .batch
                .operation_secret_key
                .clone()
                .expect("pending receives have an operation secret key");
            let invoice_id = crate::encryption::invoice_id(&recipient_id, &recipient_pk);
            let (signature, timestamp) = list_transfers_signature(&invoice_id, &seed)?;

            // a proxy that cannot list this invoice has nothing for it: skip it like the native
            // selection does, instead of failing the whole sync
            let Ok(response) = client
                .list_transfers(&invoice_id, &signature, &timestamp)
                .await
            else {
                debug!(
                    self.logger(),
                    "Skipping invoice {invoice_id}: transfer list failed"
                );
                continue;
            };
            if let Some(err) = response.error {
                debug!(self.logger(), "Skipping invoice {invoice_id}: {err:?}");
                continue;
            }
            let mut transfers: Vec<String> = response
                .result
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, state)| *state == ProxyTransferState::Pending)
                .map(|(id, _)| id)
                .collect();
            transfers.sort();

            for transfer_id in transfers {
                match self
                    .receive_proxy_transfer(proxy_url, indexer_url, &transfer_id)
                    .await?
                {
                    ReceiveOutcome::Handled => {
                        let db_data = self.db_data()?;
                        if let Some(idx) = receive_transfer_idx(&db_data, &transfer_id) {
                            handled.push(idx);
                        }
                    }
                    ReceiveOutcome::AlreadyHandled | ReceiveOutcome::Waiting => {}
                    ReceiveOutcome::NotOurs => {
                        debug!(
                            self.logger(),
                            "Skipping transfer {transfer_id}, not addressed to this wallet"
                        );
                    }
                }
            }
        }
        Ok(handled)
    }

    /// Resume a receive an earlier attempt already applied.
    ///
    /// `WaitingSafeHeight` is validated again at the current safe height and ACKed only once its
    /// unsafe history has reached it; `WaitingBroadcast` posts the ACK again through the shared
    /// path, which broadcasts the released signed TX when the sender proxy returns it. Neither
    /// path re-applies the consignment, so its colorings are not duplicated.
    async fn resume_proxy_receive(
        &mut self,
        indexer_url: &str,
        candidate: PendingReceive,
    ) -> Result<ReceiveOutcome, Error> {
        let status = candidate.batch.status;
        if !matches!(
            status,
            TransferStatus::WaitingSafeHeight | TransferStatus::WaitingBroadcast
        ) {
            debug!(
                self.logger(),
                "Skipping resume of transfer {}: only the native refresh handles {:?}",
                candidate.batch.idx,
                status
            );
            return Ok(ReceiveOutcome::Waiting);
        }
        let recipient_id = candidate
            .transfer
            .recipient_id
            .clone()
            .expect("pending receives have a recipient ID");
        let consignment_path = self.get_receive_consignment_path(&recipient_id);

        // the safe-height check resolves the unsafe history again, so prefetch those answers
        // before the database transaction opens
        let mut reject_lists = PrefetchedRejectLists::default();
        let prefetched = if status == TransferStatus::WaitingSafeHeight {
            let key = self.wallet_key(&consignment_path)?;
            let bytes = self.files().read(&key)?;
            let questions = RgbTransfer::load(bytes.as_slice()).ok();
            reject_lists = prefetch_reject_lists(self, questions.as_ref()).await?;
            Some(prefetch_chain_answers(self, indexer_url, questions.as_ref()).await?)
        } else {
            None
        };

        let txn = self.database().begin_transaction()?;
        let mode = super::receive::receive_mode_from_transfer(self, &txn, &candidate.transfer)?;
        let recipient_seed = candidate
            .batch
            .operation_secret_key
            .clone()
            .unwrap_or_default();
        let mut updated_batch_transfer: DbBatchTransferActMod = candidate.batch.clone().into();
        let outcome = {
            let transport = WasmReceiveTransport::new(self, indexer_url, &reject_lists);
            match prefetched {
                Some(chain) => {
                    self.resume_receive(
                        &transport,
                        &chain,
                        &txn,
                        &candidate.batch,
                        &candidate.asset_transfer,
                        &candidate.transfer,
                        recipient_id,
                        &consignment_path,
                        &mode,
                        &mut updated_batch_transfer,
                    )
                    .await
                }
                None => self
                    .ack_consignment_via(
                        &transport,
                        &txn,
                        &candidate.batch,
                        &candidate.transfer,
                        &mut updated_batch_transfer,
                        &mode,
                        &recipient_seed,
                        None,
                        false,
                    )
                    .await
                    .map(|outcome| (outcome, None)),
            }
        };
        match outcome {
            Ok((_, retrieval)) => {
                self.persist_and_commit(txn)?;
                // as in the fresh receive: the marker shares the snapshot with the receive
                if let Some(retrieval) = &retrieval {
                    self.save_pending_retrieval(retrieval)?;
                }
                Ok(ReceiveOutcome::Handled)
            }
            Err(e) => {
                // dropping the transaction is the rollback
                drop(txn);
                Err(e)
            }
        }
    }

    fn db_data(&self) -> Result<DbData, Error> {
        let txn = self.database().begin_transaction()?;
        txn.get_db_data(false)
    }

    /// Key of the pending-release marker of one receive.
    fn retrieved_marker_key(&self, recipient_id: &str) -> Result<WalletPath, Error> {
        self.wallet_key(
            &self
                .get_receive_consignment_path(recipient_id)
                .with_file_name(RETRIEVED_MARKER_FILE),
        )
    }

    /// Record a release the caller must post once the receive is durable.
    fn save_pending_retrieval(&self, retrieval: &PendingRetrieval) -> Result<(), Error> {
        let key = self.retrieved_marker_key(&retrieval.recipient_id)?;
        let bytes = serde_json::to_vec(retrieval).map_err(InternalError::from)?;
        self.files().atomic_write(&key, &bytes)
    }

    /// Every release marker carried by the wallet files, which the snapshot keeps across reloads.
    fn pending_retrievals(&self) -> Result<Vec<(WalletPath, PendingRetrieval)>, Error> {
        let marker_suffix = format!("/{RETRIEVED_MARKER_FILE}");
        let mut markers = vec![];
        for key in self.files().list(&self.transfers_key()?)? {
            if !key.as_str().ends_with(&marker_suffix) {
                continue;
            }
            let Ok(bytes) = self.files().read(&key) else {
                continue;
            };
            let Ok(marker) = serde_json::from_slice::<PendingRetrieval>(&bytes) else {
                continue;
            };
            markers.push((key, marker));
        }
        Ok(markers)
    }

    /// Post the releases the durable snapshot still owes, removing each marker once the proxy
    /// accepted it.
    ///
    /// The host calls this only after flushing the snapshot that holds the handled receive: the
    /// proxy may delete the only copy of the consignment on this call, so it must never run
    /// before. A marker left by a failed post is retried by the next call, and posting a release
    /// twice is harmless.
    pub async fn release_pending_retrievals(&self, indexer_url: &str) {
        let markers = match self.pending_retrievals() {
            Ok(markers) => markers,
            Err(e) => {
                warn!(self.logger(), "Cannot read pending transfer releases: {e}");
                return;
            }
        };
        if markers.is_empty() {
            return;
        }
        let db_data = match self.db_data() {
            Ok(db_data) => db_data,
            Err(e) => {
                warn!(
                    self.logger(),
                    "Cannot read the transfers of pending releases: {e}"
                );
                return;
            }
        };
        for (key, marker) in markers {
            let Some(seed) = recipient_seed_for(&db_data, &marker.transfer_id) else {
                warn!(
                    self.logger(),
                    "Dropping the release marker of {}, which names no local transfer",
                    marker.transfer_id
                );
                if let Err(e) = self.files().remove(&key) {
                    warn!(self.logger(), "Cannot remove a release marker: {e}");
                }
                continue;
            };
            let empty_lists = PrefetchedRejectLists::default();
            let transport = WasmReceiveTransport::new(self, indexer_url, &empty_lists);
            if transport
                .mark_transfer_retrieved(&marker.proxy_url, &marker.transfer_id, &seed)
                .await
            {
                if let Err(e) = self.files().remove(&key) {
                    warn!(self.logger(), "Cannot remove a release marker: {e}");
                }
            }
        }
    }

    /// Fetch, decrypt, prefetch and drive one proxy transfer.
    async fn receive_proxy_transfer(
        &mut self,
        proxy_url: &str,
        indexer_url: &str,
        transfer_id: &str,
    ) -> Result<ReceiveOutcome, Error> {
        // a re-run after the ACK may find the proxy data already deleted: the local record of the
        // transfer ID is what makes the call idempotent, so check it before any network access
        let db_data = self.db_data()?;
        if already_handled(&db_data, transfer_id).is_some() {
            return Ok(ReceiveOutcome::AlreadyHandled);
        }
        // a transfer applied by an earlier attempt is resumed, not downloaded and applied again
        if let Some(candidate) = pending_receives(&db_data)?.into_iter().find(|candidate| {
            candidate.transfer.proxy_transfer_id.as_deref() == Some(transfer_id)
                && candidate.batch.status != TransferStatus::WaitingCounterparty
        }) {
            return self.resume_proxy_receive(indexer_url, candidate).await;
        }

        // a previous attempt may have cached the consignment and its metadata before failing in the
        // prefetch or in the driver: reuse them instead of asking a proxy that may have deleted the
        // data in the meantime. A missing or unreadable cache falls back to the fetch path below.
        let cached = self.cached_receive(&db_data, proxy_url, transfer_id)?;
        if let Some(cached) = &cached
            && cached.candidate.batch.status != TransferStatus::WaitingCounterparty
        {
            return self
                .resume_proxy_receive(indexer_url, cached.candidate.clone())
                .await;
        }
        let (candidate, data, consignment_bytes, consignment_path) = match cached {
            Some(cached) => {
                debug!(
                    self.logger(),
                    "Reusing cached consignment for {transfer_id}"
                );
                (
                    cached.candidate,
                    cached.data,
                    cached.consignment_bytes,
                    cached.consignment_path,
                )
            }
            None => {
                let client = ProxyFetchClient::new(proxy_url)?;
                let response = client.get_consignment(transfer_id).await?;
                if let Some(err) = response.error {
                    return Err(map_proxy_error(err));
                }
                let Some(result) = response.result else {
                    return Err(Error::NoConsignment);
                };

                let Some(candidate) = pending_receives(&db_data)?.into_iter().find(|c| {
                    c.expected_transfer_id(&result.sender_pk).as_deref() == Some(transfer_id)
                }) else {
                    return Ok(if already_handled(&db_data, transfer_id).is_some() {
                        ReceiveOutcome::AlreadyHandled
                    } else {
                        ReceiveOutcome::NotOurs
                    });
                };

                let recipient_id = candidate
                    .transfer
                    .recipient_id
                    .clone()
                    .expect("matched receive has a recipient ID");
                let recipient_seed = candidate
                    .batch
                    .operation_secret_key
                    .clone()
                    .unwrap_or_default();
                let sender_proxy =
                    self.convert_transport_endpoint_url(&result.sender_transport_endpoint)?;
                let data = ProxyReceiveData {
                    proxy_url: proxy_url.to_string(),
                    transfer_id: transfer_id.to_string(),
                    sender_proxy,
                    sender_pubkey: result.sender_pk.clone(),
                    consignment_hash: result.consignment_hash.clone(),
                    recipient_encryption: candidate.transfer.recipient_encryption,
                    batch: result.batch,
                };
                let mode = ReceiveMode::Proxy(data.clone());

                // decode and (if needed) decrypt the consignment; a malformed payload is
                // refused like one that fails decryption or verification
                let decoded = general_purpose::STANDARD
                    .decode(&result.consignment)
                    .map_err(|e| Error::InvalidEncryptedBlob {
                        details: e.to_string(),
                    });
                let consignment_bytes = decoded.and_then(|raw| {
                    self.decrypt_blob_with_shared_key(
                        raw,
                        data.recipient_encryption,
                        &recipient_seed,
                        &data.sender_pubkey,
                        &data.consignment_hash,
                    )
                });
                let consignment_bytes = match consignment_bytes {
                    Ok(bytes) => bytes,
                    Err(e @ Error::IO { .. }) => return Err(e),
                    Err(_) => {
                        let txn = self.database().begin_transaction()?;
                        let mut updated: DbBatchTransferActMod = candidate.batch.clone().into();
                        {
                            let empty_lists = PrefetchedRejectLists::default();
                            let transport =
                                WasmReceiveTransport::new(self, indexer_url, &empty_lists);
                            self.refuse_consignment_via(
                                &transport,
                                &txn,
                                &mode,
                                &recipient_id,
                                &recipient_seed,
                                &mut updated,
                                false,
                            )
                            .await?;
                        }
                        self.persist_and_commit(txn)?;
                        return Ok(ReceiveOutcome::Handled);
                    }
                };

                let consignment_path = self.get_receive_consignment_path(&recipient_id);
                let consignment_key = self.wallet_key(&consignment_path)?;
                self.files()
                    .atomic_write(&consignment_key, &consignment_bytes)?;
                let meta = ReceivedConsignmentMeta {
                    proxy_url: Some(proxy_url.to_string()),
                    transfer_id: Some(transfer_id.to_string()),
                    sender_transport_endpoint: result.sender_transport_endpoint.clone(),
                    sender_pubkey: result.sender_pk.clone(),
                    consignment_hash: result.consignment_hash.clone(),
                    batch: result.batch,
                };
                let meta_str = serde_json::to_string(&meta).map_err(InternalError::from)?;
                let meta_key =
                    self.wallet_key(&self.get_receive_consignment_meta_path(&recipient_id))?;
                self.files().atomic_write(&meta_key, meta_str.as_bytes())?;

                if fail_after_cache() {
                    return Err(Error::Internal {
                        details: s!("injected failure after caching the consignment"),
                    });
                }

                (candidate, data, consignment_bytes, consignment_path)
            }
        };
        let recipient_id = candidate
            .transfer
            .recipient_id
            .clone()
            .expect("matched receive has a recipient ID");
        let mode = ReceiveMode::Proxy(data.clone());

        // parse once for the prefetch set; a malformed consignment still runs the driver, which
        // refuses it with the same error a native load would report
        let questions = RgbTransfer::load(consignment_bytes.as_slice()).ok();
        let reject_lists = prefetch_reject_lists(self, questions.as_ref()).await?;
        let prefetched = prefetch_chain_answers(self, indexer_url, questions.as_ref()).await?;

        let txn = self.database().begin_transaction()?;
        // mark the recipient proxy endpoint used, when the invoice persisted one
        if let Some((tte, _)) = txn
            .get_transfer_transport_endpoints_data(candidate.transfer.idx)?
            .into_iter()
            .find(|(tte, te)| {
                tte.kind == TransportEndpointKind::RecipientProxy && te.endpoint == proxy_url
            })
            && !tte.used
        {
            let mut updated_tte: DbTransferTransportEndpointActMod = tte.into();
            updated_tte.used = ActiveValue::Set(true);
            txn.update_transfer_transport_endpoint(&mut updated_tte)?;
        }
        // persist the transfer ID, consignment hash and sender proxy endpoint (for the ACK),
        // exactly like the native download does before the shared driver runs
        let mut updated_transfer: DbTransferActMod = candidate.transfer.clone().into();
        updated_transfer.consignment_hash = ActiveValue::Set(Some(data.consignment_hash.clone()));
        updated_transfer.proxy_transfer_id = ActiveValue::Set(Some(transfer_id.to_string()));
        txn.update_transfer(&mut updated_transfer)?;
        self.save_sender_transport_endpoint(&txn, candidate.transfer.idx, &data.sender_proxy)?;

        let mut updated_batch_transfer: DbBatchTransferActMod = candidate.batch.clone().into();
        let outcome = {
            let transport = WasmReceiveTransport::new(self, indexer_url, &reject_lists);
            self.drive_receive(
                &transport,
                &prefetched,
                &txn,
                &candidate.batch,
                &candidate.asset_transfer,
                &candidate.transfer,
                recipient_id,
                &consignment_path,
                mode,
                &mut updated_batch_transfer,
            )
            .await
        };
        match outcome {
            Ok((_, retrieval)) => {
                self.persist_and_commit(txn)?;
                // the marker travels in the same snapshot as the receive it releases: the host
                // flushes first and only then posts it
                if let Some(retrieval) = &retrieval {
                    self.save_pending_retrieval(retrieval)?;
                }
                Ok(ReceiveOutcome::Handled)
            }
            Err(e) => {
                // dropping the transaction is the rollback
                drop(txn);
                Err(e)
            }
        }
    }
}
