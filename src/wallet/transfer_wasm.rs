//! Browser burn and link operations.
//!
//! The authoring is the shared one: [`WalletPrepare`] selects the inputs, builds the RGB PSBT and
//! saves or updates the transfer, exactly as the native wallet does. What is browser specific is
//! the transport, so only that lives here: the reject lists are prefetched before the database
//! transaction opens (the browser cannot fetch while one is), the signed TX is broadcast over the
//! async Esplora client and the local apply afterwards is the shared one.
//!
//! No host `Online` object takes part: the caller passes the Esplora endpoint to the end call.

use super::*;
use crate::no_wallet::validation::{RejectList, RejectListSource, genesis_reject_list_source};

/// The reject lists the begin of `asset_id` needs, read before the database transaction opens.
///
/// The asset declares its list in its genesis, which lives in the RGB stock behind a transaction:
/// one short read-only transaction reads the source, then the list is fetched with the wallet
/// closed. A list kept by an EVM contract needs the configuration of the chain it lives on, which
/// a browser caller supplies as it does for a receive.
pub(super) async fn prefetch_asset_reject_lists(
    wallet: &Wallet,
    asset_id: &str,
    evm: Option<&EvmReceiveOptions>,
) -> Result<HashMap<RejectListSource, RejectList>, Error> {
    let source = {
        let txn = wallet.database().begin_transaction()?;
        let asset = txn.check_asset_exists(asset_id.to_string())?;
        let contract_id =
            ContractId::from_str(&asset.id).map_err(|_| Error::InvalidContractId {
                contract_id: asset.id.clone(),
            })?;
        let stock = wallet.rgb_stock(&txn)?;
        let source = genesis_reject_list_source(asset.schema, &stock.genesis(contract_id)?)?;
        drop(stock);
        drop(txn);
        source
    };

    let mut lists = HashMap::new();
    if let Some(source) = source {
        let list = super::receive_wasm::fetch_reject_list(wallet, &source, evm).await?;
        lists.insert(source, list);
    }
    Ok(lists)
}

/// The prefetch at begin replaced the network read the native resolver does inside the operation:
/// reaching this hook means a list was not prefetched, which the browser cannot read now.
impl WalletPrepare for Wallet {
    fn resolve_reject_list(&self, source: &RejectListSource) -> Result<RejectList, Error> {
        Err(Error::Internal {
            details: format!("no prefetched reject list for {source:?}"),
        })
    }

    fn sync_colored_fast(&mut self, _txn: &DbTxn) -> Result<(), Error> {
        // a scan is a network round trip and a transaction is open: the browser scans before it
        Err(Error::Internal {
            details: s!("an unknown TXO cannot be synced while a transaction is open"),
        })
    }
}

impl Wallet {
    /// Prepare the PSBT to burn `amount` of `asset_id`, with the provided `fee_rate` (in sat/vB).
    ///
    /// `evm` is the configuration of the EVM chain the bridge of a BFA asset lives on, needed to
    /// read the reject list such an asset keeps in its genesis; a URL list needs no configuration.
    ///
    /// If `dry_run` is true the operation is not persisted, and the PSBT and the transfer data on
    /// disk are still produced.
    #[allow(clippy::too_many_arguments)]
    pub async fn burn_begin_async(
        &mut self,
        asset_id: String,
        amount: u64,
        burn_reason: Option<String>,
        fee_rate: u64,
        min_confirmations: u8,
        evm: Option<EvmReceiveOptions>,
        dry_run: bool,
    ) -> Result<BurnBeginResult, Error> {
        let reject_lists = prefetch_asset_reject_lists(self, &asset_id, evm.as_ref()).await?;
        let txn = self.database().begin_transaction()?;
        let begin_operation_data = self.burn_begin_impl(
            &txn,
            asset_id,
            amount,
            burn_reason,
            fee_rate,
            min_confirmations,
            reject_lists,
            dry_run,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        self.persist_and_commit(txn)?;
        Ok(BurnBeginResult {
            psbt: begin_operation_data.psbt.to_string(),
            batch_transfer_idx: begin_operation_data.batch_transfer_idx,
            details: BurnDetails {
                fascia_path: begin_operation_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_operation_data.info_batch_transfer.entropy,
                burn_reason: begin_operation_data
                    .info_batch_transfer
                    .transfers
                    .values()
                    .next()
                    .and_then(|transfer| transfer.main_transition.burn_reason())
                    .map(|burn_reason| burn_reason.to_string()),
            },
        })
    }

    /// Complete the burn of the signed `signed_psbt`, broadcasting it over `indexer_url`.
    ///
    /// A consignment proving the burn is written to disk, as no recipient receives one.
    pub async fn burn_end_async(
        &mut self,
        indexer_url: &str,
        signed_psbt: &str,
    ) -> Result<OperationResult, Error> {
        let psbt = Psbt::from_str(signed_psbt)?;
        let (res, _) = self
            .end_without_recipient_async(indexer_url, &psbt, TypeOfTransition::Burn)
            .await?;
        Ok(res)
    }

    /// Prepare the PSBT to link `asset_id` to `linked_to_contract`, with the provided `fee_rate`
    /// (in sat/vB).
    ///
    /// `evm` has the same role as in [`Wallet::burn_begin_async`]. `skip_contract_checks` skips
    /// checking that the contract linked to was issued linked from this one.
    #[allow(clippy::too_many_arguments)]
    pub async fn link_begin_async(
        &mut self,
        asset_id: String,
        linked_to_contract: String,
        fee_rate: u64,
        min_confirmations: u8,
        skip_contract_checks: bool,
        evm: Option<EvmReceiveOptions>,
        dry_run: bool,
    ) -> Result<LinkBeginResult, Error> {
        let reject_lists = prefetch_asset_reject_lists(self, &asset_id, evm.as_ref()).await?;
        let txn = self.database().begin_transaction()?;
        let begin_operation_data = self.link_begin_impl(
            &txn,
            asset_id,
            linked_to_contract,
            fee_rate,
            min_confirmations,
            skip_contract_checks,
            reject_lists,
            dry_run,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        self.persist_and_commit(txn)?;
        Ok(LinkBeginResult {
            psbt: begin_operation_data.psbt.to_string(),
            batch_transfer_idx: begin_operation_data.batch_transfer_idx,
            details: LinkDetails {
                fascia_path: begin_operation_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_operation_data.info_batch_transfer.entropy,
            },
        })
    }

    /// Complete the link of the signed `signed_psbt`, broadcasting it over `indexer_url`.
    ///
    /// A consignment proving the link is written to disk, as no recipient receives one.
    pub async fn link_end_async(
        &mut self,
        indexer_url: &str,
        signed_psbt: &str,
    ) -> Result<OperationResult, Error> {
        let psbt = Psbt::from_str(signed_psbt)?;
        let (res, _) = self
            .end_without_recipient_async(indexer_url, &psbt, TypeOfTransition::Link)
            .await?;
        Ok(res)
    }

    /// End an operation that pays no one (a burn or a link): the shared steps prepare the transfer
    /// data and the consignment, the async transport broadcasts the TX, then the shared steps apply
    /// it and save the transfer.
    ///
    /// The transaction stays open across the broadcast, as it does natively: the consignment and
    /// the transfer data are its writes, and the wallet is borrowed for the whole call, so nothing
    /// else can reach the backend meanwhile.
    async fn end_without_recipient_async(
        &mut self,
        indexer_url: &str,
        psbt: &Psbt,
        main_transition: TypeOfTransition,
    ) -> Result<(OperationResult, InfoBatchTransfer), Error> {
        let txn = self.database().begin_transaction()?;
        let end = self.prepare_without_recipient_end(&txn, psbt, main_transition)?;
        let tx = psbt.clone().extract_tx().map_err(InternalError::from)?;
        if let Err(e) = super::receive_wasm::broadcast_tx_async(self, indexer_url, &tx).await {
            // dropping the transaction is the rollback: nothing of the operation is kept
            drop(txn);
            return Err(e);
        }
        let res = self.finalize_without_recipient_end(&txn, psbt, end, &tx)?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(res)
    }
}
