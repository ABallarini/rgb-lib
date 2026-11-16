//! Browser send: the shared send authoring over the async proxy and Esplora transports.
//!
//! The PSBT, the consignments, the proofs of work, the signatures and the local apply are the ones
//! the native wallet runs (see [`WalletPrepare`]): this module only supplies the browser transport
//! to them and prefetches what the shared authoring cannot fetch while its database transaction is
//! open, i.e. the reject lists of the assets being sent. No host `Online` object takes part: the
//! caller passes the Esplora endpoint to the end call.
//!
//! Proxy-level authentication is not available here: there is no host API to configure the Ed25519
//! keys the native client uses, so `ack.prepare` is sent unsigned. A proxy requiring authentication
//! therefore refuses it with its explicit `InvalidProxyAuthSignature` error.

use super::transfer_wasm::prefetch_asset_reject_lists;
use super::*;
use crate::api::fetch::ProxyFetchClient;
use crate::api::jsonrpc::{
    AckTransferData, GetAckResponse, InvoiceCheckResponse, JsonRpcResponse, PostConsignmentData,
    ServerInfoResponse, check_server_info,
};
use crate::no_wallet::validation::{RejectList, RejectListSource};

/// Fetch the reject lists of all the assets a send touches, before its transaction opens.
async fn prefetch_reject_lists(
    wallet: &Wallet,
    recipient_map: &HashMap<String, Vec<Recipient>>,
    evm: Option<&EvmReceiveOptions>,
) -> Result<HashMap<RejectListSource, RejectList>, Error> {
    let mut lists = HashMap::new();
    for asset_id in recipient_map.keys() {
        lists.extend(prefetch_asset_reject_lists(wallet, asset_id, evm).await?);
    }
    Ok(lists)
}

impl Wallet {
    /// Prepare the PSBT to send RGB assets, returning it with its details.
    ///
    /// `recipient_map` maps each asset ID to its recipients, in the same shape the native
    /// `send_begin` takes. `recipient_map` is parsed from its JSON at the binding boundary.
    ///
    /// `evm` is the configuration of the EVM chain the bridge of a BFA asset lives on, needed to
    /// read the reject list such an asset keeps in its genesis; a URL list needs no configuration.
    ///
    /// `indexer_url` is reserved for the host-supplied Esplora endpoint: the begin contacts only
    /// the recipient proxies, so it is not used here, but the same endpoint must be passed to
    /// [`Wallet::send_end_async`].
    #[allow(clippy::too_many_arguments)]
    pub async fn send_begin_async(
        &mut self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: u64,
        sender_transport_endpoint: Option<String>,
        indexer_url: &str,
        evm: Option<EvmReceiveOptions>,
    ) -> Result<SendBeginResult, Error> {
        let _ = indexer_url;
        let reject_lists = prefetch_reject_lists(self, &recipient_map, evm.as_ref()).await?;
        let txn = self.database().begin_transaction()?;
        let begin_operation_data = self
            .send_begin_impl(
                &txn,
                recipient_map,
                donation,
                fee_rate,
                min_confirmations,
                Some(expiration_timestamp as i64),
                sender_transport_endpoint,
                false,
                reject_lists,
            )
            .await?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(SendBeginResult {
            psbt: begin_operation_data.psbt.to_string(),
            batch_transfer_idx: begin_operation_data.batch_transfer_idx,
            details: SendDetails {
                fascia_path: begin_operation_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_operation_data.info_batch_transfer.entropy,
                is_donation: donation,
            },
        })
    }

    /// Complete the send of the signed `signed_psbt`, broadcasting it over `indexer_url` when it is
    /// a donation, and return the result.
    pub async fn send_end_async(
        &mut self,
        indexer_url: &str,
        signed_psbt: &str,
    ) -> Result<OperationResult, Error> {
        let psbt = Psbt::from_str(signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_end_impl(&txn, &psbt, Some(indexer_url)).await?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(res)
    }
}

impl SendTransport for Wallet {
    async fn check_proxy_usable(&self, endpoint: &str) -> bool {
        let Ok(client) = ProxyFetchClient::new(endpoint) else {
            return false;
        };
        match client.get_info().await {
            Ok(info) => check_server_info(info).is_ok(),
            Err(_) => false,
        }
    }

    async fn get_proxy_info(
        &self,
        proxy_url: &str,
    ) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        ProxyFetchClient::new(proxy_url)?.get_info().await
    }

    async fn check_invoices(
        &self,
        proxy_url: &str,
        invoice_ids: &[String],
    ) -> Result<JsonRpcResponse<HashMap<String, InvoiceCheckResponse>>, Error> {
        ProxyFetchClient::new(proxy_url)?
            .check_invoices(invoice_ids)
            .await
    }

    async fn prepare_ack(
        &self,
        proxy_url: &str,
        transfer_data: HashMap<String, AckTransferData>,
        expiration: &str,
        signed_tx_hash: &str,
        sender_pk: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        ProxyFetchClient::new(proxy_url)?
            .prepare_ack(transfer_data, expiration, signed_tx_hash, sender_pk, None)
            .await
    }

    async fn get_ack(
        &self,
        proxy_url: &str,
        transfer_ids: &[String],
        signature: &str,
        timestamp: &str,
    ) -> Result<JsonRpcResponse<GetAckResponse>, Error> {
        ProxyFetchClient::new(proxy_url)?
            .get_ack(transfer_ids, signature, timestamp)
            .await
    }

    async fn post_consignment(
        &self,
        proxy_url: &str,
        data: &PostConsignmentData,
        consignment: Vec<u8>,
        file_name: &str,
        pow_timestamp: &str,
        pow_nonce: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        ProxyFetchClient::new(proxy_url)?
            .post_consignment(data, consignment, file_name, pow_timestamp, pow_nonce)
            .await
    }

    async fn post_media(
        &self,
        proxy_url: &str,
        transfer_id: &str,
        media_id: &str,
        media: Vec<u8>,
        file_name: &str,
        signature: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        ProxyFetchClient::new(proxy_url)?
            .post_media(transfer_id, media_id, media, file_name, signature)
            .await
    }

    async fn broadcast_signed_tx(
        &self,
        indexer_url: Option<&str>,
        tx: &BdkTransaction,
    ) -> Result<(), Error> {
        let indexer_url = indexer_url.ok_or_else(|| Error::Internal {
            details: s!("missing indexer URL for the broadcast"),
        })?;
        super::receive_wasm::broadcast_tx_async(self, indexer_url, tx).await
    }
}
