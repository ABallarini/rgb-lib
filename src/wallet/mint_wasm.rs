//! Browser mint: the shared mint authoring over the async proxy, EVM and Esplora transports.
//!
//! The begin checks, the input selection, the RGB PSBT, the consignment generation and post, the
//! lock check and the local apply are the ones the native wallet runs (see [`WalletPrepare`]): this
//! module only supplies the browser transports to them and prefetches what the shared authoring
//! cannot fetch while its database transaction is open, i.e. the reject list of the minted asset.
//! No host `Online` object takes part: the caller passes the EVM configuration to both calls and
//! the Esplora endpoint to the end one.
//!
//! The EVM endpoint is configured with [`EvmReceiveOptions`], the same shape a browser receive
//! takes. Unlike the native wallet, which going online checks once, the browser checks the
//! endpoint answers with the bridge chain ID before reading any block.

use super::*;
use crate::api::evm_abi::MintLockStatus;
use crate::api::evm_fetch::EvmFetchClient;

/// The browser EVM transport of a mint: the endpoint configured for the bridge chain.
pub(super) struct FetchMint<'a> {
    evm: Option<&'a EvmReceiveOptions>,
}

impl<'a> FetchMint<'a> {
    fn new(evm: Option<&'a EvmReceiveOptions>) -> Self {
        Self { evm }
    }
}

impl MintTransport for FetchMint<'_> {
    fn mint_chain(&self, chain_id: u64) -> Result<MintChainConfig, Error> {
        let Some(config) = self.evm.and_then(|evm| evm.config(chain_id)) else {
            return Err(Error::NoEvmRpcUrl { chain_id });
        };
        Ok(MintChainConfig {
            chain_id,
            rpc_url: config.rpc_url.clone(),
            min_mint_lock_blocks: config.min_mint_lock_blocks,
            max_mint_lock_blocks: config.max_mint_lock_blocks,
        })
    }

    async fn check_mint_chain_id(&self, chain: &MintChainConfig) -> Result<(), Error> {
        let actual = EvmFetchClient::new(&chain.rpc_url)?.chain_id().await?;
        if actual != chain.chain_id {
            return Err(Error::EvmChainIdMismatch {
                expected: chain.chain_id,
                actual,
            });
        }
        Ok(())
    }

    async fn mint_block_number(&self, chain: &MintChainConfig) -> Result<u64, Error> {
        EvmFetchClient::new(&chain.rpc_url)?.block_number().await
    }

    async fn mint_finalized_block_number(&self, chain: &MintChainConfig) -> Result<u64, Error> {
        EvmFetchClient::new(&chain.rpc_url)?
            .finalized_block_number()
            .await
    }

    async fn mint_lock_status(
        &self,
        chain: &MintChainConfig,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
        finalized_block: u64,
    ) -> Result<MintLockStatus, Error> {
        EvmFetchClient::new(&chain.rpc_url)?
            .mint_lock_status(contract, lock_id, amount, before_block, finalized_block)
            .await
    }

    async fn mint_circulating_supply(
        &self,
        chain: &MintChainConfig,
        contract: &EvmAddress,
    ) -> Result<Option<u64>, Error> {
        EvmFetchClient::new(&chain.rpc_url)?
            .circulating_supply(contract)
            .await
    }
}

impl Wallet {
    /// Prepare the PSBT to mint `recipient` a fungible amount of the BFA asset `asset_id`,
    /// returning it with its details.
    ///
    /// `before_block` is the external chain block the mint commits to: the lock has to be included
    /// before it, and it has to be within the `min_mint_lock_blocks`/`max_mint_lock_blocks` bounds
    /// of the EVM configuration, as the native wallet checks. The host reads the chain tip (see
    /// [`Wallet::evm_block_number_async`]) and picks the block.
    ///
    /// `evm` is the configuration of the chain the asset's bridge contract lives on: a mint of a
    /// chain it doesn't name fails with [`Error::NoEvmRpcUrl`].
    ///
    /// `indexer_url` is reserved for the host-supplied Esplora endpoint: the begin posts only to
    /// the recipient proxy, so it is not used here, but the same endpoint must be passed to
    /// [`Wallet::mint_end_async`].
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_begin_async(
        &mut self,
        indexer_url: &str,
        evm: Option<EvmReceiveOptions>,
        asset_id: String,
        recipient: Recipient,
        before_block: u64,
        fee_rate: u64,
        min_confirmations: u8,
        sender_transport_endpoint: String,
    ) -> Result<MintBeginResult, Error> {
        let _ = indexer_url;
        let reject_lists =
            super::transfer_wasm::prefetch_asset_reject_lists(self, &asset_id, evm.as_ref())
                .await?;
        let txn = self.database().begin_transaction()?;
        let mint_io = FetchMint::new(evm.as_ref());
        let begin_op_data = self
            .mint_begin_impl(
                &txn,
                &mint_io,
                asset_id,
                recipient,
                before_block,
                fee_rate,
                min_confirmations,
                sender_transport_endpoint,
                reject_lists,
            )
            .await?;
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(MintBeginResult {
            psbt: begin_op_data.psbt.to_string(),
            batch_transfer_idx: begin_op_data
                .batch_transfer_idx
                .expect("a mint is always saved, having no dry run"),
            details: MintDetails {
                fascia_path: begin_op_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_op_data.info_batch_transfer.entropy,
                opid: begin_op_data.opid.expect("always set for mint"),
            },
        })
    }

    /// Complete the mint of the signed `signed_psbt`, broadcasting it over `indexer_url`.
    ///
    /// As the native wallet does, it checks a finalized lock of the mint before broadcasting: a
    /// missing one leaves the mint as is ([`Error::MintLockNotFound`]), an expired one fails it
    /// and releases its inputs before erroring with [`Error::MintLockExpired`].
    pub async fn mint_end_async(
        &mut self,
        indexer_url: &str,
        evm: Option<EvmReceiveOptions>,
        signed_psbt: &str,
    ) -> Result<OperationResult, Error> {
        let psbt = Psbt::from_str(signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let mint_io = FetchMint::new(evm.as_ref());
        let res = match self
            .mint_end_impl(&txn, &mint_io, &psbt, Some(indexer_url))
            .await
        {
            Ok(res) => res,
            // the mint has been failed, which needs to be committed
            Err(e @ Error::MintLockExpired { .. }) => {
                self.update_backup_info(&txn, false)?;
                self.persist_and_commit(txn)?;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        self.update_backup_info(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(res)
    }

    /// The latest block of the EVM chain `chain_id`, after checking the configured endpoint
    /// answers with that chain ID.
    ///
    /// The host reads it to pick the `before_block` of a [`Wallet::mint_begin_async`], which has
    /// to stay within the configured bounds of the chain tip.
    pub async fn evm_block_number_async(
        &self,
        evm: &EvmReceiveOptions,
        chain_id: u64,
    ) -> Result<u64, Error> {
        let mint_io = FetchMint::new(Some(evm));
        let chain = mint_io.mint_chain(chain_id)?;
        mint_io.check_mint_chain_id(&chain).await?;
        mint_io.mint_block_number(&chain).await
    }
}
