//! Read-only online access for the browser wallet.
//!
//! This is the smallest real online step on wasm32: a full scan of the BDK wallet over the async
//! Esplora transport, plus the tip height and fee estimate the host needs to show chain state. The
//! scan only reads from the indexer: the update is applied in memory and persisted through the same
//! database transaction and `persist_bdk` seam the offline operations use, so a host
//! snapshot/`flush` keeps it. Inside that transaction the shared native bookkeeping runs too, so a
//! payment to a pending witness script is reconciled and a newly seen colored TXO is registered.
//!
//! Not assembled here: `RgbWalletOpsOnline`, `OnlineOptions`, `go_online`, RGB consignment
//! reception, transfers and broadcast. They stay behind the native-only `_online` feature, and
//! `esplora_async` deliberately does not enable it. This module must not grow a duplicate of that
//! logic: it wires the existing BDK scan and indexer reads only.

use super::indexer_async::EsploraTransport;
use super::*;

/// Unused script pubkeys scanned per keychain before a full scan stops.
pub(crate) const DEFAULT_STOP_GAP: usize = 20;
/// HTTP requests the browser scan keeps in flight; a browser connection pool is small.
const PARALLEL_REQUESTS: usize = 1;
/// Same confirmation-target bounds the native fee estimation accepts.
const MIN_BLOCK_ESTIMATION: u16 = 1;
const MAX_BLOCK_ESTIMATION: u16 = 1008;

fn check_estimation_blocks(blocks: u16) -> Result<(), Error> {
    if !(MIN_BLOCK_ESTIMATION..=MAX_BLOCK_ESTIMATION).contains(&blocks) {
        return Err(Error::InvalidEstimationBlocks);
    }
    Ok(())
}

impl Wallet {
    /// Sync the BDK wallet against an Esplora endpoint, read-only.
    ///
    /// The full scan covers both keychains of the wallet (`colored` and `vanilla`), stops after
    /// `stop_gap` unused script pubkeys per keychain (20 when `None`) and applies the response to
    /// the shared BDK wallet. The resulting change is written to the wallet database in the same
    /// transaction as any other operation, so the wallet's next `snapshot`/`flush` carries it.
    ///
    /// The same transaction reconciles the pending witness state and registers the colored TXOs
    /// that became visible, exactly like the native full scan. Nothing is broadcast and no RGB
    /// consignment is received or validated: those paths need the RGB proxy and stay behind the
    /// proxy receive methods.
    pub async fn sync_async(
        &mut self,
        indexer_url: &str,
        stop_gap: Option<usize>,
    ) -> Result<(), Error> {
        let transport = EsploraTransport::new(indexer_url)?;
        let request = self
            .bdk_wallet()
            .start_full_scan_at(now().unix_timestamp() as u64);
        let response = transport
            .full_scan(
                request.into(),
                stop_gap.unwrap_or(DEFAULT_STOP_GAP),
                PARALLEL_REQUESTS,
            )
            .await?;
        self.bdk_wallet_mut()
            .apply_update(response)
            .map_err(|e| Error::FailedBdkSync {
                details: e.to_string(),
            })?;
        let txn = self.database().begin_transaction()?;
        self.sync_db_txos_from_bdk(&txn, false)?;
        self.persist_and_commit(txn)?;
        Ok(())
    }

    /// Fee estimate for confirmation within `blocks`, in sat/vB, read from an Esplora endpoint.
    ///
    /// `blocks` must be in `1..=1008`, the same range as the native wallet. The response is
    /// interpolated between the served targets exactly like the blocking Esplora indexer does. An
    /// endpoint with no fee history yields [`Error::CannotEstimateFees`].
    pub async fn fee_estimation_async(&self, indexer_url: &str, blocks: u16) -> Result<f64, Error> {
        check_estimation_blocks(blocks)?;
        EsploraTransport::new(indexer_url)?
            .fee_estimation(blocks)
            .await
    }

    /// Height of the best-chain tip reported by an Esplora endpoint.
    pub async fn tip_height_async(&self, indexer_url: &str) -> Result<u32, Error> {
        EsploraTransport::new(indexer_url)?
            .get_latest_block_height()
            .await
    }
}

// Compile-time proof that the future BDK needs to drive the scan is `Send`: the scan is what
// forces the browser sleeper onto `Send` state instead of a `JsFuture`.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<super::indexer_async::BrowserSleep>();
};

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn fee_estimation_range_matches_the_native_wallet() {
        assert!(check_estimation_blocks(0).is_err());
        assert!(check_estimation_blocks(MIN_BLOCK_ESTIMATION).is_ok());
        assert!(check_estimation_blocks(MAX_BLOCK_ESTIMATION).is_ok());
        assert!(check_estimation_blocks(MAX_BLOCK_ESTIMATION + 1).is_err());
    }
}
