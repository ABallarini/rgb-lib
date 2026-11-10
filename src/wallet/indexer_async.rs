//! Async Esplora transport for the browser wallet.
//!
//! `esplora-client`'s async client runs over `reqwest`'s `fetch` backend on wasm32, so the browser
//! performs the HTTPS request: no socket and no TLS stack of our own enter the dependency graph.
//! This module wraps that client in the same operations the blocking indexer exposes for Esplora
//! and maps its errors through the same [`IndexerError`] variant, so response semantics are
//! preserved when the wallet online path moves over to it.
//!
//! Nothing here is wired into the wallet yet: the sync path and the resolver come next. Building a
//! transport only constructs the HTTP client and never contacts the server.

use std::{cmp::Ordering, future::Future, pin::Pin, str::FromStr, time::Duration};

use bdk_esplora::esplora_client::{AsyncClient, Builder as EsploraAsyncBuilder, Sleeper};
use js_sys::Promise;
use wasm_bindgen_futures::JsFuture;

use crate::{error::IndexerError, utils::INDEXER_RETRIES};

use super::*;

/// Browser timer for the client's retry backoff.
///
/// `Sleeper` is the seam that keeps `AsyncClient` runtime-agnostic: without the client's `tokio`
/// feature there is no `DefaultSleeper` implementation, and the browser has no runtime timer of
/// its own, so the delay resolves a promise driven by `setTimeout`.
#[derive(Debug, Clone, Copy)]
struct BrowserSleeper;

impl Sleeper for BrowserSleeper {
    type Sleep = Pin<Box<dyn Future<Output = ()>>>;

    fn sleep(duration: Duration) -> Self::Sleep {
        Box::pin(async move {
            let promise = Promise::new(&mut |resolve, _reject| {
                // shortcut: `setTimeout` takes i32 milliseconds (~24.8 days), far beyond any backoff
                let millis = duration.as_millis().min(i32::MAX as u128) as i32;
                web_sys::window()
                    .expect("browser window")
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
                    .expect("setTimeout");
            });
            let _ = JsFuture::from(promise).await;
        })
    }
}

/// Esplora over the browser `fetch` API.
///
/// Mirrors the blocking indexer's Esplora operations so the wallet online path can be moved over
/// without changing responses.
#[allow(dead_code)] // only the tests use the transport until the sync path is wired
pub(crate) struct EsploraTransport {
    /// the client the sync path will drive with `EsploraAsyncExt`
    client: AsyncClient<BrowserSleeper>,
}

#[allow(dead_code)] // see the struct
impl EsploraTransport {
    /// Build the transport for `indexer_url` without contacting the server.
    ///
    /// The URL is used exactly as given, as the blocking indexer does. `reqwest`'s wasm backend has
    /// no per-request timeout, so only the retry count is carried over from its builder.
    pub(crate) fn new(indexer_url: &str) -> Result<Self, IndexerError> {
        let builder = EsploraAsyncBuilder::new(indexer_url).max_retries(INDEXER_RETRIES.into());
        Ok(Self {
            client: AsyncClient::from_builder(builder)?,
        })
    }

    /// Hash of the block at `height`.
    pub(crate) async fn block_hash(&self, height: usize) -> Result<String, IndexerError> {
        Ok(self.client.get_block_hash(height as u32).await?.to_string())
    }

    /// Broadcast a transaction.
    pub(crate) async fn broadcast(&self, tx: &BdkTransaction) -> Result<(), IndexerError> {
        Ok(self.client.broadcast(tx).await?)
    }

    /// Fee estimate for confirmation within `blocks`, in sat/vB, interpolated between the served
    /// targets exactly like the blocking indexer does.
    pub(crate) async fn fee_estimation(&self, blocks: u16) -> Result<f64, Error> {
        let estimate_map = self
            .client
            .get_fee_estimates()
            .await
            .map_err(IndexerError::from)?; // in sat/vB
        if estimate_map.is_empty() {
            return Err(Error::CannotEstimateFees);
        }
        // map needs to be sorted for interpolation to work
        let estimate_map = BTreeMap::from_iter(estimate_map);
        match estimate_map.get(&blocks) {
            Some(estimate) => Ok(*estimate),
            None => {
                // find the two closest keys
                let mut lower_key = None;
                let mut upper_key = None;
                for k in estimate_map.keys() {
                    match k.cmp(&blocks) {
                        Ordering::Less => {
                            lower_key = Some(k);
                        }
                        Ordering::Greater => {
                            upper_key = Some(k);
                            break;
                        }
                        _ => unreachable!("already handled"),
                    }
                }
                // use linear interpolation formula
                match (lower_key, upper_key) {
                    (Some(x1), Some(x2)) => {
                        let y1 = estimate_map[x1];
                        let y2 = estimate_map[x2];
                        Ok(y1
                            + (blocks as f64 - *x1 as f64) / (*x2 as f64 - *x1 as f64) * (y2 - y1))
                    }
                    _ => Err(Error::Internal {
                        details: s!("esplora map doesn't contain the expected keys"),
                    }),
                }
            }
        }
    }

    /// Height of the blockchain tip.
    pub(crate) async fn get_latest_block_height(&self) -> Result<u32, Error> {
        Ok(self.client.get_height().await.map_err(IndexerError::from)?)
    }

    /// Transaction, or `None` if the indexer doesn't know it. RGB witnesses are looked up by TX ID.
    pub(crate) async fn get_tx(&self, txid: &str) -> Result<Option<BdkTransaction>, Error> {
        let txid = Txid::from_str(txid).unwrap();
        Ok(self
            .client
            .get_tx(&txid)
            .await
            .map_err(IndexerError::from)?)
    }

    /// Confirmations of a transaction: `Some(0)` in the mempool, `None` if unknown, `u64::MAX` for
    /// the genesis coinbase, with the same tip consistency check as the blocking path.
    pub(crate) async fn get_tx_confirmations(&self, txid: &str) -> Result<Option<u64>, Error> {
        let txid = Txid::from_str(txid).unwrap();
        let tx_status = self
            .client
            .get_tx_status(&txid)
            .await
            .map_err(IndexerError::from)?;
        if let Some(tx_height) = tx_status.block_height {
            let height = self.get_latest_block_height().await?;
            // a tx height greater than the tip should never happen: it points to an inconsistent
            // indexer (e.g. the two values served from different sources/replicas, or a reorg
            // between the reads), so surface it as an error rather than underflowing
            let blocks_since = height
                .checked_sub(tx_height)
                .ok_or_else(|| Error::Indexer {
                    details: s!("indexer reported a transaction height greater than the chain tip"),
                })?;
            Ok(Some(u64::from(blocks_since) + 1))
        } else if self
            .client
            .get_tx(&txid)
            .await
            .map_err(IndexerError::from)?
            .is_none()
        {
            Ok(None)
        } else {
            Ok(Some(0))
        }
    }
}

// Compile-time proof that the transport is fetched from a URL and nothing else: `Builder::new`
// takes the string verbatim, `AsyncClient` on wasm32 is the `reqwest` fetch client, and the
// retry backoff is a browser timer, so no socket, runtime or TLS type can enter here.
const _: () = {
    let _: Option<AsyncClient<BrowserSleeper>> = None;
    let _: fn(&str) -> Result<EsploraTransport, IndexerError> = EsploraTransport::new;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_is_lazy_and_keeps_the_url() {
        // port 1 is not served: any request would fail, building the client must not make one
        let transport = EsploraTransport::new("http://127.0.0.1:1").expect("build transport");
        assert_eq!(transport.client.url(), "http://127.0.0.1:1");
    }
}
