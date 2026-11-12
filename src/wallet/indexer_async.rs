//! Async Esplora transport for the browser wallet.
//!
//! `esplora-client`'s async client runs over `reqwest`'s `fetch` backend on wasm32, so the browser
//! performs the HTTPS request: no socket and no TLS stack of our own enter the dependency graph.
//! This module wraps that client in the same operations the blocking indexer exposes for Esplora
//! and maps its errors through the same [`IndexerError`] variant, so response semantics are
//! preserved when the wallet online path moves over to it.
//!
//! The read-only BDK sync (`Wallet::sync_async` in `wasm_online`) drives the transport through
//! [`EsploraAsyncExt`](bdk_esplora::EsploraAsyncExt); the browser receive path uses the same
//! client through the prefetched resolver. Building a transport only constructs the HTTP client
//! and never contacts the server.
//!
//! `esplora-client` drops `Builder::timeout` on wasm32, so every request instead gets a hard
//! deadline from a `fetch` wrapper the transport installs before building its client. The wrapper
//! also marks responses `no-store`, because an Esplora server may send `cache-control: max-age`
//! and the browser would otherwise serve stale chain data.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};
use std::{
    cmp::Ordering,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bdk_chain::spk_client::{FullScanRequest, FullScanResponse};
use bdk_esplora::EsploraAsyncExt;
use bdk_esplora::esplora_client::{
    AsyncClient, Builder as EsploraAsyncBuilder, Sleeper, Tx as EsploraTx,
};
use rgbstd::bitcoin::constants::ChainHash;
use rgbstd::vm::WitnessPos;
use wasm_bindgen::{JsCast, closure::Closure};

use crate::{error::IndexerError, utils::INDEXER_RETRIES, utils::INDEXER_TIMEOUT};

use super::resolver_async::AsyncChainResolver;
use super::*;

/// Installs, for `base`, a `fetch` wrapper that bounds every request it serves.
///
/// `esplora-client` ignores `Builder::timeout` on wasm32 because its `reqwest` fetch backend has
/// no request timeout, so the deadline is set on the browser side: the wrapper combines the
/// request's own signal with `AbortSignal.timeout` and marks the response `no-store`. Requests are
/// matched by their normalized URL, so a trailing slash on `base` makes no difference. A browser
/// without `AbortSignal.any` or `AbortSignal.timeout` gets a plain `fetch` with `no-store` and no
/// deadline: the request is then bounded only by the network stack.
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
function normalizeBase(value) {
    return String(value).replace(/\/+$/, '');
}

function timeoutFor(url) {
    const timeouts = globalThis.__rgbLibEsploraTimeouts;
    if (!timeouts) return undefined;
    const target = normalizeBase(url);
    for (const [base, millis] of timeouts) {
        if (target === base || target.startsWith(base + '/')) return millis;
    }
    return undefined;
}

function deadlineSignal(input, init, millis) {
    const AbortSignalImpl = globalThis.AbortSignal;
    if (!AbortSignalImpl || !AbortSignalImpl.any || !AbortSignalImpl.timeout) {
        // no combinable deadline in this browser: fetch without one, as before
        return undefined;
    }
    const signals = [];
    if (input && input.signal) signals.push(input.signal);
    if (init && init.signal) signals.push(init.signal);
    signals.push(AbortSignalImpl.timeout(millis));
    return AbortSignalImpl.any(signals);
}

export function installEsploraRequestTimeout(base, timeoutMillis) {
    const g = globalThis;
    if (!g.__rgbLibEsploraTimeouts) g.__rgbLibEsploraTimeouts = new Map();
    g.__rgbLibEsploraTimeouts.set(normalizeBase(base), timeoutMillis);
    if (g.fetch && g.fetch.__rgbLibEsploraWrapped) return;
    const inner = g.fetch;
    const wrapped = function (input, init) {
        const raw = typeof input === 'string' ? input : input && (input.url || input.href);
        const millis = timeoutFor(raw || '');
        const signal = millis === undefined ? undefined : deadlineSignal(input, init, millis);
        // cloning keeps the caller's method, headers and body; only cache mode and signal change
        const options = Object.assign({}, init, { cache: 'no-store' });
        if (signal !== undefined) options.signal = signal;
        return inner.call(g, new Request(input, options));
    };
    wrapped.__rgbLibEsploraWrapped = true;
    g.fetch = wrapped;
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = installEsploraRequestTimeout)]
    fn install_esplora_request_timeout(base: &str, timeout_millis: u32);
}

/// Browser timer for the client's retry backoff.
///
/// `Sleeper` is the seam that keeps `AsyncClient` runtime-agnostic: without the client's `tokio`
/// feature there is no `DefaultSleeper` implementation, and the browser has no runtime timer of
/// its own, so the delay is a promise driven by `setTimeout`.
#[derive(Debug, Clone, Copy)]
struct BrowserSleeper;

impl Sleeper for BrowserSleeper {
    type Sleep = BrowserSleep;

    fn sleep(duration: Duration) -> Self::Sleep {
        BrowserSleep::new(duration)
    }
}

/// One `setTimeout` delay as a `Send` future.
///
/// BDK's async extension requires `S::Sleep: Send`, but [`JsFuture`](js_sys::futures::JsFuture)
/// holds an `Rc` and is not `Send`. The timer callback therefore only flips an `AtomicBool` and
/// wakes the stored waker, while the JS closure stays on the JS side: the future itself carries
/// `Send` state.
pub(crate) struct BrowserSleep {
    fired: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl BrowserSleep {
    fn new(duration: Duration) -> Self {
        let fired = Arc::new(AtomicBool::new(false));
        let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let callback_fired = Arc::clone(&fired);
        let callback_waker = Arc::clone(&waker);
        let callback = Closure::once(move || {
            callback_fired.store(true, AtomicOrdering::SeqCst);
            if let Some(waker) = callback_waker
                .lock()
                .expect("the sleeper waker is never poisoned")
                .take()
            {
                waker.wake();
            }
        });
        // shortcut: `setTimeout` takes i32 milliseconds (~24.8 days), far beyond any backoff
        let millis = duration.as_millis().min(i32::MAX as u128) as i32;
        let function = callback
            .into_js_value()
            .unchecked_into::<js_sys::Function>();
        web_sys::window()
            .expect("browser window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&function, millis)
            .expect("setTimeout");
        Self { fired, waker }
    }
}

impl Future for BrowserSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.fired.load(AtomicOrdering::SeqCst) {
            return Poll::Ready(());
        }
        *self
            .waker
            .lock()
            .expect("the sleeper waker is never poisoned") = Some(cx.waker().clone());
        // the callback may have fired between the first load and storing the waker
        if self.fired.load(AtomicOrdering::SeqCst) {
            return Poll::Ready(());
        }
        Poll::Pending
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
    /// The URL is used exactly as given, as the blocking indexer does. `reqwest`'s wasm backend
    /// has no per-request timeout, so the deadline comes from the `fetch` wrapper installed here,
    /// before the client is built; `.timeout` is still set so the builder reads the same as the
    /// native one, but `esplora-client` ignores it on wasm32.
    pub(crate) fn new(indexer_url: &str) -> Result<Self, IndexerError> {
        Self::with_request_timeout(indexer_url, INDEXER_TIMEOUT)
    }

    /// [`new`](Self::new) with an explicit per-request deadline in seconds.
    #[cfg(test)]
    pub(crate) fn new_with_timeout(
        indexer_url: &str,
        timeout_secs: u64,
    ) -> Result<Self, IndexerError> {
        Self::with_request_timeout(indexer_url, timeout_secs)
    }

    fn with_request_timeout(indexer_url: &str, timeout_secs: u64) -> Result<Self, IndexerError> {
        // bounded to u32 milliseconds: the native default is 10 s, far below the i32 `setTimeout`
        // and `AbortSignal.timeout` limits, and a caller cannot ask for an unbounded one
        let timeout_millis = u32::try_from(timeout_secs.saturating_mul(1000)).unwrap_or(u32::MAX);
        install_esplora_request_timeout(indexer_url, timeout_millis);
        let builder = EsploraAsyncBuilder::new(indexer_url)
            .max_retries(INDEXER_RETRIES.into())
            .timeout(timeout_secs);
        Ok(Self {
            client: AsyncClient::from_builder(builder)?,
        })
    }

    /// Run a BDK full scan over the browser transport.
    ///
    /// The response is the update the wallet applies; the scan stops after `stop_gap` unused
    /// script pubkeys per keychain and issues at most `parallel_requests` HTTP requests at a time.
    pub(crate) async fn full_scan(
        &self,
        request: FullScanRequest<KeychainKind>,
        stop_gap: usize,
        parallel_requests: usize,
    ) -> Result<FullScanResponse<KeychainKind>, Error> {
        self.client
            .full_scan(request, stop_gap, parallel_requests)
            .await
            .map_err(|e| Error::from(IndexerError::from(*e)))
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

    /// TX ID at `index` in the block with `block_hash`, or `None` if the index is out of range.
    /// Lets a caller name a TX without a separate API lookup.
    pub(crate) async fn get_txid_at_block_index(
        &self,
        block_hash: &crate::bitcoin::BlockHash,
        index: usize,
    ) -> Result<Option<Txid>, IndexerError> {
        Ok(self
            .client
            .get_txid_at_block_index(block_hash, index)
            .await?)
    }

    /// Transaction info (transaction plus its confirmation status), or `None` if the indexer doesn't
    /// know it: the async shape of the blocking resolver's `get_tx_info`.
    pub(crate) async fn get_tx_info(&self, txid: &Txid) -> Result<Option<EsploraTx>, IndexerError> {
        Ok(self.client.get_tx_info(txid).await?)
    }

    /// Header of the block with `block_hash`, the second half of the blocking resolver's
    /// height-to-header lookup.
    pub(crate) async fn get_header_by_hash(
        &self,
        block_hash: &crate::bitcoin::BlockHash,
    ) -> Result<crate::bitcoin::block::Header, IndexerError> {
        Ok(self.client.get_header_by_hash(block_hash).await?)
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

/// The browser [`AsyncChainResolver`]: the async counterpart of the blocking Esplora resolver.
///
/// It mirrors `rgb-ops`'s blocking Esplora resolver response for response, so validation sees the
/// same `WitnessStatus` and headers whichever transport fetched them. The HTTP client keeps its
/// own retry policy (`INDEXER_RETRIES`) for transport failures; [`PrefetchedChain`] itself asks
/// each question once and does not retry.
///
/// Not wired into the online wallet flow yet: building it and calling the methods is all this
/// step proves, and the wallet sync path moves over in a later step.
///
/// [`PrefetchedChain`]: super::resolver_async::PrefetchedChain
#[allow(dead_code)] // only the compile-time proof below and the next step use it
pub(crate) struct EsploraResolver {
    transport: EsploraTransport,
}

#[allow(dead_code)]
impl EsploraResolver {
    /// Wrap a transport; constructing it contacts no server.
    pub(crate) fn new(transport: EsploraTransport) -> Self {
        Self { transport }
    }
}

#[allow(dead_code)]
impl AsyncChainResolver for EsploraResolver {
    async fn resolve_witness(
        &self,
        witness_id: RgbTxid,
    ) -> Result<WitnessStatus, WitnessResolverError> {
        let Some(tx_info) =
            self.transport.get_tx_info(&witness_id).await.map_err(|e| {
                WitnessResolverError::ResolverIssue(Some(witness_id), e.to_string())
            })?
        else {
            return Ok(WitnessStatus::Unresolved);
        };
        let ord = match (tx_info.status.block_height, tx_info.status.block_time) {
            (Some(height), Some(time)) => {
                let height =
                    NonZeroU32::new(height).ok_or(WitnessResolverError::InvalidResolverData)?;
                let time =
                    i64::try_from(time).map_err(|_| WitnessResolverError::InvalidResolverData)?;
                WitnessOrd::Mined(
                    WitnessPos::bitcoin(height, time)
                        .ok_or(WitnessResolverError::InvalidResolverData)?,
                )
            }
            _ => WitnessOrd::Tentative,
        };
        Ok(WitnessStatus::Resolved(tx_info.to_tx(), ord))
    }

    async fn get_block_header(
        &self,
        height: NonZeroU32,
    ) -> Result<crate::bitcoin::block::Header, WitnessResolverError> {
        // esplora has no height-keyed header endpoint: resolve the height to the hash of the block
        // occupying it in the best chain first, exactly like the blocking resolver
        let block_hash = self
            .transport
            .block_hash(height.get() as usize)
            .await
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?;
        let block_hash = crate::bitcoin::BlockHash::from_str(&block_hash)
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;
        self.transport
            .get_header_by_hash(&block_hash)
            .await
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))
    }

    async fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        let block_hash = self
            .transport
            .block_hash(0)
            .await
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?;
        let block_hash = crate::bitcoin::BlockHash::from_str(&block_hash)
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;
        if chain_net.chain_hash() != ChainHash::from_genesis_block_hash(block_hash) {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}

// Compile-time proof that the browser adapter plugs into the unchanged boundary trait.
const _: () = {
    const fn assert_async_resolver<R: AsyncChainResolver>() {}
    assert_async_resolver::<EsploraResolver>();
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
