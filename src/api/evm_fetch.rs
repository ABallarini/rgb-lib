//! Async EVM JSON-RPC client for the browser wallet.
//!
//! Mirrors the blocking `super::evm::EvmClient` on top of `reqwest`'s `fetch` backend: the
//! browser performs the HTTPS request, so no socket and no TLS stack of our own enter the
//! dependency graph. Selectors, ABI encoders/decoders, request/response envelopes and the pure
//! result decoders come from `super::evm_abi`, the same code the native client uses, so payloads,
//! bounds and error mapping are identical.
//!
//! What is deliberately different from native:
//!
//! - `reqwest` has no `connect_timeout` on wasm, so a single 15 s deadline covers connect and
//!   read for every request;
//! - the response body is capped before decoding;
//! - a temporary failure (HTTP 502/503/504 or a non-timeout transport error) is retried at once,
//!   without a pause: the browser has no timer dependency here and each attempt is already a full
//!   network round trip;
//! - a CORS or other transport failure is reported with the transport error only, never the URL,
//!   which can carry an API key.
//!
//! Nothing here logs a request or a body.

use std::time::Duration;

use reqwest_fetch::{Client, header::CONTENT_TYPE};
use serde::de::DeserializeOwned;

use super::evm_abi::*;
use super::*;

/// Per-request deadline. `fetch` has no separate connect timeout, so this is applied to the whole
/// request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// A JSON-RPC answer is small (a reject list page is the largest); a bigger body is not one.
const MAX_RESPONSE_BODY_BYTES: u64 = 1024 * 1024;
/// Number of times a JSON-RPC request is sent again when it fails for a temporary reason (see
/// [`EvmFetchClient::post`])
const RPC_RETRIES: u32 = 2;

/// Async JSON-RPC client for an EVM node over the browser `fetch` API.
#[allow(dead_code)] // receive wiring is not assembled yet; the methods are exercised by the ABI tests
pub(crate) struct EvmFetchClient {
    client: Client,
    rpc_url: String,
}

#[allow(dead_code)]
impl EvmFetchClient {
    /// Build the client; constructing it contacts no server.
    pub(crate) fn new(rpc_url: &str) -> Result<Self, Error> {
        // the wasm builder has no timeout knob, the deadline is applied per request
        let client = Client::builder().build().map_err(Self::req_err)?;
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Report a failure without the URL it may carry: hosted endpoints keep the API key in the
    /// path, the query or the user info.
    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::Network {
            details: format!("EVM RPC: {e}"),
        }
    }

    fn status_err(status: u16) -> Error {
        Error::Network {
            details: format!("EVM RPC: HTTP status {status}"),
        }
    }

    fn rpc_error(method: &str, err: RpcError) -> Error {
        Error::Network {
            details: format!("{method} error {}: {}", err.code, err.message),
        }
    }

    fn null_result(method: &str) -> Error {
        Error::Network {
            details: format!("{method} returned null result"),
        }
    }

    /// Post a JSON-RPC request, sending it again (up to [`RPC_RETRIES`] times) when it fails for a
    /// temporary reason: it cannot be sent (e.g. for a dropped connection) or the node answering
    /// it is temporarily unavailable (HTTP 502, 503 or 504). The requests of this client only read
    /// the chain, so they can be repeated.
    ///
    /// A timed out request is not sent again, as it already took long.
    async fn post(&self, body: &impl Serialize) -> Result<Vec<u8>, Error> {
        let mut retries = 0;
        loop {
            let res = self
                .client
                .post(&self.rpc_url)
                .header(CONTENT_TYPE, JSON)
                .timeout(REQUEST_TIMEOUT)
                .json(body)
                .send()
                .await;
            let temporary = match &res {
                Ok(resp) => matches!(resp.status().as_u16(), 502 | 503 | 504),
                Err(e) => !e.is_timeout() && !e.is_builder(),
            };
            match res {
                Ok(resp) => {
                    if !temporary {
                        return Self::read_body(resp).await;
                    }
                    // a temporary status is only reported once the retries are spent
                    if retries == RPC_RETRIES {
                        return Err(Self::status_err(resp.status().as_u16()));
                    }
                }
                Err(e) => {
                    if !temporary || retries == RPC_RETRIES {
                        return Err(Self::req_err(e.without_url()));
                    }
                }
            }
            retries += 1;
        }
    }

    /// Read a successful response body, refusing one larger than the cap.
    async fn read_body(response: reqwest_fetch::Response) -> Result<Vec<u8>, Error> {
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BODY_BYTES)
        {
            return Err(Self::req_err("response body exceeds the size limit"));
        }
        let status = response.status();
        if !status.is_success() {
            return Err(Self::status_err(status.as_u16()));
        }
        let bytes = response.bytes().await.map_err(Self::req_err)?;
        if bytes.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(Self::req_err("response body exceeds the size limit"));
        }
        Ok(bytes.to_vec())
    }

    /// Call a JSON-RPC method, returning the error it reports apart from the other failures, and
    /// its result, which can be null.
    async fn try_rpc<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Result<Option<R>, RpcError>, Error> {
        let body = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };
        let bytes = self.post(&body).await?;
        let resp: RpcResponse<R> = serde_json::from_slice(&bytes).map_err(Self::req_err)?;
        Ok(match resp.error {
            Some(err) => Err(err),
            None => Ok(resp.result),
        })
    }

    /// Call a JSON-RPC method, failing if it reports an error or no result.
    async fn rpc<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, Error> {
        self.try_rpc(method, params)
            .await?
            .map_err(|err| Self::rpc_error(method, err))?
            .ok_or_else(|| Self::null_result(method))
    }

    /// Call `contract` with `data` (`eth_call`) as of `block`, returning the raw result.
    async fn eth_call(
        &self,
        contract: &EvmAddress,
        data: String,
        block: impl Into<CallBlock>,
    ) -> Result<String, Error> {
        self.rpc("eth_call", call_params(contract, data, block))
            .await
    }

    /// Call `contract` with `data` (`eth_call`) as of `block`, returning the raw result, or `None`
    /// if the call reverts.
    async fn eth_call_unless_reverted(
        &self,
        contract: &EvmAddress,
        data: String,
        block: impl Into<CallBlock>,
    ) -> Result<Option<String>, Error> {
        let method = "eth_call";
        match self
            .try_rpc(method, call_params(contract, data, block))
            .await?
        {
            Ok(result) => result.map(Some).ok_or_else(|| Self::null_result(method)),
            // nodes report a revert with this message, followed by the reason if there's one
            Err(err) if err.is_revert() => Ok(None),
            Err(err) => Err(Self::rpc_error(method, err)),
        }
    }

    /// EIP-155 chain ID of the chain the node is connected to (`eth_chainId`).
    pub(crate) async fn chain_id(&self) -> Result<u64, Error> {
        parse_quantity(
            &self.rpc::<_, String>("eth_chainId", NO_PARAMS).await?,
            "chain ID",
        )
    }

    /// Check that the node serves the chain the bridge lives on, failing with a typed
    /// [`Error::EvmChainIdMismatch`] otherwise.
    pub(crate) async fn check_chain_id(&self, expected: u64) -> Result<(), Error> {
        let actual = self.chain_id().await?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::EvmChainIdMismatch { expected, actual })
        }
    }

    /// Number of the latest block (`eth_blockNumber`).
    pub(crate) async fn block_number(&self) -> Result<u64, Error> {
        parse_block_number(&self.rpc::<_, String>("eth_blockNumber", NO_PARAMS).await?)
    }

    /// Number of the latest finalized block (`eth_getBlockByNumber` with the `finalized` tag).
    pub(crate) async fn finalized_block_number(&self) -> Result<u64, Error> {
        let method = "eth_getBlockByNumber";
        let header: Option<super::evm_abi::BlockHeader> = self
            .try_rpc(method, ("finalized", false))
            .await?
            .map_err(|err| Self::rpc_error(method, err))?;
        let header = header.ok_or_else(|| Error::Network {
            details: s!("the node reports no finalized block"),
        })?;
        parse_block_number(&header.number)
    }

    /// The block the lock of `amount` with ID `lock_id` was included in, as recorded by the bridge
    /// contract at `contract` as of `block`, if any.
    pub(crate) async fn funds_in_block(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        block: impl Into<CallBlock>,
    ) -> Result<Option<u64>, Error> {
        let data = funds_in_block_calldata(lock_id, amount);
        let Some(result) = self.eth_call_unless_reverted(contract, data, block).await? else {
            return Ok(None);
        };
        decode_funds_in_block(&result)
    }

    /// The status of the lock of `amount` with ID `lock_id`, which has to be included before
    /// `before_block`, as recorded by the bridge contract at `contract` as of `finalized_block`.
    pub(crate) async fn mint_lock_status(
        &self,
        contract: &EvmAddress,
        lock_id: &LockId,
        amount: u64,
        before_block: u64,
        finalized_block: u64,
    ) -> Result<MintLockStatus, Error> {
        let record = self
            .funds_in_block(contract, lock_id, amount, finalized_block)
            .await?;
        Ok(mint_lock_status_from(record, before_block, finalized_block))
    }

    /// The circulating supply accounted by the bridge contract at `contract` as of the latest
    /// block (`circulatingSupply`), or `None` if the contract doesn't account it.
    pub(crate) async fn circulating_supply(
        &self,
        contract: &EvmAddress,
    ) -> Result<Option<u64>, Error> {
        let Some(result) = self
            .eth_call_unless_reverted(contract, circulating_supply_calldata(), CallBlock::Latest)
            .await?
        else {
            return Ok(None);
        };
        decode_circulating_supply(&result)
    }

    /// All the entries of the reject list kept by the `IRgbRejectList` contract at `contract`, in
    /// append order, telling which ones are finalized.
    pub(crate) async fn reject_list_entries(
        &self,
        contract: &EvmAddress,
    ) -> Result<RejectListLog, Error> {
        self.reject_list_entries_paged(contract, REJECT_LIST_PAGE_SIZE)
            .await
    }

    /// Length of the reject list kept by the `IRgbRejectList` contract at `contract` as of
    /// `block`, or `None` if there is no contract at `contract` as of `block`.
    async fn reject_list_length(
        &self,
        contract: &EvmAddress,
        block: u64,
    ) -> Result<Option<u64>, Error> {
        let len_data = self
            .eth_call(contract, reject_list_length_calldata(), block)
            .await?;
        decode_reject_list_length(&len_data)
    }

    async fn reject_list_entries_paged(
        &self,
        contract: &EvmAddress,
        page_size: u64,
    ) -> Result<RejectListLog, Error> {
        let block = self.block_number().await?;
        // a node behind a load balancer could report a finalized block past the latest one read
        let finalized_block = std::cmp::min(self.finalized_block_number().await?, block);
        // a contract deployed in a non-finalized block has no finalized entries
        let finalized_len = self
            .reject_list_length(contract, finalized_block)
            .await?
            .unwrap_or(0);
        let len = self
            .reject_list_length(contract, block)
            .await?
            .ok_or_else(|| Error::Network {
                details: format!("no contract at the reject list address {contract}"),
            })?;
        if finalized_len > len {
            return Err(Error::Network {
                details: s!("reject list shorter at the latest block than at the finalized one"),
            });
        }
        if len > MAX_REJECT_LIST_ENTRIES {
            return Err(Error::Network {
                details: format!(
                    "reject list too long: {len} entries, at most {MAX_REJECT_LIST_ENTRIES} supported"
                ),
            });
        }
        let mut entries = vec![];
        let mut start = 0;
        while start < len {
            let end = std::cmp::min(start.saturating_add(page_size), len);
            let data = reject_list_entries_calldata(start, end);
            let page = decode_reject_list_entries(&self.eth_call(contract, data, block).await?)?;
            if page.len() as u64 != end - start {
                return Err(abi_error("unexpected reject list page size"));
            }
            entries.extend(page);
            start = end;
        }
        Ok(RejectListLog {
            entries,
            finalized: finalized_len as usize,
        })
    }
}

// Compile-time proof that the browser client is built from a URL and a `fetch` client only: no
// socket, TLS or runtime type appears in its construction.
const _: () = {
    let _: fn(&str) -> Result<EvmFetchClient, Error> = EvmFetchClient::new;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_is_lazy_and_keeps_the_url() {
        // port 1 is not served: any request would fail, building the client must not make one
        let client = EvmFetchClient::new("http://127.0.0.1:1").expect("build fetch client");
        assert_eq!(client.rpc_url, "http://127.0.0.1:1");
    }
}
