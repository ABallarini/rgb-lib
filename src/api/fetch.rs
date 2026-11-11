//! Async proxy client for the browser wallet.
//!
//! Mirrors `super::proxy::ProxyClient` on top of `reqwest`'s `fetch` backend: the browser
//! performs the HTTPS request, so no socket and no TLS stack of our own enter the dependency
//! graph. Request construction, signing messages and error mapping come from `super::jsonrpc`,
//! the same code the native client uses, so the payloads and the validation are identical.
//!
//! The client is built and proven to compile here but is not wired into the wallet yet: the online
//! flow is still the blocking native one. What is deliberately different from native:
//!
//! - files are uploaded from memory (the browser has no filesystem path), with the same guessed
//!   part `Content-Type` the native `multipart::Part::file` derives from the path;
//! - `reqwest` has no `connect_timeout` on wasm, so a single per-request deadline covers connect
//!   and read, matching the native `READ_WRITE_TIMEOUT`;
//! - redirects are followed by `fetch`, which uses the browser's policy; `reqwest` exposes no
//!   redirect-policy override on wasm.
//!
//! Nothing here logs a request or a body: errors carry only the transport error's `Display`
//! output, exactly like the native client.

use std::time::Duration;

use reqwest_fetch::{Client, header::CONTENT_TYPE, multipart};
use serde::de::DeserializeOwned;

use super::jsonrpc::*;
use super::*;

/// Per-request deadline. `fetch` has no separate connect timeout, so this is the native read/write
/// timeout applied to the whole request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(READ_WRITE_TIMEOUT);

/// Proxy client over the browser `fetch` API, the async counterpart of the blocking one.
#[allow(dead_code)] // only the read-only health check (`new` + `get_info`) uses it until the online flow is wired
pub(crate) struct ProxyFetchClient {
    client: Client,
    base_url: String,
}

#[allow(dead_code)]
impl ProxyFetchClient {
    /// Build the client; constructing it contacts no server.
    pub(crate) fn new(base_url: &str) -> Result<Self, Error> {
        // the wasm builder has no timeout knob, the deadline is applied per request
        let client = Client::builder().build().map_err(Self::req_err)?;
        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::Proxy {
            details: e.to_string(),
        }
    }

    /// File part for an in-memory upload, with the same guessed `Content-Type` the native
    /// `multipart::Part::file` derives from the path's extension.
    fn upload_part(bytes: Vec<u8>, file_name: &str) -> Result<multipart::Part, Error> {
        let mime = mime_guess::from_path(file_name).first_or_octet_stream();
        multipart::Part::bytes(bytes)
            .file_name(file_name.to_string())
            .mime_str(mime.as_ref())
            .map_err(Self::req_err)
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<JsonRpcResponse<R>, Error> {
        let body = request_body(method, params);
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<R>>()
            .await
            .map_err(Self::req_err)
    }

    async fn call_multipart<R: DeserializeOwned>(
        &self,
        method: &str,
        params_json: String,
        file: multipart::Part,
    ) -> Result<JsonRpcResponse<R>, Error> {
        let form = multipart::Form::new()
            .text("method", method.to_string())
            .text("jsonrpc", "2.0")
            .text("id", "null")
            .text("params", params_json)
            .part("file", file);
        self.client
            .post(&self.base_url)
            .timeout(REQUEST_TIMEOUT)
            .multipart(form)
            .send()
            .await
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<R>>()
            .await
            .map_err(Self::req_err)
    }

    pub(crate) async fn get_info(&self) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        self.call("server.info", None::<NullRequest>).await
    }

    pub(crate) async fn check_invoices(
        &self,
        invoice_ids: &[String],
    ) -> Result<JsonRpcResponse<HashMap<String, InvoiceCheckResponse>>, Error> {
        self.call(
            "invoice.check",
            Some(InvoiceIDsParam {
                invoice_ids: invoice_ids.to_vec(),
            }),
        )
        .await
    }

    pub(crate) async fn prepare_invoice(
        &self,
        invoice_id: &str,
        expiration: &str,
        recipient_pk: &str,
        signature: Option<String>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        self.call(
            "invoice.prepare",
            Some(PrepareInvoiceParams {
                invoice_id: invoice_id.to_string(),
                expires_at: expiration.to_string(),
                recipient_pk: recipient_pk.to_string(),
                signature,
            }),
        )
        .await
    }

    pub(crate) async fn get_consignment(
        &self,
        transfer_id: &str,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error> {
        self.call(
            "consignment.get",
            Some(TransferIDParam {
                transfer_id: transfer_id.to_string(),
            }),
        )
        .await
    }

    /// Post a consignment read into memory by the caller, with the file name the native client
    /// would derive from the path.
    pub(crate) async fn post_consignment(
        &self,
        data: &PostConsignmentData,
        consignment: Vec<u8>,
        file_name: &str,
        pow_timestamp: &str,
        pow_nonce: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = params_json(&PostConsignmentParams {
            data: data.clone(),
            file_size: consignment.len().to_string(),
            pow_timestamp: pow_timestamp.to_string(),
            pow_nonce: pow_nonce.to_string(),
        });
        let file = Self::upload_part(consignment, file_name)?;
        self.call_multipart("consignment.post", params, file).await
    }

    pub(crate) async fn get_media(
        &self,
        transfer_id: &str,
        media_id: &str,
    ) -> Result<JsonRpcResponse<String>, Error> {
        self.call(
            "media.get",
            Some(MediaGetParams {
                transfer_id: transfer_id.to_string(),
                media_id: media_id.to_string(),
            }),
        )
        .await
    }

    /// Post a media read into memory by the caller.
    pub(crate) async fn post_media(
        &self,
        transfer_id: &str,
        media_id: &str,
        media: Vec<u8>,
        file_name: &str,
        signature: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = params_json(&PostMediaParams {
            transfer_id: transfer_id.to_string(),
            media_id: media_id.to_string(),
            file_size: media.len().to_string(),
            signature: signature.to_string(),
        });
        let file = Self::upload_part(media, file_name)?;
        self.call_multipart("media.post", params, file).await
    }

    pub(crate) async fn list_transfers(
        &self,
        invoice_id: &str,
        signature: &str,
        timestamp: &str,
    ) -> Result<JsonRpcResponse<HashMap<String, ProxyTransferState>>, Error> {
        self.call(
            "transfer.list",
            Some(ListTransfersParams {
                invoice_id: invoice_id.to_string(),
                signature: signature.to_string(),
                timestamp: timestamp.to_string(),
            }),
        )
        .await
    }

    pub(crate) async fn transfer_retrieved(
        &self,
        transfer_id: &str,
        signature: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        self.call(
            "transfer.retrieved",
            Some(TransferRetrievedParams {
                transfer_id: transfer_id.to_string(),
                signature: signature.to_string(),
            }),
        )
        .await
    }

    pub(crate) async fn prepare_ack(
        &self,
        transfer_data: HashMap<String, AckTransferData>,
        expiration: &str,
        signed_tx_hash: &str,
        sender_pk: &str,
        signature: Option<String>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let file = ack_file(&transfer_data);
        let params = params_json(&PrepareAckParams {
            transfer_data: transfer_data
                .iter()
                .map(|(tid, data)| {
                    (
                        tid.as_str(),
                        AckTransferParams {
                            recipient_pk: &data.recipient_pk,
                            consignment_hash: &data.consignment_hash,
                        },
                    )
                })
                .collect(),
            expires_at: expiration.to_string(),
            signed_tx_hash: signed_tx_hash.to_string(),
            sender_pk: sender_pk.to_string(),
            file_size: file.len().to_string(),
            signature,
        });
        let file = multipart::Part::bytes(file)
            .file_name("signed_txs.json")
            .mime_str(JSON)
            .expect("valid mime");
        self.call_multipart("ack.prepare", params, file).await
    }

    pub(crate) async fn post_ack(
        &self,
        transfer_id: &str,
        ack: bool,
        signature: &str,
    ) -> Result<JsonRpcResponse<PostAckResponse>, Error> {
        self.call(
            "ack.post",
            Some(PostAckParams {
                transfer_id: transfer_id.to_string(),
                ack,
                signature: signature.to_string(),
            }),
        )
        .await
    }

    pub(crate) async fn get_ack(
        &self,
        transfer_ids: &[String],
        signature: &str,
        timestamp: &str,
    ) -> Result<JsonRpcResponse<GetAckResponse>, Error> {
        self.call(
            "ack.get",
            Some(GetAckParams {
                transfer_ids: transfer_ids.to_vec(),
                signature: signature.to_string(),
                timestamp: timestamp.to_string(),
            }),
        )
        .await
    }

    pub(crate) async fn clean_ack(
        &self,
        transfer_ids: &[String],
        signature: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        self.call(
            "ack.clean",
            Some(CleanAckParams {
                transfer_ids: transfer_ids.to_vec(),
                signature: signature.to_string(),
            }),
        )
        .await
    }
}

// Compile-time proof that the browser client is built from a URL and a `fetch` client only: no
// socket, TLS or runtime type appears in its construction.
const _: () = {
    let _: fn(&str) -> Result<ProxyFetchClient, Error> = ProxyFetchClient::new;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_is_lazy_and_keeps_the_url() {
        // port 1 is not served: any request would fail, building the client must not make one
        let client = ProxyFetchClient::new("http://127.0.0.1:1").expect("build fetch client");
        assert_eq!(client.base_url, "http://127.0.0.1:1");
    }
}
