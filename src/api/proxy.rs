//! Client for the RGB proxy protocol's JSON-RPC API.
//!
//! The protocol (v1.0) is specified in the `README.md` of
//! [rgb-http-json-rpc](https://github.com/RGB-Tools/rgb-http-json-rpc), while the rationale
//! behind it and the expected client behavior are detailed in `v1.0-changes-spec.md`, whose
//! sections the comments in this crate refer to.
//!
//! All timestamps are absolute Unix timestamps in seconds, UTC.
//!
//! This is the native blocking transport. The protocol definitions and the request builders live
//! in [`super::jsonrpc`] and are shared with the browser `fetch` client, so payloads, signatures
//! and error mapping are the same on both.

use super::*;

// keep the protocol types importable from this module, as they were before the browser transport
// moved them into `jsonrpc`
pub(crate) use super::jsonrpc::*;

pub struct ProxyClient {
    client: RestClient,
    base_url: String,
}

impl ProxyClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, Error> {
        let client = RestClient::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
            .timeout(Duration::from_secs(READ_WRITE_TIMEOUT))
            .build()?;
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

    fn file_size(path: &Path) -> Result<u64, Error> {
        Ok(std::fs::metadata(path).map_err(Self::req_err)?.len())
    }

    fn call<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<JsonRpcResponse<R>, Error> {
        let body = request_body(method, params);
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<R>>()
            .map_err(Self::req_err)
    }

    fn call_multipart<R: serde::de::DeserializeOwned>(
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
            .multipart(form)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<R>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn get_info(&self) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        self.call("server.info", None::<NullRequest>)
    }

    pub(crate) fn check_invoices(
        &self,
        invoice_ids: &[String],
    ) -> Result<JsonRpcResponse<HashMap<String, InvoiceCheckResponse>>, Error> {
        self.call(
            "invoice.check",
            Some(InvoiceIDsParam {
                invoice_ids: invoice_ids.to_vec(),
            }),
        )
    }

    pub(crate) fn prepare_invoice(
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
    }

    pub(crate) fn get_consignment(
        &self,
        transfer_id: &str,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error> {
        self.call(
            "consignment.get",
            Some(TransferIDParam {
                transfer_id: transfer_id.to_string(),
            }),
        )
    }

    pub(crate) fn post_consignment<P: AsRef<Path>>(
        &self,
        data: &PostConsignmentData,
        consignment_path: P,
        pow_timestamp: &str,
        pow_nonce: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let file_size = Self::file_size(consignment_path.as_ref())?;
        let params = params_json(&PostConsignmentParams {
            data: data.clone(),
            file_size: file_size.to_string(),
            pow_timestamp: pow_timestamp.to_string(),
            pow_nonce: pow_nonce.to_string(),
        });
        self.call_multipart(
            "consignment.post",
            params,
            multipart::Part::file(consignment_path)?,
        )
    }

    pub(crate) fn get_media(
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
    }

    pub(crate) fn post_media<P: AsRef<Path>>(
        &self,
        transfer_id: &str,
        media_id: &str,
        media_path: P,
        signature: &str,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let file_size = Self::file_size(media_path.as_ref())?;
        let params = params_json(&PostMediaParams {
            transfer_id: transfer_id.to_string(),
            media_id: media_id.to_string(),
            file_size: file_size.to_string(),
            signature: signature.to_string(),
        });
        self.call_multipart("media.post", params, multipart::Part::file(media_path)?)
    }

    pub(crate) fn list_transfers(
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
    }

    pub(crate) fn transfer_retrieved(
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
    }

    pub(crate) fn prepare_ack(
        &self,
        transfer_data: HashMap<String, AckTransferData>,
        expiration: &str,
        signed_tx_hash: &str,
        sender_pk: &str,
        signature: Option<String>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        // the signed TXs are uploaded as a file mapping each transfer ID to its signed TX
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
        self.call_multipart("ack.prepare", params, file)
    }

    pub(crate) fn post_ack(
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
    }

    pub(crate) fn get_ack(
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
    }

    pub(crate) fn clean_ack(
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_proxy_errors<T: std::fmt::Debug, F: Fn(&ProxyClient) -> Result<T, Error>>(f: F) {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        assert_matches!(f(&client).unwrap_err(), Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        assert_matches!(f(&client).unwrap_err(), Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        assert_matches!(f(&client).unwrap_err(), Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn map_proxy_error_expiration() {
        let map = |code: i64, data: Option<serde_json::Value>| {
            map_proxy_error(JsonRpcError {
                code,
                message: s!("msg"),
                data,
            })
        };

        // invalid expires_at, alone or among other invalid fields
        let err = map(-200, Some(serde_json::json!({"fields": ["expires_at"]})));
        assert_matches!(err, Error::ExpirationInvalid);
        let fields = serde_json::json!({"fields": ["invoice_id", "expires_at"]});
        let err = map(-200, Some(fields));
        assert_matches!(err, Error::ExpirationInvalid);

        // other invalid fields, no data, unexpected data
        let err = map(-200, Some(serde_json::json!({"fields": ["signature"]})));
        assert_matches!(err, Error::Proxy { .. });
        let err = map(-200, None);
        assert_matches!(err, Error::Proxy { .. });
        let err = map(-200, Some(serde_json::json!("expires_at")));
        assert_matches!(err, Error::Proxy { .. });

        // a missing expires_at is not an invalid expiration
        let err = map(-300, Some(serde_json::json!({"fields": ["expires_at"]})));
        assert_matches!(err, Error::Proxy { .. });
    }

    // confirm the error mapping is correct
    //
    // -502 (InvalidEndpointAuthSignature, ack.clean/ack.get) has no reachable integration
    // test today: the auto-generated per-operation key it authenticates has no public API to
    // corrupt. The wallet's handling of it is unit-tested in wallet::online::tests
    #[test]
    fn map_proxy_error_endpoint_auth_signature() {
        let err = map_proxy_error(JsonRpcError {
            code: -502,
            message: s!("Invalid endpoint auth signature"),
            data: None,
        });
        assert_matches!(err, Error::InvalidEndpointAuthSignature);
    }

    #[test]
    fn map_proxy_error_signed_tx_cleared() {
        let map = |data: Option<serde_json::Value>| {
            map_proxy_error(JsonRpcError {
                code: -100,
                message: s!("Cannot change"),
                data,
            })
        };

        // signed_tx is the sole reported change: a benign post-ack.clean recovery
        let err = map(Some(serde_json::json!({"fields": ["signed_tx"]})));
        assert_matches!(err, Error::SignedTxCleared);

        // any other field, alone or together with signed_tx, is a genuine conflict
        let err = map(Some(serde_json::json!({"fields": ["sender_pk"]})));
        assert_matches!(err, Error::ProxyCannotChange { .. });
        let err = map(Some(
            serde_json::json!({"fields": ["signed_tx", "sender_pk"]}),
        ));
        assert_matches!(err, Error::ProxyCannotChange { .. });

        // no or unexpected data also falls back to the generic error
        let err = map(None);
        assert_matches!(err, Error::ProxyCannotChange { .. });
        let err = map(Some(serde_json::json!("signed_tx")));
        assert_matches!(err, Error::ProxyCannotChange { .. });
    }

    #[test]
    fn get_info_error() {
        assert_proxy_errors(|c| c.get_info());
    }

    #[test]
    fn check_invoices_error() {
        assert_proxy_errors(|c| c.check_invoices(&[s!("123")]));
    }

    #[test]
    fn prepare_invoice_error() {
        assert_proxy_errors(|c| c.prepare_invoice("123", "999", "pk", None));
    }

    #[test]
    fn list_transfers_error() {
        assert_proxy_errors(|c| c.list_transfers("123", "00", "999"));
    }

    #[test]
    fn transfer_retrieved_error() {
        assert_proxy_errors(|c| c.transfer_retrieved("123", "00"));
    }

    #[test]
    fn map_proxy_error_invoice_reuse() {
        let map = |code: i64| {
            map_proxy_error(JsonRpcError {
                code,
                message: s!("msg"),
                data: None,
            })
        };
        assert_matches!(map(-101), Error::InvoiceNotReserved);
        assert_matches!(map(-102), Error::TransferIDInUse);
        assert_matches!(map(-111), Error::InvoiceExpired);
        assert_matches!(map(-112), Error::InvoiceQuotaExceeded);
        assert_matches!(map(-113), Error::TransferIDDeleted);
        assert_matches!(map(-115), Error::ProxyDraining);
        assert_matches!(map(-116), Error::ProxyTooManyMedia);
        assert_matches!(map(-402), Error::NoConsignment);
        assert_matches!(map(-403), Error::NoConsignment);
    }

    #[test]
    fn pow_difficulty_from_error() {
        let err = |code: i64, data: Option<serde_json::Value>| JsonRpcError {
            code,
            message: s!("msg"),
            data,
        };
        let data = Some(serde_json::json!({"pow_difficulty": "12"}));
        assert_eq!(pow_difficulty_required(&err(-114, data.clone())), Some(12));
        assert_eq!(pow_difficulty_required(&err(-200, data)), None);
        assert_eq!(pow_difficulty_required(&err(-114, None)), None);
        let bad = Some(serde_json::json!({"pow_difficulty": "x"}));
        assert_eq!(pow_difficulty_required(&err(-114, bad)), None);
    }

    #[test]
    fn get_consignment_error() {
        assert_proxy_errors(|c| c.get_consignment("123"));
    }

    #[test]
    fn get_media_error() {
        assert_proxy_errors(|c| c.get_media("123", "456"));
    }

    #[test]
    fn post_ack_error() {
        assert_proxy_errors(|c| c.post_ack("123", true, "00"));
    }

    #[test]
    fn get_ack_error() {
        assert_proxy_errors(|c| c.get_ack(&[s!("123")], "00", "999"));
    }

    #[test]
    fn clean_ack_error() {
        assert_proxy_errors(|c| c.clean_ack(&[s!("123")], "00"));
    }

    #[test]
    fn post_consignment_error() {
        let tmp_path = tempfile::NamedTempFile::new().unwrap();
        let data = PostConsignmentData {
            invoice_id: s!("iid"),
            transfer_id: s!("123"),
            sender_transport_endpoint: s!("rpc://x"),
            sender_pk: s!("pk"),
            consignment_hash: s!("h"),
            batch: false,
            signature: s!("00"),
        };
        assert_proxy_errors(|c| c.post_consignment(&data, tmp_path.path(), "999", "0"));
    }

    #[test]
    fn post_media_error() {
        let tmp_path = tempfile::NamedTempFile::new().unwrap();
        assert_proxy_errors(|c| c.post_media("123", "456", tmp_path.path(), "00"));
    }

    #[test]
    fn prepare_ack_error() {
        assert_proxy_errors(|c| c.prepare_ack(HashMap::new(), "999", "h", "pk", None));
    }

    // Wire parity with the browser client: both build the JSON-RPC envelope and the multipart
    // `params` field through `jsonrpc`, so the body the native client puts on the wire is exactly
    // the body the shared builder produces.
    #[test]
    fn native_wire_body_matches_the_shared_builder() {
        let expected = serde_json::to_string(&request_body(
            "consignment.get",
            Some(TransferIDParam {
                transfer_id: s!("123"),
            }),
        ))
        .unwrap();
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_header("content-type", JSON)
            .match_body(mockito::Matcher::Exact(expected.clone()))
            .with_status(200)
            .with_header("content-type", JSON)
            .with_body(r#"{"jsonrpc":"2.0","result":{"consignment":"c","sender_transport_endpoint":"rpc://x","sender_pk":"pk","consignment_hash":"h","batch":false}}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        assert!(client.get_consignment("123").unwrap().result.is_some());
        mock.assert();
    }

    #[test]
    fn native_multipart_params_match_the_shared_builder() {
        let expected = params_json(&PostMediaParams {
            transfer_id: s!("123"),
            media_id: s!("456"),
            file_size: s!("0"),
            signature: s!("00"),
        });
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(regex::escape(&expected)))
            .with_status(200)
            .with_header("content-type", JSON)
            .with_body(r#"{"jsonrpc":"2.0","result":true}"#)
            .create();
        let tmp_path = tempfile::NamedTempFile::new().unwrap();
        let client = ProxyClient::new(&server.url()).unwrap();
        assert!(
            client
                .post_media("123", "456", tmp_path.path(), "00")
                .unwrap()
                .result
                .unwrap()
        );
        mock.assert();
    }
}
