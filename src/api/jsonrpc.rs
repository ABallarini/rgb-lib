//! Transport-agnostic half of the RGB proxy protocol client.
//!
//! The JSON-RPC envelope, the request parameters, the response types, the signing-message builders
//! and the error mapping live here so the native blocking client (`super::proxy`) and the browser
//! `fetch` client (`super::fetch`) build their requests through the same code. The signing,
//! authentication and validation inputs are therefore identical on both transports, and only the
//! HTTP layer differs.

use super::*;

/// Number of transfers an invoice is reserved for: invoices are single-use.
pub(crate) const INVOICE_QUOTA: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
    // -100 (cannot change), -200 (invalid) and -300 (missing) errors list the offending fields
    // under data.fields
    #[serde(default)]
    pub(crate) data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// Whether the error reports `field` among its offending ones (`data.fields`).
    fn has_field(&self, field: &str) -> bool {
        self.data
            .as_ref()
            .and_then(|d| d.get("fields"))
            .and_then(|f| f.as_array())
            .is_some_and(|fields| fields.iter().any(|f| f.as_str() == Some(field)))
    }

    /// Whether `data.fields` reports exactly `field` as the sole offending one.
    fn only_field(&self, field: &str) -> bool {
        self.data
            .as_ref()
            .and_then(|d| d.get("fields"))
            .and_then(|f| f.as_array())
            .is_some_and(|fields| fields.len() == 1 && fields[0].as_str() == Some(field))
    }

    /// The error message, followed by the offending fields (`data.fields`) when reported.
    fn details(&self) -> String {
        let fields: Vec<&str> = self
            .data
            .as_ref()
            .and_then(|d| d.get("fields"))
            .and_then(|f| f.as_array())
            .map(|fields| fields.iter().filter_map(|f| f.as_str()).collect())
            .unwrap_or_default();
        if fields.is_empty() {
            self.message.clone()
        } else {
            format!("{}: {}", self.message, fields.join(", "))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcRequest<P> {
    method: String,
    jsonrpc: String,
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<P>,
}

/// The JSON-RPC request envelope, shared by the native and browser clients so the serialized bytes
/// cannot drift between the two transports.
pub(crate) fn request_body<P: Serialize>(method: &str, params: Option<P>) -> JsonRpcRequest<P> {
    JsonRpcRequest {
        method: method.to_string(),
        jsonrpc: s!("2.0"),
        id: None,
        params,
    }
}

/// Serialized `params` field of the multipart calls, shared by both transports as well.
pub(crate) fn params_json<T: Serialize>(params: &T) -> String {
    serde_json::to_string(params).expect("serializable")
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcResponse<R> {
    jsonrpc: String,
    id: Option<String>,
    pub(crate) result: Option<R>,
    pub(crate) error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct NullRequest;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ServerInfoResponse {
    pub(crate) protocol_version: String,
    pub(crate) version: String,
    pub(crate) uptime: i64,
    // optional so the protocol-version check still works against older/non-compliant proxies whose
    // server.info response lacks v1.0 fields
    #[serde(default)]
    pub(crate) current_time: Option<String>,
    #[serde(default)]
    pub(crate) max_expiry_secs: Option<String>,
    #[serde(default)]
    pub(crate) max_quota: Option<String>,
    #[serde(default)]
    pub(crate) max_pow_difficulty: Option<String>,
    #[serde(default)]
    pub(crate) retention_grace_secs: Option<String>,
    #[serde(default)]
    pub(crate) max_media: Option<String>,
}

/// Status of an invoice on a recipient proxy, as reported by `invoice.check`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InvoiceStatus {
    /// the invoice is not known to the proxy (not reserved, or its data has been deleted)
    Unknown,
    /// the invoice is reserved and can still accept transfers
    Available,
    /// the invoice is reserved and its quota is full
    Full,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct InvoiceCheckResponse {
    pub(crate) status: InvoiceStatus,
    pub(crate) pow_difficulty: String,
}

/// State of a transfer on a recipient proxy, as reported by `transfer.list`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProxyTransferState {
    /// the transfer data (consignment and media) is available
    Pending,
    /// the transfer data has been deleted via `transfer.retrieved`
    Retrieved,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetConsignmentResponse {
    pub(crate) consignment: String,
    pub(crate) sender_transport_endpoint: String,
    pub(crate) sender_pk: String,
    pub(crate) consignment_hash: String,
    pub(crate) batch: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostAckResponse {
    pub(crate) result: bool,
    pub(crate) sender_pk: Option<String>,
    pub(crate) signed_tx: Option<String>,
    pub(crate) signed_tx_hash: Option<String>,
    // the operation expiration, which together with the sender proxy retention grace sets the
    // broadcast deadline; optional so responses from non-compliant proxies are still accepted
    #[serde(default)]
    pub(crate) expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct GetAckResponse {
    // transfers that have not been responded to yet (pending) are absent from both maps
    pub(crate) acks: HashMap<String, bool>,
    pub(crate) signatures: HashMap<String, String>,
}

/// Per-transfer data registered with `ack.prepare`, whose signed TX travels in the uploaded file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AckTransferData {
    pub(crate) recipient_pk: String,
    pub(crate) consignment_hash: String,
    pub(crate) signed_tx: String,
}

/// Data of a transfer posted with `consignment.post`, besides the consignment file.
#[derive(Debug, Clone, Serialize)]
pub struct PostConsignmentData {
    pub(crate) invoice_id: String,
    pub(crate) transfer_id: String,
    pub(crate) sender_transport_endpoint: String,
    pub(crate) sender_pk: String,
    pub(crate) consignment_hash: String,
    pub(crate) batch: bool,
    /// signature of `transfer_id ‖ consignment_hash ‖ blob_hash ‖ "consignment"` with the sender
    /// key
    pub(crate) signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TransferIDParam {
    pub(crate) transfer_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct InvoiceIDsParam {
    pub(crate) invoice_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct MediaGetParams {
    pub(crate) transfer_id: String,
    pub(crate) media_id: String,
}

/// Message authenticating an `invoice.prepare` call on a proxy with proxy-level authentication
/// enabled: `invoice_id ‖ expires_at ‖ recipient_pk ‖ quota`.
pub(crate) fn prepare_invoice_auth_message(
    invoice_id: &str,
    expires_at: &str,
    recipient_pk: &str,
) -> String {
    format!("{invoice_id}{expires_at}{recipient_pk}{INVOICE_QUOTA}")
}

/// Message authenticating an `ack.prepare` call on a proxy with proxy-level authentication
/// enabled: `sender_pk ‖ expires_at ‖ signed_tx_hash` followed, for each transfer sorted
/// lexicographically by transfer ID, by `transfer_id ‖ recipient_pk ‖ consignment_hash`.
pub(crate) fn prepare_ack_auth_message(
    sender_pk: &str,
    expires_at: &str,
    signed_tx_hash: &str,
    transfer_data: &HashMap<String, AckTransferData>,
) -> String {
    let mut message = format!("{sender_pk}{expires_at}{signed_tx_hash}");
    let mut transfer_ids: Vec<&String> = transfer_data.keys().collect();
    transfer_ids.sort();
    for transfer_id in transfer_ids {
        let data = &transfer_data[transfer_id];
        message.push_str(transfer_id);
        message.push_str(&data.recipient_pk);
        message.push_str(&data.consignment_hash);
    }
    message
}

/// Message signed by the sender to post a consignment:
/// `transfer_id ‖ consignment_hash ‖ blob_hash ‖ "consignment"`, the literal keeping it distinct
/// from the `media.post` one.
pub(crate) fn post_consignment_message(
    transfer_id: &str,
    consignment_hash: &str,
    blob_hash: &str,
) -> String {
    format!("{transfer_id}{consignment_hash}{blob_hash}consignment")
}

/// Message signed by the sender to post a media: `transfer_id ‖ media_id ‖ blob_hash ‖ "media"`,
/// the literal keeping it distinct from the `consignment.post` one.
pub(crate) fn post_media_message(transfer_id: &str, media_id: &str, blob_hash: &str) -> String {
    format!("{transfer_id}{media_id}{blob_hash}media")
}

/// Message signed by the recipient to list the transfers of an invoice: `invoice_id ‖ timestamp`.
pub(crate) fn list_transfers_message(invoice_id: &str, timestamp: &str) -> String {
    format!("{invoice_id}{timestamp}")
}

/// Message signed by the sender to get the ACKs of an operation: `sorted transfer_ids ‖ timestamp`.
pub(crate) fn get_ack_message(transfer_ids: &[String], timestamp: &str) -> String {
    let mut sorted_ids = transfer_ids.to_vec();
    sorted_ids.sort();
    format!("{}{timestamp}", sorted_ids.concat())
}

/// Message signed by the recipient to mark a transfer as retrieved: `transfer_id ‖ "retrieved"`.
pub(crate) fn transfer_retrieved_message(transfer_id: &str) -> String {
    format!("{transfer_id}retrieved")
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PrepareInvoiceParams {
    pub(crate) invoice_id: String,
    pub(crate) expires_at: String,
    pub(crate) recipient_pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PostConsignmentParams {
    #[serde(flatten)]
    pub(crate) data: PostConsignmentData,
    pub(crate) file_size: String,
    pub(crate) pow_timestamp: String,
    pub(crate) pow_nonce: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PostMediaParams {
    pub(crate) transfer_id: String,
    pub(crate) media_id: String,
    pub(crate) file_size: String,
    pub(crate) signature: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListTransfersParams {
    pub(crate) invoice_id: String,
    pub(crate) signature: String,
    pub(crate) timestamp: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct TransferRetrievedParams {
    pub(crate) transfer_id: String,
    pub(crate) signature: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AckTransferParams<'a> {
    pub(crate) recipient_pk: &'a str,
    pub(crate) consignment_hash: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct PrepareAckParams<'a> {
    pub(crate) transfer_data: HashMap<&'a str, AckTransferParams<'a>>,
    pub(crate) expires_at: String,
    pub(crate) signed_tx_hash: String,
    pub(crate) sender_pk: String,
    pub(crate) file_size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PostAckParams {
    pub(crate) transfer_id: String,
    pub(crate) ack: bool,
    pub(crate) signature: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GetAckParams {
    pub(crate) transfer_ids: Vec<String>,
    pub(crate) signature: String,
    pub(crate) timestamp: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CleanAckParams {
    pub(crate) transfer_ids: Vec<String>,
    pub(crate) signature: String,
}

/// The signed-TX file uploaded by `ack.prepare`, shared so both transports upload the same bytes.
pub(crate) fn ack_file(transfer_data: &HashMap<String, AckTransferData>) -> Vec<u8> {
    let signed_txs: HashMap<&str, &str> = transfer_data
        .iter()
        .map(|(tid, data)| (tid.as_str(), data.signed_tx.as_str()))
        .collect();
    serde_json::to_vec(&signed_txs).expect("serializable")
}

/// The proof of work difficulty required by a proxy refusing a `consignment.post` call with an
/// "invalid proof of work" error, if that is the error.
pub(crate) fn pow_difficulty_required(err: &JsonRpcError) -> Option<u32> {
    if err.code != -114 {
        return None;
    }
    err.data
        .as_ref()
        .and_then(|d| d.get("pow_difficulty"))
        .and_then(|d| d.as_str())
        .and_then(|d| d.parse().ok())
}

/// Map a proxy JSON-RPC error to a typed [`Error`].
pub(crate) fn map_proxy_error(err: JsonRpcError) -> Error {
    match err.code {
        // ack.clean nulls only signed_tx (rest of the operation is untouched); a later
        // ack.prepare re-supplying it is a legitimate recovery, not a conflict
        -100 if err.only_field("signed_tx") => Error::SignedTxCleared,
        -100 => Error::ProxyCannotChange {
            details: err.details(),
        },
        -101 => Error::InvoiceNotReserved,
        -102 => Error::TransferIDInUse,
        -104 => Error::OperationNotFound,
        -105 => Error::OperationExpired,
        // all the recipients have ACKed an operation, so its TX was released and can no longer be
        // revoked
        -107 => Error::ProxyTxAlreadyReleased,
        -111 => Error::InvoiceExpired,
        -112 => Error::InvoiceQuotaExceeded,
        -113 => Error::TransferIDDeleted,
        // the proxy refuses calls starting a new transfer
        -115 => Error::ProxyDraining,
        // the transfer already has the max number of media the proxy accepts
        -116 => Error::ProxyTooManyMedia,
        // the consignment is not (or no longer, after transfer.retrieved) available
        -400 | -402 | -403 => Error::NoConsignment,
        -401 => Error::NoMedia,
        -501 => Error::InvalidProxyAuthSignature,
        -502 => Error::InvalidEndpointAuthSignature,
        -503 => Error::InvalidContentSignature,
        // an expiration in the past or beyond the proxy's max_expiry_secs
        -200 if err.has_field("expires_at") => Error::ExpirationInvalid,
        // other -200 (invalid), -300 (missing), -301 (missing file) and anything else
        _ => Error::Proxy {
            details: err.details(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The serialized bytes are the parity contract between the native blocking client and the
    // browser fetch client: both call `request_body`, so pinning the string here pins both.
    #[test]
    fn request_body_serialization() {
        let null =
            serde_json::to_string(&request_body("server.info", None::<NullRequest>)).unwrap();
        assert_eq!(
            null,
            r#"{"method":"server.info","jsonrpc":"2.0","id":null}"#
        );

        let params = TransferIDParam {
            transfer_id: s!("123"),
        };
        let body = serde_json::to_string(&request_body("consignment.get", Some(params))).unwrap();
        assert_eq!(
            body,
            r#"{"method":"consignment.get","jsonrpc":"2.0","id":null,"params":{"transfer_id":"123"}}"#
        );
    }

    #[test]
    fn signing_messages_are_stable() {
        assert_eq!(
            prepare_invoice_auth_message("iid", "999", "pk"),
            "iid999pk1"
        );
        assert_eq!(
            post_consignment_message("tid", "ch", "bh"),
            "tidchbhconsignment"
        );
        assert_eq!(post_media_message("tid", "mid", "bh"), "tidmidbhmedia");
        assert_eq!(list_transfers_message("iid", "999"), "iid999");
        assert_eq!(get_ack_message(&[s!("b"), s!("a")], "999"), "ab999");
        assert_eq!(transfer_retrieved_message("tid"), "tidretrieved");
    }

    // The `ack.prepare` params used to be built inline; both transports now share this code. The
    // signed-TX file is the secret-adjacent part: assert it is still a plain transfer-id map and
    // nothing else.
    #[test]
    fn ack_file_is_a_transfer_to_signed_tx_map() {
        let mut transfer_data = HashMap::new();
        transfer_data.insert(
            s!("tid"),
            AckTransferData {
                recipient_pk: s!("pk"),
                consignment_hash: s!("ch"),
                signed_tx: s!("ff"),
            },
        );
        let file = ack_file(&transfer_data);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, String>>(&file).unwrap(),
            HashMap::from([(s!("tid"), s!("ff"))])
        );
    }

    // the signed TX travels only in the uploaded file, never in the params JSON or, therefore, in
    // an error built from those params
    #[test]
    fn ack_params_carry_no_signed_tx() {
        let mut transfer_data = HashMap::new();
        transfer_data.insert(
            s!("tid"),
            AckTransferData {
                recipient_pk: s!("pk"),
                consignment_hash: s!("ch"),
                signed_tx: s!("secret-signed-tx"),
            },
        );
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
            expires_at: s!("999"),
            signed_tx_hash: s!("h"),
            sender_pk: s!("pk"),
            file_size: s!("2"),
            signature: None,
        });
        assert!(!params.contains("secret-signed-tx"));
        assert!(
            String::from_utf8(ack_file(&transfer_data))
                .unwrap()
                .contains("secret-signed-tx")
        );
    }
}
