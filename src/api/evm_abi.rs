//! EVM ABI and JSON-RPC request types shared by the blocking and the browser `fetch` clients.
//!
//! This module holds everything that does not depend on the transport: selectors, the ABI
//! encoders and decoders, the request/response envelopes and the pure functions that turn a call
//! result into a value. `super::evm` keeps the blocking client and `super::evm_fetch` the browser
//! one, both delegating here, so payloads, bounds and error mapping cannot drift between them.

use super::*;

/// Selector of `getFundsInBlock(uint256,uint256)` on a bridge contract (`MinimalBridge`)
pub(crate) const FUNDS_IN_BLOCK_SELECTOR: &str = "0x2ce06e2d";
/// Selector of `circulatingSupply()` on a bridge contract (`MinimalBridge`)
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) const CIRCULATING_SUPPLY_SELECTOR: &str = "0x9358928b";

/// Selector of `length()` on a reject list contract (`IRgbRejectList`)
pub(crate) const REJECT_LIST_LENGTH_SELECTOR: &str = "0x1f7b6d32";
/// Selector of `entries(uint256,uint256)` on a reject list contract (`IRgbRejectList`)
pub(crate) const REJECT_LIST_ENTRIES_SELECTOR: &str = "0x17b937e6";
/// Maximum number of reject list entries requested with a single `entries` call
///
/// The contract doesn't bound pages, the `eth_call` gas cap and timeout of the node do.
pub(crate) const REJECT_LIST_PAGE_SIZE: u64 = 1000;

/// The status of the lock confirming a mint, which has to be included on the external chain
/// before the block the mint commits to (`before_block`), as recorded by the bridge contract as of
/// the latest finalized block (see the blocking client's `mint_lock_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintLockStatus {
    /// The lock is recorded, included before `before_block`
    Confirmed,
    /// No lock is recorded yet, but one may still be included before `before_block`
    Pending,
    /// The mint will never be confirmed: the block at height `before_block - 1` is finalized and
    /// no lock is recorded in it or in a previous block
    Expired,
}

/// The block an `eth_call` reads the state as of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallBlock {
    /// The block with this number
    Number(u64),
    /// The latest block (`latest` tag), whichever it is when the node answers the call
    #[cfg(any(
        feature = "_online",
        all(target_arch = "wasm32", feature = "esplora_async")
    ))]
    Latest,
}

impl CallBlock {
    /// The block parameter of the call: the hex-encoded block number or the tag.
    pub(crate) fn param(self) -> String {
        match self {
            Self::Number(block) => format!("0x{block:x}"),
            #[cfg(any(
                feature = "_online",
                all(target_arch = "wasm32", feature = "esplora_async")
            ))]
            Self::Latest => s!("latest"),
        }
    }
}

impl From<u64> for CallBlock {
    fn from(block: u64) -> Self {
        Self::Number(block)
    }
}

/// Strip the `0x` prefix the JSON-RPC API puts on every hex-encoded value, refusing values
/// without it.
pub(crate) fn strip_hex_prefix<'a>(value: &'a str, what: &str) -> Result<&'a str, Error> {
    value.strip_prefix("0x").ok_or_else(|| Error::Network {
        details: format!("invalid EVM {what} {value}: missing 0x prefix"),
    })
}

/// Parse a hex-encoded (`0x`-prefixed) quantity.
pub(crate) fn parse_quantity(value: &str, what: &str) -> Result<u64, Error> {
    u64::from_str_radix(strip_hex_prefix(value, what)?, 16).map_err(|e| Error::Network {
        details: format!("invalid EVM {what} {value}: {e}"),
    })
}

/// Parse a hex-encoded (`0x`-prefixed) block number.
pub(crate) fn parse_block_number(hex_block: &str) -> Result<u64, Error> {
    parse_quantity(hex_block, "block number")
}

/// The parameters of a method taking none, serialized as an empty array: JSON-RPC 2.0 allows
/// `params` to be omitted or to be an array or an object, not `null` (as a unit struct would be).
pub(crate) const NO_PARAMS: [(); 0] = [];

/// Decode a hex-encoded ABI word (32 bytes) at the given word index from `data`.
/// `data` must start with "0x".
fn abi_word(data: &str, index: usize) -> Result<[u8; 32], Error> {
    // work on bytes: slicing the str could split a (bogus) multi-byte char and panic
    let hex = strip_hex_prefix(data, "ABI data")?.as_bytes();
    // the index can come from the data itself (e.g. an array offset)
    let end = index
        .checked_add(1)
        .and_then(|words| words.checked_mul(64))
        .ok_or_else(|| abi_error("word index out of range"))?;
    let start = end - 64;
    if hex.len() < end {
        return Err(Error::Network {
            details: format!("ABI data too short: expected at least {end} hex chars"),
        });
    }
    let mut buf = [0u8; 32];
    hex::decode_to_slice(&hex[start..end], &mut buf).map_err(|e| Error::Network {
        details: format!("ABI hex decode error: {e}"),
    })?;
    Ok(buf)
}

/// Decode a hex-encoded ABI word as a `u64` at the given word index from `data`.
/// Returns `None` if the uint256 value doesn't fit in a `u64`.
fn abi_word_u64(data: &str, index: usize) -> Result<Option<u64>, Error> {
    let word = abi_word(data, index)?;
    if word[..24].iter().any(|b| *b != 0) {
        return Ok(None);
    }
    Ok(Some(u64::from_be_bytes(word[24..32].try_into().unwrap())))
}

/// An entry of a reject list kept by an EVM contract (`IRgbRejectList.Entry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RejectListEntry {
    /// RGB operation output the decision applies to.
    pub opout: Opout,
    /// Whether the opout is rejected (`true`) or allowed (`false`).
    pub reject: bool,
}

/// The entries of a reject list kept by an EVM contract, in append order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RejectListLog {
    /// All the entries, as of the latest block.
    pub entries: Vec<RejectListEntry>,
    /// How many of the leading entries were appended in finalized blocks.
    pub finalized: usize,
}

impl RejectListLog {
    /// The opouts currently rejected and allowed, as `(reject, allow)`.
    ///
    /// The latest entry for an opout wins, but entries in non-finalized blocks could still be
    /// dropped or reordered by a reorg. So, erring on the safe side, a reject counts as soon as
    /// it's seen, while an allow counts only once finalized: an opout is rejected if its finalized
    /// decision is a reject or if any non-finalized entry rejects it, and allowed if its finalized
    /// decision is an allow and no non-finalized entry rejects it.
    // only the native validation path reads a reject list until BFA receive is wired on wasm
    #[cfg_attr(
        all(target_arch = "wasm32", not(feature = "_validation")),
        allow(dead_code)
    )]
    pub(crate) fn decisions(&self) -> (HashSet<Opout>, HashSet<Opout>) {
        let (finalized, pending) = self.entries.split_at(self.finalized);
        let finalized = finalized
            .iter()
            .map(|e| (e.opout, e.reject))
            .collect::<HashMap<_, _>>();
        let pending_rejects = pending
            .iter()
            .filter(|e| e.reject)
            .map(|e| e.opout)
            .collect::<HashSet<_>>();
        let (mut reject, mut allow) = (pending_rejects, HashSet::new());
        for (opout, rejected) in finalized {
            if rejected {
                reject.insert(opout);
            } else if !reject.contains(&opout) {
                allow.insert(opout);
            }
        }
        (reject, allow)
    }
}

pub(crate) fn abi_error(details: &str) -> Error {
    Error::Network {
        details: format!("invalid ABI data: {details}"),
    }
}

/// Decode a hex-encoded ABI word as a `uint16` at the given word index from `data`.
fn abi_word_u16(data: &str, index: usize) -> Result<u16, Error> {
    abi_word_u64(data, index)?
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| abi_error("bad uint16"))
}

/// Decode the result of `entries(uint256,uint256)`, an ABI-encoded
/// `(bytes32, uint16, uint16, bool)[]`: the offset of the array, its length, then each entry
/// inline as four words.
pub(crate) fn decode_reject_list_entries(data: &str) -> Result<Vec<RejectListEntry>, Error> {
    // the offset and the length come from the (untrusted) contract: both are checked against the
    // data size before being used, so that they can't make the indexes overflow
    let words = strip_hex_prefix(data, "ABI data")?.len() / 64;
    let len_index = abi_word_u64(data, 0)?
        .filter(|o| o % 32 == 0)
        .and_then(|o| usize::try_from(o / 32).ok())
        .filter(|i| *i < words)
        .ok_or_else(|| abi_error("bad array offset"))?;
    let len = abi_word_u64(data, len_index)?
        .and_then(|l| usize::try_from(l).ok())
        .filter(|l| {
            l.checked_mul(4)
                .and_then(|entry_words| entry_words.checked_add(len_index + 1))
                .is_some_and(|end| end <= words)
        })
        .ok_or_else(|| abi_error("bad array length"))?;
    let mut entries = vec![];
    for i in 0..len {
        let base = len_index + 1 + 4 * i;
        let opout = Opout {
            op: OpId::from(abi_word(data, base)?),
            ty: AssignmentType::with(abi_word_u16(data, base + 1)?),
            no: abi_word_u16(data, base + 2)?,
        };
        let reject = match abi_word_u64(data, base + 3)? {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(abi_error("bad bool")),
        };
        entries.push(RejectListEntry { opout, reject });
    }
    Ok(entries)
}

/// ABI-encode a `uint256` argument as a hex word.
pub(crate) fn abi_encode_u64(value: u64) -> String {
    format!("{value:064x}")
}

/// JSON-RPC request envelope.
#[derive(Debug, Serialize)]
pub(crate) struct RpcRequest<P: Serialize> {
    pub(crate) jsonrpc: &'static str,
    pub(crate) method: &'static str,
    pub(crate) params: P,
    pub(crate) id: u64,
}

/// JSON-RPC response envelope, carrying either the result or the error of the request.
#[derive(Debug, Deserialize)]
pub(crate) struct RpcResponse<R> {
    pub(crate) result: Option<R>,
    pub(crate) error: Option<RpcError>,
}

/// Error object of a JSON-RPC response.
#[derive(Debug, Deserialize)]
pub(crate) struct RpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
}

impl RpcError {
    /// Whether the node reports a reverted `eth_call`, which nodes spell with this message
    /// followed by the reason if there's one.
    pub(crate) fn is_revert(&self) -> bool {
        self.message.starts_with("execution reverted")
    }
}

/// Transaction call object for `eth_call`.
#[derive(Debug, Serialize)]
pub(crate) struct CallObject {
    /// Contract address to call.
    pub(crate) to: String,
    /// ABI-encoded call data (hex).
    pub(crate) data: String,
}

/// The part of a block header returned by `eth_getBlockByNumber` that is needed here.
#[derive(Debug, Deserialize)]
pub(crate) struct BlockHeader {
    /// Block number (hex).
    pub(crate) number: String,
}

/// The parameters of an `eth_call` of `contract` with `data` as of `block`.
pub(crate) fn call_params(
    contract: &EvmAddress,
    data: String,
    block: impl Into<CallBlock>,
) -> (CallObject, String) {
    let call = CallObject {
        to: contract.to_string(),
        data,
    };
    (call, block.into().param())
}

/// The call data of `getFundsInBlock(uint256,uint256)` for the lock with ID `lock_id` and
/// `amount`.
pub(crate) fn funds_in_block_calldata(lock_id: &LockId, amount: u64) -> String {
    format!(
        "{FUNDS_IN_BLOCK_SELECTOR}{}{}",
        hex::encode(lock_id.to_byte_array()),
        abi_encode_u64(amount)
    )
}

/// Decode the result of `getFundsInBlock`, returning the block the lock was included in, if any.
///
/// The record is the block plus one, zero meaning there's none. An empty result (an address with
/// no code) means no record too.
pub(crate) fn decode_funds_in_block(result: &str) -> Result<Option<u64>, Error> {
    if result == "0x" {
        return Ok(None);
    }
    // compare the hex length exactly: a length rounded to whole words would let trailing data
    // through
    if strip_hex_prefix(result, "ABI data")?.len() != 64 {
        return Err(abi_error("unexpected getFundsInBlock result size"));
    }
    // the record is the block plus one, zero meaning there's none
    let block_plus_one =
        abi_word_u64(result, 0)?.ok_or_else(|| abi_error("lock block doesn't fit in a u64"))?;
    Ok(block_plus_one.checked_sub(1))
}

/// The status of a mint lock from its `getFundsInBlock` record, as of `finalized_block`.
pub(crate) fn mint_lock_status_from(
    record: Option<u64>,
    before_block: u64,
    finalized_block: u64,
) -> MintLockStatus {
    match record {
        Some(block) if block < before_block => MintLockStatus::Confirmed,
        Some(_) => MintLockStatus::Expired,
        // a lock not recorded as of the finalized block can only be included after it
        None if finalized_block.saturating_add(1) >= before_block => MintLockStatus::Expired,
        None => MintLockStatus::Pending,
    }
}

/// The call data of `circulatingSupply()`.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn circulating_supply_calldata() -> String {
    CIRCULATING_SUPPLY_SELECTOR.to_string()
}

/// Decode the result of `circulatingSupply`, returning `None` when the contract doesn't account
/// it (an address with no code returns no data).
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decode_circulating_supply(result: &str) -> Result<Option<u64>, Error> {
    if result == "0x" {
        return Ok(None);
    }
    // compare the hex length exactly: a length rounded to whole words would let trailing data
    // through
    if strip_hex_prefix(result, "ABI data")?.len() != 64 {
        return Err(abi_error("unexpected circulatingSupply result size"));
    }
    abi_word_u64(result, 0)?
        .map(Some)
        .ok_or_else(|| abi_error("circulating supply doesn't fit in a u64"))
}

/// The call data of `length()` on a reject list contract.
pub(crate) fn reject_list_length_calldata() -> String {
    REJECT_LIST_LENGTH_SELECTOR.to_string()
}

/// Decode the result of `length()`, returning `None` when there is no contract at the address
/// (calling an address with no code returns no data).
pub(crate) fn decode_reject_list_length(data: &str) -> Result<Option<u64>, Error> {
    if data == "0x" {
        return Ok(None);
    }
    abi_word_u64(data, 0)?
        .map(Some)
        .ok_or_else(|| abi_error("reject list length doesn't fit in a u64"))
}

/// The call data of `entries(uint256,uint256)` for the half-open range `start..end`.
pub(crate) fn reject_list_entries_calldata(start: u64, end: u64) -> String {
    format!(
        "{REJECT_LIST_ENTRIES_SELECTOR}{}{}",
        abi_encode_u64(start),
        abi_encode_u64(end)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_block_param() {
        assert_eq!(CallBlock::from(0x1a4).param(), "0x1a4");
        #[cfg(any(
            feature = "_online",
            all(target_arch = "wasm32", feature = "esplora_async")
        ))]
        assert_eq!(CallBlock::Latest.param(), "latest");
    }

    #[test]
    fn quantities() {
        assert_eq!(parse_quantity("0x7a69", "chain ID").unwrap(), 31337);
        assert!(parse_quantity("7a69", "chain ID").is_err());
        assert!(parse_quantity("0xzz", "chain ID").is_err());
        assert_eq!(parse_block_number("0x10").unwrap(), 16);
    }

    #[test]
    fn funds_in_block_calldata_and_decoding() {
        let lock_id = LockId::from([1u8; 32]);
        assert_eq!(
            funds_in_block_calldata(&lock_id, 7),
            format!("{FUNDS_IN_BLOCK_SELECTOR}{}{:064x}", "01".repeat(32), 7)
        );
        // the record is the block plus one
        assert_eq!(
            decode_funds_in_block(&format!("0x{:064x}", 0x12)).unwrap(),
            Some(0x11)
        );
        assert_eq!(
            decode_funds_in_block(&format!("0x{:064x}", 1)).unwrap(),
            Some(0)
        );
        // zero means there's no record
        assert_eq!(
            decode_funds_in_block(&format!("0x{:064x}", 0)).unwrap(),
            None
        );
        // an address with no code has no records
        assert_eq!(decode_funds_in_block("0x").unwrap(), None);
        // a result that isn't a single word is refused, whatever its content
        assert!(decode_funds_in_block(&format!("0x{:062x}", 1)).is_err());
        assert!(decode_funds_in_block(&format!("0x{:064x}{:064x}", 1, 0)).is_err());
        // a block that doesn't fit in a u64 is refused, not truncated
        assert!(
            decode_funds_in_block(&format!("0x{}1{}", "0".repeat(47), "0".repeat(16))).is_err()
        );
    }

    #[test]
    fn mint_lock_status_from_record() {
        // a lock included in block 0x11 confirms the mint only if that's before the block
        assert_eq!(
            mint_lock_status_from(Some(0x11), 0x12, 0x20),
            MintLockStatus::Confirmed
        );
        assert_eq!(
            mint_lock_status_from(Some(0x11), 0x11, 0x20),
            MintLockStatus::Expired
        );
        // with no lock recorded as of block 0x20, one may only be included from block 0x21
        assert_eq!(
            mint_lock_status_from(None, 0x22, 0x20),
            MintLockStatus::Pending
        );
        assert_eq!(
            mint_lock_status_from(None, 0x21, 0x20),
            MintLockStatus::Expired
        );
        assert_eq!(
            mint_lock_status_from(None, 0x10, 0x20),
            MintLockStatus::Expired
        );
    }

    #[cfg(any(
        feature = "_online",
        all(target_arch = "wasm32", feature = "esplora_async")
    ))]
    #[test]
    fn circulating_supply_calldata_and_decoding() {
        assert_eq!(circulating_supply_calldata(), CIRCULATING_SUPPLY_SELECTOR);
        assert_eq!(
            decode_circulating_supply(&format!("0x{:064x}", 0)).unwrap(),
            Some(0)
        );
        assert_eq!(
            decode_circulating_supply(&format!("0x{:064x}", u64::MAX)).unwrap(),
            Some(u64::MAX)
        );
        // an address with no code doesn't account it
        assert_eq!(decode_circulating_supply("0x").unwrap(), None);
        // a result that isn't a single word is refused, whatever its content
        assert!(decode_circulating_supply(&format!("0x{:062x}", 1)).is_err());
        assert!(decode_circulating_supply(&format!("0x{:064x}{:064x}", 1, 0)).is_err());
        // a supply that doesn't fit in a u64 is refused, not truncated
        assert!(
            decode_circulating_supply(&format!("0x{}1{}", "0".repeat(47), "0".repeat(16))).is_err()
        );
    }

    #[test]
    fn reject_list_calldata_and_decoding() {
        assert_eq!(reject_list_length_calldata(), REJECT_LIST_LENGTH_SELECTOR);
        assert_eq!(
            reject_list_entries_calldata(0, 2),
            format!("{REJECT_LIST_ENTRIES_SELECTOR}{:064x}{:064x}", 0, 2)
        );
        assert_eq!(
            decode_reject_list_length(&format!("0x{:064x}", 5)).unwrap(),
            Some(5)
        );
        // no contract at the address
        assert_eq!(decode_reject_list_length("0x").unwrap(), None);
        assert!(
            decode_reject_list_length(&format!("0x{}1{}", "0".repeat(47), "0".repeat(16))).is_err()
        );
    }

    #[test]
    fn call_params_serialization() {
        let contract = EvmAddress::default();
        let (call, block) = call_params(&contract, s!("0xabcd"), 0x10);
        assert_eq!(call.to, contract.to_string());
        assert_eq!(call.data, "0xabcd");
        assert_eq!(block, "0x10");
        #[cfg(any(
            feature = "_online",
            all(target_arch = "wasm32", feature = "esplora_async")
        ))]
        assert_eq!(
            call_params(&contract, s!("0xabcd"), CallBlock::Latest).1,
            "latest"
        );
    }
}
