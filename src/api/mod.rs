// The ABI and claim-prefetch modules build in wallet-only targets to keep their pure logic
// testable, where nothing consumes most of their surface yet.
#![cfg_attr(
    all(
        feature = "wallet",
        not(feature = "_validation"),
        not(all(target_arch = "wasm32", feature = "esplora_async"))
    ),
    allow(dead_code)
)]

#[cfg(feature = "_validation")]
pub(crate) mod evm;

// Protocol definitions, request builders and pure decoders shared by the native blocking client
// and the browser `fetch` one, so payloads and error mapping cannot drift between the transports.
#[cfg(any(
    feature = "wallet",
    feature = "_validation",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) mod evm_abi;
// EVM claim prefetch: the browser fetches the mint locks before the receive transaction opens.
// The module also builds natively without the `fetch` client, so its pure logic is testable with
// a fake EVM client.
#[cfg(feature = "wallet")]
pub(crate) mod evm_claims;
// Browser EVM transport: `reqwest`'s `fetch` backend, wasm32 only, over the shared ABI code.
#[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
pub(crate) mod evm_fetch;
#[cfg(feature = "_online")]
pub(crate) mod multisig_hub;
#[cfg(feature = "_online")]
pub(crate) mod proxy;
#[cfg(feature = "_online")]
pub(crate) mod reject_list;

// Protocol definitions and request builders shared by the native blocking proxy client and the
// browser `fetch` one, so payloads and error mapping cannot drift between the transports.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
// the signing-message helpers are consumed by the wallet online flow, which is still native-only;
// the browser client only needs the requests and the error mapping
#[cfg_attr(not(feature = "_online"), allow(dead_code))]
pub(crate) mod jsonrpc;
// Browser proxy transport: `reqwest`'s `fetch` backend, wasm32 only.
#[cfg(all(target_arch = "wasm32", feature = "esplora_async"))]
pub(crate) mod fetch;

use super::*;

const JSON: &str = "application/json";
#[cfg(feature = "_online")]
const OCTET_STREAM: &str = "application/octet-stream";
#[cfg(feature = "_online")]
const CONNECT_TIMEOUT: u64 = 10;
// the browser transport has no separable connect timeout, so it applies this one to the whole
// request
const READ_WRITE_TIMEOUT: u64 = 120;
/// Maximum number of entries of a reject list, whether kept by an EVM contract or served at a URL
///
/// The source a reject list is read from is chosen by the contract issuer, so it is not trusted: a
/// contract reporting a huge length and serving every page, or a server streaming a huge body,
/// would otherwise keep a client reading it (and holding it in memory) without bound, at every
/// check against the list.
const MAX_REJECT_LIST_ENTRIES: u64 = 100_000;
