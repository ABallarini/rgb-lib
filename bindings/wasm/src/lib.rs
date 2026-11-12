//! `wasm-bindgen` API for the [`rgb-lib`] wallet, for browsers and other JavaScript runtimes
//! with no filesystem and no SQLite driver.
//!
//! The bindings are a thin shell: every wallet operation is the shared `rgb-lib` implementation,
//! built over the in-memory backend with [`Wallet::new_in_memory`] and restored with
//! [`Wallet::from_snapshot`]. There is no copied wallet logic here.
//!
//! # Lifecycle
//!
//! * [`RgbLibWallet::create`] builds a fresh wallet; [`RgbLibWallet::restore`] rebuilds one from
//!   the bytes of [`RgbLibWallet::snapshot`]. [`RgbLibWallet::load`] does the same asynchronously,
//!   reading the snapshot from IndexedDB first.
//! * [`RgbLibWallet::snapshot`] serializes the whole state (database, BDK data and browser blobs,
//!   never the mnemonic) into bytes the host can store wherever it wants.
//! * [`RgbLibWallet::flush`] is the durable-write boundary: it stores those bytes in IndexedDB
//!   (database `rgb-lib`, store `snapshots`, keyed by the wallet name) and resolves once the
//!   transaction commits. The write carries this instance's writer id and snapshot sequence, so a
//!   stale instance is rejected instead of overwriting a newer snapshot; `load` adopts the stored
//!   writer and sequence, while the synchronous `restore` starts a fresh writer at sequence `0`.
//!   Only available where IndexedDB exists, i.e. in a browser.
//! * [`RgbLibWallet::delete_snapshot`] removes that record and detaches the instance: it refuses a
//!   name other than the wallet's own, and every later `flush` fails instead of recreating the
//!   deleted snapshot, so the host must `load` a new instance to start over.
//!
//! `name` is the durable key: two wallets created with the same name share one snapshot entry, so
//! keep it stable per wallet. The wallet identity itself is the master fingerprint returned by
//! [`RgbLibWallet::id`].
//!
//! # Secrets
//!
//! The mnemonic is only used to derive the keys: it is not stored in the snapshot and no error
//! returned here echoes it. Errors carry the failing operation and the `rgb-lib` message, which
//! describes settings and state, never key material.

use std::cell::{Cell, RefCell, RefMut};
use std::rc::Rc;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use rgb_lib::{
    AssetSchema, Assignment, BitcoinNetwork, Encryption, Error,
    keys::{
        Keys, WitnessVersion, generate_keys as core_generate_keys,
        restore_keys as core_restore_keys,
    },
    no_wallet::validate_consignment_offchain as core_validate_consignment_offchain,
    wallet::{
        AssetFilter, DatabaseType, Invoice as CoreInvoice, MultisigKeys, MultisigWallet,
        RgbWalletOpsOffline, SinglesigKeys, TransferScope, Wallet, WalletData,
        backup_info_bytes as core_backup_info_bytes,
        persistence::{
            delete_snapshot as core_delete_snapshot, load_snapshot_record, new_writer_id,
            save_snapshot_record,
        },
        restore_backup_bytes as core_restore_backup_bytes,
    },
};

#[cfg(target_arch = "wasm32")]
use rgb_lib::wallet::rust_only::check_proxy_url_async as core_check_proxy_url_async;

/// `rgb-lib` default: allocations allowed per UTXO.
const MAX_ALLOCATIONS_PER_UTXO: u32 = 5;

/// Settings of a browser wallet, over the in-memory backend.
fn wallet_data(network: BitcoinNetwork) -> WalletData {
    WalletData {
        // no filesystem on the host: the wallet data lives in memory and travels in snapshots
        data_dir: String::new(),
        bitcoin_network: network,
        // the only `DatabaseType` value; an injected in-memory backend ignores it
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
        supported_schemas: vec![
            AssetSchema::Nia,
            AssetSchema::Uda,
            AssetSchema::Cfa,
            AssetSchema::Ifa,
        ],
    }
}

fn parse_network(network: &str) -> Result<BitcoinNetwork, JsValue> {
    network.parse().map_err(|_| {
        JsValue::from_str(&format!(
            "unsupported bitcoin network '{network}': use mainnet, testnet, testnet4, regtest or signet"
        ))
    })
}

/// Derive the signing keys from a mnemonic.
///
/// The reason is deliberately opaque: the underlying parser can echo a word of the phrase, so it
/// never reaches the caller.
fn taproot_keys(network: BitcoinNetwork, mnemonic: &str) -> Result<Keys, JsValue> {
    core_restore_keys(network, mnemonic.to_string(), WitnessVersion::Taproot)
        .map_err(|_| JsValue::from_str("invalid mnemonic phrase for the given network"))
}

fn derived_keys(network: BitcoinNetwork, mnemonic: &str) -> Result<SinglesigKeys, JsValue> {
    Ok(SinglesigKeys::from_keys(
        &taproot_keys(network, mnemonic)?,
        None,
    ))
}

/// Parse the public keys of a watch-only wallet, in the `rgb-lib` [`SinglesigKeys`] JSON shape.
///
/// A mnemonic is refused instead of dropped: a watch-only wallet must not carry signing keys.
fn watch_only_keys(keys: &str) -> Result<SinglesigKeys, JsValue> {
    let keys: SinglesigKeys = serde_json::from_str(keys)
        .map_err(|e| JsValue::from_str(&format!("cannot parse the wallet keys: {e}")))?;
    if keys.mnemonic.is_some() {
        return Err(JsValue::from_str(
            "watch-only keys must not contain a mnemonic",
        ));
    }
    Ok(keys)
}

fn multisig_keys(keys: &str) -> Result<MultisigKeys, JsValue> {
    serde_json::from_str(keys)
        .map_err(|e| JsValue::from_str(&format!("cannot parse the multisig keys: {e}")))
}

fn failure(context: &str, e: Error) -> JsValue {
    JsValue::from_str(&format!("{context}: {e}"))
}

/// The error of a call that starts while another call still holds the wallet.
const WALLET_BUSY: &str = "the wallet is busy with another operation";

fn wallet_busy() -> JsValue {
    JsValue::from_str(WALLET_BUSY)
}

/// Take exclusive access to a wallet slot for the duration of one operation.
///
/// JavaScript can start a second call while an async one is suspended at an await, so a plain
/// `borrow_mut` would panic there: the non-panicking `try_borrow_mut` returns the busy error
/// instead.
fn try_borrow_wallet<T>(slot: &RefCell<Option<T>>) -> Result<RefMut<'_, T>, JsValue> {
    let slot = slot.try_borrow_mut().map_err(|_| wallet_busy())?;
    RefMut::filter_map(slot, Option::as_mut).map_err(|_| wallet_busy())
}

/// Parse an RGB assignment from the core serde shape: `{"Fungible":1000}`, `"NonFungible"`,
/// `{"InflationRight":1000}` or `"Any"`.
fn parse_assignment(assignment: &str) -> Result<Assignment, JsValue> {
    serde_json::from_str(assignment).map_err(|e| {
        JsValue::from_str(&format!(
            "cannot parse the assignment: {e}; use the core shape, e.g. {{\"Fungible\":1000}} or \"Any\""
        ))
    })
}

/// Parse an optional encryption preference: `required`, `unsupported` or `optional`.
fn parse_encryption(encryption: Option<String>) -> Result<Option<Encryption>, JsValue> {
    let Some(encryption) = encryption else {
        return Ok(None);
    };
    let encryption = match encryption.to_ascii_lowercase().as_str() {
        "required" => Encryption::Required,
        "unsupported" => Encryption::Unsupported,
        "optional" => Encryption::Optional,
        _ => {
            return Err(JsValue::from_str(
                "unsupported encryption: use required, unsupported or optional",
            ));
        }
    };
    Ok(Some(encryption))
}

/// Serialize an `rgb-lib` object for the host.
///
/// The JSON uses the `rgb-lib` serde field names (`snake_case`); the bindings do not rename them.
fn json_result<T: Serialize>(context: &str, value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|e| JsValue::from_str(&format!("{context}: {e}")))
}

/// Generate a fresh Taproot key set for `network` and return it as JSON.
///
/// The JSON is the `rgb-lib` [`Keys`] shape (`snake_case`): mnemonic, master xpub, account xpubs for
/// the vanilla and colored sides, master fingerprint and witness version. The phrase is secret and
/// the host must store it itself; no error returned here echoes it.
#[wasm_bindgen(js_name = generateKeys)]
pub fn generate_keys(network: String) -> Result<String, JsValue> {
    let network = parse_network(&network)?;
    let keys = core_generate_keys(network, WitnessVersion::Taproot);
    json_result("cannot serialize the wallet keys", &keys)
}

/// Recreate the Taproot key set of `mnemonic` for `network` and return it as JSON.
///
/// The JSON is the `rgb-lib` [`Keys`] shape; an invalid phrase is an error with a fixed sanitized
/// message.
#[wasm_bindgen(js_name = restoreKeys)]
pub fn restore_keys(network: String, mnemonic: String) -> Result<String, JsValue> {
    let network = parse_network(&network)?;
    let keys = taproot_keys(network, &mnemonic)?;
    json_result("cannot serialize the wallet keys", &keys)
}

/// Validate a transfer consignment using the witness data bundled in it, before its witness
/// transaction is broadcast.
///
/// `consignment_bytes` is a `Uint8Array` of the raw strict-encoded consignment (not armored, not
/// base64), `txid` the witness transaction ID and `network` the Bitcoin network to check it
/// against. Returns JSON: `{"valid", "warnings"?, "error"?, "details"?}` where `error` is one of
/// `invalid`, `resolver`, `external_anchors` or `unexpected`. Invalid consignment bytes and an
/// invalid TXID throw. A valid result does not prove the witness transaction has been broadcast.
#[wasm_bindgen(js_name = validateConsignmentOffchain)]
pub fn validate_consignment_offchain(
    consignment_bytes: Vec<u8>,
    txid: String,
    network: String,
) -> Result<String, JsValue> {
    let network = parse_network(&network)?;
    let result = core_validate_consignment_offchain(&consignment_bytes, &txid, network)
        .map_err(|e| failure("cannot validate the consignment", e))?;
    json_result("cannot serialize the consignment validation", &result)
}

/// Return the public metadata of an encrypted backup as JSON.
///
/// It reads the archive only: no password is needed and no secret is returned. The JSON carries
/// the backup `version` and the `scrypt_params` its key was derived with.
#[wasm_bindgen(js_name = backupInfo)]
pub fn backup_info(backup_bytes: Vec<u8>) -> Result<String, JsValue> {
    let info = core_backup_info_bytes(&backup_bytes)
        .map_err(|e| failure("cannot read the backup info", e))?;
    json_result("cannot serialize the backup info", &info)
}

/// Check that the proxy at `url` speaks the supported protocol version.
///
/// Async and read-only: validates an RGB transport endpoint (`rpc://host` or `rpcs://host`) with
/// the shared parser, performs the proxy's `server.info` request over browser `fetch` and resolves
/// to `true` when the reported protocol version matches. An invalid URL, an unreachable proxy or an
/// unsupported protocol version throws a sanitized error; no write is ever sent.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = checkProxyUrl)]
pub async fn check_proxy_url(url: String) -> Result<bool, JsValue> {
    core_check_proxy_url_async(&url)
        .await
        .map_err(|e| failure("cannot check the proxy URL", e))
}

/// An RGB invoice parsed from a string.
#[wasm_bindgen]
pub struct WasmInvoice {
    invoice: CoreInvoice,
}

#[wasm_bindgen]
impl WasmInvoice {
    /// Parse an RGB invoice for `network`.
    ///
    /// The network is checked against the one encoded in the invoice: a mismatch is an error, never
    /// a silently re-interpreted invoice. Invalid input throws a sanitized error.
    pub fn parse(invoice: String, network: String) -> Result<WasmInvoice, JsValue> {
        let network = parse_network(&network)?;
        let invoice =
            CoreInvoice::new(invoice).map_err(|e| failure("cannot parse the invoice", e))?;
        let invoice_network = invoice.invoice_data().network;
        if invoice_network != network {
            return Err(JsValue::from_str(&format!(
                "the invoice is for {invoice_network:?}, not for the given network {network:?}"
            )));
        }
        Ok(Self { invoice })
    }

    /// Return the parsed invoice data as JSON, in the core `InvoiceData` shape.
    #[wasm_bindgen(js_name = invoiceData)]
    pub fn invoice_data(&self) -> Result<String, JsValue> {
        json_result(
            "cannot serialize the invoice data",
            &self.invoice.invoice_data(),
        )
    }

    /// Return the invoice string the data was parsed from.
    #[wasm_bindgen(js_name = invoiceString)]
    pub fn invoice_string(&self) -> String {
        self.invoice.invoice_string()
    }
}

/// A `rgb-lib` singlesig wallet over the in-memory backend.
#[wasm_bindgen]
pub struct RgbLibWallet {
    /// Held for the whole of one call, so a second overlapping call gets the busy error.
    wallet: Rc<RefCell<Option<Wallet>>>,
    name: String,
    /// This instance's id in the snapshot record; a flush writes it next to the bytes.
    writer: String,
    /// Sequence this instance last saw or wrote; a guarded flush needs it to match the store.
    sequence: Cell<u64>,
    /// Set once this instance deleted its own snapshot: a later flush must not resurrect it.
    detached: Cell<bool>,
}

impl RgbLibWallet {
    /// Take the wallet for one operation; a call made while another holds it gets the busy error.
    fn borrow_wallet(&self) -> Result<RefMut<'_, Wallet>, JsValue> {
        try_borrow_wallet(&self.wallet)
    }
}

/// A fresh writer id at sequence 0: a wallet with no stored record yet.
fn fresh_writer() -> (String, Cell<u64>) {
    (new_writer_id(), Cell::new(0))
}

#[wasm_bindgen]
impl RgbLibWallet {
    /// Create a wallet from a mnemonic and a network, deriving the keys with
    /// [`WitnessVersion::Taproot`].
    pub fn create(
        name: String,
        mnemonic: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let wallet = Wallet::new_in_memory(wallet_data(network), derived_keys(network, &mnemonic)?)
            .map_err(|e| failure("cannot create the wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Rebuild a wallet from the bytes of [`RgbLibWallet::snapshot`].
    ///
    /// The snapshot carries the wallet settings, which are validated against the supplied
    /// mnemonic and network; a mismatch is an error, never a fresh wallet. Restoring is
    /// synchronous, so the stored sequence cannot be read here: this instance starts a fresh
    /// writer at sequence `0`. Use [`RgbLibWallet::load`] to attach to an existing IndexedDB
    /// record, or the first flush is rejected when that record is already newer.
    #[wasm_bindgen]
    pub fn restore(
        name: String,
        snapshot: Vec<u8>,
        mnemonic: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let wallet = Wallet::from_snapshot(
            &snapshot,
            wallet_data(network),
            derived_keys(network, &mnemonic)?,
        )
        .map_err(|e| failure("cannot restore the wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Create a watch-only wallet from public keys JSON.
    ///
    /// `keys` is the `rgb-lib` [`SinglesigKeys`] JSON shape: `account_xpub_vanilla`,
    /// `account_xpub_colored`, `vanilla_keychain`, `master_fingerprint` and `witness_version`.
    /// `mnemonic` must be absent or `null`, so the wallet derives addresses and signs nothing; the
    /// binding refuses keys that carry a phrase instead of silently dropping it. Build the JSON
    /// from [`generateKeys`] or [`restoreKeys`] and keep only the public fields.
    #[wasm_bindgen(js_name = createWatchOnly)]
    pub fn create_watch_only(
        name: String,
        keys: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = watch_only_keys(&keys)?;
        let wallet = Wallet::new_in_memory(wallet_data(network), keys)
            .map_err(|e| failure("cannot create the watch-only wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Rebuild a watch-only wallet from the bytes of [`RgbLibWallet::snapshot`] and its public keys.
    #[wasm_bindgen(js_name = restoreWatchOnly)]
    pub fn restore_watch_only(
        name: String,
        snapshot: Vec<u8>,
        keys: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = watch_only_keys(&keys)?;
        let wallet = Wallet::from_snapshot(&snapshot, wallet_data(network), keys)
            .map_err(|e| failure("cannot restore the watch-only wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Load the snapshot stored under `name` from IndexedDB and rebuild the wallet.
    ///
    /// When no snapshot exists yet, a fresh wallet is created instead, so this is the single entry
    /// point a host needs on startup. Await it before using the wallet. The stored writer id and
    /// sequence are adopted, so this instance's next flush is guarded against a newer one; a stale
    /// wallet must call `load` again instead of retrying the clashing flush.
    #[wasm_bindgen]
    pub async fn load(
        name: String,
        mnemonic: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = derived_keys(network, &mnemonic)?;
        let wallet_data = wallet_data(network);
        match load_snapshot_record(&name)
            .await
            .map_err(|e| failure("cannot read the wallet snapshot", e))?
        {
            Some(record) => Wallet::from_snapshot(&record.bytes, wallet_data, keys)
                .map(|wallet| Self {
                    wallet: Rc::new(RefCell::new(Some(wallet))),
                    name,
                    writer: record.writer,
                    sequence: Cell::new(record.sequence),
                    detached: Cell::new(false),
                })
                .map_err(|e| failure("cannot restore the wallet", e)),
            // a corrupt snapshot is an error above, never a fresh wallet: no fallback here
            None => {
                let wallet = Wallet::new_in_memory(wallet_data, keys)
                    .map_err(|e| failure("cannot create the wallet", e))?;
                let (writer, sequence) = fresh_writer();
                Ok(Self {
                    wallet: Rc::new(RefCell::new(Some(wallet))),
                    name,
                    writer,
                    sequence,
                    detached: Cell::new(false),
                })
            }
        }
    }

    /// The wallet name, i.e. the key of its durable snapshot.
    ///
    /// Unlike the other reads this only touches the instance, but it still takes the guard so a
    /// long operation cannot be observed half-way through.
    pub fn name(&self) -> Result<String, JsValue> {
        let _wallet = self.borrow_wallet()?;
        Ok(self.name.clone())
    }

    /// The wallet identity: the master fingerprint of its keys.
    pub fn id(&self) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        Ok(wallet.get_keys().master_fingerprint)
    }

    /// Return the BTC balances (in sats) as JSON, from local data only.
    ///
    /// No chain sync is performed, so this reflects the last known state carried by the wallet.
    #[wasm_bindgen(js_name = getBtcBalance)]
    pub fn get_btc_balance(&self) -> Result<String, JsValue> {
        let mut wallet = self.borrow_wallet()?;
        let balance = wallet
            .get_btc_balance(None, true)
            .map_err(|e| failure("cannot get the BTC balance", e))?;
        drop(wallet);
        json_result("cannot serialize the BTC balance", &balance)
    }

    /// Sync the BDK wallet against an Esplora endpoint, read-only.
    ///
    /// Runs a full scan of both wallet keychains and applies the result to the shared wallet. The
    /// change is in the in-memory database when this resolves; call `flush()` to make it durable.
    /// `stop_gap` is the unused script count per keychain (default 20). No RGB state is touched
    /// here: use [`RgbLibWallet::sync_online`] to also receive pending RGB transfers.
    #[cfg(target_arch = "wasm32")]
    pub async fn sync(&self, indexer_url: String, stop_gap: Option<u32>) -> Result<(), JsValue> {
        let mut wallet = self.borrow_wallet()?;
        wallet
            .sync_async(&indexer_url, stop_gap.map(|gap| gap as usize))
            .await
            .map_err(|e| failure("cannot sync the wallet", e))
    }

    /// Receive one RGB transfer from a proxy and ACK it, then leave persistence to `flush()`.
    ///
    /// `proxy_url` is the recipient proxy holding the consignment, `indexer_url` the Esplora
    /// endpoint used for the chain answers the validation needs and for broadcasting a released
    /// signed TX, and `transfer_id` the proxy transfer ID. The transfer must belong to a pending
    /// incoming invoice of this wallet: a repeated call on an already handled transfer is a no-op
    /// and a transfer not addressed to this wallet throws. The whole receive, including the ACK,
    /// happens in one wallet transaction; a failure rolls it back. This call flushes the new state
    /// before releasing the proxy data, so a failed flush leaves the release pending for the next
    /// call instead of deleting the only copy of the consignment.
    ///
    /// Returns JSON: the handled `batch_transfer_idx`, or `null` when the transfer was already
    /// handled before this call.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = receiveTransfer)]
    pub async fn receive_transfer(
        &self,
        proxy_url: String,
        indexer_url: String,
        transfer_id: String,
    ) -> Result<String, JsValue> {
        let mut wallet = self.borrow_wallet()?;
        let idx = wallet
            .receive_transfer_async(&proxy_url, &indexer_url, &transfer_id)
            .await
            .map_err(|e| failure("cannot receive the transfer", e))?;
        // the release marker is in the snapshot only once this resolves: post after it
        self.flush_wallet(&wallet).await?;
        wallet.release_pending_retrievals(&indexer_url).await;
        drop(wallet);
        json_result("cannot serialize the receive result", &idx)
    }

    /// Sync the BDK wallet and receive every pending RGB transfer from a proxy.
    ///
    /// Runs the read-only BDK full scan, then lists the transfers of each pending incoming invoice
    /// on `proxy_url`, receiving and ACKing each one through the same shared driver as
    /// [`RgbLibWallet::receive_transfer`]. Only `Pending` transfers addressed to this wallet are
    /// considered and an already handled one is skipped, so a repeated call is idempotent. This
    /// call flushes the new state before releasing the proxy data of the handled transfers; a
    /// failed flush returns its error and leaves every release pending for the next call.
    ///
    /// Returns JSON: the array of `batch_transfer_idx` handled by this call, in processing order.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = syncOnline)]
    pub async fn sync_online(
        &self,
        proxy_url: String,
        indexer_url: String,
        stop_gap: Option<u32>,
    ) -> Result<String, JsValue> {
        let mut wallet = self.borrow_wallet()?;
        let handled = wallet
            .sync_online_async(&proxy_url, &indexer_url, stop_gap.map(|gap| gap as usize))
            .await
            .map_err(|e| failure("cannot sync the wallet online", e))?;
        // same order as receiveTransfer, for every release the handled transfers left behind
        self.flush_wallet(&wallet).await?;
        wallet.release_pending_retrievals(&indexer_url).await;
        drop(wallet);
        json_result("cannot serialize the online sync result", &handled)
    }

    /// Fee estimate for confirmation within `blocks`, in sat/vB, from an Esplora endpoint.
    ///
    /// `blocks` must be in `1..=1008`. An endpoint without fee history throws the sanitized
    /// `Cannot estimate fees` error.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = getFeeEstimation)]
    pub async fn get_fee_estimation(
        &self,
        indexer_url: String,
        blocks: u16,
    ) -> Result<f64, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .fee_estimation_async(&indexer_url, blocks)
            .await
            .map_err(|e| failure("cannot estimate the fee", e))
    }

    /// Height of the best-chain tip reported by an Esplora endpoint.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = getTipHeight)]
    pub async fn get_tip_height(&self, indexer_url: String) -> Result<u32, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .tip_height_async(&indexer_url)
            .await
            .map_err(|e| failure("cannot get the tip height", e))
    }

    /// Return the RGB asset balance as JSON, from local data only.
    #[wasm_bindgen(js_name = getAssetBalance)]
    pub fn get_asset_balance(&self, asset_id: String) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        let balance = wallet
            .get_asset_balance(asset_id)
            .map_err(|e| failure("cannot get the asset balance", e))?;
        drop(wallet);
        json_result("cannot serialize the asset balance", &balance)
    }

    /// Return the RGB asset metadata as JSON.
    #[wasm_bindgen(js_name = getAssetMetadata)]
    pub fn get_asset_metadata(&self, asset_id: String) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        let metadata = wallet
            .get_asset_metadata(asset_id)
            .map_err(|e| failure("cannot get the asset metadata", e))?;
        drop(wallet);
        json_result("cannot serialize the asset metadata", &metadata)
    }

    /// List the known RGB assets as JSON, grouped by schema.
    #[wasm_bindgen(js_name = listAssets)]
    pub fn list_assets(&self) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        let assets = wallet
            .list_assets(vec![])
            .map_err(|e| failure("cannot list the assets", e))?;
        drop(wallet);
        json_result("cannot serialize the asset list", &assets)
    }

    /// List the known RGB transfers as JSON, optionally filtered by `asset_id`.
    #[wasm_bindgen(js_name = listTransfers)]
    pub fn list_transfers(&self, asset_id: Option<String>) -> Result<String, JsValue> {
        let filter = match asset_id {
            Some(asset_id) => AssetFilter::Id(asset_id),
            None => AssetFilter::AnyOrNone,
        };
        let transfers = {
            let wallet = self.borrow_wallet()?;
            wallet
                .list_transfers(filter, TransferScope::All)
                .map_err(|e| failure("cannot list the transfers", e))?
        };
        json_result("cannot serialize the transfer list", &transfers)
    }

    /// List the known unspents as JSON, from local data only.
    ///
    /// `settled_only` excludes allocations on pending RGB operations.
    #[wasm_bindgen(js_name = listUnspents)]
    pub fn list_unspents(&self, settled_only: bool) -> Result<String, JsValue> {
        let unspents = {
            let mut wallet = self.borrow_wallet()?;
            wallet
                .list_unspents(None, settled_only, true)
                .map_err(|e| failure("cannot list the unspents", e))?
        };
        json_result("cannot serialize the unspent list", &unspents)
    }

    /// List the known Bitcoin transactions as JSON, newest first, from local data only.
    #[wasm_bindgen(js_name = listTransactions)]
    pub fn list_transactions(&self) -> Result<String, JsValue> {
        let transactions = {
            let mut wallet = self.borrow_wallet()?;
            wallet
                .list_transactions(None, true)
                .map_err(|e| failure("cannot list the transactions", e))?
        };
        json_result("cannot serialize the transaction list", &transactions)
    }

    /// Return the data that defines the wallet as JSON.
    #[wasm_bindgen(js_name = getWalletData)]
    pub fn get_wallet_data(&self) -> Result<String, JsValue> {
        let wallet_data = {
            let wallet = self.borrow_wallet()?;
            wallet.get_wallet_data()
        };
        json_result("cannot serialize the wallet data", &wallet_data)
    }

    /// Return a new receive address from the vanilla wallet.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&self) -> Result<String, JsValue> {
        let mut wallet = self.borrow_wallet()?;
        wallet
            .get_address()
            .map_err(|e| failure("cannot derive a receive address", e))
    }

    /// Create an out-of-band blind receive request and return its `ReceiveData` as JSON.
    ///
    /// `assignment` is the core serde shape (`{"Fungible":1000}`, `"NonFungible"`,
    /// `{"InflationRight":1000}` or `"Any"`). `encryption` is `required`, `unsupported` or
    /// `optional`. Transport endpoints are always empty: the invoice carries no proxy endpoint and
    /// the consignment is exchanged out-of-band, so no proxy reservation is made. A blind receive
    /// allocates on an existing colored UTXO; a wallet without one throws the core error.
    #[wasm_bindgen(js_name = blindReceive)]
    pub fn blind_receive(
        &self,
        asset_id: Option<String>,
        assignment: String,
        expiration_timestamp: u64,
        min_confirmations: u8,
        encryption: Option<String>,
    ) -> Result<String, JsValue> {
        let assignment = parse_assignment(&assignment)?;
        let encryption = parse_encryption(encryption)?;
        let receive_data = {
            let mut wallet = self.borrow_wallet()?;
            wallet
                .blind_receive(
                    None,
                    asset_id,
                    assignment,
                    expiration_timestamp,
                    vec![],
                    min_confirmations,
                    encryption,
                )
                .map_err(|e| failure("cannot create the blind receive", e))?
        };
        json_result("cannot serialize the receive data", &receive_data)
    }

    /// Create an out-of-band witness receive request and return its `ReceiveData` as JSON.
    ///
    /// Arguments and out-of-band semantics are the same as [`RgbLibWallet::blind_receive`], but the
    /// recipient is a new script and no colored UTXO is needed.
    #[wasm_bindgen(js_name = witnessReceive)]
    pub fn witness_receive(
        &self,
        asset_id: Option<String>,
        assignment: String,
        expiration_timestamp: u64,
        min_confirmations: u8,
        encryption: Option<String>,
    ) -> Result<String, JsValue> {
        let assignment = parse_assignment(&assignment)?;
        let encryption = parse_encryption(encryption)?;
        let receive_data = {
            let mut wallet = self.borrow_wallet()?;
            wallet
                .witness_receive(
                    None,
                    asset_id,
                    assignment,
                    expiration_timestamp,
                    vec![],
                    min_confirmations,
                    encryption,
                )
                .map_err(|e| failure("cannot create the witness receive", e))?
        };
        json_result("cannot serialize the receive data", &receive_data)
    }

    /// Issue a NIA asset and return its asset ID.
    ///
    /// Like every RGB issuance, it allocates on an existing colored UTXO, so the wallet must
    /// already hold one: a fresh browser wallet has to be funded and synced before this succeeds.
    /// `amounts` is a `BigUint64Array` on the JS side.
    #[wasm_bindgen(js_name = issueNia)]
    pub fn issue_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .issue_asset_nia(ticker, name, precision, amounts)
            .map(|asset| asset.asset_id)
            .map_err(|e| failure("cannot issue the asset", e))
    }

    /// Issue a UDA asset and return its asset ID.
    ///
    /// Media attachments need a filesystem and are not passed by the bindings.
    #[wasm_bindgen(js_name = issueUda)]
    pub fn issue_uda(
        &self,
        ticker: String,
        name: String,
        details: Option<String>,
        precision: u8,
    ) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .issue_asset_uda(ticker, name, details, precision, None, vec![])
            .map(|asset| asset.asset_id)
            .map_err(|e| failure("cannot issue the asset", e))
    }

    /// Issue a CFA asset and return its asset ID.
    ///
    /// Media attachments need a filesystem and are not passed by the bindings.
    /// `amounts` is a `BigUint64Array` on the JS side.
    #[wasm_bindgen(js_name = issueCfa)]
    pub fn issue_cfa(
        &self,
        name: String,
        details: Option<String>,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .issue_asset_cfa(name, details, precision, amounts, None)
            .map(|asset| asset.asset_id)
            .map_err(|e| failure("cannot issue the asset", e))
    }

    /// Issue an IFA asset and return its asset ID.
    ///
    /// `amounts` and `inflation_amounts` are `BigUint64Array` on the JS side; the latter can be
    /// empty. The optional `reject_list_url` is embedded in the contract.
    #[wasm_bindgen(js_name = issueIfa)]
    pub fn issue_ifa(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
        inflation_amounts: Vec<u64>,
        reject_list_url: Option<String>,
    ) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .issue_asset_ifa(
                ticker,
                name,
                precision,
                amounts,
                inflation_amounts,
                reject_list_url,
            )
            .map(|asset| asset.asset_id)
            .map_err(|e| failure("cannot issue the asset", e))
    }

    /// Sign a PSBT with the wallet keys and return the signed PSBT.
    ///
    /// The wallet must have private keys; a watch-only wallet returns an error.
    #[wasm_bindgen(js_name = signPsbt)]
    pub fn sign_psbt(&self, psbt: String) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .sign_psbt(psbt, None)
            .map_err(|e| failure("cannot sign the PSBT", e))
    }

    /// Finalize a signed PSBT and return the finalized PSBT.
    #[wasm_bindgen(js_name = finalizePsbt)]
    pub fn finalize_psbt(&self, psbt: String) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .finalize_psbt(psbt, None)
            .map_err(|e| failure("cannot finalize the PSBT", e))
    }

    /// Delete eligible failed transfers and return whether any was deleted.
    ///
    /// With `batch_transfer_idx` it operates on that batch transfer only; without it, all failed
    /// transfers are eligible. `no_asset_only` skips transfers with an associated asset ID.
    #[wasm_bindgen(js_name = deleteTransfers)]
    pub fn delete_transfers(
        &self,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
    ) -> Result<bool, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .delete_transfers(batch_transfer_idx, no_asset_only)
            .map_err(|e| failure("cannot delete the transfers", e))
    }

    /// Serialize the whole wallet state into bytes for the host to store.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .snapshot()
            .map_err(|e| failure("cannot serialize the wallet", e))?
            .ok_or_else(|| JsValue::from_str("the wallet runs without a snapshot-capable backend"))
    }

    /// Create an encrypted backup of the wallet and return its bytes.
    ///
    /// The archive and encryption format is the native one; the browser wallet carries its
    /// snapshot envelope instead of a wallet directory. The password derives the key and is never
    /// stored or logged.
    pub fn backup(&self, password: String) -> Result<Vec<u8>, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .backup_bytes(&password)
            .map_err(|e| failure("cannot create the backup", e))
    }

    /// Restore this wallet from the bytes of [`RgbLibWallet::backup`].
    ///
    /// The backup must belong to the wallet keys already held here: the shared restore path
    /// validates them and rebuilds the database, BDK state and files from the backup snapshot. A
    /// wrong password, a different wallet or a corrupt archive is an error, never a fresh wallet.
    /// The new wallet replaces the old one under the operation guard, so an overlapping call can
    /// never observe a half-swapped instance; the snapshot sequence and writer stay unchanged, so
    /// the next `flush` is still guarded against a newer stored record.
    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(&self, backup_bytes: Vec<u8>, password: String) -> Result<(), JsValue> {
        // the key derivation is slow: do it before taking the guard
        let restored = core_restore_backup_bytes(&backup_bytes, &password)
            .map_err(|e| failure("cannot restore the backup", e))?;
        let snapshot = restored
            .wallet_snapshot()
            .map_err(|e| failure("cannot restore the backup", e))?;
        let mut slot = self.wallet.try_borrow_mut().map_err(|_| wallet_busy())?;
        let current = slot.as_ref().ok_or_else(wallet_busy)?;
        let wallet =
            Wallet::from_snapshot(&snapshot, current.get_wallet_data(), current.get_keys())
                .map_err(|e| failure("cannot restore the backup", e))?;
        *slot = Some(wallet);
        Ok(())
    }

    /// Store the wallet state in IndexedDB and resolve once the transaction commits.
    ///
    /// The write is guarded: it carries this instance's writer id and sequence, and IndexedDB
    /// rejects it when the stored sequence is newer. The error names the stored sequence and its
    /// writer; call `load` again to adopt the newer state. A successful flush adopts the returned
    /// sequence for the next call. After `deleteSnapshot` this instance is detached and every flush
    /// fails instead of recreating the deleted record.
    pub async fn flush(&self) -> Result<(), JsValue> {
        // held across the write: an overlapping flush or any other call gets the busy error
        let wallet = self.borrow_wallet()?;
        self.flush_wallet(&wallet).await
    }

    /// Flush while the caller already holds the operation guard, so a receive and its snapshot
    /// write cannot be interleaved with another call.
    async fn flush_wallet(&self, wallet: &Wallet) -> Result<(), JsValue> {
        if self.detached.get() {
            return Err(JsValue::from_str(
                "the wallet snapshot was deleted: this instance is detached, call load again to start a new wallet",
            ));
        }
        let bytes = wallet
            .snapshot()
            .map_err(|e| failure("cannot serialize the wallet", e))?
            .ok_or_else(|| {
                JsValue::from_str("the wallet runs without a snapshot-capable backend")
            })?;
        let sequence = save_snapshot_record(&self.name, &bytes, &self.writer, self.sequence.get())
            .await
            .map_err(|e| failure("cannot persist the wallet", e))?;
        self.sequence.set(sequence);
        Ok(())
    }

    /// Delete the snapshot stored under `name` from IndexedDB and detach this instance.
    ///
    /// `name` must be this wallet's name: any other key is refused, so the call can never remove
    /// another wallet's record. A missing record is not an error, so a repeated call succeeds. The
    /// in-memory wallet stays usable, but this instance is detached: every later `flush` fails
    /// instead of recreating the deleted snapshot with a stale sequence. Recreate the record
    /// deliberately with `load` on a new instance, which starts at sequence `0`, or drop the
    /// instance.
    #[wasm_bindgen(js_name = deleteSnapshot)]
    pub async fn delete_snapshot(&self, name: String) -> Result<(), JsValue> {
        // held across the delete, so a flush cannot recreate the record while it is being removed
        let _wallet = self.borrow_wallet()?;
        if name != self.name {
            return Err(JsValue::from_str(&format!(
                "cannot delete the snapshot '{name}': this wallet stores its snapshot under '{}'",
                self.name
            )));
        }
        core_delete_snapshot(&self.name)
            .await
            .map_err(|e| failure("cannot delete the wallet snapshot", e))?;
        self.detached.set(true);
        Ok(())
    }
}

/// An `rgb-lib` multisig wallet over the in-memory backend.
///
/// Only the hub-free subset exists on wasm: the wallet derives addresses from its descriptors and
/// persists them with a snapshot. Hub-coordinated operations (`getAddress` by shared index,
/// `goOnline`, voting, sends) need the native-only `_online` feature and are not exposed.
#[wasm_bindgen]
pub struct RgbLibMultisigWallet {
    /// Held for the whole of one call, so a second overlapping call gets the busy error.
    wallet: Rc<RefCell<Option<MultisigWallet>>>,
    name: String,
    /// This instance's id in the snapshot record; a flush writes it next to the bytes.
    writer: String,
    /// Sequence this instance last saw or wrote; a guarded flush needs it to match the store.
    sequence: Cell<u64>,
    /// Set once this instance deleted its own snapshot: a later flush must not resurrect it.
    detached: Cell<bool>,
}

impl RgbLibMultisigWallet {
    /// Take the wallet for one operation; a call made while another holds it gets the busy error.
    fn borrow_wallet(&self) -> Result<RefMut<'_, MultisigWallet>, JsValue> {
        try_borrow_wallet(&self.wallet)
    }
}

#[wasm_bindgen]
impl RgbLibMultisigWallet {
    /// Create a multisig wallet from a [`MultisigKeys`] JSON string.
    ///
    /// The JSON is the `rgb-lib` shape `{"cosigners": [{"account_xpub_vanilla",
    /// "account_xpub_colored", "vanilla_keychain", "master_fingerprint"}], "threshold_colored",
    /// "threshold_vanilla"}`; build each cosigner from the public fields of [`generateKeys`] or
    /// [`restoreKeys`]. No mnemonic is stored.
    pub fn create(
        name: String,
        keys: String,
        network: String,
    ) -> Result<RgbLibMultisigWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = multisig_keys(&keys)?;
        let wallet = MultisigWallet::new(wallet_data(network), keys)
            .map_err(|e| failure("cannot create the multisig wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Rebuild a multisig wallet from the bytes of [`RgbLibMultisigWallet::snapshot`] and its keys.
    #[wasm_bindgen]
    pub fn restore(
        name: String,
        snapshot: Vec<u8>,
        keys: String,
        network: String,
    ) -> Result<RgbLibMultisigWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = multisig_keys(&keys)?;
        let wallet = MultisigWallet::from_snapshot(&snapshot, wallet_data(network), keys)
            .map_err(|e| failure("cannot restore the multisig wallet", e))?;
        let (writer, sequence) = fresh_writer();
        Ok(Self {
            wallet: Rc::new(RefCell::new(Some(wallet))),
            name,
            writer,
            sequence,
            detached: Cell::new(false),
        })
    }

    /// Load the snapshot stored under `name` from IndexedDB and rebuild the multisig wallet.
    ///
    /// When no snapshot exists yet, a fresh wallet is created. The stored writer id and sequence
    /// are adopted, so this instance's next flush is guarded like the singlesig one.
    #[wasm_bindgen]
    pub async fn load(
        name: String,
        keys: String,
        network: String,
    ) -> Result<RgbLibMultisigWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = multisig_keys(&keys)?;
        let wallet_data = wallet_data(network);
        match load_snapshot_record(&name)
            .await
            .map_err(|e| failure("cannot read the wallet snapshot", e))?
        {
            Some(record) => MultisigWallet::from_snapshot(&record.bytes, wallet_data, keys)
                .map(|wallet| Self {
                    wallet: Rc::new(RefCell::new(Some(wallet))),
                    name,
                    writer: record.writer,
                    sequence: Cell::new(record.sequence),
                    detached: Cell::new(false),
                })
                .map_err(|e| failure("cannot restore the multisig wallet", e)),
            None => {
                let wallet = MultisigWallet::new(wallet_data, keys)
                    .map_err(|e| failure("cannot create the multisig wallet", e))?;
                let (writer, sequence) = fresh_writer();
                Ok(Self {
                    wallet: Rc::new(RefCell::new(Some(wallet))),
                    name,
                    writer,
                    sequence,
                    detached: Cell::new(false),
                })
            }
        }
    }

    /// The wallet name, i.e. the key of its durable snapshot.
    ///
    /// Takes the guard like every other call, so an overlapping operation is reported instead of
    /// being observed half-way through.
    pub fn name(&self) -> Result<String, JsValue> {
        let _wallet = self.borrow_wallet()?;
        Ok(self.name.clone())
    }

    /// The wallet identity, derived from the descriptors: a multisig group has no single master
    /// fingerprint.
    pub fn id(&self) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        Ok(wallet.get_wallet_id())
    }

    /// Return the data that defines the wallet as JSON.
    #[wasm_bindgen(js_name = getWalletData)]
    pub fn get_wallet_data(&self) -> Result<String, JsValue> {
        let wallet_data = {
            let wallet = self.borrow_wallet()?;
            wallet.get_wallet_data()
        };
        json_result("cannot serialize the wallet data", &wallet_data)
    }

    /// Return the cosigners and thresholds of the wallet as JSON.
    #[wasm_bindgen(js_name = getKeys)]
    pub fn get_keys(&self) -> Result<String, JsValue> {
        let keys = {
            let wallet = self.borrow_wallet()?;
            wallet.get_keys()
        };
        json_result("cannot serialize the multisig keys", &keys)
    }

    /// Return the colored and vanilla descriptors of the wallet as JSON.
    #[wasm_bindgen(js_name = getDescriptors)]
    pub fn get_descriptors(&self) -> Result<String, JsValue> {
        let descriptors = {
            let wallet = self.borrow_wallet()?;
            wallet.get_descriptors()
        };
        json_result("cannot serialize the descriptors", &descriptors)
    }

    /// Return the vanilla receive address at `index`, derived from the wallet descriptors.
    ///
    /// Unlike the native, hub-coordinated `getAddress`, this neither reveals nor persists the
    /// index: every cosigner derives the same address for the same `index`.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&self, index: u32) -> Result<String, JsValue> {
        let wallet = self.borrow_wallet()?;
        Ok(wallet.peek_address(index))
    }

    /// Serialize the whole wallet state into bytes for the host to store.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        let wallet = self.borrow_wallet()?;
        wallet
            .snapshot()
            .map_err(|e| failure("cannot serialize the wallet", e))?
            .ok_or_else(|| JsValue::from_str("the wallet runs without a snapshot-capable backend"))
    }

    /// Store the wallet state in IndexedDB and resolve once the transaction commits.
    ///
    /// The write is guarded like the singlesig one: a stale sequence is rejected and the error
    /// names the stored sequence and its writer. Call `load` again to adopt the newer state. After
    /// `deleteSnapshot` this instance is detached and every flush fails.
    pub async fn flush(&self) -> Result<(), JsValue> {
        // held across the write: an overlapping flush or any other call gets the busy error
        let wallet = self.borrow_wallet()?;
        if self.detached.get() {
            return Err(JsValue::from_str(
                "the wallet snapshot was deleted: this instance is detached, call load again to start a new wallet",
            ));
        }
        let bytes = wallet
            .snapshot()
            .map_err(|e| failure("cannot serialize the wallet", e))?
            .ok_or_else(|| {
                JsValue::from_str("the wallet runs without a snapshot-capable backend")
            })?;
        let sequence = save_snapshot_record(&self.name, &bytes, &self.writer, self.sequence.get())
            .await
            .map_err(|e| failure("cannot persist the wallet", e))?;
        self.sequence.set(sequence);
        Ok(())
    }

    /// Delete the snapshot stored under `name` from IndexedDB and detach this instance.
    ///
    /// `name` must be this wallet's name: any other key is refused. A missing record is not an
    /// error. The in-memory wallet stays usable, but every later `flush` fails instead of
    /// recreating the deleted snapshot; `load` on a new instance recreates the record at sequence
    /// `0` deliberately.
    #[wasm_bindgen(js_name = deleteSnapshot)]
    pub async fn delete_snapshot(&self, name: String) -> Result<(), JsValue> {
        // held across the delete, so a flush cannot recreate the record while it is being removed
        let _wallet = self.borrow_wallet()?;
        if name != self.name {
            return Err(JsValue::from_str(&format!(
                "cannot delete the snapshot '{name}': this wallet stores its snapshot under '{}'",
                self.name
            )));
        }
        core_delete_snapshot(&self.name)
            .await
            .map_err(|e| failure("cannot delete the wallet snapshot", e))?;
        self.detached.set(true);
        Ok(())
    }
}

/// Re-entrancy guard coverage, run in a real browser by the `wasm_browser_lifecycle` CI job.
///
/// A JavaScript host can start a second call while an async method is suspended at an await. The
/// guard must report that overlap as the busy error, never panic in `borrow_mut` or alias the
/// wallet. An async method cannot be suspended on purpose here (no network in the test), so the
/// borrow an in-flight operation holds is simulated directly and the public methods are observed
/// around it.
#[cfg(test)]
mod tests {
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    use super::*;
    use rgb_lib::wallet::Cosigner;

    wasm_bindgen_test_configure!(run_in_browser);

    /// A fixed BIP-39 phrase: every wallet below is built offline, nothing touches the chain.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn singlesig(name: &str) -> RgbLibWallet {
        RgbLibWallet::create(
            name.to_string(),
            MNEMONIC.to_string(),
            "regtest".to_string(),
        )
        .expect("the wallet is created offline")
    }

    fn multisig() -> RgbLibMultisigWallet {
        let cosigner = || {
            let keys = core_generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
            Cosigner {
                account_xpub_vanilla: keys.account_xpub_vanilla,
                account_xpub_colored: keys.account_xpub_colored,
                vanilla_keychain: None,
                master_fingerprint: keys.master_fingerprint,
            }
        };
        let keys = MultisigKeys::new(vec![cosigner(), cosigner()], 2, 2);
        RgbLibMultisigWallet::create(
            "busy-multisig".to_string(),
            serde_json::to_string(&keys).expect("the multisig keys serialize"),
            "regtest".to_string(),
        )
        .expect("the multisig wallet is created offline")
    }

    fn message(err: JsValue) -> String {
        err.as_string().expect("the bindings throw a string")
    }

    /// The second call on a held instance reports the busy error; once the first operation ends
    /// the same instance serves the next call.
    #[wasm_bindgen_test]
    fn overlapping_calls_are_rejected() {
        let wallet = singlesig("busy-test");
        // stand in for an async operation suspended at an await
        let slot = Rc::clone(&wallet.wallet);
        let held = slot.try_borrow_mut().expect("the fresh wallet is free");

        for err in [
            wallet.get_btc_balance().unwrap_err(),
            wallet.snapshot().unwrap_err(),
            wallet.name().unwrap_err(),
            wallet.id().unwrap_err(),
            wallet.get_wallet_data().unwrap_err(),
            wallet.list_assets().unwrap_err(),
            wallet.get_address().unwrap_err(),
        ] {
            assert_eq!(message(err), WALLET_BUSY);
        }

        drop(held);
        // the first operation finished: the same instance is usable and its state advanced
        assert_eq!(wallet.name().unwrap(), "busy-test");
        assert_eq!(wallet.id().unwrap().len(), 8);
        assert!(!wallet.get_btc_balance().unwrap().is_empty());
        assert!(wallet.get_address().unwrap().starts_with("bcrt1"));
    }

    /// The multisig class carries the same guard.
    #[wasm_bindgen_test]
    fn overlapping_multisig_calls_are_rejected() {
        let wallet = multisig();
        let slot = Rc::clone(&wallet.wallet);
        let held = slot.try_borrow_mut().expect("the fresh wallet is free");

        for err in [
            wallet.name().unwrap_err(),
            wallet.id().unwrap_err(),
            wallet.get_address(0).unwrap_err(),
        ] {
            assert_eq!(message(err), WALLET_BUSY);
        }

        drop(held);
        assert_eq!(wallet.name().unwrap(), "busy-multisig");
        assert!(wallet.get_address(0).unwrap().starts_with("bcrt1"));
        assert!(!wallet.snapshot().unwrap().is_empty());
    }
}
