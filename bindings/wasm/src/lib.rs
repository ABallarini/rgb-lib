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
//!   transaction commits. Only available where IndexedDB exists, i.e. in a browser.
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

use serde::Serialize;
use wasm_bindgen::prelude::*;

use rgb_lib::{
    AssetSchema, BitcoinNetwork, Error,
    keys::{
        Keys, WitnessVersion, generate_keys as core_generate_keys,
        restore_keys as core_restore_keys,
    },
    no_wallet::validate_consignment_offchain as core_validate_consignment_offchain,
    wallet::{
        AssetFilter, DatabaseType, Invoice as CoreInvoice, MultisigKeys, MultisigWallet,
        RgbWalletOpsOffline, SinglesigKeys, TransferScope, Wallet, WalletData,
        backup_info_bytes as core_backup_info_bytes, persistence::load_snapshot,
        restore_backup_bytes as core_restore_backup_bytes,
    },
};

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
    wallet: Wallet,
    name: String,
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
        Ok(Self { wallet, name })
    }

    /// Rebuild a wallet from the bytes of [`RgbLibWallet::snapshot`].
    ///
    /// The snapshot carries the wallet settings, which are validated against the supplied
    /// mnemonic and network; a mismatch is an error, never a fresh wallet.
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
        Ok(Self { wallet, name })
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
        Ok(Self { wallet, name })
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
        Ok(Self { wallet, name })
    }

    /// Load the snapshot stored under `name` from IndexedDB and rebuild the wallet.
    ///
    /// When no snapshot exists yet, a fresh wallet is created instead, so this is the single entry
    /// point a host needs on startup. Await it before using the wallet.
    #[wasm_bindgen]
    pub async fn load(
        name: String,
        mnemonic: String,
        network: String,
    ) -> Result<RgbLibWallet, JsValue> {
        let network = parse_network(&network)?;
        let keys = derived_keys(network, &mnemonic)?;
        let wallet_data = wallet_data(network);
        match load_snapshot(&name)
            .await
            .map_err(|e| failure("cannot read the wallet snapshot", e))?
        {
            Some(snapshot) => Wallet::from_snapshot(&snapshot, wallet_data, keys)
                .map(|wallet| Self { wallet, name })
                .map_err(|e| failure("cannot restore the wallet", e)),
            // a corrupt snapshot is an error above, never a fresh wallet: no fallback here
            None => Wallet::new_in_memory(wallet_data, keys)
                .map(|wallet| Self { wallet, name })
                .map_err(|e| failure("cannot create the wallet", e)),
        }
    }

    /// The wallet name, i.e. the key of its durable snapshot.
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// The wallet identity: the master fingerprint of its keys.
    pub fn id(&self) -> String {
        self.wallet.get_keys().master_fingerprint
    }

    /// Return the BTC balances (in sats) as JSON, from local data only.
    ///
    /// No chain sync is performed, so this reflects the last known state carried by the wallet.
    #[wasm_bindgen(js_name = getBtcBalance)]
    pub fn get_btc_balance(&mut self) -> Result<String, JsValue> {
        let balance = self
            .wallet
            .get_btc_balance(None, true)
            .map_err(|e| failure("cannot get the BTC balance", e))?;
        json_result("cannot serialize the BTC balance", &balance)
    }

    /// Return the RGB asset balance as JSON, from local data only.
    #[wasm_bindgen(js_name = getAssetBalance)]
    pub fn get_asset_balance(&self, asset_id: String) -> Result<String, JsValue> {
        let balance = self
            .wallet
            .get_asset_balance(asset_id)
            .map_err(|e| failure("cannot get the asset balance", e))?;
        json_result("cannot serialize the asset balance", &balance)
    }

    /// Return the RGB asset metadata as JSON.
    #[wasm_bindgen(js_name = getAssetMetadata)]
    pub fn get_asset_metadata(&self, asset_id: String) -> Result<String, JsValue> {
        let metadata = self
            .wallet
            .get_asset_metadata(asset_id)
            .map_err(|e| failure("cannot get the asset metadata", e))?;
        json_result("cannot serialize the asset metadata", &metadata)
    }

    /// List the known RGB assets as JSON, grouped by schema.
    #[wasm_bindgen(js_name = listAssets)]
    pub fn list_assets(&self) -> Result<String, JsValue> {
        let assets = self
            .wallet
            .list_assets(vec![])
            .map_err(|e| failure("cannot list the assets", e))?;
        json_result("cannot serialize the asset list", &assets)
    }

    /// List the known RGB transfers as JSON, optionally filtered by `asset_id`.
    #[wasm_bindgen(js_name = listTransfers)]
    pub fn list_transfers(&self, asset_id: Option<String>) -> Result<String, JsValue> {
        let filter = match asset_id {
            Some(asset_id) => AssetFilter::Id(asset_id),
            None => AssetFilter::AnyOrNone,
        };
        let transfers = self
            .wallet
            .list_transfers(filter, TransferScope::All)
            .map_err(|e| failure("cannot list the transfers", e))?;
        json_result("cannot serialize the transfer list", &transfers)
    }

    /// List the known unspents as JSON, from local data only.
    ///
    /// `settled_only` excludes allocations on pending RGB operations.
    #[wasm_bindgen(js_name = listUnspents)]
    pub fn list_unspents(&mut self, settled_only: bool) -> Result<String, JsValue> {
        let unspents = self
            .wallet
            .list_unspents(None, settled_only, true)
            .map_err(|e| failure("cannot list the unspents", e))?;
        json_result("cannot serialize the unspent list", &unspents)
    }

    /// List the known Bitcoin transactions as JSON, newest first, from local data only.
    #[wasm_bindgen(js_name = listTransactions)]
    pub fn list_transactions(&mut self) -> Result<String, JsValue> {
        let transactions = self
            .wallet
            .list_transactions(None, true)
            .map_err(|e| failure("cannot list the transactions", e))?;
        json_result("cannot serialize the transaction list", &transactions)
    }

    /// Return the data that defines the wallet as JSON.
    #[wasm_bindgen(js_name = getWalletData)]
    pub fn get_wallet_data(&self) -> Result<String, JsValue> {
        let wallet_data = self.wallet.get_wallet_data();
        json_result("cannot serialize the wallet data", &wallet_data)
    }

    /// Return a new receive address from the vanilla wallet.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&mut self) -> Result<String, JsValue> {
        self.wallet
            .get_address()
            .map_err(|e| failure("cannot derive a receive address", e))
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
        self.wallet
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
        self.wallet
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
        self.wallet
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
        self.wallet
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
        self.wallet
            .sign_psbt(psbt, None)
            .map_err(|e| failure("cannot sign the PSBT", e))
    }

    /// Finalize a signed PSBT and return the finalized PSBT.
    #[wasm_bindgen(js_name = finalizePsbt)]
    pub fn finalize_psbt(&self, psbt: String) -> Result<String, JsValue> {
        self.wallet
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
        self.wallet
            .delete_transfers(batch_transfer_idx, no_asset_only)
            .map_err(|e| failure("cannot delete the transfers", e))
    }

    /// Serialize the whole wallet state into bytes for the host to store.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.wallet
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
        self.wallet
            .backup_bytes(&password)
            .map_err(|e| failure("cannot create the backup", e))
    }

    /// Restore this wallet from the bytes of [`RgbLibWallet::backup`].
    ///
    /// The backup must belong to the wallet keys already held here: the shared restore path
    /// validates them and rebuilds the database, BDK state and files from the backup snapshot. A
    /// wrong password, a different wallet or a corrupt archive is an error, never a fresh wallet.
    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(
        &mut self,
        backup_bytes: Vec<u8>,
        password: String,
    ) -> Result<(), JsValue> {
        let restored = core_restore_backup_bytes(&backup_bytes, &password)
            .map_err(|e| failure("cannot restore the backup", e))?;
        let snapshot = restored
            .wallet_snapshot()
            .map_err(|e| failure("cannot restore the backup", e))?;
        let wallet = Wallet::from_snapshot(
            &snapshot,
            self.wallet.get_wallet_data(),
            self.wallet.get_keys(),
        )
        .map_err(|e| failure("cannot restore the backup", e))?;
        self.wallet = wallet;
        Ok(())
    }

    /// Store the wallet state in IndexedDB and resolve once the transaction commits.
    pub async fn flush(&self) -> Result<(), JsValue> {
        self.wallet
            .flush(&self.name)
            .await
            .map_err(|e| failure("cannot persist the wallet", e))
    }
}

/// An `rgb-lib` multisig wallet over the in-memory backend.
///
/// Only the hub-free subset exists on wasm: the wallet derives addresses from its descriptors and
/// persists them with a snapshot. Hub-coordinated operations (`getAddress` by shared index,
/// `goOnline`, voting, sends) need the native-only `_online` feature and are not exposed.
#[wasm_bindgen]
pub struct RgbLibMultisigWallet {
    wallet: MultisigWallet,
    name: String,
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
        Ok(Self { wallet, name })
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
        Ok(Self { wallet, name })
    }

    /// The wallet name, i.e. the key of its durable snapshot.
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// The wallet identity, derived from the descriptors: a multisig group has no single master
    /// fingerprint.
    pub fn id(&self) -> String {
        self.wallet.get_wallet_id()
    }

    /// Return the data that defines the wallet as JSON.
    #[wasm_bindgen(js_name = getWalletData)]
    pub fn get_wallet_data(&self) -> Result<String, JsValue> {
        let wallet_data = self.wallet.get_wallet_data();
        json_result("cannot serialize the wallet data", &wallet_data)
    }

    /// Return the cosigners and thresholds of the wallet as JSON.
    #[wasm_bindgen(js_name = getKeys)]
    pub fn get_keys(&self) -> Result<String, JsValue> {
        let keys = self.wallet.get_keys();
        json_result("cannot serialize the multisig keys", &keys)
    }

    /// Return the colored and vanilla descriptors of the wallet as JSON.
    #[wasm_bindgen(js_name = getDescriptors)]
    pub fn get_descriptors(&self) -> Result<String, JsValue> {
        let descriptors = self.wallet.get_descriptors();
        json_result("cannot serialize the descriptors", &descriptors)
    }

    /// Return the vanilla receive address at `index`, derived from the wallet descriptors.
    ///
    /// Unlike the native, hub-coordinated `getAddress`, this neither reveals nor persists the
    /// index: every cosigner derives the same address for the same `index`.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&self, index: u32) -> String {
        self.wallet.peek_address(index)
    }

    /// Serialize the whole wallet state into bytes for the host to store.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.wallet
            .snapshot()
            .map_err(|e| failure("cannot serialize the wallet", e))?
            .ok_or_else(|| JsValue::from_str("the wallet runs without a snapshot-capable backend"))
    }

    /// Store the wallet state in IndexedDB and resolve once the transaction commits.
    pub async fn flush(&self) -> Result<(), JsValue> {
        self.wallet
            .flush(&self.name)
            .await
            .map_err(|e| failure("cannot persist the wallet", e))
    }
}
