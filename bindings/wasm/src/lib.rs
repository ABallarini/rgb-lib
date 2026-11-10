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

use wasm_bindgen::prelude::*;

use rgb_lib::{
    AssetSchema, BitcoinNetwork, Error,
    keys::{WitnessVersion, restore_keys},
    wallet::{DatabaseType, SinglesigKeys, Wallet, WalletData, persistence::load_snapshot},
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
fn derived_keys(network: BitcoinNetwork, mnemonic: &str) -> Result<SinglesigKeys, JsValue> {
    let keys = restore_keys(network, mnemonic.to_string(), WitnessVersion::Taproot)
        .map_err(|_| JsValue::from_str("invalid mnemonic phrase for the given network"))?;
    Ok(SinglesigKeys::from_keys(&keys, None))
}

fn failure(context: &str, e: Error) -> JsValue {
    JsValue::from_str(&format!("{context}: {e}"))
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
