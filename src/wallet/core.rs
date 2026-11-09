//! Core wallet functionality.
//!
//! This module defines abstractions to implement common methods across different wallet types.

use super::*;

// BDK file store of wallets created before the changeset moved into the rgb-lib DB
#[cfg(feature = "bdk_file_store_migration")]
pub(crate) const BDK_DB_NAME: &str = "bdk_db";
// BDK changes that have been applied in memory but whose transaction has not committed yet
pub(crate) const BDK_PENDING_FILE: &str = "bdk_pending.json";

pub(crate) const NUM_KNOWN_SCHEMAS: usize = 4;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) const RGB_LIB_DB_NAME: &str = "rgb_lib_db";

pub(crate) const ASSETS_DIR: &str = "assets";
pub(crate) const MEDIA_DIR: &str = "media_files";

pub(crate) const WALLET_MANIFEST_FILE: &str = "wallet_manifest.json";
pub(crate) const WALLET_MANIFEST_VERSION: u8 = 1;

// wasm wallet snapshot envelope: the manifest travels in front of the memory-backend snapshot.
const WASM_SNAPSHOT_MAGIC: &[u8; 5] = b"RGBWL";
const WASM_SNAPSHOT_VERSION: u8 = 2;
const WASM_SNAPSHOT_HEADER_LEN: usize = WASM_SNAPSHOT_MAGIC.len() + 1 + 4;

/// Build a wasm wallet snapshot: the manifest JSON, then the raw memory-backend snapshot.
///
/// The envelope keeps the settings the wallet was created with next to the database bytes, so a
/// restore can validate the caller's [`WalletData`] and [`SinglesigKeys`] without a manifest file.
/// The manifest is the non-secret settings record; the mnemonic never reaches it.
#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
pub(crate) fn encode_wasm_snapshot(
    manifest: &WalletManifest,
    db_snapshot: &[u8],
) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(manifest).map_err(|e| Error::Internal {
        details: format!("cannot serialize the wallet manifest into the snapshot: {e}"),
    })?;
    let json_len = u32::try_from(json.len()).map_err(|_| Error::Internal {
        details: "the wallet manifest is too large for the snapshot envelope".to_string(),
    })?;
    let mut out = Vec::with_capacity(WASM_SNAPSHOT_HEADER_LEN + json.len() + db_snapshot.len());
    out.extend_from_slice(WASM_SNAPSHOT_MAGIC);
    out.push(WASM_SNAPSHOT_VERSION);
    out.extend_from_slice(&json_len.to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(db_snapshot);
    Ok(out)
}

/// Split a wasm wallet snapshot into its manifest and the raw memory-backend snapshot.
///
/// Only the envelope is validated here: the database snapshot is decoded by the memory backend.
/// The old raw database format has no envelope magic and is rejected.
#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
pub(crate) fn decode_wasm_snapshot(bytes: &[u8]) -> Result<(WalletManifest, Vec<u8>), Error> {
    let invalid = |details: String| Error::Internal { details };
    let header = bytes.get(..WASM_SNAPSHOT_HEADER_LEN).ok_or_else(|| {
        invalid("the wallet snapshot is shorter than its envelope header".to_string())
    })?;
    if &header[..WASM_SNAPSHOT_MAGIC.len()] != WASM_SNAPSHOT_MAGIC {
        return Err(invalid(
            "the wallet snapshot does not start with the expected envelope magic".to_string(),
        ));
    }
    let version = header[WASM_SNAPSHOT_MAGIC.len()];
    if version != WASM_SNAPSHOT_VERSION {
        return Err(invalid(format!(
            "unsupported wallet snapshot envelope version {version} (expected {WASM_SNAPSHOT_VERSION})"
        )));
    }
    let json_len = u32::from_le_bytes([
        header[WASM_SNAPSHOT_MAGIC.len() + 1],
        header[WASM_SNAPSHOT_MAGIC.len() + 2],
        header[WASM_SNAPSHOT_MAGIC.len() + 3],
        header[WASM_SNAPSHOT_MAGIC.len() + 4],
    ]) as usize;
    let json_end = WASM_SNAPSHOT_HEADER_LEN
        .checked_add(json_len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| {
            invalid("the wallet snapshot manifest length is larger than the snapshot".to_string())
        })?;
    let manifest: WalletManifest =
        serde_json::from_slice(&bytes[WASM_SNAPSHOT_HEADER_LEN..json_end]).map_err(|e| {
            invalid(format!(
                "cannot deserialize the wallet snapshot manifest: {e}"
            ))
        })?;
    let db_snapshot = &bytes[json_end..];
    if db_snapshot.is_empty() {
        return Err(invalid(
            "the wallet snapshot carries no database snapshot body".to_string(),
        ));
    }
    Ok((manifest, db_snapshot.to_vec()))
}

// Only the version field, so an unsupported manifest reports its version instead of failing to
// deserialize.
#[derive(Deserialize)]
struct WalletManifestVersion {
    version: u8,
}

// The non-secret parts of a WalletData and a SinglesigKeys, persisted inside the wallet
// directory so the wallet can be re-opened via Wallet::load without re-supplying them.
//
// The mnemonic must never be stored here: it's the wallet's only secret and the manifest sits in
// plaintext next to the databases.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WalletManifest {
    pub(crate) version: u8,
    pub(crate) bitcoin_network: BitcoinNetwork,
    pub(crate) database_type: DatabaseType,
    pub(crate) max_allocations_per_utxo: u32,
    pub(crate) supported_schemas: Vec<AssetSchema>,
    pub(crate) account_xpub_vanilla: String,
    pub(crate) account_xpub_colored: String,
    pub(crate) vanilla_keychain: u8,
    pub(crate) master_fingerprint: String,
    pub(crate) witness_version: WitnessVersion,
}

impl WalletManifest {
    pub(crate) fn new(wallet_data: &WalletData, keys: &SinglesigKeys) -> Self {
        Self {
            version: WALLET_MANIFEST_VERSION,
            bitcoin_network: wallet_data.bitcoin_network,
            database_type: wallet_data.database_type.clone(),
            max_allocations_per_utxo: wallet_data.max_allocations_per_utxo,
            supported_schemas: wallet_data.supported_schemas.clone(),
            account_xpub_vanilla: keys.account_xpub_vanilla.clone(),
            account_xpub_colored: keys.account_xpub_colored.clone(),
            vanilla_keychain: keys.vanilla_keychain.unwrap_or(KEYCHAIN_BTC),
            master_fingerprint: keys.master_fingerprint.clone(),
            witness_version: keys.witness_version,
        }
    }

    fn path(wallet_dir: &Path) -> PathBuf {
        wallet_dir.join(WALLET_MANIFEST_FILE)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn write(&self, wallet_dir: &Path) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(self).map_err(InternalError::from)?;
        atomic_write(&Self::path(wallet_dir), json.as_bytes())?;
        Ok(())
    }

    /// wasm: there is no wallet directory on disk; the manifest is stored in the in-memory
    /// backend so it can travel in the snapshot envelope.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn write(&self, _wallet_dir: &Path) -> Result<(), Error> {
        Ok(())
    }

    pub(crate) fn read(wallet_dir: &Path) -> Result<Self, Error> {
        let manifest_path = Self::path(wallet_dir);
        if !manifest_path.exists() {
            return Err(Error::InexistentWalletManifest {
                path: manifest_path.to_string_lossy().to_string(),
            });
        }
        let json = fs::read_to_string(&manifest_path)?;
        let manifest_version: WalletManifestVersion =
            serde_json::from_str(&json).map_err(InternalError::from)?;
        if manifest_version.version != WALLET_MANIFEST_VERSION {
            return Err(Error::UnsupportedWalletManifestVersion {
                version: manifest_version.version.to_string(),
            });
        }
        serde_json::from_str(&json).map_err(|e| InternalError::from(e).into())
    }

    // Fail if wallet_data or keys disagree with settings fixed at wallet creation. Settings that
    // are allowed to change are not checked on purpose.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn check_settings_unchanged(
        wallet_dir: &Path,
        wallet_data: &WalletData,
        keys: &SinglesigKeys,
    ) -> Result<(), Error> {
        if !Self::path(wallet_dir).exists() {
            // skip when no manifest exists (legacy directory or first creation)
            return Ok(());
        }
        Self::read(wallet_dir)?.check_unchanged_inner(wallet_data, keys, false)
    }

    /// Fail if `wallet_data` or `keys` disagree with this manifest.
    ///
    /// Used when restoring a wasm wallet, where the manifest comes from the snapshot instead of a
    /// file. Unlike the file-based check, the mutable settings are checked too: the database bytes
    /// in the snapshot were built with the settings the manifest records.
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    pub(crate) fn check_unchanged(
        &self,
        wallet_data: &WalletData,
        keys: &SinglesigKeys,
    ) -> Result<(), Error> {
        self.check_unchanged_inner(wallet_data, keys, true)
    }

    // `include_mutable` keeps the file-based check's historical behaviour, where `new` may update
    // the settings that are not fixed at creation.
    fn check_unchanged_inner(
        &self,
        wallet_data: &WalletData,
        keys: &SinglesigKeys,
        include_mutable: bool,
    ) -> Result<(), Error> {
        let created_with = self;
        let requested = Self::new(wallet_data, keys);

        if created_with.bitcoin_network != requested.bitcoin_network {
            return Err(Error::BitcoinNetworkMismatch);
        }

        macro_rules! check {
            ($($field:ident),+ $(,)?) => {
                $(if created_with.$field != requested.$field {
                    return Err(Error::WalletSettingMismatch {
                        setting: stringify!($field).to_string(),
                        expected: format!("{:?}", created_with.$field),
                        provided: format!("{:?}", requested.$field),
                    });
                })+
            };
        }

        if include_mutable {
            check!(database_type, max_allocations_per_utxo, supported_schemas,);
        }

        // ordered so the root cause is reported ahead of what it derives: a changed witness
        // version also changes the account xpubs it produces
        check!(
            master_fingerprint,
            witness_version,
            vanilla_keychain,
            account_xpub_colored,
            account_xpub_vanilla,
        );
        Ok(())
    }

    /// wasm: there is no manifest file. The manifest travels in the snapshot envelope and
    /// [`Self::check_unchanged`] validates it on restore, so construction has nothing on disk to
    /// compare against.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn check_settings_unchanged(
        _wallet_dir: &Path,
        _wallet_data: &WalletData,
        _keys: &SinglesigKeys,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub(crate) fn into_parts(
        self,
        data_dir: String,
        mnemonic: Option<String>,
    ) -> (WalletData, SinglesigKeys) {
        (
            WalletData {
                data_dir,
                bitcoin_network: self.bitcoin_network,
                database_type: self.database_type,
                max_allocations_per_utxo: self.max_allocations_per_utxo,
                supported_schemas: self.supported_schemas,
            },
            SinglesigKeys {
                account_xpub_vanilla: self.account_xpub_vanilla,
                account_xpub_colored: self.account_xpub_colored,
                vanilla_keychain: Some(self.vanilla_keychain),
                master_fingerprint: self.master_fingerprint,
                mnemonic,
                witness_version: self.witness_version,
            },
        )
    }
}

/// Which keychain contributes SPKs to the sync request.
#[cfg(feature = "_online")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncKeychain {
    /// Sync the colored keychain
    Colored,
    /// Sync the vanilla keychain
    Vanilla {
        /// Number of addresses preceding the lookback anchor (last used or, if none, last
        /// revealed) to scan
        lookback: u32,
    },
}

#[cfg(feature = "_online")]
impl SyncKeychain {
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn keychain(&self) -> KeychainKind {
        match self {
            SyncKeychain::Colored => KeychainKind::External,
            SyncKeychain::Vanilla { .. } => KeychainKind::Internal,
        }
    }
}

/// Strategy used to build the indexer sync request.
#[cfg(feature = "_online")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStrategy {
    /// BIP44 stop-gap full scan
    FullScan,
    /// Sync all revealed SPKs
    FullSync,
    /// Sync only SPKs we strictly need to observe:
    /// - colored: SPKs used in pending transfers or unconfirmed transactions
    /// - vanilla: a tail of recently revealed SPKs
    FastSync,
}

/// Options driving a single sync invocation.
#[cfg(feature = "_online")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOptions {
    /// Which keychain to sync
    pub keychain: SyncKeychain,
    /// Sync strategy
    pub strategy: SyncStrategy,
}

pub struct WalletInternals {
    pub(crate) wallet_data: WalletData,
    pub(crate) logger: Logger,
    pub(crate) _logger_guard: LoggerGuard,
    pub(crate) database: Arc<RgbLibDatabase>,
    pub(crate) wallet_dir: PathBuf,
    pub(crate) bdk_wallet: BdkWallet,
    pub(crate) bdk_pending: Arc<Mutex<ChangeSet>>,
    #[cfg(feature = "_online")]
    pub(crate) online_data: Option<OnlineData>,
}

impl WalletInternals {
    /// Borrow the bitcoind client and the BDK wallet at the same time, when the wallet is online
    /// via a bitcoind indexer. The wallet accessor methods borrow the whole struct, so callers
    /// needing both use this field-level split borrow instead.
    #[cfg(feature = "bitcoind")]
    pub(crate) fn bitcoind_and_bdk_mut(&mut self) -> Option<(&BitcoindClient, &mut BdkWallet)> {
        match &self.online_data.as_ref().expect("wallet is online").indexer {
            Indexer::Bitcoind(client) => Some((client, &mut self.bdk_wallet)),
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            _ => None,
        }
    }
}

pub(crate) fn setup_rgb(
    database: &RgbLibDatabase,
    supported_schemas: Vec<AssetSchema>,
    bitcoin_network: BitcoinNetwork,
) -> Result<(), Error> {
    if supported_schemas.is_empty() {
        return Err(Error::NoSupportedSchemas);
    }
    if bitcoin_network == BitcoinNetwork::Mainnet && supported_schemas.contains(&AssetSchema::Ifa) {
        return Err(Error::CannotUseIfaOnMainnet);
    }
    let txn = database.begin_transaction()?;
    let mut stock = RgbStock::new(&txn);
    let known_schemas = stock.schemata()?;
    if known_schemas.len() < NUM_KNOWN_SCHEMAS {
        let known: HashSet<_> = known_schemas.iter().map(|s| s.id).collect();
        for schema in supported_schemas {
            if !known.contains(&SchemaId::from(schema)) {
                schema.import_schema_definition(&mut stock)?;
            }
        }
    }
    txn.commit()?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn setup_db<P: AsRef<Path>>(wallet_dir: P) -> Result<RgbLibDatabase, Error> {
    let db_path = wallet_dir.as_ref().join(RGB_LIB_DB_NAME);
    let display_db_path = adjust_canonicalization(db_path);
    let connection_string = format!("sqlite:{display_db_path}?mode=rwc");
    let mut opt = ConnectOptions::new(connection_string);
    opt.max_connections(1)
        .min_connections(0)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8));
    let db_cnn = block_on(Database::connect(opt));
    let connection = db_cnn?;
    block_on(Migrator::up(&connection, None))?;
    Ok(RgbLibDatabase::new(connection))
}

/// On `wasm32` there is no filesystem to hold the SQLite database: the wallet data lives in the
/// in-memory backend, which the host persists as a snapshot.
#[cfg(target_arch = "wasm32")]
pub(crate) fn setup_db<P: AsRef<Path>>(_wallet_dir: P) -> Result<RgbLibDatabase, Error> {
    Ok(RgbLibDatabase::new_memory())
}

/// Import the BDK data of a wallet created before the changeset moved into the rgb-lib DB.
///
/// Such wallets keep their data in `bdk_file_store` files inside the wallet directory. Chain data
/// could be rebuilt by a rescan, but the revealed-address indices could not: a rescan only
/// restores up to the last *used* index, so an address that was revealed and never paid would be
/// handed out again. The signing and watch-only wallets had a store each, so both are imported;
/// `last_revealed` is persisted monotonically, so the higher of the two wins regardless of order.
///
/// A store that was read in full is added to `migrated`, for the caller to remove once the import
/// has been durably committed, so the stale copy cannot be picked up again by an older rgb-lib. A
/// truncated one is left in place, since the entries past the truncation were never imported.
/// Keeping it costs nothing at load time: this runs only while the stored changeset is empty, and
/// by the end of the first setup it no longer is (either the import filled it or the freshly
/// created wallet wrote its descriptors) so a left-behind store is never read a second time.
///
/// Returns whether anything was imported.
#[cfg(all(feature = "bdk_file_store_migration", not(target_arch = "wasm32")))]
fn import_legacy_bdk_store(
    txn: &DbTxn,
    wallet_dir: &Path,
    migrated: &mut Vec<PathBuf>,
) -> Result<bool, Error> {
    let mut imported = false;
    for name in [BDK_DB_NAME.to_string(), format!("{BDK_DB_NAME}_watch_only")] {
        let path = wallet_dir.join(name);
        if !path.exists() {
            continue;
        }
        // a truncated trailing entry still leaves the earlier ones usable, so take the partial
        // dump rather than failing the whole import
        let (changeset, complete) = match Store::<ChangeSet>::load(BDK_DB_NAME.as_bytes(), &path) {
            Ok((_, changeset)) => (changeset.map(Box::new), true),
            Err(e) => {
                if e.changeset.is_none() {
                    return Err(Error::Internal {
                        details: format!("cannot read legacy BDK store {path:?}: {}", e.error),
                    });
                }
                (e.changeset, false)
            }
        };
        if let Some(changeset) = changeset {
            txn.update_bdk_changeset(&changeset)?;
            imported = true;
        }
        // the file is the caller's to drop, once its contents are durably in the DB
        if complete {
            migrated.push(path);
        }
    }
    Ok(imported)
}

/// Without the `bdk_file_store_migration` feature there is nothing to import from.
#[cfg(all(not(feature = "bdk_file_store_migration"), not(target_arch = "wasm32")))]
fn import_legacy_bdk_store(
    _txn: &DbTxn,
    _wallet_dir: &Path,
    _migrated: &mut Vec<PathBuf>,
) -> Result<bool, Error> {
    Ok(false)
}

/// Load (or create) the BDK wallet whose data lives in the rgb-lib DB.
///
/// Owns the transaction that the load needs, so that the files whose contents it takes over - a
/// legacy file store, the crash-recovery copy of the pending changes - are deleted only once that
/// transaction has committed. Were one deleted first, a rollback would lose the data it held.
pub(crate) fn setup_bdk<P: AsRef<Path>>(
    database: &RgbLibDatabase,
    wallet_dir: P,
    desc_colored: String,
    desc_vanilla: String,
    bitcoin_network: BitcoinNetwork,
) -> Result<BdkWallet, Error> {
    let txn = database.begin_transaction()?;
    let chain_net: ChainNet = bitcoin_network.into();
    let wallet_params = BdkWallet::load()
        .descriptor(KeychainKind::External, Some(desc_colored.clone()))
        .descriptor(KeychainKind::Internal, Some(desc_vanilla.clone()))
        .use_spk_cache(false)
        .check_genesis_hash(BlockHash::from_byte_array(
            chain_net.chain_hash().to_bytes(),
        ));
    let mut changeset = txn.get_bdk_changeset()?;
    // wasm: no filesystem, the in-memory backend is the only store, so there is nothing to fold in
    #[cfg(target_arch = "wasm32")]
    let _ = wallet_dir.as_ref();
    // files this transaction takes the contents of, to be dropped once it has committed
    #[cfg(not(target_arch = "wasm32"))]
    let mut migrated = Vec::new();
    // an empty changeset means either a brand-new wallet or one whose data still lives in the
    // legacy file store
    #[cfg(not(target_arch = "wasm32"))]
    let mut reload =
        changeset.is_empty() && import_legacy_bdk_store(&txn, wallet_dir.as_ref(), &mut migrated)?;
    #[cfg(target_arch = "wasm32")]
    let reload = false;
    // a crash between the temporary write and the rename leaves the newer changeset in the .tmp
    // file, so fold both in; the pending buffer only ever grows, so applying them in this order
    // ends on the newest state
    #[cfg(not(target_arch = "wasm32"))]
    {
        let pending_path = wallet_dir.as_ref().join(BDK_PENDING_FILE);
        let pending_tmp_path = atomic_tmp_path(&pending_path)?;
        for pending_file in [pending_path, pending_tmp_path] {
            if !pending_file.exists() {
                continue;
            }
            // a file that fails to parse was still being written when the crash happened, so its
            // contents were never complete: drop it rather than refusing to open the wallet
            if let Ok(pending) = serde_json::from_slice::<ChangeSet>(&fs::read(&pending_file)?) {
                txn.update_bdk_changeset(&pending)?;
                reload = true;
            }
            migrated.push(pending_file);
        }
    }
    if reload {
        changeset = txn.get_bdk_changeset()?;
    }
    let bdk_wallet = match wallet_params.load_wallet_no_persist(changeset)? {
        Some(wallet) => wallet,
        None => {
            let mut wallet = BdkWallet::create(desc_colored, desc_vanilla)
                .network(BdkNetwork::from(bitcoin_network))
                .use_spk_cache(false)
                .create_wallet_no_persist()
                .map_err(InternalError::from)?;
            if let Some(changeset) = wallet.take_staged() {
                txn.update_bdk_changeset(&changeset)?;
            }
            wallet
        }
    };
    txn.commit()?;
    // only now that their contents are durably in the DB
    #[cfg(not(target_arch = "wasm32"))]
    for path in migrated {
        let _ = fs::remove_file(path);
    }
    Ok(bdk_wallet)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn setup_new_wallet(
    wallet_data: &WalletData,
    fingerprint: &str,
) -> Result<(PathBuf, Logger, LoggerGuard), Error> {
    if wallet_data.max_allocations_per_utxo == 0 {
        return Err(Error::NoMaxAllocationsPerUtxo);
    }
    let data_dir_path = Path::new(&wallet_data.data_dir);
    if !data_dir_path.exists() {
        return Err(Error::InexistentDataDir);
    }
    let data_dir_path = fs::canonicalize(data_dir_path)?;
    let wallet_dir = data_dir_path.join(fingerprint);
    if !wallet_dir.exists() {
        fs::create_dir(&wallet_dir)?;
        fs::create_dir(wallet_dir.join(ASSETS_DIR))?;
        fs::create_dir(wallet_dir.join(MEDIA_DIR))?;
    }
    let (logger, logger_guard) = setup_logger(&wallet_dir, None)?;
    info!(logger.clone(), "New wallet in '{:?}'", wallet_dir);
    let panic_logger = logger.clone();
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        error!(panic_logger.clone(), "PANIC: {:?}", info);
        prev_hook(info);
    }));
    Ok((wallet_dir, logger, logger_guard))
}

/// wasm: the host owns durable storage (snapshot/IndexedDB), so there is no data directory to
/// check or create and no file log to install. The logger and guard are no-ops.
#[cfg(target_arch = "wasm32")]
pub(crate) fn setup_new_wallet(
    wallet_data: &WalletData,
    _fingerprint: &str,
) -> Result<(PathBuf, Logger, LoggerGuard), Error> {
    if wallet_data.max_allocations_per_utxo == 0 {
        return Err(Error::NoMaxAllocationsPerUtxo);
    }
    Ok((
        PathBuf::new(),
        Logger::root(slog::Discard, o!()),
        LoggerGuard,
    ))
}

pub trait WalletCore {
    fn internals(&self) -> &WalletInternals;

    fn internals_mut(&mut self) -> &mut WalletInternals;

    fn bdk_wallet(&self) -> &BdkWallet {
        &self.internals().bdk_wallet
    }

    fn bdk_wallet_mut(&mut self) -> &mut BdkWallet {
        &mut self.internals_mut().bdk_wallet
    }

    /// Add the full previous transaction to each PSBT input missing it.
    ///
    /// BDK never sets it for taproot inputs, but its signer refuses to sign without it unless it
    /// already knows the previous transaction, which a separate signer (e.g. for a watch-only or
    /// multisig wallet) doesn't.
    fn add_non_witness_utxos(&self, psbt: &mut Psbt) {
        let tx_graph = self.bdk_wallet().tx_graph();
        for (input, txin) in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input) {
            if input.non_witness_utxo.is_none()
                && let Some(prev_tx) = tx_graph.get_tx(txin.previous_output.txid)
            {
                input.non_witness_utxo = Some(prev_tx.as_ref().clone());
            }
        }
    }

    /// Persist the BDK wallet's staged changes through the given rgb-lib transaction.
    ///
    /// The changes are moved out of BDK's stage into `bdk_pending` and only dropped once `txn`
    /// commits, so neither a failed write nor a rollback can lose them: the next `persist_bdk`
    /// writes them again (the mapping is made of upserts, so re-writing is idempotent). This
    /// mirrors [`PersistedWallet::persist`](bdk_wallet::PersistedWallet), where the persister
    /// write is itself the commit.
    fn persist_bdk(&mut self, txn: &DbTxn) -> Result<(), Error> {
        let staged = self.bdk_wallet_mut().take_staged();
        let pending = Arc::clone(&self.internals().bdk_pending);
        {
            let mut guard = pending.lock().expect("bdk_pending is never poisoned");
            if let Some(staged) = staged {
                guard.merge(staged);
            }
            if guard.is_empty() {
                return Ok(());
            }
            txn.update_bdk_changeset(&guard)?;
        }
        let pending_file = self.wallet_dir().join(BDK_PENDING_FILE);
        txn.on_commit(move || {
            pending
                .lock()
                .expect("bdk_pending is never poisoned")
                .take();
            // the changes are in the DB now, so the crash-recovery copy is no longer needed
            let _ = fs::remove_file(pending_file);
        });
        Ok(())
    }

    /// Write the pending BDK changes to disk, outside the rgb-lib transaction.
    ///
    /// The file is read back by [`setup_bdk`] and removed once its contents reach the DB. So is
    /// the temporary file, in case a crash landed between the write and the rename.
    fn flush_bdk_pending(&mut self) -> Result<(), Error> {
        let staged = self.bdk_wallet_mut().take_staged();
        let pending = Arc::clone(&self.internals().bdk_pending);
        let serialized = {
            let mut guard = pending.lock().expect("bdk_pending is never poisoned");
            if let Some(staged) = staged {
                guard.merge(staged);
            }
            if guard.is_empty() {
                return Ok(());
            }
            serde_json::to_vec(&*guard).map_err(InternalError::from)?
        };
        // a crash mid-write cannot leave a half-written file, which would fail to parse on reload
        // and leave the wallet unopenable
        atomic_write(&self.wallet_dir().join(BDK_PENDING_FILE), &serialized)
    }

    /// Persist any pending BDK changes and commit the transaction.
    ///
    /// This is an operation's single persist point: BDK changes accumulate in memory while the
    /// operation runs and reach the DB once, in the same commit as the rgb-lib changes they belong
    /// to. Operations that cannot touch BDK take `&self` and commit the transaction directly.
    fn persist_and_commit(&mut self, txn: DbTxn) -> Result<(), Error> {
        self.persist_bdk(&txn)?;
        txn.commit()
    }

    fn database(&self) -> &RgbLibDatabase {
        &self.internals().database
    }

    fn logger(&self) -> &Logger {
        &self.internals().logger
    }

    fn wallet_data(&self) -> &WalletData {
        &self.internals().wallet_data
    }

    fn wallet_dir(&self) -> &PathBuf {
        &self.internals().wallet_dir
    }

    #[cfg(feature = "_online")]
    fn online_data(&self) -> &Option<OnlineData> {
        &self.internals().online_data
    }

    #[cfg(feature = "_online")]
    fn online_data_mut(&mut self) -> &mut Option<OnlineData> {
        &mut self.internals_mut().online_data
    }

    #[cfg(feature = "_online")]
    fn indexer(&self) -> &Indexer {
        &self.online_data().as_ref().unwrap().indexer
    }

    fn spv_resolver(&self) -> Option<&dyn ResolveSpvProof> {
        #[cfg(feature = "_online")]
        {
            self.online_data()
                .as_ref()
                .map(|d| &d.resolver as &dyn ResolveSpvProof)
        }
        #[cfg(not(feature = "_online"))]
        {
            None
        }
    }

    #[cfg(feature = "_online")]
    fn vanilla_sync_lookback(&self) -> u32 {
        self.online_data().as_ref().unwrap().vanilla_sync_lookback
    }

    #[cfg(feature = "_online")]
    fn failed_witness_receive_grace_secs(&self) -> u32 {
        self.online_data()
            .as_ref()
            .unwrap()
            .failed_witness_receive_grace_secs
    }

    #[cfg(feature = "_online")]
    fn check_online(&self, online: Online) -> Result<(), Error> {
        if let Some(online_data) = &self.online_data() {
            if online_data.id != online.id {
                error!(self.logger(), "Cannot change online object");
                return Err(Error::CannotChangeOnline);
            }
        } else {
            error!(self.logger(), "Wallet is offline");
            return Err(Error::Offline);
        }
        Ok(())
    }

    /// Reconcile the pending witness state with the status of the witness receives it belongs to.
    ///
    /// A witness receive registers its script as pending witness and, once its consignment is
    /// accepted, a TXO flagged as pending witness. Both are meant to live only while the receive is
    /// pending, but the receive may end in ways that leave them behind (e.g. it is failed, or the
    /// counterparty broadcasts despite a refusal), so they are checked against the receive status
    /// on every colored sync:
    /// - the script of a pending receive is kept and a payment to it is a pending witness UTXO
    /// - the script of a failed receive is kept for a grace time (see
    ///   [`OnlineOptions::failed_witness_receive_grace_secs`]), so that a payment the counterparty
    ///   broadcasts anyway is still detected by fast sync, but as an ordinary UTXO
    /// - any other script (failed receive past its grace time, settled receive, or unknown one, e.g.
    ///   deleted) is dropped
    /// - a TXO flagged as pending witness whose receive is not pending anymore gets unflagged
    ///
    /// The script of a receive that gets paid is instead dropped once the TXO paying it is
    /// registered, by [`Self::update_db_colored_txos_from_bdk`].
    ///
    /// Returns the kept scripts, mapped to whether their receive is still pending.
    #[cfg(feature = "_online")]
    fn reconcile_pending_witness(&self, txn: &DbTxn) -> Result<HashMap<String, bool>, Error> {
        let pending_witness_scripts = txn.iter_pending_witness_scripts()?;
        let pending_witness_txos = txn.iter_pending_witness_txos()?;
        if pending_witness_scripts.is_empty() && pending_witness_txos.is_empty() {
            return Ok(HashMap::new());
        }

        // incoming witness receives that are pending or failed within the grace time, by script
        // and by asset transfer: any other receive is not pending (outgoing transfers can pay one
        // of this wallet's scripts too, when sending to oneself)
        let failed_since = now().unix_timestamp() - self.failed_witness_receive_grace_secs() as i64;
        let mut receives: HashMap<String, DbBatchTransfer> = HashMap::new();
        let mut receives_by_asset_transfer: HashMap<i32, DbBatchTransfer> = HashMap::new();
        for (transfer, batch_transfer) in
            txn.get_pending_or_recently_failed_incoming_transfers(failed_since)?
        {
            if !matches!(
                transfer.recipient_type,
                Some(RecipientTypeFull::Witness { .. })
            ) {
                continue;
            }
            let Some(recipient_id) = transfer.recipient_id else {
                continue;
            };
            let Some(script) = script_buf_from_recipient_id(recipient_id)? else {
                continue;
            };
            receives.insert(script.to_hex_string(), batch_transfer.clone());
            receives_by_asset_transfer.insert(transfer.asset_transfer_idx, batch_transfer);
        }

        let mut kept_scripts = HashMap::new();
        for pws in pending_witness_scripts {
            match receives.get(&pws.script) {
                Some(b) => {
                    kept_scripts.insert(pws.script, b.status.pending());
                }
                None => {
                    debug!(
                        self.logger(),
                        "Dropping stale pending witness script {}", pws.script
                    );
                    txn.del_pending_witness_script(pws.script)?;
                }
            }
        }

        let receive_colorings = txn.get_receive_colorings_by_txo_idxs(
            pending_witness_txos.iter().map(|t| t.idx).collect(),
        )?;
        for txo in pending_witness_txos {
            // the receive the TXO belongs to: via its receive coloring once the consignment has
            // been accepted, via the script it pays otherwise (detected by a sync before that)
            let batch_transfer = receive_colorings
                .iter()
                .filter(|c| c.txo_idx == txo.idx)
                .find_map(|c| receives_by_asset_transfer.get(&c.asset_transfer_idx))
                .or_else(|| {
                    self.bdk_wallet()
                        .tx_graph()
                        .get_txout(txo.outpoint().into())
                        .and_then(|txout| receives.get(&txout.script_pubkey.to_hex_string()))
                });
            if batch_transfer.is_some_and(|b| b.status.pending()) {
                continue;
            }
            debug!(
                self.logger(),
                "Clearing pending witness flag of TXO {}, its receive is not pending",
                txo.outpoint()
            );
            let mut txo: DbTxoActMod = txo.into();
            txo.pending_witness = ActiveValue::Set(false);
            txn.update_txo(txo)?;
        }

        Ok(kept_scripts)
    }

    #[cfg(feature = "_online")]
    fn fast_sync_vanilla_spks(&self, lookback: u32) -> HashSet<ScriptBuf> {
        let spk_index = self.bdk_wallet().spk_index();
        let Some(last_revealed) = spk_index.last_revealed_index(KeychainKind::Internal) else {
            return HashSet::new();
        };
        let lookback_anchor = spk_index
            .last_used_index(KeychainKind::Internal)
            .unwrap_or(last_revealed);
        let start = lookback_anchor.saturating_sub(lookback);
        spk_index
            .revealed_keychain_spks(KeychainKind::Internal)
            .filter(|(i, _)| *i >= start && *i <= last_revealed)
            .map(|(_, spk)| spk)
            .collect()
    }

    #[cfg(feature = "_online")]
    fn unconfirmed_colored_spks(&self) -> HashSet<ScriptBuf> {
        let spk_index = self.bdk_wallet().spk_index();
        let mut spks: HashSet<ScriptBuf> = HashSet::new();
        for tx in self
            .bdk_wallet()
            .transactions()
            .filter(|tx| matches!(tx.chain_position, ChainPosition::Unconfirmed { .. }))
        {
            // first input is enough for the indexer's to return the TX info
            for input in tx.tx_node.tx.input.iter() {
                if let Some(((kc, _), txout)) = spk_index.txout(input.previous_output)
                    && kc == KeychainKind::External
                {
                    spks.insert(txout.script_pubkey.clone());
                    break;
                }
            }
        }
        spks
    }

    #[cfg(feature = "_online")]
    fn sync_bdk_and_db_txos(
        &mut self,
        txn: &DbTxn,
        options: SyncOptions,
        include_spent: bool,
    ) -> Result<(), Error> {
        debug!(self.logger(), "Syncing {:?}...", options);

        let pending_witness_scripts = match options.keychain {
            SyncKeychain::Colored => self.reconcile_pending_witness(txn)?,
            SyncKeychain::Vanilla { .. } => HashMap::new(),
        };

        #[cfg(feature = "bitcoind")]
        if let Some((client, bdk_wallet)) = self.internals_mut().bitcoind_and_bdk_mut() {
            // a node has no address index, so there is no per-SPK request to make: whatever the
            // strategy, the wallet is brought up to date by applying every block since its last
            // checkpoint (the first sync scans the whole chain) plus the mempool
            client.sync_bdk_wallet(bdk_wallet)?;
            return self.finish_sync(txn, options, include_spent, &pending_witness_scripts);
        }

        #[cfg(not(any(feature = "electrum", feature = "esplora")))]
        unreachable!("without electrum/esplora the indexer can only be bitcoind");

        #[cfg(any(feature = "electrum", feature = "esplora"))]
        {
            self.sync_bdk_via_requests(options, &pending_witness_scripts)?;
            self.finish_sync(txn, options, include_spent, &pending_witness_scripts)
        }
    }

    /// DB-side bookkeeping shared by both sync paths, run after the BDK wallet has been synced.
    #[cfg(feature = "_online")]
    fn finish_sync(
        &mut self,
        txn: &DbTxn,
        options: SyncOptions,
        include_spent: bool,
        pending_witness_scripts: &HashMap<String, bool>,
    ) -> Result<(), Error> {
        if matches!(options.keychain, SyncKeychain::Colored) {
            self.update_db_colored_txos_from_bdk(txn, include_spent, pending_witness_scripts)?;
        }
        debug!(self.logger(), "Synced");
        Ok(())
    }

    /// Sync the BDK wallet via SPK-based requests to an electrum/esplora indexer.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn sync_bdk_via_requests(
        &mut self,
        options: SyncOptions,
        pending_witness_scripts: &HashMap<String, bool>,
    ) -> Result<(), Error> {
        let kc = options.keychain.keychain();
        let latest_checkpoint = self.bdk_wallet().latest_checkpoint();
        let update: Update = match options.strategy {
            SyncStrategy::FullScan => {
                let mut iters = self.bdk_wallet().spk_index().all_unbounded_spk_iters();
                let iter = iters.remove(&kc).expect("keychain must exist");
                let request = FullScanRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks_for_keychain(kc, iter);
                self.indexer().full_scan(request)?.into()
            }
            SyncStrategy::FullSync => {
                let spks: Vec<ScriptBuf> = self
                    .bdk_wallet()
                    .spk_index()
                    .revealed_keychain_spks(kc)
                    .map(|(_, spk)| spk)
                    .collect();
                let request = SyncRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks(spks);
                self.indexer().sync(request)?.into()
            }
            SyncStrategy::FastSync => {
                let mut spks: HashSet<ScriptBuf> = HashSet::new();
                match options.keychain {
                    SyncKeychain::Colored => {
                        spks.extend(
                            pending_witness_scripts
                                .keys()
                                .map(|s| ScriptBuf::from_hex(s).expect("valid script")),
                        );
                        spks.extend(self.unconfirmed_colored_spks());
                    }
                    SyncKeychain::Vanilla { lookback } => {
                        spks.extend(self.fast_sync_vanilla_spks(lookback));
                    }
                }
                let request = SyncRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks(spks);
                self.indexer().sync(request)?.into()
            }
        };
        self.bdk_wallet_mut()
            .apply_update(update)
            .map_err(|e| Error::FailedBdkSync {
                details: e.to_string(),
            })?;
        Ok(())
    }

    /// Register in the DB the colored TXOs known to BDK but not to the DB yet.
    ///
    /// `pending_witness_scripts` are the pending witness scripts returned by
    /// [`Self::reconcile_pending_witness`]: a TXO paying one of them is flagged as pending witness
    /// only if its receive is still pending, and the script is dropped as it has been paid.
    #[cfg(feature = "_online")]
    fn update_db_colored_txos_from_bdk(
        &mut self,
        txn: &DbTxn,
        include_spent: bool,
        pending_witness_scripts: &HashMap<String, bool>,
    ) -> Result<(), Error> {
        let db_txos = txn.iter_txos()?;

        let db_outpoints: HashSet<String> = db_txos
            .into_iter()
            .filter(|t| t.exists && (include_spent || !t.spent))
            .map(|u| u.outpoint().to_string())
            .collect();

        let iter: Box<dyn Iterator<Item = LocalOutput>> = if include_spent {
            Box::new(self.bdk_wallet().list_output())
        } else {
            Box::new(self.bdk_wallet().list_unspent())
        };

        for new_utxo in iter
            .filter(|u| u.keychain == KeychainKind::External)
            .filter(|u| !db_outpoints.contains(&u.outpoint.to_string()))
        {
            let mut new_db_utxo: DbTxoActMod = new_utxo.clone().into();
            let script = new_utxo.txout.script_pubkey.to_hex_string();
            if let Some(receive_pending) = pending_witness_scripts.get(&script) {
                new_db_utxo.pending_witness = ActiveValue::Set(*receive_pending);
                txn.del_pending_witness_script(script)?;
            }
            txn.set_txo(new_db_utxo.clone())?;
        }

        Ok(())
    }

    #[cfg(feature = "_online")]
    fn sync_wallet(
        &mut self,
        txn: &DbTxn,
        options: SyncOptions,
        include_spent: bool,
    ) -> Result<(), Error> {
        self.sync_bdk_and_db_txos(txn, options, include_spent)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod wasm_snapshot_tests {
    use super::*;
    use crate::keys::generate_keys;

    fn test_manifest() -> (WalletManifest, String) {
        let network = BitcoinNetwork::Regtest;
        let keys = generate_keys(network, WitnessVersion::Taproot);
        let wallet_data = WalletData {
            data_dir: String::new(),
            bitcoin_network: network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: 5,
            supported_schemas: AssetSchema::VALUES.to_vec(),
        };
        let manifest = WalletManifest::new(&wallet_data, &SinglesigKeys::from_keys(&keys, None));
        (manifest, keys.mnemonic)
    }

    fn envelope(manifest: &WalletManifest) -> Vec<u8> {
        encode_wasm_snapshot(manifest, b"the memory-backend snapshot").unwrap()
    }

    fn assert_internal(result: Result<impl std::fmt::Debug, Error>, needle: &str) {
        match result {
            Err(Error::Internal { details }) => assert!(
                details.contains(needle),
                "unexpected error details: {details}"
            ),
            other => panic!("expected Error::Internal, got {other:?}"),
        }
    }

    #[test]
    fn envelope_round_trip() {
        let (manifest, mnemonic) = test_manifest();
        let bytes = envelope(&manifest);

        assert_eq!(&bytes[..WASM_SNAPSHOT_MAGIC.len()], WASM_SNAPSHOT_MAGIC);
        assert_eq!(bytes[WASM_SNAPSHOT_MAGIC.len()], WASM_SNAPSHOT_VERSION);
        // the envelope carries no secret
        assert!(
            !bytes
                .windows(mnemonic.len())
                .any(|window| window == mnemonic.as_bytes())
        );

        let (decoded, db_snapshot) = decode_wasm_snapshot(&bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            serde_json::to_vec(&manifest).unwrap()
        );
        assert_eq!(db_snapshot, b"the memory-backend snapshot");
    }

    #[test]
    fn envelope_rejects_short_header() {
        let (manifest, _) = test_manifest();
        let bytes = envelope(&manifest);
        assert_internal(
            decode_wasm_snapshot(&bytes[..WASM_SNAPSHOT_HEADER_LEN - 1]),
            "shorter than its envelope header",
        );
    }

    #[test]
    fn envelope_rejects_bad_magic() {
        let (manifest, _) = test_manifest();
        let mut bytes = envelope(&manifest);
        // the old raw database snapshot starts with a version byte, not the envelope magic
        bytes[0] = 1;
        assert_internal(decode_wasm_snapshot(&bytes), "envelope magic");
    }

    #[test]
    fn envelope_rejects_bad_version() {
        let (manifest, _) = test_manifest();
        let mut bytes = envelope(&manifest);
        bytes[WASM_SNAPSHOT_MAGIC.len()] = WASM_SNAPSHOT_VERSION + 1;
        assert_internal(decode_wasm_snapshot(&bytes), "envelope version");
    }

    #[test]
    fn envelope_rejects_length_overflow() {
        let (manifest, _) = test_manifest();
        let mut bytes = envelope(&manifest);
        let len_start = WASM_SNAPSHOT_MAGIC.len() + 1;
        bytes[len_start..len_start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_internal(decode_wasm_snapshot(&bytes), "manifest length");
    }

    #[test]
    fn envelope_rejects_invalid_json() {
        let (manifest, _) = test_manifest();
        let mut bytes = envelope(&manifest);
        bytes[WASM_SNAPSHOT_HEADER_LEN] = 0xff;
        assert_internal(decode_wasm_snapshot(&bytes), "snapshot manifest");
    }

    #[test]
    fn envelope_rejects_truncated_body() {
        let (manifest, _) = test_manifest();
        let bytes = envelope(&manifest);
        let len_start = WASM_SNAPSHOT_MAGIC.len() + 1;
        let json_len = u32::from_le_bytes(
            bytes[len_start..len_start + 4]
                .try_into()
                .expect("four length bytes"),
        ) as usize;
        let without_body = &bytes[..WASM_SNAPSHOT_HEADER_LEN + json_len];
        assert_internal(
            decode_wasm_snapshot(without_body),
            "no database snapshot body",
        );
    }
}
