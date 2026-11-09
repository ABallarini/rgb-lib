//! The wallet routes its file operations through its adapter.

use super::*;

#[cfg(feature = "_online")]
use crate::database::entities::txo::ActiveModel as DbTxoActMod;
use crate::wallet::files::NativeFiles;
#[cfg(feature = "_online")]
use sea_orm::ActiveValue;

/// A delegating adapter that records every key it is asked to write.
///
/// Used to prove that a real wallet operation reaches the wallet's own adapter, rather than
/// going to the filesystem behind its back.
struct RecordingFiles {
    inner: NativeFiles,
    written: Mutex<Vec<String>>,
}

impl RecordingFiles {
    fn new(root: &Path) -> Self {
        Self {
            inner: NativeFiles::new(root),
            written: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, key: &WalletPath) {
        self.written.lock().unwrap().push(key.to_string());
    }
}

impl WalletFiles for RecordingFiles {
    fn read(&self, path: &WalletPath) -> Result<Vec<u8>, Error> {
        self.inner.read(path)
    }

    fn write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        self.record(path);
        self.inner.write(path, bytes)
    }

    fn atomic_write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        self.record(path);
        self.inner.atomic_write(path, bytes)
    }

    fn exists(&self, path: &WalletPath) -> Result<bool, Error> {
        self.inner.exists(path)
    }

    fn remove(&self, path: &WalletPath) -> Result<(), Error> {
        self.inner.remove(path)
    }

    fn list(&self, dir: &WalletPath) -> Result<Vec<WalletPath>, Error> {
        self.inner.list(dir)
    }

    fn create_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        self.inner.create_dir_all(dir)
    }

    fn remove_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        self.inner.remove_dir_all(dir)
    }

    fn rename(&self, from: &WalletPath, to: &WalletPath) -> Result<(), Error> {
        self.inner.rename(from, to)
    }
}

fn new_test_wallet(data_dir: &Path) -> Wallet {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let wallet_data = WalletData {
        data_dir: data_dir.to_string_lossy().to_string(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 1,
        supported_schemas: AssetSchema::VALUES.to_vec(),
    };
    Wallet::new(wallet_data, SinglesigKeys::from_keys(&keys, Some(2))).unwrap()
}

/// The wallet writes its manifest through the adapter, to the same bytes and the same path as
/// before, leaving no temporary sibling behind.
#[test]
#[parallel]
fn manifest_is_written_through_the_adapter() {
    let data_dir = tempfile::tempdir().unwrap();
    let wallet = new_test_wallet(data_dir.path());
    let wallet_dir = wallet.get_wallet_dir();

    let manifest_path = wallet_dir.join(WALLET_MANIFEST_FILE);
    let manifest_key = WalletPath::from_segments(&[WALLET_MANIFEST_FILE]).unwrap();
    // the adapter resolves the key to exactly the wallet directory: reading it through the wallet
    // gives the bytes on disk
    let through_adapter = wallet.files().read(&manifest_key).unwrap();
    assert_eq!(through_adapter, fs::read(&manifest_path).unwrap());

    // the bytes are those of the pretty-printed manifest, and no temp sibling was left behind
    let manifest = WalletManifest::read(&*wallet.files(), &wallet_dir).unwrap();
    assert_eq!(
        through_adapter,
        serde_json::to_string_pretty(&manifest).unwrap().as_bytes()
    );
    assert!(!wallet_dir.join(".wallet_manifest.json.tmp").exists());

    // the on-disk JSON shape and format version are pinned: the same field names, in the same
    // order, with version 1. Existing wallet directories must stay readable.
    let text = String::from_utf8(through_adapter).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["version"], Value::from(WALLET_MANIFEST_VERSION));
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "version",
            "bitcoin_network",
            "database_type",
            "max_allocations_per_utxo",
            "supported_schemas",
            "account_xpub_vanilla",
            "account_xpub_colored",
            "vanilla_keychain",
            "master_fingerprint",
            "witness_version",
        ]
    );

    // the directory layout a backup walks is unchanged
    assert!(manifest_path.is_file());
    assert!(wallet_dir.join(ASSETS_DIR).is_dir());
    assert!(wallet_dir.join(MEDIA_DIR).is_dir());
}

/// A real BDK crash-recovery write goes through the wallet's adapter, to `bdk_pending.json`, with
/// the exact bytes and no temporary sibling left behind.
#[test]
#[parallel]
fn bdk_pending_is_written_through_the_adapter() {
    let data_dir = tempfile::tempdir().unwrap();
    let mut wallet = new_test_wallet(data_dir.path());
    let wallet_dir = wallet.get_wallet_dir();

    // swap in a recording adapter rooted at the wallet directory, as the constructor built it
    let recorder = Arc::new(RecordingFiles::new(&wallet_dir));
    wallet.internals_mut().files = recorder.clone();

    // stage a change and flush it to the crash-recovery file
    wallet
        .bdk_wallet_mut()
        .reveal_next_address(KeychainKind::External);
    wallet.flush_bdk_pending().unwrap();

    assert_eq!(
        *recorder.written.lock().unwrap(),
        vec![BDK_PENDING_FILE.to_string()]
    );

    let pending_path = wallet_dir.join(BDK_PENDING_FILE);
    let expected = serde_json::to_vec(&*wallet.internals().bdk_pending.lock().unwrap()).unwrap();
    assert_eq!(fs::read(&pending_path).unwrap(), expected);
    assert_eq!(
        wallet
            .files()
            .read(&WalletPath::from_segments(&[BDK_PENDING_FILE]).unwrap())
            .unwrap(),
        expected
    );
    assert!(!wallet_dir.join(format!(".{BDK_PENDING_FILE}.tmp")).exists());
}

/// The media and transfer layout the adapter addresses is the one the wallet already had.
#[test]
#[parallel]
fn media_and_transfer_layout_is_unchanged() {
    let data_dir = tempfile::tempdir().unwrap();
    let wallet = new_test_wallet(data_dir.path());
    let wallet_dir = wallet.get_wallet_dir();

    // media: the host file is copied to `media_files/<digest>`, byte for byte
    let host_dir = tempfile::tempdir().unwrap();
    let host_file = host_dir.path().join("attachment.txt");
    let bytes = b"media payload";
    fs::write(&host_file, bytes).unwrap();
    let digest = hex::encode(hash_bytes(bytes));
    let media = Media {
        file_path: wallet
            .get_media_dir()
            .join(&digest)
            .to_string_lossy()
            .to_string(),
        digest: digest.clone(),
        mime: "text/plain".to_string(),
    };
    wallet.copy_media_file(&host_file, &media).unwrap();
    let media_key = WalletPath::from_segments(&[MEDIA_DIR, &digest]).unwrap();
    assert_eq!(media_key.as_str(), format!("media_files/{digest}"));
    assert_eq!(wallet.files().read(&media_key).unwrap(), bytes);
    let media_path = wallet_dir.join(MEDIA_DIR).join(&digest);
    assert_eq!(fs::read(&media_path).unwrap(), bytes);
    assert_eq!(
        wallet
            .files()
            .list(&WalletPath::from_segments(&[MEDIA_DIR]).unwrap())
            .unwrap(),
        vec![media_key.clone()]
    );
    assert!(
        !wallet_dir
            .join(MEDIA_DIR)
            .join(format!(".{digest}.tmp"))
            .exists()
    );

    // transfers: the key layout is `transfers/<txid>/<file>`, and the bytes read back unchanged
    let txid = "a".repeat(64);
    let transfer_key = wallet.transfer_key(&txid).unwrap();
    wallet.files().create_dir_all(&transfer_key).unwrap();
    let data_key = transfer_key.join(TRANSFER_DATA_FILE).unwrap();
    assert_eq!(
        data_key.as_str(),
        format!("transfers/{txid}/{TRANSFER_DATA_FILE}")
    );
    wallet.files().atomic_write(&data_key, b"{}").unwrap();
    assert_eq!(wallet.files().read(&data_key).unwrap(), b"{}");
    let transfer_data = wallet_dir
        .join(TRANSFERS_DIR)
        .join(&txid)
        .join(TRANSFER_DATA_FILE);
    assert_eq!(fs::read(&transfer_data).unwrap(), b"{}");
    assert!(
        !wallet_dir
            .join(TRANSFERS_DIR)
            .join(&txid)
            .join(format!(".{TRANSFER_DATA_FILE}.tmp"))
            .exists()
    );
}

/// The media deduplication gate and the cleanup sweep address exactly the digest-named keys.
///
/// The receive path skips a blob whose key already exists and removes the keys it saved when the
/// transfer is refused; both are expressed as adapter operations on `media_files/<digest>`.
#[test]
#[parallel]
fn media_dedup_and_cleanup_use_the_digest_keys() {
    let data_dir = tempfile::tempdir().unwrap();
    let wallet = new_test_wallet(data_dir.path());
    let media_dir = WalletPath::from_segments(&[MEDIA_DIR]).unwrap();

    let first = WalletPath::from_segments(&[MEDIA_DIR, "first"]).unwrap();
    let second = WalletPath::from_segments(&[MEDIA_DIR, "second"]).unwrap();
    wallet.files().atomic_write(&first, b"blob").unwrap();

    // the receive path checks this before it writes, so an existing digest is not rewritten
    assert!(wallet.files().exists(&first).unwrap());

    wallet.files().atomic_write(&second, b"other").unwrap();
    let mut keys = wallet.files().list(&media_dir).unwrap();
    keys.sort();
    assert_eq!(keys, vec![first.clone(), second.clone()]);

    // refusing a receive removes exactly the keys it saved
    for key in &keys {
        wallet.files().remove(key).unwrap();
    }
    assert!(wallet.files().list(&media_dir).unwrap().is_empty());
}

/// The multisig hub cache is created, listed, read and removed by its `hub_ops/<file_id>` keys.
#[test]
#[parallel]
fn hub_ops_cache_uses_wallet_keys() {
    let data_dir = tempfile::tempdir().unwrap();
    let wallet = new_test_wallet(data_dir.path());
    let ops = WalletPath::from_segments(&["hub_ops"]).unwrap();
    wallet.files().create_dir_all(&ops).unwrap();
    assert!(wallet.files().exists(&ops).unwrap());

    let first = ops.join("file-one").unwrap();
    let second = ops.join("file-two").unwrap();
    assert_eq!(first.as_str(), "hub_ops/file-one");
    wallet.files().atomic_write(&first, b"one").unwrap();
    wallet.files().atomic_write(&second, b"two").unwrap();
    assert_eq!(
        wallet.files().list(&ops).unwrap(),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(wallet.files().read(&first).unwrap(), b"one");

    // an approved operation sweeps every cached file
    for key in wallet.files().list(&ops).unwrap() {
        wallet.files().remove(&key).unwrap();
    }
    assert!(wallet.files().list(&ops).unwrap().is_empty());
}

/// A multisig wallet creates its hub ops cache through the adapter, in the same directory.
#[test]
#[parallel]
fn multisig_hub_ops_layout_is_unchanged() {
    let data_dir = tempfile::tempdir().unwrap();
    let cosigner = || {
        let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
        Cosigner::from_str(&format!(
            "{}:{}:{}:0",
            keys.master_fingerprint, keys.account_xpub_vanilla, keys.account_xpub_colored
        ))
        .unwrap()
    };
    let wallet_data = WalletData {
        data_dir: data_dir.path().to_string_lossy().to_string(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 1,
        supported_schemas: AssetSchema::VALUES.to_vec(),
    };
    let wallet = MultisigWallet::new(
        wallet_data,
        MultisigKeys::new(vec![cosigner(), cosigner()], 2, 2),
    )
    .unwrap();
    assert!(wallet.get_wallet_dir().join("hub_ops").is_dir());
}

/// Offline issuance writes the validated consignment to `assets/<asset id>` through the adapter,
/// with the exact bytes rgb-ops writes and the asset id untouched.
#[test]
#[cfg(feature = "_online")]
#[parallel]
fn issued_contract_consignment_is_written_through_the_adapter() {
    let data_dir = tempfile::tempdir().unwrap();
    let mut wallet = new_test_wallet(data_dir.path());
    let wallet_dir = wallet.get_wallet_dir();

    // the offline issuer needs one unspent colored TXO; no indexer takes part
    let txn = wallet.database().begin_transaction().unwrap();
    txn.set_txo(DbTxoActMod {
        idx: ActiveValue::NotSet,
        txid: ActiveValue::Set(
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        ),
        vout: ActiveValue::Set(0),
        btc_amount: ActiveValue::Set("1000".to_string()),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(true),
        pending_witness: ActiveValue::Set(false),
    })
    .unwrap();
    txn.commit().unwrap();

    let asset = wallet
        .issue_asset_nia("TICKER".to_string(), "NAME".to_string(), 0, vec![100])
        .unwrap();
    let asset_id = asset.asset_id.clone();
    assert!(
        asset_id.starts_with("rgb:"),
        "the id keeps its scheme prefix"
    );

    // same relative key as before the refactor: `assets/` plus the full asset id
    let key = WalletPath::new(&format!("{ASSETS_DIR}/{asset_id}")).unwrap();
    assert_eq!(key.as_str(), format!("assets/{asset_id}"));
    let bytes = wallet.files().read(&key).unwrap();
    let path = wallet_dir.join(ASSETS_DIR).join(&asset_id);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(
        !wallet_dir
            .join(ASSETS_DIR)
            .join(format!(".{asset_id}.tmp"))
            .exists()
    );

    // the adapter bytes are exactly the validated-consignment bytes `save_file` writes
    let loaded = ValidContract::load_file(&path).unwrap();
    assert_eq!(loaded.contract_id().to_string(), asset_id);
    assert_eq!(contract_file_bytes(&loaded).unwrap(), bytes);
}
