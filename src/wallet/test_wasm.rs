//! Browser wallet lifecycle over IndexedDB.
//!
//! Runs under `wasm-bindgen-test` in a real browser (see the `wasm_browser_lifecycle` job). It
//! builds a wallet over the in-memory backend, issues an asset offline, flushes it through the
//! wallet twice, rebuilds the wallet from the loaded bytes and checks the newest state survived. It
//! also covers the browser blob adapter: media/consignment-shaped files written through the wallet
//! travel in the snapshot and come back on restore, overwrites keep the last bytes, the namespace
//! rejects traversal keys, a pre-browser v2 snapshot restores with an empty adapter and multisig
//! wallets carry their files too. No indexer or network access is involved.
//!
//! `bdk_pending.json` is deliberately not exercised here: on wasm, `setup_bdk` skips the
//! crash-recovery files because the database is the in-memory backend, so a commit and the
//! snapshot flush are the only persistence steps and there is no window in which the changeset
//! exists only on disk.
//!
//! The test lives inside the crate, so it compiles against the public API the way a host would use
//! it: the wallet flush entry point and the persistence functions.

use wasm_bindgen::JsValue;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

use super::*;
use crate::wallet::persistence::{
    InjectedFailure, delete_snapshot, load_snapshot, save_snapshot, set_injected_failure,
};
use crate::{
    Error,
    database::entities::txo::ActiveModel as DbTxoActMod,
    keys::generate_keys,
    wallet::{core::WalletCore, offline::RgbWalletOpsOffline},
};
use sea_orm::ActiveValue;

wasm_bindgen_test_configure!(run_in_browser);

const WALLET_ID: &str = "lifecycle-test";
const MAX_ALLOCATIONS_PER_UTXO: u32 = 5;

fn wallet_data() -> WalletData {
    WalletData {
        // wasm wallet construction ignores the filesystem
        data_dir: String::new(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
        supported_schemas: AssetSchema::VALUES.to_vec(),
    }
}

#[wasm_bindgen_test]
async fn wallet_lifecycle_over_indexed_db() {
    // start from a known state: the browser profile may already hold a snapshot
    delete_snapshot(WALLET_ID).await.unwrap();
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());

    let wallet_data = wallet_data();
    let keys = generate_keys(wallet_data.bitcoin_network, WitnessVersion::Taproot);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);

    let mut wallet = Wallet::new_with_database(
        wallet_data.clone(),
        wallet_keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .expect("wallet construction over the in-memory backend");
    assert_eq!(
        wallet.get_wallet_data().bitcoin_network,
        wallet_data.bitcoin_network
    );

    // the offline issuer needs one unspent colored TXO; no indexer takes part
    wallet
        .database()
        .memory_backend()
        .expect("the wallet runs over the memory backend")
        .db
        .set_txo(DbTxoActMod {
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

    let asset = wallet
        .issue_asset_nia("TICKER".to_string(), "NAME".to_string(), 0, vec![100])
        .expect("offline asset issuance");
    let fingerprint = wallet.get_keys().master_fingerprint.clone();

    // issuance writes the validated consignment through the browser adapter under the native key
    let consignment_key = WalletPath::new(&format!("{ASSETS_DIR}/{}", asset.asset_id)).unwrap();
    let issued_consignment = wallet.files().read(&consignment_key).unwrap();
    assert_eq!(&issued_consignment[..7], b"RGB\0VCO");

    let snapshot = wallet
        .snapshot()
        .unwrap()
        .expect("the memory wallet snapshots");
    assert!(!snapshot.is_empty());
    // the snapshot carries the wallet state, never the mnemonic
    let mnemonic = keys.mnemonic.as_bytes();
    assert!(
        !snapshot
            .windows(mnemonic.len())
            .any(|window| window == mnemonic)
    );

    // flush through the wallet, then read back what IndexedDB stored
    wallet.flush(WALLET_ID).await.unwrap();
    let stored = load_snapshot(WALLET_ID).await.unwrap();
    assert_eq!(stored.as_deref(), Some(snapshot.as_slice()));

    // a second flush must persist the newer state: derive two addresses, flush, then derive one
    // more that the restored wallet has to hand out next
    let _ = wallet.get_address().unwrap();
    let _ = wallet.get_address().unwrap();
    wallet.flush(WALLET_ID).await.unwrap();
    let next_address = wallet.get_address().unwrap();
    drop(wallet);

    // rebuild the wallet from the stored bytes alone
    let loaded = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the snapshot saved above");
    let mut restored = Wallet::from_snapshot(&loaded, wallet_data.clone(), wallet_keys.clone())
        .expect("wallet restore");
    assert_eq!(restored.get_keys().master_fingerprint, fingerprint);
    assert_eq!(
        restored.get_wallet_data().bitcoin_network,
        wallet_data.bitcoin_network
    );
    let assets = restored.list_assets(vec![]).unwrap();
    assert!(
        assets
            .nia
            .unwrap_or_default()
            .iter()
            .any(|a| a.asset_id == asset.asset_id),
        "the asset issued before the snapshot is missing after the restore"
    );
    assert_eq!(
        restored.files().read(&consignment_key).unwrap(),
        issued_consignment,
        "the issued consignment did not come back byte for byte"
    );
    assert_eq!(
        restored.get_address().unwrap(),
        next_address,
        "the second flush did not persist the newest state"
    );

    // a restore with settings the snapshot was not created with is rejected: the manifest travels
    // in the envelope and is validated before the database is rebuilt
    let mut changed_data = wallet_data.clone();
    changed_data.max_allocations_per_utxo += 1;
    let err = Wallet::from_snapshot(&loaded, changed_data, wallet_keys.clone())
        .err()
        .expect("a changed setting must be rejected");
    assert!(matches!(err, Error::WalletSettingMismatch { .. }));
    let mut changed_data = wallet_data.clone();
    changed_data.supported_schemas = vec![AssetSchema::Nia];
    let err = Wallet::from_snapshot(&loaded, changed_data, wallet_keys)
        .err()
        .expect("a changed setting must be rejected");
    assert!(matches!(err, Error::WalletSettingMismatch { .. }));

    delete_snapshot(WALLET_ID).await.unwrap();
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());
}

fn singlesig_keys() -> SinglesigKeys {
    let wallet_data = wallet_data();
    SinglesigKeys::from_keys(
        &generate_keys(wallet_data.bitcoin_network, WitnessVersion::Taproot),
        None,
    )
}

fn memory_wallet() -> (Wallet, SinglesigKeys) {
    let keys = singlesig_keys();
    let wallet = Wallet::new_with_database(
        wallet_data(),
        keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .expect("wallet construction over the in-memory backend");
    (wallet, keys)
}

/// Turn a snapshot write into a JS promise so two writes can be in flight at once.
fn save_promise(wallet_id: &str, bytes: Vec<u8>) -> js_sys::Promise {
    let wallet_id = wallet_id.to_string();
    wasm_bindgen_futures::future_to_promise(async move {
        save_snapshot(&wallet_id, &bytes)
            .await
            .map(|()| JsValue::UNDEFINED)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    })
}

#[wasm_bindgen_test]
async fn indexeddb_unavailable() {
    const WALLET_ID: &str = "unavailable-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    set_injected_failure(Some(InjectedFailure::Unavailable));
    let saved = save_snapshot(WALLET_ID, b"snapshot").await;
    let loaded = load_snapshot(WALLET_ID).await;
    let deleted = delete_snapshot(WALLET_ID).await;
    set_injected_failure(None);

    assert!(matches!(saved, Err(Error::Internal { .. })));
    assert!(matches!(loaded, Err(Error::Internal { .. })));
    assert!(matches!(deleted, Err(Error::Internal { .. })));
    // the failure happened before any transaction, so nothing was written
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());
}

#[wasm_bindgen_test]
async fn write_failure_keeps_previous_snapshot() {
    const WALLET_ID: &str = "write-failure-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let first = b"first committed snapshot".to_vec();
    save_snapshot(WALLET_ID, &first).await.unwrap();

    set_injected_failure(Some(InjectedFailure::WriteFailed));
    let result = save_snapshot(WALLET_ID, b"second snapshot").await;
    set_injected_failure(None);

    assert!(matches!(result, Err(Error::Internal { .. })));
    // the aborted transaction rolled back, so the committed snapshot is unchanged
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(first.as_slice())
    );
    delete_snapshot(WALLET_ID).await.unwrap();
}

#[wasm_bindgen_test]
async fn interrupted_write_keeps_previous_snapshot() {
    const WALLET_ID: &str = "interrupted-write-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let (mut wallet, _keys) = memory_wallet();
    let first = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    wallet.flush(WALLET_ID).await.unwrap();
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(first.as_slice())
    );

    // a newer in-memory state that must not replace the committed snapshot when the write aborts
    let _ = wallet.get_address().unwrap();
    set_injected_failure(Some(InjectedFailure::AbortBeforeCommit));
    let result = wallet.flush(WALLET_ID).await;
    set_injected_failure(None);

    assert!(matches!(result, Err(Error::Internal { .. })));
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(first.as_slice())
    );
    // the wallet stays usable: a retry commits the newer state
    wallet.flush(WALLET_ID).await.unwrap();
    let latest = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(latest.as_slice())
    );
    delete_snapshot(WALLET_ID).await.unwrap();
}

#[wasm_bindgen_test]
async fn malformed_snapshot_fails_restore() {
    const WALLET_ID: &str = "malformed-snapshot-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let garbage = b"not an rgb-lib wallet snapshot".to_vec();
    save_snapshot(WALLET_ID, &garbage).await.unwrap();
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(garbage.as_slice())
    );

    let error = Wallet::from_snapshot(&garbage, wallet_data(), singlesig_keys())
        .err()
        .expect("a malformed snapshot must not produce a wallet");
    assert!(matches!(&error, Error::Internal { .. }));
    assert!(error.to_string().contains("envelope"));

    // the stored value is untouched, so the host can inspect or overwrite it
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(garbage.as_slice())
    );
    delete_snapshot(WALLET_ID).await.unwrap();
}

#[wasm_bindgen_test]
async fn stale_snapshot_version_fails_restore() {
    const WALLET_ID: &str = "stale-version-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    // envelope header: 5-byte magic, one version byte, then a little-endian manifest length
    let mut stale = b"RGBWL".to_vec();
    stale.push(1);
    stale.extend_from_slice(&0u32.to_le_bytes());
    stale.extend_from_slice(b"body");
    save_snapshot(WALLET_ID, &stale).await.unwrap();

    let error = Wallet::from_snapshot(&stale, wallet_data(), singlesig_keys())
        .err()
        .expect("a stale envelope version must not produce a wallet");
    assert!(matches!(&error, Error::Internal { .. }));
    assert!(error.to_string().contains("version"));

    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(stale.as_slice())
    );
    delete_snapshot(WALLET_ID).await.unwrap();
}

#[wasm_bindgen_test]
async fn concurrent_flush_last_write_wins() {
    const WALLET_ID: &str = "concurrent-flush-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    // two snapshots of the same wallet, taken before and after deriving an address
    let (mut wallet, keys) = memory_wallet();
    let first = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    let _ = wallet.get_address().unwrap();
    let second = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    assert_ne!(first, second);

    // both writes are in flight together: IndexedDB serializes their read-write transactions on
    // the single `snapshots` store, so both commit and the last one wins
    let both = js_sys::Promise::all(&js_sys::Array::of2(
        &save_promise(WALLET_ID, first.clone()),
        &save_promise(WALLET_ID, second.clone()),
    ));
    wasm_bindgen_futures::JsFuture::from(both)
        .await
        .expect("both concurrent writes commit");

    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the concurrent write");
    assert!(
        stored == first || stored == second,
        "the store holds one whole snapshot, never a mix of the two writes"
    );
    // whichever write won, the stored bytes still rebuild the wallet
    Wallet::from_snapshot(&stored, wallet_data(), keys).expect("wallet restore");

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// A media blob key, the shape the wallet uses for stored media files.
fn media_key(digest: &str) -> WalletPath {
    WalletPath::from_segments(&["media_files", digest]).unwrap()
}

#[wasm_bindgen_test]
async fn browser_files_survive_flush_and_restore() {
    const WALLET_ID: &str = "browser-files-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let (wallet, keys) = memory_wallet();

    // a media blob written through the wallet adapter: on wasm it lands in the in-memory adapter
    let media = media_key("abc123");
    let media_bytes = b"\x00media blob\xff".to_vec();
    wallet.files().atomic_write(&media, &media_bytes).unwrap();
    // a consignment-shaped blob in a nested transfer directory, directories included
    let transfer = WalletPath::new("transfers/deadbeef/consignment_out").unwrap();
    wallet
        .files()
        .create_dir_all(&WalletPath::new("transfers/deadbeef").unwrap())
        .unwrap();
    wallet
        .files()
        .atomic_write(&transfer, b"consignment")
        .unwrap();
    assert!(wallet.files().exists(&media).unwrap());

    wallet.flush(WALLET_ID).await.unwrap();
    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the flushed snapshot");
    drop(wallet);

    // the files travel in the snapshot and are in the adapter before the wallet is handed back
    let restored = Wallet::from_snapshot(&stored, wallet_data(), keys.clone()).expect("restore");
    assert_eq!(restored.files().read(&media).unwrap(), media_bytes);
    assert!(restored.files().exists(&media).unwrap());
    assert_eq!(restored.files().read(&transfer).unwrap(), b"consignment");
    assert!(
        restored
            .files()
            .exists(&WalletPath::new("transfers/deadbeef").unwrap())
            .unwrap(),
        "the logical directory came back with the file"
    );
    assert_eq!(
        restored
            .files()
            .list(&WalletPath::new("transfers").unwrap())
            .unwrap(),
        vec![transfer]
    );

    // the restored wallet persists the files again, keeping the last bytes written
    restored.files().atomic_write(&media, b"second").unwrap();
    restored.flush(WALLET_ID).await.unwrap();
    let reloaded = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the second flush");
    let restored = Wallet::from_snapshot(&reloaded, wallet_data(), keys).expect("second restore");
    assert_eq!(restored.files().read(&media).unwrap(), b"second");

    delete_snapshot(WALLET_ID).await.unwrap();
}

#[wasm_bindgen_test]
fn adapter_rejects_traversal_keys() {
    let (wallet, _keys) = memory_wallet();
    for key in [
        "",
        ".",
        "..",
        "/absolute",
        "../escape",
        "a/../../b",
        "a\\b",
        "a\0b",
        "a:b",
        "C:/wallet",
    ] {
        assert!(
            WalletPath::new(key).is_err(),
            "expected {key:?} to be rejected"
        );
    }

    // the only keys the adapter can hold are wallet-relative ones
    let media = media_key("abc");
    wallet.files().atomic_write(&media, b"media").unwrap();
    assert_eq!(
        wallet
            .files()
            .list(&WalletPath::new("media_files").unwrap())
            .unwrap(),
        vec![media]
    );
}

#[wasm_bindgen_test]
fn adapter_overwrite_keeps_only_the_last_bytes() {
    let (wallet, _keys) = memory_wallet();
    let media = media_key("abc");
    wallet.files().write(&media, b"first").unwrap();
    wallet.files().atomic_write(&media, b"second").unwrap();
    assert_eq!(wallet.files().read(&media).unwrap(), b"second");
    // no temporary file and no stale key: the browser writes in place, the flush is the atomic unit
    assert_eq!(
        wallet
            .files()
            .list(&WalletPath::new("media_files").unwrap())
            .unwrap(),
        vec![media.clone()]
    );
    assert!(
        !wallet
            .files()
            .exists(&WalletPath::new("media_files/.abc.tmp").unwrap())
            .unwrap()
    );
}

#[wasm_bindgen_test]
async fn v2_snapshot_restores_with_an_empty_adapter() {
    const WALLET_ID: &str = "v2-snapshot-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let (wallet, keys) = memory_wallet();
    let media = media_key("abc");
    wallet.files().atomic_write(&media, b"media").unwrap();

    let current = wallet.snapshot().unwrap().expect("the wallet snapshot");
    let (manifest, _, db_snapshot) =
        crate::wallet::core::decode_wasm_snapshot(&current).expect("decode the current snapshot");
    let manifest = manifest.expect("a singlesig snapshot carries the manifest");
    // rebuild the pre-browser v2 envelope: it has no files section at all
    let json = serde_json::to_vec(&manifest).unwrap();
    let mut v2 = b"RGBWL".to_vec();
    v2.push(2);
    v2.extend_from_slice(&(json.len() as u32).to_le_bytes());
    v2.extend_from_slice(&json);
    v2.extend_from_slice(&db_snapshot);
    save_snapshot(WALLET_ID, &v2).await.unwrap();

    let restored = Wallet::from_snapshot(&v2, wallet_data(), keys).expect("v2 restore");
    assert!(
        !restored.files().exists(&media).unwrap(),
        "an old snapshot has no browser files"
    );
    assert!(
        restored
            .files()
            .list(&WalletPath::new("media_files").unwrap())
            .unwrap()
            .is_empty()
    );

    delete_snapshot(WALLET_ID).await.unwrap();
}

fn multisig_keys() -> MultisigKeys {
    let keys_1 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let keys_2 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    MultisigKeys::new(
        vec![
            Cosigner::from_keys(&keys_1, None),
            Cosigner::from_keys(&keys_2, None),
        ],
        2,
        2,
    )
}

#[wasm_bindgen_test]
async fn multisig_browser_files_survive_restore() {
    const WALLET_ID: &str = "multisig-files-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    let keys = multisig_keys();
    let wallet = MultisigWallet::new_with_database(
        wallet_data(),
        keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .expect("multisig construction over the in-memory backend");

    let media = media_key("abc");
    wallet
        .files()
        .atomic_write(&media, b"multisig media")
        .unwrap();
    wallet.flush(WALLET_ID).await.unwrap();
    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the flushed multisig snapshot");
    drop(wallet);

    let restored = MultisigWallet::from_snapshot(&stored, wallet_data(), keys).expect("restore");
    assert_eq!(restored.files().read(&media).unwrap(), b"multisig media");

    delete_snapshot(WALLET_ID).await.unwrap();
}
