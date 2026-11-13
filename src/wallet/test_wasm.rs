//! Browser wallet lifecycle over IndexedDB.
//!
//! Runs under `wasm-bindgen-test` in a real browser (see the `wasm_browser_lifecycle` job). It
//! builds a wallet over the in-memory backend, issues an asset offline, flushes it through the
//! wallet twice, rebuilds the wallet from the loaded bytes and checks the newest state survived. It
//! also covers watch-only and multisig lifecycle round trips: watched keys derive and persist
//! addresses without a mnemonic, and a multisig wallet keeps its descriptors and database state
//! across a hub-free flush/restore. It also covers the browser blob adapter: media/consignment-shaped
//! files written through the wallet travel in the snapshot and come back on restore, overwrites keep
//! the last bytes, the namespace
//! rejects traversal keys, a pre-browser v2 snapshot restores with an empty adapter and multisig
//! wallets carry their files too. No indexer or network access is involved.
//!
//! The native-only legacy paths are pinned too: a plain load leaves `rgb/` untouched, a legacy
//! RGB store that somehow reaches the adapter is an explicit error, the filesystem backup entry
//! points still require a path, and the byte backup/restore/info path works without a filesystem.
//! The legacy BDK file store is a path-based native store, so its import is compile-time absent
//! here rather than a runtime error; the multisig hub download cache needs a real path too and
//! lives behind the native-only online features.
//!
//! `bdk_pending.json` is deliberately not exercised here: on wasm, `setup_bdk` skips the
//! crash-recovery files because the database is the in-memory backend, so a commit and the
//! snapshot flush are the only persistence steps and there is no window in which the changeset
//! exists only on disk.
//!
//! The test lives inside the crate, so it compiles against the public API the way a host would use
//! it: the wallet flush entry point and the persistence functions.

use slog::{debug, info};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

#[cfg(feature = "esplora_async")]
use super::receive_wasm::set_fail_after_cache;
use super::*;

/// Build a `Response` whose `url` is absolute. A constructed browser `Response` has an empty URL,
/// which `reqwest`'s wasm client rejects when it parses the response URL.
fn mock_response(body: &str, url: &str) -> JsValue {
    let global = js_sys::global();
    let response = js_sys::Reflect::get(&global, &JsValue::from_str("Response"))
        .unwrap()
        .dyn_into::<js_sys::Function>()
        .unwrap();
    let response =
        js_sys::Reflect::construct(&response, &js_sys::Array::of1(&JsValue::from_str(body)))
            .unwrap();
    let descriptor = js_sys::Object::new();
    js_sys::Reflect::set(
        descriptor.as_ref(),
        &JsValue::from_str("value"),
        &JsValue::from_str(url),
    )
    .unwrap();
    js_sys::Object::define_property(
        response.unchecked_ref::<js_sys::Object>(),
        &JsValue::from_str("url"),
        &descriptor,
    );
    response
}
use crate::wallet::persistence::{
    InjectedFailure, delete_snapshot, load_snapshot, load_snapshot_record, new_writer_id,
    save_snapshot, save_snapshot_record, set_injected_failure,
};
use crate::{
    Error, LoggerGuard,
    database::entities::txo::ActiveModel as DbTxoActMod,
    keys::generate_keys,
    setup_logger,
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
        allow_reckless_schemas: false,
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
    add_unspent_colored_txo(&wallet);

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
    let writer = new_writer_id();
    let mut sequence = wallet.flush(WALLET_ID, &writer, 0).await.unwrap();
    assert_eq!(sequence, 1);
    let stored = load_snapshot(WALLET_ID).await.unwrap();
    assert_eq!(stored.as_deref(), Some(snapshot.as_slice()));

    // a second flush must persist the newer state: derive two addresses, flush, then derive one
    // more that the restored wallet has to hand out next
    let _ = wallet.get_address().unwrap();
    let _ = wallet.get_address().unwrap();
    sequence = wallet.flush(WALLET_ID, &writer, sequence).await.unwrap();
    assert_eq!(sequence, 2);
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

/// A watched key set signs nothing: the wallet derives addresses from the account xpubs and the
/// mnemonic never reaches the snapshot. Generate the keys, restore them from the mnemonic, then
/// drop the mnemonic before construction.
#[wasm_bindgen_test]
async fn watch_only_wallet_lifecycle_over_indexed_db() {
    const WALLET_ID: &str = "watch-only-lifecycle-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());

    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let restored_keys = crate::keys::restore_keys(
        BitcoinNetwork::Regtest,
        keys.mnemonic.clone(),
        WitnessVersion::Taproot,
    )
    .expect("the generated mnemonic restores");
    assert_eq!(restored_keys.master_fingerprint, keys.master_fingerprint);

    let watch_only_keys = SinglesigKeys::from_keys_no_mnemonic(&restored_keys, None);
    assert!(watch_only_keys.mnemonic.is_none());
    let mut wallet = Wallet::new_with_database(
        wallet_data(),
        watch_only_keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .expect("watch-only wallet construction");
    assert!(wallet.get_keys().mnemonic.is_none());

    // the watch-only wallet still hands out addresses; capture the next index without revealing it
    let first = wallet.get_address().unwrap();
    let second = wallet.get_address().unwrap();
    assert_ne!(first, second);
    let index = wallet
        .bdk_wallet()
        .spk_index()
        .last_revealed_index(KeychainKind::Internal)
        .expect("two addresses were revealed");
    let next = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::Internal, index + 1)
        .address
        .to_string();
    let descriptors = wallet.get_descriptors();
    let fingerprint = wallet.get_keys().master_fingerprint.clone();

    wallet.flush(WALLET_ID, &new_writer_id(), 0).await.unwrap();
    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the watch-only snapshot");
    assert!(
        !stored
            .windows(keys.mnemonic.len())
            .any(|window| window == keys.mnemonic.as_bytes()),
        "the watch-only snapshot carries the watched mnemonic"
    );
    drop(wallet);

    let mut restored =
        Wallet::from_snapshot(&stored, wallet_data(), watch_only_keys).expect("watch-only restore");
    assert!(restored.get_keys().mnemonic.is_none());
    assert_eq!(restored.get_keys().master_fingerprint, fingerprint);
    assert_eq!(restored.get_descriptors(), descriptors);
    assert_eq!(
        restored.get_address().unwrap(),
        next,
        "the restored watch-only wallet did not resume at the stored address index"
    );
    assert_eq!(
        restored
            .bdk_wallet()
            .spk_index()
            .last_revealed_index(KeychainKind::Internal),
        Some(index + 1)
    );

    delete_snapshot(WALLET_ID).await.unwrap();
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

/// Give the offline issuer one unspent colored TXO. No indexer takes part.
fn add_unspent_colored_txo(wallet: &impl WalletCore) {
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
}

/// The bookkeeping `sync_async` runs in its transaction: a stale pending-witness TXO and script are
/// reconciled away, and a colored TXO the full scan just found is registered in the DB.
#[cfg(feature = "esplora_async")]
#[wasm_bindgen_test]
fn sync_bookkeeping_reconciles_witness_and_registers_colored_txo() {
    use crate::database::entities::pending_witness_script::ActiveModel as DbPendingWitnessScriptActMod;
    use bdk_wallet::bitcoin::{Amount, TxOut, absolute, transaction};

    let (mut wallet, _keys) = memory_wallet();
    let stale = Outpoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        vout: 1,
    };
    {
        let txn = wallet.database().begin_transaction().unwrap();
        txn.set_txo(DbTxoActMod {
            txid: ActiveValue::Set(stale.txid.clone()),
            vout: ActiveValue::Set(stale.vout),
            btc_amount: ActiveValue::Set("0".to_string()),
            spent: ActiveValue::Set(false),
            exists: ActiveValue::Set(true),
            pending_witness: ActiveValue::Set(true),
            ..Default::default()
        })
        .unwrap();
        txn.set_pending_witness_script(DbPendingWitnessScriptActMod {
            script: ActiveValue::Set("0014000000000000000000000000000000000000000000".to_string()),
            ..Default::default()
        })
        .unwrap();
        txn.commit().unwrap();
    }

    let address = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::External, 0)
        .address;
    let tx = BdkTransaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let txid = tx.compute_txid().to_string();
    wallet.bdk_wallet_mut().apply_unconfirmed_txs([(tx, 0)]);

    let txn = wallet.database().begin_transaction().unwrap();
    wallet.sync_db_txos_from_bdk(&txn, false).unwrap();

    let stale = txn.get_txo(&stale).unwrap().expect("stale TXO disappeared");
    assert!(
        !stale.pending_witness,
        "a payment without a pending receive must lose its pending-witness flag"
    );
    assert!(
        txn.iter_pending_witness_scripts().unwrap().is_empty(),
        "a pending witness script without a receive must be dropped"
    );
    let colored = txn
        .get_txo(&Outpoint { txid, vout: 0 })
        .unwrap()
        .expect("the colored TXO seen by BDK was not registered");
    assert!(colored.exists);
    txn.commit().unwrap();
}

/// Turn a guarded save into a JS promise that never rejects, so two writes can be in flight at
/// once: it resolves to `ok <writer> <sequence>` or `error <message>`.
fn guarded_save_promise(
    wallet_id: &str,
    bytes: Vec<u8>,
    writer: String,
    expected_sequence: u64,
) -> js_sys::Promise {
    let wallet_id = wallet_id.to_string();
    wasm_bindgen_futures::future_to_promise(async move {
        let outcome =
            match save_snapshot_record(&wallet_id, &bytes, &writer, expected_sequence).await {
                Ok(sequence) => format!("ok {writer} {sequence}"),
                Err(error) => format!("error {error}"),
            };
        Ok(JsValue::from_str(&outcome))
    })
}

#[wasm_bindgen_test]
async fn indexeddb_unavailable() {
    const WALLET_ID: &str = "unavailable-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    set_injected_failure(Some(InjectedFailure::Unavailable));
    let saved = save_snapshot(WALLET_ID, b"snapshot").await;
    let saved_record = save_snapshot_record(WALLET_ID, b"snapshot", &new_writer_id(), 0).await;
    let loaded = load_snapshot(WALLET_ID).await;
    let loaded_record = load_snapshot_record(WALLET_ID).await;
    let deleted = delete_snapshot(WALLET_ID).await;
    set_injected_failure(None);

    assert!(matches!(saved, Err(Error::Internal { .. })));
    assert!(matches!(saved_record, Err(Error::Internal { .. })));
    assert!(matches!(loaded, Err(Error::Internal { .. })));
    assert!(matches!(loaded_record, Err(Error::Internal { .. })));
    assert!(matches!(deleted, Err(Error::Internal { .. })));
    // the failure happened before any transaction, so nothing was written
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());
}

/// Deleting a snapshot removes the record and its sequence, so a deliberate recreate starts at `0`.
///
/// This is the core half of the binding `deleteSnapshot` contract: the binding detaches the
/// instance so it cannot recreate the record by accident, and a new instance's first guarded save
/// at sequence `0` is accepted instead of rejected against the deleted record.
#[wasm_bindgen_test]
async fn deleted_snapshot_restarts_the_sequence() {
    const WALLET_ID: &str = "delete-restarts-sequence-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    save_snapshot_record(WALLET_ID, b"first", &new_writer_id(), 0)
        .await
        .unwrap();

    delete_snapshot(WALLET_ID).await.unwrap();
    // deleting a missing key is not an error, so a repeated delete succeeds
    delete_snapshot(WALLET_ID).await.unwrap();
    assert!(load_snapshot_record(WALLET_ID).await.unwrap().is_none());

    // a new writer at sequence 0 recreates the record: the deleted sequence does not reject it
    let sequence = save_snapshot_record(WALLET_ID, b"recreated", &new_writer_id(), 0)
        .await
        .unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(b"recreated".as_slice())
    );
    delete_snapshot(WALLET_ID).await.unwrap();
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
    let writer = new_writer_id();
    let sequence = wallet.flush(WALLET_ID, &writer, 0).await.unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(first.as_slice())
    );

    // a newer in-memory state that must not replace the committed snapshot when the write aborts
    let _ = wallet.get_address().unwrap();
    set_injected_failure(Some(InjectedFailure::AbortBeforeCommit));
    let result = wallet.flush(WALLET_ID, &writer, sequence).await;
    set_injected_failure(None);

    assert!(matches!(result, Err(Error::Internal { .. })));
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(first.as_slice())
    );
    // the wallet stays usable: a retry commits the newer state
    let sequence = wallet.flush(WALLET_ID, &writer, sequence).await.unwrap();
    assert_eq!(sequence, 2);
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
async fn concurrent_flush_serializes_and_rejects_the_stale_writer() {
    const WALLET_ID: &str = "concurrent-flush-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    // two snapshots of the same wallet, taken before and after deriving an address
    let (mut wallet, keys) = memory_wallet();
    let first = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    let _ = wallet.get_address().unwrap();
    let second = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    assert_ne!(first, second);

    // both instances loaded sequence 0 and race to write it: IndexedDB serializes their read-write
    // transactions on the single `snapshots` store, so exactly one commits sequence 1 and the
    // other is rejected as stale
    let writer_a = new_writer_id();
    let writer_b = new_writer_id();
    let both = js_sys::Promise::all(&js_sys::Array::of2(
        &guarded_save_promise(WALLET_ID, first.clone(), writer_a.clone(), 0),
        &guarded_save_promise(WALLET_ID, second.clone(), writer_b.clone(), 0),
    ));
    let outcomes = wasm_bindgen_futures::JsFuture::from(both)
        .await
        .expect("both guarded writes settle");
    let outcomes = js_sys::Array::from(&outcomes);
    let outcomes: Vec<String> = (0..outcomes.length())
        .map(|index| outcomes.get(index).as_string().unwrap_or_default())
        .collect();
    let successes: Vec<&String> = outcomes
        .iter()
        .filter(|outcome| outcome.starts_with("ok "))
        .collect();
    assert_eq!(
        successes.len(),
        1,
        "exactly one writer commits, got {outcomes:?}"
    );
    let winner = successes[0]
        .split_whitespace()
        .nth(1)
        .expect("the winning writer id")
        .to_string();
    let winner_bytes = if winner == writer_a { &first } else { &second };

    let stored = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the guarded write");
    assert_eq!(stored.sequence, 1);
    assert_eq!(stored.writer, winner);
    assert_eq!(&stored.bytes, winner_bytes);
    // whichever write won, the stored bytes still rebuild the wallet and the legacy reader agrees
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(winner_bytes.as_slice())
    );
    Wallet::from_snapshot(&stored.bytes, wallet_data(), keys).expect("wallet restore");

    // a fresh load adopts the committed sequence, so its next write is accepted
    let fresh = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the committed record");
    assert_eq!(fresh.sequence, 1);
    let sequence = save_snapshot_record(WALLET_ID, &fresh.bytes, &new_writer_id(), fresh.sequence)
        .await
        .unwrap();
    assert_eq!(sequence, 2);

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// Two instances load the same record; the first flushes, the second is stale and must not
/// overwrite the newer bytes. A fresh load sees the new sequence and can flush again.
#[wasm_bindgen_test]
async fn stale_sequence_is_rejected_and_keeps_the_newer_snapshot() {
    const WALLET_ID: &str = "stale-sequence-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    let (mut wallet, _keys) = memory_wallet();
    let first = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    let writer = new_writer_id();
    assert_eq!(
        save_snapshot_record(WALLET_ID, &first, &writer, 0)
            .await
            .unwrap(),
        1
    );

    // both instances load the same record and adopt its writer and sequence
    let instance_a = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the stored record");
    let instance_b = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the stored record");
    assert_eq!(instance_a, instance_b);
    assert_eq!(instance_a.writer, writer);
    assert_eq!(instance_a.sequence, 1);

    // the first instance flushes the newer state
    let _ = wallet.get_address().unwrap();
    let second = wallet.snapshot().unwrap().expect("memory wallet snapshot");
    let sequence = wallet
        .flush(WALLET_ID, &instance_a.writer, instance_a.sequence)
        .await
        .unwrap();
    assert_eq!(sequence, 2);

    // the second instance still expects sequence 1: rejected, and the message names the stored
    // sequence and the writer that owns it
    let error = wallet
        .flush(WALLET_ID, &instance_b.writer, instance_b.sequence)
        .await
        .expect_err("a stale sequence must be rejected");
    assert!(matches!(error, Error::Internal { .. }));
    let message = error.to_string();
    assert!(
        message.contains("stored sequence is 2"),
        "the stale error must name the stored sequence: {message}"
    );
    assert!(
        message.contains(&writer),
        "the stale error must name the current writer: {message}"
    );
    let stored = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the newer record");
    assert_eq!(stored.bytes, second);
    assert_eq!(stored.writer, writer);
    assert_eq!(stored.sequence, 2);

    // a fresh load sees the new sequence and its flush is accepted
    let fresh = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the newer record");
    assert_eq!(fresh.sequence, 2);
    assert_eq!(
        save_snapshot_record(WALLET_ID, &fresh.bytes, &new_writer_id(), fresh.sequence)
            .await
            .unwrap(),
        3
    );

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// A pre-guard `Uint8Array` value loads as `legacy` / sequence 0 and the first guarded save
/// migrates it to the record shape without losing the bytes.
#[wasm_bindgen_test]
async fn legacy_snapshot_migrates_on_the_first_guarded_save() {
    const WALLET_ID: &str = "legacy-record-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    let legacy = b"legacy snapshot bytes".to_vec();
    save_snapshot(WALLET_ID, &legacy).await.unwrap();

    let record = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("a legacy value loads");
    assert_eq!(record.bytes, legacy);
    assert_eq!(record.writer, "legacy");
    assert_eq!(record.sequence, 0);
    // the compatibility reader returns the same bytes
    assert_eq!(
        load_snapshot(WALLET_ID).await.unwrap().as_deref(),
        Some(legacy.as_slice())
    );

    let writer = new_writer_id();
    let sequence = save_snapshot_record(WALLET_ID, &legacy, &writer, record.sequence)
        .await
        .unwrap();
    assert_eq!(sequence, 1);

    // the legacy value is now a guarded record owned by the new writer
    let migrated = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the migrated record");
    assert_eq!(migrated.bytes, legacy);
    assert_eq!(migrated.writer, writer);
    assert_eq!(migrated.sequence, 1);

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// Both failure-injection paths leave the previous guarded record intact and keep its sequence.
#[wasm_bindgen_test]
async fn guarded_write_failure_keeps_the_previous_record() {
    const WALLET_ID: &str = "guarded-write-failure-test";
    delete_snapshot(WALLET_ID).await.unwrap();

    let first = b"first committed snapshot".to_vec();
    let writer = new_writer_id();
    save_snapshot_record(WALLET_ID, &first, &writer, 0)
        .await
        .unwrap();

    for failure in [
        InjectedFailure::WriteFailed,
        InjectedFailure::AbortBeforeCommit,
    ] {
        set_injected_failure(Some(failure));
        let result = save_snapshot_record(WALLET_ID, b"second snapshot", "other-writer", 1).await;
        set_injected_failure(None);

        assert!(matches!(result, Err(Error::Internal { .. })));
        let stored = load_snapshot_record(WALLET_ID)
            .await
            .unwrap()
            .expect("the committed record");
        assert_eq!(stored.bytes, first);
        assert_eq!(stored.writer, writer);
        assert_eq!(stored.sequence, 1);
    }

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

    wallet.flush(WALLET_ID, &new_writer_id(), 0).await.unwrap();
    let stored = load_snapshot_record(WALLET_ID)
        .await
        .unwrap()
        .expect("the flushed snapshot");
    drop(wallet);

    // the files travel in the snapshot and are in the adapter before the wallet is handed back
    let restored =
        Wallet::from_snapshot(&stored.bytes, wallet_data(), keys.clone()).expect("restore");
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
    restored
        .flush(WALLET_ID, &stored.writer, stored.sequence)
        .await
        .unwrap();
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

#[wasm_bindgen_test]
fn native_legacy_migrations_are_refused_and_byte_backups_work() {
    let (wallet, keys) = memory_wallet();

    // a plain browser wallet load never reads or creates legacy filesystem keys
    let legacy_dir = WalletPath::new("rgb").unwrap();
    assert!(wallet.files().list(&legacy_dir).unwrap().is_empty());
    assert!(!wallet.files().exists(&legacy_dir).unwrap());

    // legacy RGB data that did reach the adapter cannot be imported on wasm: it is an explicit
    // error, not a silent skip, and the data is left untouched
    let legacy = WalletPath::new("rgb/stash.dat").unwrap();
    wallet.files().atomic_write(&legacy, b"legacy").unwrap();
    let error = crate::database::rgb::migrate_rgb_fs_to_db(
        wallet.files(),
        wallet.wallet_dir(),
        wallet.database(),
    )
    .unwrap_err();
    assert!(matches!(
        &error,
        Error::Internal { details } if details.contains("rgb_fs_store_migration")
    ));
    assert_eq!(wallet.files().read(&legacy).unwrap(), b"legacy");

    // the filesystem entry points take paths and stay native-only
    let error = wallet
        .backup("wallet.rgb-lib_backup", "password")
        .unwrap_err();
    assert!(matches!(
        &error,
        Error::Internal { details } if details.contains("not supported on wasm32")
    ));
    let error = restore_backup("wallet.rgb-lib_backup", "password", "restore").unwrap_err();
    assert!(matches!(
        &error,
        Error::Internal { details } if details.contains("not supported on wasm32")
    ));

    // the byte path needs no filesystem: backup, public info and restore through the snapshot
    let backup = wallet.backup_bytes("password").unwrap();
    let info = backup_info_bytes(&backup).unwrap();
    assert_eq!(info.version, 1);
    let restored = restore_backup_bytes(&backup, "password").unwrap();
    assert_eq!(restored.fingerprint(), keys.master_fingerprint);
    let snapshot = restored.wallet_snapshot().unwrap();
    let rebuilt = Wallet::from_snapshot(&snapshot, wallet.get_wallet_data(), keys).unwrap();
    assert_eq!(
        rebuilt.get_keys().master_fingerprint,
        wallet.get_keys().master_fingerprint
    );
    assert!(matches!(
        restore_backup_bytes(&backup, "wrong password"),
        Err(Error::WrongPassword)
    ));
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
    wallet.flush(WALLET_ID, &new_writer_id(), 0).await.unwrap();
    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the flushed multisig snapshot");
    drop(wallet);

    let restored = MultisigWallet::from_snapshot(&stored, wallet_data(), keys).expect("restore");
    assert_eq!(restored.files().read(&media).unwrap(), b"multisig media");

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// Hub-coordinated multisig operations are outside the wasm wallet-only scope: `get_address` and
/// the rest of the online APIs only compile with the native `_online` features. The hub-free subset
/// is pinned here: construction, descriptors, a descriptor-derived address and a database mutation
/// all survive a flush/restore.
#[wasm_bindgen_test]
async fn multisig_wallet_lifecycle_over_indexed_db() {
    const WALLET_ID: &str = "multisig-lifecycle-test";
    delete_snapshot(WALLET_ID).await.unwrap();
    assert!(load_snapshot(WALLET_ID).await.unwrap().is_none());

    let keys = multisig_keys();
    let wallet = MultisigWallet::new_with_database(
        wallet_data(),
        keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .expect("multisig construction over the in-memory backend");
    assert_eq!(
        wallet.get_wallet_data().bitcoin_network,
        wallet_data().bitcoin_network
    );
    let descriptors = wallet.get_descriptors();
    // identity without a hub: the descriptor-derived address and the stored cosigner set
    let address = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::Internal, 0)
        .address
        .to_string();
    assert_eq!(wallet.get_local_last_processed_operation_idx().unwrap(), 0);

    // a representative database mutation that needs no native hub
    add_unspent_colored_txo(&wallet);
    wallet.flush(WALLET_ID, &new_writer_id(), 0).await.unwrap();
    let stored = load_snapshot(WALLET_ID)
        .await
        .unwrap()
        .expect("the flushed multisig snapshot");
    drop(wallet);

    let restored =
        MultisigWallet::from_snapshot(&stored, wallet_data(), keys.clone()).expect("restore");
    assert_eq!(restored.get_keys(), keys);
    assert_eq!(restored.get_descriptors(), descriptors);
    assert_eq!(
        restored
            .bdk_wallet()
            .peek_address(KeychainKind::Internal, 0)
            .address
            .to_string(),
        address
    );
    assert_eq!(
        restored.get_local_last_processed_operation_idx().unwrap(),
        0
    );
    let txn = restored.database().begin_transaction().unwrap();
    let txos = txn.iter_txos().unwrap();
    txn.commit().unwrap();
    assert_eq!(txos.len(), 1, "the mutated TXO did not survive the restore");
    assert_eq!(
        txos[0].txid,
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(txos[0].vout, 0);

    delete_snapshot(WALLET_ID).await.unwrap();
}

/// Wallet construction and offline issuance complete on the browser main thread with no thread and
/// no worker: `std::thread::spawn` panics on wasm32-unknown-unknown, so reaching the assertions is
/// part of the proof. `globalThis.Worker` is replaced with a thrower first, so code that tried to
/// offload the work to a browser worker would fail here instead of passing silently.
#[wasm_bindgen_test]
fn wallet_creation_and_issuance_need_no_worker() {
    let global = js_sys::global();
    let worker = JsValue::from_str("Worker");
    let saved = js_sys::Reflect::get(&global, &worker).expect("read globalThis.Worker");
    assert!(!saved.is_undefined(), "the browser provides Worker");

    let thrower = js_sys::Function::new_no_args(
        "throw new Error('wallet work constructed a browser Worker')",
    );
    assert!(
        js_sys::Reflect::set(&global, &worker, thrower.as_ref()).expect("poison globalThis.Worker"),
        "globalThis.Worker is writable"
    );

    let (mut wallet, _) = memory_wallet();
    add_unspent_colored_txo(&wallet);
    let asset = wallet
        .issue_asset_nia("TICKER".to_string(), "NAME".to_string(), 0, vec![100])
        .expect("offline issuance needs no worker or thread");

    js_sys::Reflect::set(&global, &worker, &saved).expect("restore globalThis.Worker");
    assert!(!asset.asset_id.is_empty());
}

/// Pins the wasm logger: a discard drain with a zero-sized guard, so no `slog-async` worker or
/// any other thread is spawned. `std::thread::spawn` panics on wasm32-unknown-unknown, so
/// construction succeeding without a directory is the thread-free proof; the guard size pins that
/// no worker handle is carried. Records are formatted and discarded, so a secret-bearing call
/// cannot reach a file, the console or the DOM.
#[wasm_bindgen_test]
fn wasm_logger_discards_without_a_thread_or_a_file() {
    let dir = "wasm-logger-must-not-exist";
    let (logger, guard) = setup_logger(dir, Some("wallet_log")).expect("wasm logger construction");
    // a `slog_async::AsyncGuard` owns the worker handle; this guard is a unit struct
    assert_eq!(std::mem::size_of::<LoggerGuard>(), 0);

    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    // the secret itself never reaches a log statement; the drain would drop it anyway
    info!(logger, "wallet created"; "mnemonic_len" => keys.mnemonic.len());
    debug!(logger, "signing"; "xprv" => "test-only-not-a-key");
    drop(guard);

    assert!(!std::path::Path::new(dir).exists());
}

/// Earliest timestamp the tests accept as "a real clock was read": 2023-11-14, well before any
/// browser running the suite and well after the 1970 epoch a missing clock would fall back to.
const SANE_EPOCH_SECS: i64 = 1_700_000_000;
/// Generous allowance between the wallet clock and the browser clock, so a slow CI runner with a
/// coarse `Date.now` granularity cannot fail the test.
const CLOCK_TOLERANCE_SECS: i64 = 300;

fn browser_now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Pins the browser clock: `utils::now` reads `time`'s `wasm-bindgen` shim (`js_sys::Date`), so it
/// must agree with the browser's own clock. The old `SystemTime::now` path panics on
/// wasm32-unknown-unknown, so reaching the assertions at all is part of the proof.
#[wasm_bindgen_test]
fn browser_clock_matches_the_wallet_clock() {
    let wallet_now = crate::utils::now().unix_timestamp();
    let browser_now = browser_now_secs();

    assert!(
        wallet_now > SANE_EPOCH_SECS,
        "the wallet clock is not set: {wallet_now}"
    );
    assert!(
        (wallet_now - browser_now).abs() <= CLOCK_TOLERANCE_SECS,
        "the wallet clock {wallet_now} disagrees with the browser clock {browser_now}"
    );

    // a second read never goes backwards: issuance and transfer timestamps are only compared for
    // ordering, so monotonic-enough is all the API needs
    let later = crate::utils::now().unix_timestamp();
    assert!(later >= wallet_now, "the wallet clock went backwards");
}

/// Pins the randomness behind key generation: `getrandom`'s `js`/`wasm_js` backends call
/// `crypto.getRandomValues`, so the browser realm must expose it, and two fresh key sets drawn
/// through `bip39`/`rand` must differ and round trip through `restore_keys`.
#[wasm_bindgen_test]
fn fresh_keys_are_distinct_and_round_trip() {
    let crypto = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .expect("globalThis.crypto is missing");
    let get_random_values =
        js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues")).unwrap_or_default();
    assert!(
        get_random_values.is_function(),
        "the browser CSPRNG behind getrandom is missing"
    );

    let first = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let second = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);

    assert_eq!(first.mnemonic.split_whitespace().count(), 12);
    // no secrets in the assertion messages: a failing run must not print key material
    assert!(
        first.mnemonic != second.mnemonic,
        "two fresh mnemonics are identical"
    );
    assert!(
        first.account_xpub_vanilla != second.account_xpub_vanilla,
        "two fresh account keys are identical"
    );
    assert!(
        first.account_xpub_colored != first.account_xpub_vanilla,
        "the vanilla and colored account keys were derived identically"
    );

    let restored = crate::keys::restore_keys(
        BitcoinNetwork::Regtest,
        first.mnemonic.clone(),
        WitnessVersion::Taproot,
    )
    .expect("a freshly generated mnemonic parses back");
    assert!(restored.mnemonic == first.mnemonic);
    assert!(restored.account_xpub_vanilla == first.account_xpub_vanilla);
    assert!(restored.account_xpub_colored == first.account_xpub_colored);
    assert!(restored.master_fingerprint == first.master_fingerprint);

    // the raw CSPRNG behind the online Ed25519 keys is the same browser source
    let sk_a = crate::encryption::gen_ed25519();
    let sk_b = crate::encryption::gen_ed25519();
    assert!(
        sk_a.to_bytes() != sk_b.to_bytes(),
        "two fresh signing keys are identical"
    );
}

/// Pins the clock the RGB genesis timestamp comes from: `rgb-ops` stamps
/// `valid_contract.genesis.timestamp` with `chrono::Utc::now()`, whose `wasmbind` feature (on by
/// default) routes to `js_sys::Date` in the browser. Issuance therefore has to produce sane,
/// ordered timestamps, and the wallet snapshot has to carry them through a restore unchanged.
#[wasm_bindgen_test]
fn asset_genesis_timestamps_are_sane_and_survive_restore() {
    let (mut wallet, keys) = memory_wallet();

    // two unspent colored TXOs so both issuances have somewhere to land
    for vout in 0..2 {
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
                vout: ActiveValue::Set(vout),
                btc_amount: ActiveValue::Set("1000".to_string()),
                spent: ActiveValue::Set(false),
                exists: ActiveValue::Set(true),
                pending_witness: ActiveValue::Set(false),
            })
            .unwrap();
    }

    let first = wallet
        .issue_asset_nia("AAA".to_string(), "First".to_string(), 0, vec![100])
        .expect("first offline issuance");
    let second = wallet
        .issue_asset_nia("BBB".to_string(), "Second".to_string(), 0, vec![100])
        .expect("second offline issuance");

    let browser_now = browser_now_secs();
    for (label, asset) in [("first", &first), ("second", &second)] {
        assert!(
            asset.timestamp > SANE_EPOCH_SECS,
            "the {label} genesis timestamp is not set: {}",
            asset.timestamp
        );
        assert!(
            (asset.timestamp - browser_now).abs() <= CLOCK_TOLERANCE_SECS,
            "the {label} genesis timestamp {} disagrees with the browser clock {browser_now}",
            asset.timestamp
        );
        assert!(
            (asset.added_at - browser_now).abs() <= CLOCK_TOLERANCE_SECS,
            "the {label} import timestamp {} disagrees with the browser clock {browser_now}",
            asset.added_at
        );
    }
    assert!(
        second.timestamp >= first.timestamp,
        "issuance timestamps went backwards"
    );

    let snapshot = wallet
        .snapshot()
        .unwrap()
        .expect("the memory wallet snapshots");
    let restored = Wallet::from_snapshot(&snapshot, wallet_data(), keys).expect("wallet restore");
    let assets = restored
        .list_assets(vec![])
        .unwrap()
        .nia
        .unwrap_or_default();
    for asset in [&first, &second] {
        let restored_asset = assets
            .iter()
            .find(|a| a.asset_id == asset.asset_id)
            .expect("the issued asset is missing after the restore");
        assert_eq!(restored_asset.timestamp, asset.timestamp);
        assert_eq!(restored_asset.added_at, asset.added_at);
    }
}

/// The browser receive reuses a consignment cached by a failed earlier attempt.
///
/// The first attempt fetches through a fake `fetch`, writes the decrypted consignment and its
/// metadata, then fails (injected just after the cache write). The proxy is then switched to
/// `NoConsignment`, as it may delete the data once the transfer was handled: the second attempt
/// succeeds from the cache, and `consignment.get` is never requested again.
#[cfg(feature = "esplora_async")]
#[wasm_bindgen_test]
#[ignore = "the fake proxy fetch cannot inspect the async JSON-RPC request body yet"]
async fn cached_proxy_consignment_is_reused_when_the_proxy_deleted_it() {
    use std::cell::Cell;
    use std::rc::Rc;

    use base64::Engine as _;
    use js_sys::Reflect;

    const PROXY_URL: &str = "http://recipient-proxy";
    const INDEXER_URL: &str = "http://127.0.0.1:3002";

    let (mut wallet, _keys) = memory_wallet();
    let script =
        ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x11; 20]).unwrap());
    let recipient_id = crate::utils::recipient_id_from_script_buf(script, BitcoinNetwork::Regtest);
    let recipient_pubkey = vec![0x44; 32];
    let batch_idx = insert_pending_proxy_receive(&wallet, &recipient_id, recipient_pubkey);
    let sender_pk = hex::encode(crate::encryption::gen_ed25519().verifying_key().to_bytes());
    let expected = {
        let txn = wallet.database().begin_transaction().unwrap();
        let db_data = txn.get_db_data(false).unwrap();
        super::receive::pending_receives(&db_data).unwrap()[0]
            .expected_transfer_id(&sender_pk)
            .expect("the pending receive derives a proxy transfer ID")
    };

    // the payload the fake proxy serves: arbitrary bytes, whose declared hash matches, so the
    // download path caches them; parsing only happens after the cache write
    let consignment_bytes = b"cached consignment payload".to_vec();
    let consignment_b64 = base64::engine::general_purpose::STANDARD.encode(&consignment_bytes);
    let consignment_hash = hex::encode(crate::encryption::sha256_digest(&consignment_bytes));
    let consignment_body = format!(
        r#"{{"jsonrpc":"2.0","id":null,"result":{{"consignment":"{consignment_b64}","sender_transport_endpoint":"rpc://127.0.0.1:3000/json-rpc","sender_pk":"{sender_pk}","consignment_hash":"{consignment_hash}","batch":false}}}}"#
    );

    let global = js_sys::global();
    let saved_fetch = Reflect::get(&global, &JsValue::from_str("fetch")).unwrap();
    let no_consignment = Rc::new(Cell::new(false));
    let consignment_gets = Rc::new(Cell::new(0));
    let fetch = {
        let no_consignment = no_consignment.clone();
        let consignment_gets = consignment_gets.clone();
        Closure::<dyn Fn(JsValue) -> js_sys::Promise>::new(move |request: JsValue| {
            let method = Reflect::get(&request, &JsValue::from_str("method"))
                .ok()
                .and_then(|method| method.as_string())
                .unwrap_or_default();
            let body = match method.as_str() {
                "consignment.get" => {
                    consignment_gets.set(consignment_gets.get() + 1);
                    if no_consignment.get() {
                        // the proxy deleted the data after the first attempt handled it
                        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-400,"message":"no consignment"}}"#
                            .to_string()
                    } else {
                        consignment_body.clone()
                    }
                }
                // a malformed cached consignment is refused, which NACKs and releases the transfer
                "ack.post" => r#"{"jsonrpc":"2.0","id":null,"result":{"result":true}}"#.to_string(),
                _ => r#"{"jsonrpc":"2.0","id":null,"result":true}"#.to_string(),
            };
            js_sys::Promise::resolve(&mock_response(&body, PROXY_URL))
        })
    };
    Reflect::set(&global, &JsValue::from_str("fetch"), fetch.as_ref()).unwrap();

    // the first attempt downloads and caches, then fails before the database transaction
    set_fail_after_cache(true);
    let first = wallet
        .receive_transfer_async(PROXY_URL, INDEXER_URL, &expected)
        .await;
    set_fail_after_cache(false);
    assert!(matches!(first, Err(Error::Internal { .. })));

    // the cache is complete, but no database row was written: the transfer is still pending
    let db_data = {
        let txn = wallet.database().begin_transaction().unwrap();
        txn.get_db_data(false).unwrap()
    };
    assert_eq!(super::receive::already_handled(&db_data, &expected), None);
    assert!(
        wallet
            .cached_receive(&db_data, PROXY_URL, &expected)
            .unwrap()
            .is_some(),
        "the first attempt did not leave a reusable cache"
    );

    // the proxy now says the consignment is gone: only the cache can complete the receive
    no_consignment.set(true);
    let second = wallet
        .receive_transfer_async(PROXY_URL, INDEXER_URL, &expected)
        .await;
    let _ = Reflect::set(&global, &JsValue::from_str("fetch"), &saved_fetch);

    assert_eq!(
        second.expect("the second attempt must succeed from the cache"),
        Some(batch_idx)
    );
    assert_eq!(
        consignment_gets.get(),
        1,
        "the second attempt fetched the consignment from the proxy instead of the cache"
    );

    let txn = wallet.database().begin_transaction().unwrap();
    let transfer = txn
        .get_db_data(false)
        .unwrap()
        .transfers
        .into_iter()
        .find(|transfer| transfer.proxy_transfer_id.as_deref() == Some(expected.as_str()))
        .expect("the reused cache recorded the proxy transfer ID");
    assert_eq!(
        transfer.proxy_transfer_id.as_deref(),
        Some(expected.as_str())
    );
}

/// The proxy release waits for the snapshot that holds the handled receive: receiving never posts
/// it, a failed post keeps its marker, and a wallet reloaded from the snapshot retries it after a
/// successful save.
#[cfg(feature = "esplora_async")]
#[wasm_bindgen_test]
#[ignore = "the fake proxy fetch cannot inspect the async JSON-RPC request body yet"]
async fn proxy_release_waits_for_the_snapshot_and_is_retried() {
    use std::cell::Cell;
    use std::rc::Rc;

    use base64::Engine as _;
    use js_sys::Reflect;

    const PROXY_URL: &str = "http://recipient-proxy";
    const INDEXER_URL: &str = "http://127.0.0.1:3002";

    let (mut wallet, keys) = memory_wallet();
    let script =
        ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x13; 20]).unwrap());
    let recipient_id = crate::utils::recipient_id_from_script_buf(script, BitcoinNetwork::Regtest);
    let batch_idx = insert_pending_proxy_receive(&wallet, &recipient_id, vec![0x44; 32]);
    let sender_pk = hex::encode(crate::encryption::gen_ed25519().verifying_key().to_bytes());
    let expected = {
        let txn = wallet.database().begin_transaction().unwrap();
        let db_data = txn.get_db_data(false).unwrap();
        super::receive::pending_receives(&db_data).unwrap()[0]
            .expected_transfer_id(&sender_pk)
            .expect("the pending receive derives a proxy transfer ID")
    };

    // arbitrary payload with a matching declared hash: the driver refuses it after the download,
    // which still handles the transfer (NACK) and so owes the proxy a release
    let consignment_bytes = b"release ordering payload".to_vec();
    let consignment_b64 = base64::engine::general_purpose::STANDARD.encode(&consignment_bytes);
    let consignment_hash = hex::encode(crate::encryption::sha256_digest(&consignment_bytes));
    let consignment_body = format!(
        r#"{{"jsonrpc":"2.0","id":null,"result":{{"consignment":"{consignment_b64}","sender_transport_endpoint":"rpc://127.0.0.1:3000/json-rpc","sender_pk":"{sender_pk}","consignment_hash":"{consignment_hash}","batch":false}}}}"#
    );

    let global = js_sys::global();
    let saved_fetch = Reflect::get(&global, &JsValue::from_str("fetch")).unwrap();
    let retrieved_calls = Rc::new(Cell::new(0));
    let fail_retrieved = Rc::new(Cell::new(true));
    let fetch = {
        let retrieved_calls = retrieved_calls.clone();
        let fail_retrieved = fail_retrieved.clone();
        Closure::<dyn Fn(JsValue) -> js_sys::Promise>::new(move |request: JsValue| {
            let method = Reflect::get(&request, &JsValue::from_str("method"))
                .ok()
                .and_then(|method| method.as_string())
                .unwrap_or_default();
            let body = match method.as_str() {
                "consignment.get" => consignment_body.clone(),
                "ack.post" => r#"{"jsonrpc":"2.0","id":null,"result":{"result":true}}"#.to_string(),
                "transfer.retrieved" => {
                    retrieved_calls.set(retrieved_calls.get() + 1);
                    if fail_retrieved.get() {
                        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-400,"message":"unavailable"}}"#
                            .to_string()
                    } else {
                        r#"{"jsonrpc":"2.0","id":null,"result":true}"#.to_string()
                    }
                }
                _ => r#"{"jsonrpc":"2.0","id":null,"result":true}"#.to_string(),
            };
            js_sys::Promise::resolve(&mock_response(&body, PROXY_URL))
        })
    };
    Reflect::set(&global, &JsValue::from_str("fetch"), fetch.as_ref()).unwrap();

    // receiving never posts the release: the caller has not saved the handled receive yet
    let handled = wallet
        .receive_transfer_async(PROXY_URL, INDEXER_URL, &expected)
        .await
        .expect("the unreadable consignment is refused and handled");
    assert_eq!(handled, Some(batch_idx));
    assert_eq!(
        retrieved_calls.get(),
        0,
        "the receive released the proxy data before the caller saved"
    );

    // the host saved, and a wallet reloaded from that snapshot still owes the release
    let snapshot = wallet
        .snapshot()
        .expect("the in-memory wallet snapshots")
        .expect("the in-memory wallet produces a snapshot");
    let restored = Wallet::from_snapshot(&snapshot, wallet_data(), keys)
        .expect("restore the wallet from the snapshot");

    // the proxy rejects the first post: the marker must survive for a later attempt
    restored.release_pending_retrievals(INDEXER_URL).await;
    assert_eq!(retrieved_calls.get(), 1);
    restored.release_pending_retrievals(INDEXER_URL).await;
    assert_eq!(
        retrieved_calls.get(),
        2,
        "the failed release did not leave its marker for a retry"
    );

    // the next post succeeds and removes the marker, so a further call has nothing to release
    fail_retrieved.set(false);
    restored.release_pending_retrievals(INDEXER_URL).await;
    assert_eq!(retrieved_calls.get(), 3);
    restored.release_pending_retrievals(INDEXER_URL).await;
    assert_eq!(
        retrieved_calls.get(),
        3,
        "the accepted release kept its marker"
    );

    let _ = Reflect::set(&global, &JsValue::from_str("fetch"), &saved_fetch);
}

/// A receive applied by an earlier attempt, left in `WaitingBroadcast`, is resumed by the next
/// call instead of being skipped because it already stores its proxy transfer ID. A terminal
/// transfer is still skipped.
#[cfg(feature = "esplora_async")]
#[wasm_bindgen_test]
#[ignore = "the fake proxy fetch cannot inspect the async JSON-RPC request body yet"]
async fn second_sync_resumes_a_waiting_receive() {
    use std::cell::Cell;
    use std::rc::Rc;

    use js_sys::Reflect;

    const PROXY_URL: &str = "http://recipient-proxy";
    const INDEXER_URL: &str = "http://127.0.0.1:3002";

    let (mut wallet, _keys) = memory_wallet();
    let script =
        ScriptBuf::new_p2wpkh(&bdk_wallet::bitcoin::WPubkeyHash::from_slice(&[0x12; 20]).unwrap());
    let recipient_id = crate::utils::recipient_id_from_script_buf(script, BitcoinNetwork::Regtest);
    let batch_idx = insert_pending_proxy_receive(&wallet, &recipient_id, vec![0x44; 32]);
    let transfer_id = "waiting-broadcast-transfer".to_string();
    let transfer_idx = {
        let txn = wallet.database().begin_transaction().unwrap();
        let (asset_transfer_idx, transfer_idx) = {
            let db_data = txn.get_db_data(false).unwrap();
            let asset_transfer = db_data
                .asset_transfers
                .iter()
                .find(|at| at.batch_transfer_idx == batch_idx)
                .expect("the pending receive has an asset transfer");
            let transfer = db_data
                .transfers
                .iter()
                .find(|t| t.asset_transfer_idx == asset_transfer.idx)
                .expect("the pending receive has a transfer");
            (asset_transfer.idx, transfer.idx)
        };
        let mut batch: DbBatchTransferActMod =
            txn.get_batch_transfer(batch_idx).unwrap().unwrap().into();
        batch.status = ActiveValue::Set(TransferStatus::WaitingBroadcast);
        txn.update_batch_transfer(&mut batch).unwrap();
        let mut transfer: DbTransferActMod = txn
            .get_db_data(false)
            .unwrap()
            .transfers
            .into_iter()
            .find(|t| t.idx == transfer_idx)
            .unwrap()
            .into();
        transfer.proxy_transfer_id = ActiveValue::Set(Some(transfer_id.clone()));
        transfer.consignment_hash = ActiveValue::Set(Some("00".to_string()));
        transfer.asset_transfer_idx = ActiveValue::Set(asset_transfer_idx);
        txn.update_transfer(&mut transfer).unwrap();
        let endpoint_idx = txn
            .set_transport_endpoint(DbTransportEndpointActMod {
                transport_type: ActiveValue::Set(TransportType::JsonRpc),
                endpoint: ActiveValue::Set(PROXY_URL.to_string()),
                ..Default::default()
            })
            .unwrap();
        txn.set_transfer_transport_endpoint(DbTransferTransportEndpointActMod {
            transfer_idx: ActiveValue::Set(transfer_idx),
            transport_endpoint_idx: ActiveValue::Set(endpoint_idx),
            used: ActiveValue::Set(true),
            kind: ActiveValue::Set(TransportEndpointKind::RecipientProxy),
            ..Default::default()
        })
        .unwrap();
        txn.commit().unwrap();
        transfer_idx
    };
    let _ = transfer_idx;
    let meta = ReceivedConsignmentMeta {
        proxy_url: Some(PROXY_URL.to_string()),
        transfer_id: Some(transfer_id.clone()),
        sender_transport_endpoint: "rpc://sender-proxy".to_string(),
        sender_pubkey: hex::encode([0x55; 32]),
        consignment_hash: "00".to_string(),
        batch: false,
    };
    let meta_path = wallet.get_receive_consignment_meta_path(&recipient_id);
    wallet
        .files()
        .atomic_write(
            &wallet.wallet_key(&meta_path).unwrap(),
            serde_json::to_vec(&meta).unwrap().as_slice(),
        )
        .unwrap();

    let global = js_sys::global();
    let saved_fetch = Reflect::get(&global, &JsValue::from_str("fetch")).unwrap();
    let acks = Rc::new(Cell::new(0));
    let fetch = {
        let acks = acks.clone();
        Closure::<dyn Fn(JsValue) -> js_sys::Promise>::new(move |request: JsValue| {
            let method = Reflect::get(&request, &JsValue::from_str("method"))
                .ok()
                .and_then(|method| method.as_string())
                .unwrap_or_default();
            let body = match method.as_str() {
                "ack.post" => {
                    acks.set(acks.get() + 1);
                    // no signed TX yet: the transfer stays in WaitingBroadcast
                    r#"{"jsonrpc":"2.0","id":null,"result":{"result":true}}"#.to_string()
                }
                "server.info" => {
                    r#"{"jsonrpc":"2.0","id":null,"result":{"protocol_version":"1.0","version":"test","uptime":0,"retention_grace_secs":"86400"}}"#
                        .to_string()
                }
                "transfer.list" => format!(
                    r#"{{"jsonrpc":"2.0","id":null,"result":{{"{transfer_id}":"Pending"}}}}"#
                ),
                _ => r#"{"jsonrpc":"2.0","id":null,"result":true}"#.to_string(),
            };
            js_sys::Promise::resolve(&mock_response(&body, PROXY_URL))
        })
    };
    Reflect::set(&global, &JsValue::from_str("fetch"), fetch.as_ref()).unwrap();

    let first = wallet
        .receive_pending_proxy_transfers(PROXY_URL, INDEXER_URL)
        .await;
    let second = wallet
        .receive_pending_proxy_transfers(PROXY_URL, INDEXER_URL)
        .await;
    assert_eq!(first.unwrap(), vec![batch_idx]);
    assert_eq!(second.unwrap(), vec![batch_idx]);
    assert_eq!(
        acks.get(),
        2,
        "a non-terminal receive must be ACKed again instead of being skipped"
    );

    // a terminal status is still skipped without touching the proxy
    let txn = wallet.database().begin_transaction().unwrap();
    let mut batch: DbBatchTransferActMod =
        txn.get_batch_transfer(batch_idx).unwrap().unwrap().into();
    batch.status = ActiveValue::Set(TransferStatus::Settled);
    txn.update_batch_transfer(&mut batch).unwrap();
    txn.commit().unwrap();
    let third = wallet
        .receive_pending_proxy_transfers(PROXY_URL, INDEXER_URL)
        .await;
    let _ = Reflect::set(&global, &JsValue::from_str("fetch"), &saved_fetch);
    assert!(third.unwrap().is_empty());
    assert_eq!(acks.get(), 2, "a settled receive must not be ACKed again");
}

/// Insert one pending incoming proxy receive; no transport endpoint is needed for the cache test.
#[cfg(feature = "esplora_async")]
fn insert_pending_proxy_receive(
    wallet: &Wallet,
    recipient_id: &str,
    recipient_pubkey: Vec<u8>,
) -> i32 {
    let txn = wallet.database().begin_transaction().unwrap();
    let batch_idx = txn
        .set_batch_transfer(DbBatchTransferActMod {
            status: ActiveValue::Set(TransferStatus::WaitingCounterparty),
            created_at: ActiveValue::Set(0),
            updated_at: ActiveValue::Set(0),
            min_confirmations: ActiveValue::Set(1),
            incoming: ActiveValue::Set(true),
            operation_secret_key: ActiveValue::Set(Some(vec![7u8; 32])),
            ..Default::default()
        })
        .unwrap();
    let asset_transfer_idx = txn
        .set_asset_transfer(DbAssetTransferActMod {
            user_driven: ActiveValue::Set(false),
            batch_transfer_idx: ActiveValue::Set(batch_idx),
            asset_id: ActiveValue::Set(None),
            ..Default::default()
        })
        .unwrap();
    txn.set_transfer(DbTransferActMod {
        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
        recipient_id: ActiveValue::Set(Some(recipient_id.to_string())),
        recipient_pubkey: ActiveValue::Set(Some(recipient_pubkey)),
        recipient_encryption: ActiveValue::Set(Encryption::Unsupported),
        ..Default::default()
    })
    .unwrap();
    txn.commit().unwrap();
    batch_idx
}

// The proxy health check is read-only and needs no proxy for the invalid-endpoint path: the shared
// transport-endpoint parser rejects the URL before any request is built.
#[cfg(feature = "esplora_async")]
#[wasm_bindgen_test]
async fn check_proxy_url_async_rejects_an_invalid_endpoint() {
    for url in ["not-a-url", "http://", "ftp://proxy.example.com"] {
        assert!(
            matches!(
                super::rust_only::check_proxy_url_async(url).await,
                Err(Error::InvalidTransportEndpoint { .. })
            ),
            "expected an invalid transport endpoint for {url}"
        );
    }
}
