//! Browser wallet lifecycle over IndexedDB.
//!
//! Runs under `wasm-bindgen-test` in a real browser (see the `wasm_browser_lifecycle` job). It
//! builds a wallet over the in-memory backend, issues an asset offline, flushes it through the
//! wallet to IndexedDB twice, rebuilds the wallet from the loaded bytes and checks the newest state
//! survived. No indexer or network access is involved.
//!
//! The test lives inside the crate, so it compiles against the public API the way a host would use
//! it: the wallet flush entry point and the persistence functions.

use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

use super::*;
use crate::wallet::persistence::{delete_snapshot, load_snapshot};
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
