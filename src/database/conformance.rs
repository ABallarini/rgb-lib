//! Cross-backend conformance suite.
//!
//! Every scenario runs twice, once through a SQLite [`RgbLibDatabase`] in a tempdir and once
//! through the in-memory backend, and the two results are compared with `assert_eq!`.
//!
//! The comparison is on observable results only: the owned entity `Model`s the wallet reads
//! back, the returned indices, and small owned snapshots. SQL statements, internal data
//! structures and storage layout are never inspected.
//!
//! Every scenario asserts that the two backends return the same observable result, including
//! the same errors for constraint violations.
//!
//! The transaction and savepoint scenarios of the online features live in the [`online`]
//! module: the default wallet gate (`wallet,sqlite`) cannot reach them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sea_orm::ActiveValue;

use crate::database::entities::pending_witness_script::ActiveModel as DbPendingWitnessScriptActMod;
#[cfg(feature = "_online")]
use crate::database::entities::pending_witness_script::Model as DbPendingWitnessScript;
#[cfg(feature = "_online")]
use crate::database::entities::reserved_txo::ActiveModel as DbReservedTxoActMod;
use crate::database::entities::reserved_txo::Model as DbReservedTxo;
#[cfg(feature = "_online")]
use crate::database::entities::wallet_transaction::ActiveModel as DbWalletTransactionActMod;
use crate::database::enums::{
    AssetSchema, Assignment, Encryption, RecipientTypeFull, TransferStatus, TransportEndpointKind,
    TransportType,
};
#[cfg(feature = "_online")]
use crate::database::enums::{ColoringType, WalletTransactionType};
use crate::wallet::core::setup_db;
use crate::{
    AssetFilter, DbAsset, DbAssetActMod, DbAssetTransfer, DbAssetTransferActMod, DbBackupInfo,
    DbBackupInfoActMod, DbBatchTransfer, DbBatchTransferActMod, DbColoring, DbMedia, DbMediaActMod,
    DbToken, DbTokenActMod, DbTokenMedia, DbTokenMediaActMod, DbTransfer, DbTransferActMod,
    DbTransferTransportEndpointActMod, DbTransportEndpointActMod, DbTxo, DbWalletTransaction,
    RgbLibDatabase,
};
#[cfg(feature = "_online")]
use crate::{DbColoringActMod, DbTxoActMod};

// ────────────────────────────────────────────────────────────
// Backend harness
// ────────────────────────────────────────────────────────────

/// Run `scenario` against a fresh SQLite database and a fresh in-memory database.
fn on_both_backends<T>(scenario: impl Fn(&RgbLibDatabase) -> T) -> (T, T) {
    let dir = tempfile::tempdir().unwrap();
    let sqlite = {
        let db = setup_db(dir.path()).unwrap();
        scenario(&db)
    };
    let memory = scenario(&RgbLibDatabase::new_memory());
    (sqlite, memory)
}

/// Run `scenario` on both backends and require the same observable result.
fn assert_backends_match<T>(scenario: impl Fn(&RgbLibDatabase) -> T)
where
    T: PartialEq + std::fmt::Debug,
{
    let (sqlite, memory) = on_both_backends(scenario);
    assert_eq!(sqlite, memory, "SQLite and in-memory backends disagree");
}

// ────────────────────────────────────────────────────────────
// Row fixtures
// ────────────────────────────────────────────────────────────

fn asset(id: &str) -> DbAssetActMod {
    DbAssetActMod {
        id: ActiveValue::Set(id.to_string()),
        schema: ActiveValue::Set(AssetSchema::Nia),
        added_at: ActiveValue::Set(1),
        initial_supply: ActiveValue::Set("1000".to_string()),
        name: ActiveValue::Set(format!("name-{id}")),
        precision: ActiveValue::Set(8),
        timestamp: ActiveValue::Set(1),
        ..Default::default()
    }
}

fn asset_with_media(id: &str, media_idx: i32) -> DbAssetActMod {
    DbAssetActMod {
        media_idx: ActiveValue::Set(Some(media_idx)),
        details: ActiveValue::Set(Some("details".to_string())),
        ticker: ActiveValue::Set(Some("TKN".to_string())),
        max_supply: ActiveValue::Set(Some("1000".to_string())),
        known_circulating_supply: ActiveValue::Set(Some("100".to_string())),
        reject_list_url: ActiveValue::Set(Some("https://example.com/reject".to_string())),
        ..asset(id)
    }
}

fn media(digest: &str, mime: &str) -> DbMediaActMod {
    DbMediaActMod {
        digest: ActiveValue::Set(digest.to_string()),
        mime: ActiveValue::Set(mime.to_string()),
        ..Default::default()
    }
}

fn batch_transfer(
    txid: Option<&str>,
    incoming: bool,
    status: TransferStatus,
) -> DbBatchTransferActMod {
    DbBatchTransferActMod {
        txid: ActiveValue::Set(txid.map(str::to_string)),
        status: ActiveValue::Set(status),
        created_at: ActiveValue::Set(10),
        updated_at: ActiveValue::Set(10),
        expiration: ActiveValue::Set(incoming.then_some(100)),
        min_confirmations: ActiveValue::Set(2),
        incoming: ActiveValue::Set(incoming),
        ..Default::default()
    }
}

fn asset_transfer(batch_transfer_idx: i32, asset_id: Option<&str>) -> DbAssetTransferActMod {
    DbAssetTransferActMod {
        user_driven: ActiveValue::Set(true),
        batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
        asset_id: ActiveValue::Set(asset_id.map(str::to_string)),
        ..Default::default()
    }
}

fn transfer(asset_transfer_idx: i32) -> DbTransferActMod {
    DbTransferActMod {
        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
        requested_assignment: ActiveValue::Set(Some(Assignment::Fungible(42))),
        recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness { vout: Some(1) })),
        recipient_id: ActiveValue::Set(Some("recipient-1".to_string())),
        ack: ActiveValue::Set(Some(true)),
        invoice_string: ActiveValue::Set(Some("invoice-1".to_string())),
        recipient_pubkey: ActiveValue::Set(Some(vec![1, 2, 3])),
        consignment_hash: ActiveValue::Set(Some("consignment-hash".to_string())),
        recipient_encryption: ActiveValue::Set(Encryption::Optional),
        ack_signature: ActiveValue::Set(Some(vec![4, 5])),
        proxy_transfer_id: ActiveValue::Set(Some("proxy-transfer-1".to_string())),
        invoice_expiration: ActiveValue::Set(Some(123)),
        ..Default::default()
    }
}

#[cfg(feature = "_online")]
fn coloring(
    txo_idx: i32,
    asset_transfer_idx: i32,
    r#type: ColoringType,
    assignment: Assignment,
) -> DbColoringActMod {
    DbColoringActMod {
        txo_idx: ActiveValue::Set(txo_idx),
        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
        r#type: ActiveValue::Set(r#type),
        assignment: ActiveValue::Set(assignment),
        ..Default::default()
    }
}

fn token(asset_idx: i32) -> DbTokenActMod {
    DbTokenActMod {
        asset_idx: ActiveValue::Set(asset_idx),
        index: ActiveValue::Set(0),
        ticker: ActiveValue::Set(Some("TKN".to_string())),
        name: ActiveValue::Set(Some("Token".to_string())),
        details: ActiveValue::Set(Some("details".to_string())),
        embedded_media: ActiveValue::Set(true),
        reserves: ActiveValue::Set(false),
        ..Default::default()
    }
}

fn token_media(token_idx: i32, media_idx: i32) -> DbTokenMediaActMod {
    DbTokenMediaActMod {
        token_idx: ActiveValue::Set(token_idx),
        media_idx: ActiveValue::Set(media_idx),
        attachment_id: ActiveValue::Set(Some(3)),
        ..Default::default()
    }
}

#[cfg(feature = "_online")]
fn txo(txid: &str, vout: u32, btc_amount: &str) -> DbTxoActMod {
    DbTxoActMod {
        txid: ActiveValue::Set(txid.to_string()),
        vout: ActiveValue::Set(vout),
        btc_amount: ActiveValue::Set(btc_amount.to_string()),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(true),
        pending_witness: ActiveValue::Set(false),
        ..Default::default()
    }
}

#[cfg(feature = "_online")]
fn reserved_txo(
    txid: &str,
    vout: u32,
    reserved_for_vanilla: Option<i32>,
    reserved_for_colored: Option<i32>,
) -> DbReservedTxoActMod {
    DbReservedTxoActMod {
        txid: ActiveValue::Set(txid.to_string()),
        vout: ActiveValue::Set(vout),
        reserved_for_vanilla: ActiveValue::Set(reserved_for_vanilla),
        reserved_for_colored: ActiveValue::Set(reserved_for_colored),
        ..Default::default()
    }
}

#[cfg(feature = "_online")]
fn wallet_transaction(txid: &str) -> DbWalletTransactionActMod {
    DbWalletTransactionActMod {
        txid: ActiveValue::Set(txid.to_string()),
        r#type: ActiveValue::Set(WalletTransactionType::CreateUtxos),
        ..Default::default()
    }
}

// ────────────────────────────────────────────────────────────
// Owned dataset
// ────────────────────────────────────────────────────────────

/// Every observable wallet-table row, in the order the iterators return it.
#[derive(Debug, PartialEq)]
struct Dataset {
    assets: Vec<DbAsset>,
    media: Vec<DbMedia>,
    batch_transfers: Vec<DbBatchTransfer>,
    asset_transfers: Vec<DbAssetTransfer>,
    transfers: Vec<DbTransfer>,
    colorings: Vec<DbColoring>,
    txos: Vec<DbTxo>,
    tokens: Vec<DbToken>,
    token_medias: Vec<DbTokenMedia>,
    reserved_txos: Vec<DbReservedTxo>,
    wallet_transactions: Vec<DbWalletTransaction>,
    backup_info: Option<DbBackupInfo>,
    #[cfg(feature = "_online")]
    pending_witness_scripts: Vec<DbPendingWitnessScript>,
}

fn read_dataset(db: &RgbLibDatabase) -> Dataset {
    let txn = db.begin_transaction().unwrap();
    let dataset = Dataset {
        assets: txn.iter_assets().unwrap(),
        media: txn.iter_media().unwrap(),
        batch_transfers: txn.iter_batch_transfers().unwrap(),
        asset_transfers: txn.iter_asset_transfers().unwrap(),
        transfers: txn.iter_transfers().unwrap(),
        colorings: txn.iter_colorings().unwrap(),
        txos: txn.iter_txos().unwrap(),
        tokens: txn.iter_tokens().unwrap(),
        token_medias: txn.iter_token_medias().unwrap(),
        reserved_txos: txn.iter_reserved_txos().unwrap(),
        wallet_transactions: txn.iter_wallet_transactions().unwrap(),
        backup_info: txn.get_backup_info().unwrap(),
        #[cfg(feature = "_online")]
        pending_witness_scripts: txn.iter_pending_witness_scripts().unwrap(),
    };
    txn.commit().unwrap();
    dataset
}

/// The pieces of [`DbData`], compared as owned rows.
#[derive(Debug, PartialEq)]
struct DbDataParts {
    batch_transfers: Vec<DbBatchTransfer>,
    asset_transfers: Vec<DbAssetTransfer>,
    transfers: Vec<DbTransfer>,
    colorings: Vec<DbColoring>,
    txos: Vec<DbTxo>,
}

impl DbDataParts {
    fn from(data: crate::DbData) -> Self {
        Self {
            batch_transfers: data.batch_transfers,
            asset_transfers: data.asset_transfers,
            transfers: data.transfers,
            colorings: data.colorings,
            txos: data.txos,
        }
    }
}

/// Store one row of every always-available table, plus the online-only rows when the feature
/// is enabled, and return the dataset read back after the commit.
fn seed(db: &RgbLibDatabase) -> Dataset {
    let txn = db.begin_transaction().unwrap();
    let media_idx = txn.set_media(media("digest-1", "image/png")).unwrap();
    let asset_idx = txn
        .set_asset(asset_with_media("asset-1", media_idx))
        .unwrap();
    let batch_idx = txn
        .set_batch_transfer(batch_transfer(
            Some("batch-txid"),
            true,
            TransferStatus::WaitingCounterparty,
        ))
        .unwrap();
    let asset_transfer_idx = txn
        .set_asset_transfer(asset_transfer(batch_idx, Some("asset-1")))
        .unwrap();
    txn.set_transfer(transfer(asset_transfer_idx)).unwrap();
    let token_idx = txn.set_token(token(asset_idx)).unwrap();
    txn.set_token_media(token_media(token_idx, media_idx))
        .unwrap();
    txn.set_backup_info(DbBackupInfoActMod {
        last_backup_timestamp: ActiveValue::Set("1".to_string()),
        last_operation_timestamp: ActiveValue::Set("2".to_string()),
        last_processed_operation_idx: ActiveValue::Set(Some(3)),
        ..Default::default()
    })
    .unwrap();
    txn.set_pending_witness_script(DbPendingWitnessScriptActMod {
        script: ActiveValue::Set("script-1".to_string()),
        ..Default::default()
    })
    .unwrap();

    #[cfg(feature = "_online")]
    {
        let txo_idx = txn.set_txo(txo("txo-a", 0, "1000")).unwrap();
        txn.set_coloring(coloring(
            txo_idx,
            asset_transfer_idx,
            ColoringType::Receive,
            Assignment::Fungible(100),
        ))
        .unwrap();
        let wallet_transaction_idx = txn
            .set_wallet_transaction(wallet_transaction("wtx-1"))
            .unwrap();
        txn.set_reserved_txos(vec![reserved_txo(
            "txo-a",
            1,
            Some(wallet_transaction_idx),
            None,
        )])
        .unwrap();
    }

    txn.commit().unwrap();
    read_dataset(db)
}

// ────────────────────────────────────────────────────────────
// Assets
// ────────────────────────────────────────────────────────────

#[test]
fn assets_roundtrip_and_iteration_order() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let media_idx = txn.set_media(media("asset-media", "image/png")).unwrap();
        let first = txn.set_asset(asset("asset-1")).unwrap();
        let second = txn
            .set_asset(asset_with_media("asset-2", media_idx))
            .unwrap();
        let third = txn.set_asset(asset("asset-3")).unwrap();
        let result = (
            first,
            second,
            third,
            txn.get_asset("asset-1".to_string()).unwrap(),
            txn.get_asset("asset-2".to_string()).unwrap(),
            txn.get_asset("missing".to_string()).unwrap(),
            txn.iter_assets().unwrap(),
        );
        txn.commit().unwrap();
        result
    });
}

#[test]
fn duplicate_unique_keys_are_rejected_by_both_backends() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let first_asset = txn.set_asset(asset("duplicate")).unwrap();
        let second_asset = txn.set_asset(asset("duplicate"));
        let first_media = txn
            .set_media(media("duplicate-digest", "image/png"))
            .unwrap();
        let second_media = txn.set_media(media("duplicate-digest", "image/png"));
        let result = (
            first_asset,
            second_asset,
            first_media,
            second_media,
            txn.iter_assets().unwrap().len(),
            txn.iter_media().unwrap().len(),
        );
        txn.commit().unwrap();
        result
    });
}

// ────────────────────────────────────────────────────────────
// Media
// ────────────────────────────────────────────────────────────

#[test]
fn media_roundtrip_and_get_or_insert() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let first = txn.set_media(media("digest-1", "image/png")).unwrap();
        let second = txn.set_media(media("digest-2", "image/jpeg")).unwrap();
        let same = txn
            .get_or_insert_media("digest-1".to_string(), "ignored".to_string())
            .unwrap();
        let new = txn
            .get_or_insert_media("digest-3".to_string(), "image/webp".to_string())
            .unwrap();
        let result = (
            first,
            second,
            same,
            new,
            txn.get_media(first).unwrap(),
            txn.get_media_by_digest("digest-2".to_string()).unwrap(),
            txn.get_media_by_digest("missing".to_string()).unwrap(),
            txn.iter_media().unwrap(),
        );
        txn.commit().unwrap();
        result
    });
}

// ────────────────────────────────────────────────────────────
// Batch transfers
// ────────────────────────────────────────────────────────────

#[test]
fn batch_transfers_roundtrip_and_delete() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let first = txn
            .set_batch_transfer(batch_transfer(
                Some("txid-1"),
                true,
                TransferStatus::WaitingCounterparty,
            ))
            .unwrap();
        let second = txn
            .set_batch_transfer(batch_transfer(None, false, TransferStatus::Settled))
            .unwrap();
        let before_delete = (
            txn.get_batch_transfer(first).unwrap(),
            txn.get_batch_transfer(second).unwrap(),
            txn.get_batch_transfers_by_txid("txid-1").unwrap(),
            txn.iter_batch_transfers().unwrap(),
        );
        let second_row = txn.get_batch_transfer(second).unwrap().unwrap();
        txn.del_batch_transfer(&second_row).unwrap();
        let after_delete = (
            txn.get_batch_transfer(second).unwrap(),
            txn.iter_batch_transfers().unwrap(),
        );
        txn.commit().unwrap();
        (before_delete, after_delete)
    });
}

// ────────────────────────────────────────────────────────────
// Transfer graph and composite reads
// ────────────────────────────────────────────────────────────

#[test]
fn transfer_graph_and_composite_reads() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        txn.set_media(media("digest-1", "image/png")).unwrap();
        txn.set_asset(asset("asset-1")).unwrap();
        let batch_idx = txn
            .set_batch_transfer(batch_transfer(
                Some("txid-1"),
                false,
                TransferStatus::WaitingConfirmations,
            ))
            .unwrap();
        let asset_transfer_idx = txn
            .set_asset_transfer(asset_transfer(batch_idx, Some("asset-1")))
            .unwrap();
        let transfer_idx = txn.set_transfer(transfer(asset_transfer_idx)).unwrap();
        let endpoint_idx = txn
            .set_transport_endpoint(DbTransportEndpointActMod {
                transport_type: ActiveValue::Set(TransportType::JsonRpc),
                endpoint: ActiveValue::Set("https://proxy.example.com".to_string()),
                ..Default::default()
            })
            .unwrap();
        let tte_idx = txn
            .set_transfer_transport_endpoint(DbTransferTransportEndpointActMod {
                transfer_idx: ActiveValue::Set(transfer_idx),
                transport_endpoint_idx: ActiveValue::Set(endpoint_idx),
                used: ActiveValue::Set(false),
                kind: ActiveValue::Set(TransportEndpointKind::RecipientProxy),
                ..Default::default()
            })
            .unwrap();

        let all = DbDataParts::from(txn.get_db_data(false).unwrap());
        let without_transfers = DbDataParts::from(txn.get_db_data(true).unwrap());
        let (user_driven, endpoints) = txn
            .get_transfers_db_data(None, &AssetFilter::AnyOrNone)
            .unwrap();
        let endpoints_by_transfer = txn
            .get_transport_endpoints_by_transfer(&[transfer_idx])
            .unwrap();
        let result = (
            tte_idx,
            txn.iter_asset_transfers().unwrap(),
            txn.iter_transfers().unwrap(),
            txn.get_transport_endpoint("https://proxy.example.com".to_string())
                .unwrap(),
            all,
            without_transfers,
            DbDataParts::from(user_driven),
            endpoints,
            endpoints_by_transfer,
        );
        txn.commit().unwrap();
        result
    });
}

// ────────────────────────────────────────────────────────────
// Tokens and pending witness scripts
// ────────────────────────────────────────────────────────────

#[test]
fn tokens_and_token_media_roundtrip() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let media_idx = txn.set_media(media("digest-1", "image/png")).unwrap();
        let asset_idx = txn.set_asset(asset("asset-1")).unwrap();
        let token_idx = txn.set_token(token(asset_idx)).unwrap();
        let token_media_idx = txn
            .set_token_media(token_media(token_idx, media_idx))
            .unwrap();
        // nullable token fields must round-trip as NULL/None on both backends
        txn.set_token(DbTokenActMod {
            asset_idx: ActiveValue::Set(asset_idx),
            index: ActiveValue::Set(1),
            ticker: ActiveValue::Set(None),
            name: ActiveValue::Set(None),
            details: ActiveValue::Set(None),
            embedded_media: ActiveValue::Set(false),
            reserves: ActiveValue::Set(true),
            ..Default::default()
        })
        .unwrap();
        let result = (
            token_idx,
            token_media_idx,
            txn.iter_tokens().unwrap(),
            txn.iter_token_medias().unwrap(),
        );
        txn.commit().unwrap();
        result
    });
}

#[test]
fn pending_witness_scripts_insert_indices() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let first = txn
            .set_pending_witness_script(DbPendingWitnessScriptActMod {
                script: ActiveValue::Set("script-1".to_string()),
                ..Default::default()
            })
            .unwrap();
        let second = txn
            .set_pending_witness_script(DbPendingWitnessScriptActMod {
                script: ActiveValue::Set("script-2".to_string()),
                ..Default::default()
            })
            .unwrap();
        txn.commit().unwrap();
        (first, second)
    });
}

// ────────────────────────────────────────────────────────────
// Backup info
// ────────────────────────────────────────────────────────────

#[test]
fn backup_info_roundtrip_update_and_delete() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let idx = txn
            .set_backup_info(DbBackupInfoActMod {
                last_backup_timestamp: ActiveValue::Set("1".to_string()),
                last_operation_timestamp: ActiveValue::Set("2".to_string()),
                last_processed_operation_idx: ActiveValue::Set(Some(3)),
                ..Default::default()
            })
            .unwrap();
        let inserted = txn.get_backup_info().unwrap();
        let mut update = DbBackupInfoActMod {
            idx: ActiveValue::Set(idx),
            last_backup_timestamp: ActiveValue::Set("4".to_string()),
            last_operation_timestamp: ActiveValue::Set("5".to_string()),
            ..Default::default()
        };
        txn.update_backup_info(&mut update).unwrap();
        let updated = txn.get_backup_info().unwrap();
        txn.del_backup_info().unwrap();
        let deleted = txn.get_backup_info().unwrap();
        txn.commit().unwrap();
        (idx, inserted, updated, deleted)
    });
}

#[test]
fn backup_info_update_persists_the_nullable_operation_idx() {
    assert_backends_match(|db| {
        let txn = db.begin_transaction().unwrap();
        let idx = txn
            .set_backup_info(DbBackupInfoActMod {
                last_backup_timestamp: ActiveValue::Set("1".to_string()),
                last_operation_timestamp: ActiveValue::Set("2".to_string()),
                last_processed_operation_idx: ActiveValue::Set(Some(3)),
                ..Default::default()
            })
            .unwrap();
        let mut update = DbBackupInfoActMod {
            idx: ActiveValue::Set(idx),
            last_processed_operation_idx: ActiveValue::Set(Some(9)),
            ..Default::default()
        };
        txn.update_backup_info(&mut update).unwrap();
        let result = txn
            .get_backup_info()
            .unwrap()
            .map(|info| info.last_processed_operation_idx);
        txn.commit().unwrap();
        result
    });
}

// ────────────────────────────────────────────────────────────
// Transactions
// ────────────────────────────────────────────────────────────

#[test]
fn transactions_commit_rollback_and_callbacks() {
    assert_backends_match(|db| {
        let committed_callbacks = Arc::new(AtomicUsize::new(0));

        let txn = db.begin_transaction().unwrap();
        txn.set_asset(asset("committed")).unwrap();
        let callback = committed_callbacks.clone();
        txn.on_commit(move || {
            callback.fetch_add(1, Ordering::SeqCst);
        });
        txn.commit().unwrap();

        let txn = db.begin_transaction().unwrap();
        txn.set_asset(asset("dropped")).unwrap();
        let callback = committed_callbacks.clone();
        txn.on_commit(move || {
            callback.fetch_add(1, Ordering::SeqCst);
        });
        drop(txn);

        // a new transaction starts after the rolled-back one
        let txn = db.begin_transaction().unwrap();
        let after_drop = txn.iter_assets().unwrap();
        txn.set_asset(asset("after-drop")).unwrap();
        txn.commit().unwrap();

        let callbacks_before_read = committed_callbacks.load(Ordering::SeqCst);
        let txn = db.begin_transaction().unwrap();
        let after_commit = txn.iter_assets().unwrap();
        txn.commit().unwrap();
        (
            after_drop,
            after_commit,
            callbacks_before_read,
            committed_callbacks.load(Ordering::SeqCst),
        )
    });
}

// ────────────────────────────────────────────────────────────
// Restart
// ────────────────────────────────────────────────────────────

#[test]
fn restart_preserves_the_dataset() {
    let dir = tempfile::tempdir().unwrap();
    let sqlite = {
        let db = setup_db(dir.path()).unwrap();
        let before = seed(&db);
        drop(db);
        let reopened = setup_db(dir.path()).unwrap();
        let after = read_dataset(&reopened);
        assert_eq!(after, before, "SQLite did not survive a close/reopen");
        after
    };

    let memory = {
        let db = RgbLibDatabase::new_memory();
        let before = seed(&db);
        let snapshot = db
            .snapshot()
            .unwrap()
            .expect("the memory backend has a snapshot");
        let reopened = RgbLibDatabase::new_memory_from_snapshot(&snapshot).unwrap();
        let after = read_dataset(&reopened);
        assert_eq!(
            after, before,
            "the memory snapshot did not survive a restart"
        );
        after
    };

    assert_eq!(sqlite, memory, "restarted backends disagree");
}

// ────────────────────────────────────────────────────────────
// Online-only scenarios
// ────────────────────────────────────────────────────────────

/// Scenarios that need the online features (`_online`), which the default wallet gate does not
/// enable. Run them with `--features wallet,sqlite,bitcoind`, never by enabling `_online` in the
/// gate.
#[cfg(feature = "_online")]
mod online {
    use super::*;
    use crate::{Balance, Error, Outpoint, group_colorings_by_asset_transfer};

    #[test]
    fn txos_upsert_unspent_and_delete() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            let first = txn.set_txo(txo("txo-a", 0, "1000")).unwrap();
            let second = txn.set_txo(txo("txo-b", 1, "2000")).unwrap();
            // zero amount and existing row: the amount and the spent flag are left untouched
            let upserted = txn.set_txo(DbTxoActMod {
                txid: ActiveValue::Set("txo-a".to_string()),
                vout: ActiveValue::Set(0),
                btc_amount: ActiveValue::Set("0".to_string()),
                spent: ActiveValue::Set(true),
                exists: ActiveValue::Set(true),
                pending_witness: ActiveValue::Set(false),
                ..Default::default()
            });
            let positive_upsert = txn.set_txo(DbTxoActMod {
                txid: ActiveValue::Set("txo-a".to_string()),
                vout: ActiveValue::Set(0),
                btc_amount: ActiveValue::Set("3000".to_string()),
                spent: ActiveValue::Set(false),
                exists: ActiveValue::Set(false),
                pending_witness: ActiveValue::Set(false),
                ..Default::default()
            });
            txn.update_txo(DbTxoActMod {
                idx: ActiveValue::Set(second),
                spent: ActiveValue::Set(true),
                ..Default::default()
            })
            .unwrap();
            let result = (
                first,
                second,
                upserted.ok(),
                positive_upsert.ok(),
                txn.get_txo(&Outpoint {
                    txid: "txo-a".to_string(),
                    vout: 0,
                })
                .unwrap(),
                txn.iter_txos().unwrap(),
                txn.get_unspent_txos(vec![]).unwrap(),
                txn.get_unspent_txos(vec![txn.iter_txos().unwrap()[1].clone()])
                    .unwrap(),
            );
            txn.del_txo(first).unwrap();
            let after_delete = txn.iter_txos().unwrap();
            txn.commit().unwrap();
            (result, after_delete)
        });
    }

    #[test]
    fn deleting_a_colored_txo_is_rejected_by_both_backends() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            txn.set_asset(asset("asset-1")).unwrap();
            let batch_idx = txn
                .set_batch_transfer(batch_transfer(None, false, TransferStatus::Settled))
                .unwrap();
            let asset_transfer_idx = txn
                .set_asset_transfer(asset_transfer(batch_idx, Some("asset-1")))
                .unwrap();
            let txo_idx = txn.set_txo(txo("txo-a", 0, "1000")).unwrap();
            txn.set_coloring(coloring(
                txo_idx,
                asset_transfer_idx,
                ColoringType::Receive,
                Assignment::Fungible(100),
            ))
            .unwrap();
            let delete = txn.del_txo(txo_idx);
            let result = (
                delete,
                txn.get_txo(&Outpoint {
                    txid: "txo-a".to_string(),
                    vout: 0,
                })
                .unwrap()
                .is_some(),
                txn.iter_colorings().unwrap().len(),
            );
            txn.commit().unwrap();
            result
        });
    }

    #[test]
    fn asset_nullable_fields_set_clear_set() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            let media_idx = txn.set_media(media("digest-1", "image/png")).unwrap();
            let asset_idx = txn
                .set_asset(asset_with_media("asset-1", media_idx))
                .unwrap();
            let inserted = txn.get_asset("asset-1".to_string()).unwrap();

            let mut clear = DbAssetActMod {
                idx: ActiveValue::Set(asset_idx),
                media_idx: ActiveValue::Set(None),
                details: ActiveValue::Set(None),
                ticker: ActiveValue::Set(None),
                max_supply: ActiveValue::Set(None),
                known_circulating_supply: ActiveValue::Set(None),
                reject_list_url: ActiveValue::Set(None),
                ..Default::default()
            };
            txn.update_asset(&mut clear).unwrap();
            let cleared = txn.get_asset("asset-1".to_string()).unwrap();

            let mut set = DbAssetActMod {
                idx: ActiveValue::Set(asset_idx),
                media_idx: ActiveValue::Set(Some(media_idx)),
                details: ActiveValue::Set(Some("details-2".to_string())),
                ticker: ActiveValue::Set(Some("TKN2".to_string())),
                max_supply: ActiveValue::Set(Some("2000".to_string())),
                known_circulating_supply: ActiveValue::Set(Some("200".to_string())),
                reject_list_url: ActiveValue::Set(Some("https://example.com/reject-2".to_string())),
                ..Default::default()
            };
            txn.update_asset(&mut set).unwrap();
            let set_again = txn.get_asset("asset-1".to_string()).unwrap();
            txn.commit().unwrap();
            (inserted, cleared, set_again)
        });
    }

    #[test]
    fn batch_transfer_update_refreshes_updated_at_on_both_backends() {
        let (sqlite, memory) = on_both_backends(|db| {
            let txn = db.begin_transaction().unwrap();
            let idx = txn
                .set_batch_transfer(batch_transfer(
                    None,
                    false,
                    TransferStatus::WaitingCounterparty,
                ))
                .unwrap();
            let mut update = DbBatchTransferActMod {
                idx: ActiveValue::Set(idx),
                txid: ActiveValue::Set(Some("txid-updated".to_string())),
                status: ActiveValue::Set(TransferStatus::WaitingConfirmations),
                expiration: ActiveValue::Set(None),
                incoming: ActiveValue::Set(true),
                ..Default::default()
            };
            txn.update_batch_transfer(&mut update).unwrap();
            let row = txn.get_batch_transfer(idx).unwrap().unwrap();
            txn.commit().unwrap();
            row
        });

        assert_eq!(sqlite, memory);
        assert!(sqlite.updated_at > sqlite.created_at);
    }

    #[test]
    fn reserved_txos_and_wallet_transaction_relations() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            let batch_idx = txn
                .set_batch_transfer(batch_transfer(None, false, TransferStatus::Settled))
                .unwrap();
            let wallet_idx = txn
                .set_wallet_transaction(wallet_transaction("wtx-1"))
                .unwrap();
            txn.set_reserved_txos(vec![
                reserved_txo("reserved-a", 0, Some(wallet_idx), None),
                reserved_txo("reserved-b", 1, None, Some(batch_idx)),
                reserved_txo("reserved-c", 2, Some(wallet_idx), None),
            ])
            .unwrap();
            let inserted = txn.iter_reserved_txos().unwrap();
            let relation = txn
                .get_wallet_transaction_with_reserved_txos_by_txid("wtx-1")
                .unwrap();
            let by_idx = txn.get_wallet_transactions_by_idxs(&[wallet_idx]).unwrap();

            txn.del_reserved_txos(&[inserted[0].clone()]).unwrap();
            let after_idx_delete = txn.iter_reserved_txos().unwrap();

            txn.del_colored_reserved_txos_by_outpoints(&[Outpoint {
                txid: "reserved-b".to_string(),
                vout: 1,
            }])
            .unwrap();
            let after_outpoint_delete = txn.iter_reserved_txos().unwrap();

            txn.del_reserved_txos_for_batch_transfer(batch_idx).unwrap();
            let after_batch_delete = txn.iter_reserved_txos().unwrap();
            txn.commit().unwrap();
            (
                inserted,
                relation,
                by_idx,
                after_idx_delete,
                after_outpoint_delete,
                after_batch_delete,
            )
        });
    }

    #[test]
    fn pending_witness_scripts_iter_and_delete() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            for script in ["script-1", "script-2", "script-3"] {
                txn.set_pending_witness_script(DbPendingWitnessScriptActMod {
                    script: ActiveValue::Set(script.to_string()),
                    ..Default::default()
                })
                .unwrap();
            }
            let inserted = txn.iter_pending_witness_scripts().unwrap();
            txn.del_pending_witness_script("script-2".to_string())
                .unwrap();
            let after_delete = txn.iter_pending_witness_scripts().unwrap();
            txn.commit().unwrap();
            (inserted, after_delete)
        });
    }

    #[test]
    fn colorings_grouping_and_balance() {
        assert_backends_match(|db| {
            let txn = db.begin_transaction().unwrap();
            txn.set_asset(asset("asset-1")).unwrap();
            let batch_idx = txn
                .set_batch_transfer(batch_transfer(None, false, TransferStatus::Settled))
                .unwrap();
            let asset_transfer_idx = txn
                .set_asset_transfer(asset_transfer(batch_idx, Some("asset-1")))
                .unwrap();
            let unspent_txo = txn.set_txo(txo("txo-a", 0, "1000")).unwrap();
            let spent_txo = txn.set_txo(txo("txo-b", 1, "2000")).unwrap();
            txn.update_txo(DbTxoActMod {
                idx: ActiveValue::Set(spent_txo),
                spent: ActiveValue::Set(true),
                ..Default::default()
            })
            .unwrap();
            txn.set_coloring(coloring(
                unspent_txo,
                asset_transfer_idx,
                ColoringType::Receive,
                Assignment::Fungible(100),
            ))
            .unwrap();
            txn.set_coloring(coloring(
                unspent_txo,
                asset_transfer_idx,
                ColoringType::Change,
                Assignment::Fungible(50),
            ))
            .unwrap();
            txn.set_coloring(coloring(
                spent_txo,
                asset_transfer_idx,
                ColoringType::Input,
                Assignment::Fungible(150),
            ))
            .unwrap();

            let colorings = txn.iter_colorings().unwrap();
            let grouped = group_colorings_by_asset_transfer(colorings.clone());
            let receive = txn
                .get_receive_colorings_by_txo_idxs(vec![unspent_txo, spent_txo])
                .unwrap();
            let all = DbDataParts::from(txn.get_db_data(false).unwrap());
            let (user_driven, endpoints) = txn
                .get_transfers_db_data(None, &AssetFilter::AnyOrNone)
                .unwrap();
            let balance = txn
                .get_asset_balance("asset-1".to_string(), None, None, None, None, None)
                .unwrap();
            txn.commit().unwrap();
            (
                colorings,
                grouped,
                receive,
                all,
                DbDataParts::from(user_driven),
                endpoints,
                balance,
            )
        });
    }

    #[test]
    fn savepoint_success_failure_and_callbacks() {
        assert_backends_match(|db| {
            let callbacks = Arc::new(AtomicUsize::new(0));
            let txn = db.begin_transaction().unwrap();
            txn.set_asset(asset("kept")).unwrap();

            txn.with_savepoint(|t| t.set_asset(asset("kept-inner")))
                .unwrap();
            let after_success: Vec<String> = txn
                .iter_assets()
                .unwrap()
                .into_iter()
                .map(|a| a.id)
                .collect();

            let failed: Result<(), Error> = txn.with_savepoint(|t| {
                t.set_asset(asset("dropped-inner"))?;
                let callback = callbacks.clone();
                t.on_commit(move || {
                    callback.fetch_add(1, Ordering::SeqCst);
                });
                Err(Error::Internal {
                    details: "savepoint failure".to_string(),
                })
            });
            let after_failure: Vec<String> = txn
                .iter_assets()
                .unwrap()
                .into_iter()
                .map(|a| a.id)
                .collect();

            txn.with_savepoint(|t| {
                let callback = callbacks.clone();
                t.on_commit(move || {
                    callback.fetch_add(1, Ordering::SeqCst);
                });
                Ok(())
            })
            .unwrap();
            let callbacks_before_commit = callbacks.load(Ordering::SeqCst);
            txn.commit().unwrap();
            (
                after_success,
                failed.is_err(),
                after_failure,
                callbacks_before_commit,
                callbacks.load(Ordering::SeqCst),
            )
        });
    }

    #[test]
    fn balance_is_the_same_on_both_backends() {
        let (sqlite, memory) = on_both_backends(|db| {
            let txn = db.begin_transaction().unwrap();
            let balance: Balance = txn
                .get_asset_balance("missing".to_string(), None, None, None, None, None)
                .unwrap();
            txn.commit().unwrap();
            balance
        });
        assert_eq!(sqlite, memory);
    }
}
