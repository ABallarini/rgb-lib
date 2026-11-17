//! In-memory storage backend spike (Option A).
//!
//! The S05 spike evaluates whether the reference WASM in-memory RGB store
//! can back the same operations as the SQLite store. `rgb_store` is a port
//! of the reference implementation, kept behind `cfg(test)` until the S06
//! decision.

pub(crate) mod db;
pub(crate) mod rgb_store;

use std::sync::{Arc, Mutex};

use rgbstd::persistence::{RgbStore, TxMode};

use crate::Error;
use db::InMemoryDb;
use rgb_store::{MemRgbStore, RgbSavepoint};

/// The in-memory storage of a wallet: the typed wallet tables and the RGB
/// stock, committed and rolled back together.
pub(crate) struct MemoryBackend {
    pub(crate) db: InMemoryDb,
    pub(crate) rgb: Mutex<MemRgbStore>,
    // the wallet manifest rides in the wallet snapshot envelope, not in the inner snapshot
    manifest_json: Mutex<Option<String>>,
}

impl MemoryBackend {
    pub(crate) fn new() -> Self {
        Self {
            db: InMemoryDb::new(),
            rgb: Mutex::new(MemRgbStore::default()),
            manifest_json: Mutex::new(None),
        }
    }

    /// Test-only operation counters of the wallet tables.
    #[cfg(test)]
    pub(crate) fn counters(&self) -> &db::MemoryOpCounters {
        &self.db.counters
    }

    /// Store the wallet manifest JSON that travels in the wallet snapshot envelope.
    pub(crate) fn set_wallet_manifest(&self, json: String) {
        *self
            .manifest_json
            .lock()
            .expect("manifest mutex is never poisoned") = Some(json);
    }

    /// The wallet manifest JSON stored by [`Self::set_wallet_manifest`].
    pub(crate) fn wallet_manifest(&self) -> Option<String> {
        self.manifest_json
            .lock()
            .expect("manifest mutex is never poisoned")
            .clone()
    }

    /// Version byte of the snapshot format written by [`Self::to_snapshot`].
    const SNAPSHOT_VERSION: u8 = 1;

    /// Serialize the whole backend: one version byte, the little-endian `u32` length of the
    /// JSON part, the JSON of the wallet tables, then the RGB store bytes.
    pub(crate) fn to_snapshot(&self) -> Result<Vec<u8>, crate::Error> {
        if self.db.has_open_tx() {
            return Err(crate::Error::Internal {
                details: "cannot snapshot the memory backend with a wallet transaction open"
                    .to_string(),
            });
        }
        let rgb = self.rgb.lock().expect("rgb store mutex is never poisoned");
        if rgb.has_open_tx() {
            return Err(crate::Error::Internal {
                details: "cannot snapshot the memory backend with an RGB transaction open"
                    .to_string(),
            });
        }
        let json = serde_json::to_vec(&self.db).map_err(|e| crate::Error::Internal {
            details: format!("cannot serialize the memory wallet tables: {e}"),
        })?;
        // `to_bytes` must be called outside a transaction, checked above.
        let rgb_bytes = rgb.to_bytes().map_err(|e| crate::Error::Internal {
            details: format!("cannot serialize the memory RGB store: {e}"),
        })?;
        let mut out = Vec::with_capacity(5 + json.len() + rgb_bytes.len());
        out.push(Self::SNAPSHOT_VERSION);
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(&json);
        out.extend_from_slice(&rgb_bytes);
        Ok(out)
    }

    /// Rebuild a backend from the bytes of [`Self::to_snapshot`].
    pub(crate) fn from_snapshot(bytes: &[u8]) -> Result<Self, crate::Error> {
        let invalid = |details: String| crate::Error::Internal { details };
        let header = bytes
            .get(..5)
            .ok_or_else(|| invalid("snapshot is shorter than its 5-byte header".to_string()))?;
        if header[0] != Self::SNAPSHOT_VERSION {
            return Err(invalid(format!(
                "unsupported snapshot version {} (expected {})",
                header[0],
                Self::SNAPSHOT_VERSION
            )));
        }
        let json_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let json_end = 5usize
            .checked_add(json_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| {
                invalid("snapshot JSON length is larger than the snapshot".to_string())
            })?;
        let db: InMemoryDb = serde_json::from_slice(&bytes[5..json_end])
            .map_err(|e| invalid(format!("cannot deserialize the memory wallet tables: {e}")))?;
        let rgb = MemRgbStore::from_bytes(&bytes[json_end..])
            .map_err(|e| invalid(format!("cannot deserialize the memory RGB store: {e}")))?;
        Ok(Self {
            db,
            rgb: Mutex::new(rgb),
            manifest_json: Mutex::new(None),
        })
    }

    /// Open one transaction covering both halves. The returned guard restores
    /// both snapshots on drop and releases both on commit.
    pub(crate) fn begin_transaction(self: &Arc<Self>) -> Result<MemoryTxn, Error> {
        self.db.open_tx()?;
        #[cfg(test)]
        self.db
            .counters
            .begin_transactions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let db_snapshot = Some(self.db.snapshot());
        let (rgb_snapshot, begun) = {
            let rgb = self.rgb.lock().expect("rgb store mutex is never poisoned");
            let snapshot = rgb.savepoint();
            (snapshot, rgb.begin(TxMode::Write))
        };
        // MemRgbStore's error is `Infallible`.
        let _ = match begun {
            Ok(begin) => begin,
            Err(never) => match never {},
        };
        Ok(MemoryTxn {
            backend: self.clone(),
            db_snapshot,
            rgb_snapshot: Some(rgb_snapshot),
            on_commit: std::cell::RefCell::new(Vec::new()),
        })
    }
}

/// Transaction over [`MemoryBackend`]: both the wallet tables and the RGB
/// stock are rolled back together, so the two cannot diverge.
pub(crate) struct MemoryTxn {
    pub(crate) backend: Arc<MemoryBackend>,
    db_snapshot: Option<InMemoryDb>,
    rgb_snapshot: Option<RgbSavepoint>,
    on_commit: std::cell::RefCell<Vec<Box<dyn FnOnce()>>>,
}

#[allow(dead_code)]
impl MemoryTxn {
    pub(crate) fn on_commit(&self, f: impl FnOnce() + 'static) {
        self.on_commit.borrow_mut().push(Box::new(f));
    }

    /// Snapshot both halves of the backend for a savepoint of this transaction.
    #[cfg(feature = "_online")]
    pub(crate) fn savepoint_state(&self) -> (InMemoryDb, RgbSavepoint) {
        let db = self.backend.db.snapshot();
        let rgb = self
            .backend
            .rgb
            .lock()
            .expect("rgb store mutex is never poisoned")
            .savepoint();
        (db, rgb)
    }

    /// Restore both halves of the backend to a state taken with [`Self::savepoint_state`].
    #[cfg(feature = "_online")]
    pub(crate) fn restore_savepoint(&self, db: InMemoryDb, rgb: RgbSavepoint) {
        self.backend.db.restore(db);
        self.backend
            .rgb
            .lock()
            .expect("rgb store mutex is never poisoned")
            .restore_savepoint(rgb);
    }

    /// Number of `on_commit` callbacks registered so far, a savepoint boundary.
    #[cfg(feature = "_online")]
    pub(crate) fn callbacks_len(&self) -> usize {
        self.on_commit.borrow().len()
    }

    /// Drop the callbacks registered after the boundary taken with [`Self::callbacks_len`].
    #[cfg(feature = "_online")]
    pub(crate) fn truncate_callbacks(&self, len: usize) {
        self.on_commit.borrow_mut().truncate(len);
    }

    // kept for callers that hold a `MemoryTxn` directly; `DbTxn::with_savepoint` uses the
    // snapshot helpers above so it can pass its own handle to the closure
    #[allow(dead_code)]
    pub(crate) fn with_savepoint<T>(
        &self,
        f: impl FnOnce(&MemoryTxn) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let db_snapshot = self.backend.db.snapshot();
        let (rgb_snapshot, begun) = {
            let rgb = self
                .backend
                .rgb
                .lock()
                .expect("rgb store mutex is never poisoned");
            (rgb.savepoint(), rgb.begin(TxMode::Write))
        };
        let _ = match begun {
            Ok(begin) => begin,
            Err(never) => match never {},
        };
        match f(self) {
            Ok(value) => Ok(value),
            Err(err) => {
                self.backend.db.restore(db_snapshot);
                self.backend
                    .rgb
                    .lock()
                    .expect("rgb store mutex is never poisoned")
                    .restore_savepoint(rgb_snapshot);
                Err(err)
            }
        }
    }

    pub(crate) fn commit(mut self) -> Result<(), Error> {
        self.db_snapshot = None;
        self.rgb_snapshot = None;
        self.backend.db.close_tx();
        {
            let rgb = self
                .backend
                .rgb
                .lock()
                .expect("rgb store mutex is never poisoned");
            let _ = rgb.commit();
        }
        for callback in std::mem::take(&mut *self.on_commit.borrow_mut()) {
            callback();
        }
        Ok(())
    }
}

impl Drop for MemoryTxn {
    fn drop(&mut self) {
        if let Some(snapshot) = self.db_snapshot.take() {
            self.backend.db.restore(snapshot);
            self.backend.db.close_tx();
            self.backend
                .rgb
                .lock()
                .expect("rgb store mutex is never poisoned")
                .rollback();
        }
    }
}

// the inner snapshot state is not `Debug`
impl std::fmt::Debug for MemoryTxn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTxn").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use rgbstd::persistence::{RgbStore, Stock};

    use super::rgb_store::MemRgbStore;
    use crate::BitcoinNetwork;
    use crate::RgbStock;
    use crate::database::enums::AssetSchema;
    use crate::wallet::{setup_db, setup_rgb};

    /// `RgbLibDatabase` in memory mode must run the same `setup_rgb` schema
    /// import as the SQLite mode, through the whole dispatched stack
    /// (`DbTxn` -> `&DbTxn: RgbStore` -> `&MemoryTxn: RgbStore`).
    #[test]
    fn setup_db_memory_mode_runs_schema_import() {
        use crate::RgbLibDatabase;

        let db = RgbLibDatabase::new_memory();
        setup_rgb(
            &db,
            vec![AssetSchema::Nia],
            BitcoinNetwork::Regtest,
            false,
            &slog::Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();

        let txn = db.begin_transaction().unwrap();
        let stock = RgbStock::new(&txn);
        assert!(
            stock.schemata().unwrap().into_iter().next().is_some(),
            "schema(s) must be readable back from the memory backend"
        );
        drop(stock);
        txn.commit().unwrap();
    }

    /// The schemas imported by `setup_rgb` must be the same whether they are
    /// written through SQLite or through the in-memory store.
    #[test]
    fn memory_rgb_store_imports_the_same_schemata_as_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let db = setup_db(dir.path()).unwrap();
        setup_rgb(
            &db,
            vec![AssetSchema::Nia],
            BitcoinNetwork::Regtest,
            false,
            &slog::Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();

        let txn = db.begin_transaction().unwrap();
        let stock = RgbStock::new(&txn);
        let sqlite_ids: BTreeSet<_> = stock
            .schemata()
            .unwrap()
            .into_iter()
            .map(|s| s.id.to_string())
            .collect();
        drop(stock);
        txn.commit().unwrap();

        let mem = MemRgbStore::default();
        let mut mem_stock = Stock::with(mem.clone());
        mem_stock
            .import_schema_definition(AssetSchema::Nia.schema_definition())
            .unwrap();
        let mem_ids: BTreeSet<_> = mem_stock
            .schemata()
            .map(|s| s.unwrap().id.to_string())
            .collect();

        assert!(!sqlite_ids.is_empty());
        assert_eq!(sqlite_ids, mem_ids);
    }

    /// The wallet tables must behave the same through SQLite and through the
    /// in-memory backend: same insert ids, same rows, same semantics for the
    /// representative asset/media operations.
    #[test]
    fn memory_db_wallet_rows_match_sqlite() {
        use super::db::InMemoryDb;
        use crate::{DbAssetActMod, DbMediaActMod};
        use sea_orm::ActiveValue;

        let dir = tempfile::tempdir().unwrap();
        let sql_db = setup_db(dir.path()).unwrap();
        let sql_txn = sql_db.begin_transaction().unwrap();
        let sql_asset_idx = sql_txn
            .set_asset(DbAssetActMod {
                id: sea_orm::ActiveValue::Set("asset-1".to_string()),
                schema: sea_orm::ActiveValue::Set(AssetSchema::Nia),
                added_at: sea_orm::ActiveValue::Set(1),
                name: sea_orm::ActiveValue::Set("name".to_string()),
                precision: sea_orm::ActiveValue::Set(8),
                initial_supply: sea_orm::ActiveValue::Set("1000".to_string()),
                timestamp: sea_orm::ActiveValue::Set(1),
                ..Default::default()
            })
            .unwrap();
        let sql_media_idx = sql_txn
            .set_media(DbMediaActMod {
                digest: sea_orm::ActiveValue::Set("digest-1".to_string()),
                mime: sea_orm::ActiveValue::Set("image/png".to_string()),
                ..Default::default()
            })
            .unwrap();
        let sql_asset_ids = sql_txn
            .iter_assets()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect::<Vec<_>>();
        let sql_media = sql_txn.get_media_by_digest("digest-1".to_string()).unwrap();
        sql_txn.commit().unwrap();

        let mem_db = InMemoryDb::new();
        let mem_txn = mem_db.begin_transaction().unwrap();
        let mem_asset_idx = mem_txn
            .set_asset(DbAssetActMod {
                id: ActiveValue::Set("asset-1".to_string()),
                schema: ActiveValue::Set(AssetSchema::Nia),
                added_at: ActiveValue::Set(1),
                name: ActiveValue::Set("name".to_string()),
                precision: ActiveValue::Set(8),
                initial_supply: ActiveValue::Set("1000".to_string()),
                timestamp: ActiveValue::Set(1),
                ..Default::default()
            })
            .unwrap();
        let mem_media_idx = mem_txn
            .set_media(DbMediaActMod {
                digest: ActiveValue::Set("digest-1".to_string()),
                mime: ActiveValue::Set("image/png".to_string()),
                ..Default::default()
            })
            .unwrap();
        let mem_asset_ids = mem_txn
            .iter_assets()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect::<Vec<_>>();
        let mem_media = mem_txn.get_media_by_digest("digest-1".to_string()).unwrap();
        mem_txn.commit().unwrap();

        assert_eq!(sql_asset_idx, mem_asset_idx);
        assert_eq!(sql_media_idx, mem_media_idx);
        assert_eq!(sql_asset_ids, mem_asset_ids);
        assert_eq!(
            sql_media.map(|m| (m.digest, m.mime)),
            mem_media.map(|m| (m.digest, m.mime))
        );
    }

    /// One transaction must cover the typed tables and the RGB stock: commit
    /// keeps both, drop rolls both back.
    #[test]
    fn memory_transaction_covers_db_and_rgb() {
        use super::MemoryBackend;
        use crate::DbAssetActMod;
        use bdk_wallet::bitcoin::{Txid, hashes::Hash};
        use rgbstd::vm::WitnessOrd;
        use sea_orm::ActiveValue;
        use std::sync::Arc;

        fn asset(id: &str) -> DbAssetActMod {
            DbAssetActMod {
                id: ActiveValue::Set(id.to_string()),
                schema: ActiveValue::Set(AssetSchema::Nia),
                added_at: ActiveValue::Set(1),
                name: ActiveValue::Set("name".to_string()),
                precision: ActiveValue::Set(8),
                initial_supply: ActiveValue::Set("1000".to_string()),
                timestamp: ActiveValue::Set(1),
                ..Default::default()
            }
        }

        #[allow(clippy::arc_with_non_send_sync)]
        let backend = Arc::new(MemoryBackend::new());
        let txid_kept = Txid::from_byte_array([1; 32]);
        let txid_dropped = Txid::from_byte_array([2; 32]);

        let txn = backend.begin_transaction().unwrap();
        backend.db.set_asset(asset("kept")).unwrap();
        {
            let mut rgb = backend.rgb.lock().unwrap();
            rgb.put_witness_ord(txid_kept, WitnessOrd::Tentative)
                .unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(backend.db.iter_assets().unwrap().len(), 1);
        assert_eq!(
            backend.rgb.lock().unwrap().witness_ord(txid_kept).unwrap(),
            Some(WitnessOrd::Tentative)
        );

        let txn = backend.begin_transaction().unwrap();
        backend.db.set_asset(asset("dropped")).unwrap();
        {
            let mut rgb = backend.rgb.lock().unwrap();
            rgb.put_witness_ord(txid_dropped, WitnessOrd::Tentative)
                .unwrap();
        }
        drop(txn);

        let ids: Vec<_> = backend
            .db
            .iter_assets()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, vec!["kept".to_string()]);
        assert_eq!(
            backend
                .rgb
                .lock()
                .unwrap()
                .witness_ord(txid_dropped)
                .unwrap(),
            None
        );
        assert_eq!(
            backend.rgb.lock().unwrap().witness_ord(txid_kept).unwrap(),
            Some(WitnessOrd::Tentative)
        );
    }

    /// Savepoints over the memory backend: a successful one keeps its writes and its
    /// callbacks, a failing one restores the tables and drops its callbacks, all inside the
    /// same transaction.
    #[cfg(feature = "_online")]
    mod savepoint {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use sea_orm::ActiveValue;

        use super::*;
        use crate::database::DbTxn;
        use crate::{DbAssetActMod, Error, RgbLibDatabase};

        fn asset(id: &str) -> DbAssetActMod {
            DbAssetActMod {
                id: ActiveValue::Set(id.to_string()),
                schema: ActiveValue::Set(AssetSchema::Nia),
                added_at: ActiveValue::Set(1),
                name: ActiveValue::Set("name".to_string()),
                precision: ActiveValue::Set(8),
                initial_supply: ActiveValue::Set("1000".to_string()),
                timestamp: ActiveValue::Set(1),
                ..Default::default()
            }
        }

        fn asset_ids(txn: &DbTxn) -> Vec<String> {
            txn.iter_assets()
                .unwrap()
                .into_iter()
                .map(|a| a.id)
                .collect()
        }

        fn setup() -> RgbLibDatabase {
            let db = RgbLibDatabase::new_memory();
            setup_rgb(
                &db,
                vec![AssetSchema::Nia],
                BitcoinNetwork::Regtest,
                false,
                &slog::Logger::root(slog::Discard, slog::o!()),
            )
            .unwrap();
            db
        }

        #[test]
        fn savepoint_keeps_changes_on_success() {
            let db = setup();
            let txn = db.begin_transaction().unwrap();
            txn.with_savepoint(|t| {
                t.set_asset(asset("committed"))?;
                Ok(())
            })
            .unwrap();
            txn.commit().unwrap();

            let txn = db.begin_transaction().unwrap();
            assert_eq!(asset_ids(&txn), vec!["committed".to_string()]);
            txn.commit().unwrap();
        }

        #[test]
        fn failed_savepoint_restores_the_previous_state() {
            let db = setup();
            let txn = db.begin_transaction().unwrap();
            txn.set_asset(asset("kept")).unwrap();

            let res: Result<(), Error> = txn.with_savepoint(|t| {
                t.set_asset(asset("dropped"))?;
                Err(Error::Internal {
                    details: "savepoint failure".to_string(),
                })
            });
            assert!(res.is_err());
            assert_eq!(asset_ids(&txn), vec!["kept".to_string()]);

            txn.commit().unwrap();
            let txn = db.begin_transaction().unwrap();
            assert_eq!(asset_ids(&txn), vec!["kept".to_string()]);
            txn.commit().unwrap();
        }

        #[test]
        fn failed_savepoint_drops_its_callbacks() {
            let db = setup();
            let ran = Arc::new(AtomicUsize::new(0));
            let txn = db.begin_transaction().unwrap();

            let failing = ran.clone();
            let res: Result<(), Error> = txn.with_savepoint(|t| {
                t.on_commit(move || {
                    failing.fetch_add(1, Ordering::SeqCst);
                });
                Err(Error::Internal {
                    details: "savepoint failure".to_string(),
                })
            });
            assert!(res.is_err());

            let succeeding = ran.clone();
            txn.with_savepoint(|t| {
                t.on_commit(move || {
                    succeeding.fetch_add(1, Ordering::SeqCst);
                });
                Ok(())
            })
            .unwrap();
            assert_eq!(ran.load(Ordering::SeqCst), 0);

            txn.commit().unwrap();
            assert_eq!(ran.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn snapshot_round_trip_keeps_every_half() {
        use super::MemoryBackend;
        use crate::database::entities::wallet_transaction::ActiveModel as DbWalletTransactionActMod;
        use crate::database::enums::{SCHEMA_ID_NIA, WalletTransactionType};
        use crate::{DbAssetActMod, DbMediaActMod, RgbLibDatabase};
        use bdk_wallet::ChangeSet;
        use bdk_wallet::bitcoin::Network;
        use sea_orm::ActiveValue;

        let db = RgbLibDatabase::new_memory();
        setup_rgb(
            &db,
            vec![AssetSchema::Nia],
            BitcoinNetwork::Regtest,
            false,
            &slog::Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();
        let backend = db.memory_backend().unwrap().clone();

        {
            let txn = db.begin_transaction().unwrap();
            txn.set_asset(DbAssetActMod {
                id: ActiveValue::Set("asset-1".to_string()),
                schema: ActiveValue::Set(AssetSchema::Nia),
                added_at: ActiveValue::Set(1),
                name: ActiveValue::Set("name".to_string()),
                precision: ActiveValue::Set(8),
                initial_supply: ActiveValue::Set("1000".to_string()),
                timestamp: ActiveValue::Set(1),
                ..Default::default()
            })
            .unwrap();
            txn.set_media(DbMediaActMod {
                digest: ActiveValue::Set("digest-1".to_string()),
                mime: ActiveValue::Set("image/png".to_string()),
                ..Default::default()
            })
            .unwrap();
            backend
                .db
                .set_wallet_transaction(DbWalletTransactionActMod {
                    txid: ActiveValue::Set("wtx-1".to_string()),
                    r#type: ActiveValue::Set(WalletTransactionType::CreateUtxos),
                    ..Default::default()
                })
                .unwrap();
            backend
                .db
                .update_bdk_changeset(&ChangeSet {
                    network: Some(Network::Regtest),
                    ..Default::default()
                })
                .unwrap();
            txn.commit().unwrap();
        }

        let bytes = backend.to_snapshot().unwrap();
        let restored = MemoryBackend::from_snapshot(&bytes).unwrap();

        assert_eq!(
            restored.db.iter_assets().unwrap(),
            backend.db.iter_assets().unwrap()
        );
        assert_eq!(
            restored.db.iter_media().unwrap(),
            backend.db.iter_media().unwrap()
        );
        assert_eq!(
            restored.db.iter_wallet_transactions().unwrap(),
            backend.db.iter_wallet_transactions().unwrap()
        );
        assert_eq!(
            restored.db.get_bdk_changeset().unwrap().network,
            Some(Network::Regtest)
        );

        let schemata: Vec<String> = {
            let rgb = restored.rgb.lock().unwrap();
            <MemRgbStore as RgbStore>::schemata(&rgb)
                .map(|schema| schema.unwrap().schema_id().to_string())
                .collect()
        };
        assert!(schemata.contains(&SCHEMA_ID_NIA.to_string()));
    }

    #[test]
    fn snapshot_rejects_corrupt_input() {
        use super::MemoryBackend;
        use super::db::InMemoryDb;

        // truncated header
        assert!(MemoryBackend::from_snapshot(&[]).is_err());
        assert!(MemoryBackend::from_snapshot(&[1, 0, 0]).is_err());

        // wrong version
        assert!(MemoryBackend::from_snapshot(&[2, 0, 0, 0, 0]).is_err());

        // length larger than the input
        assert!(MemoryBackend::from_snapshot(&[1, 255, 255, 255, 255]).is_err());

        // invalid JSON
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(b"nope");
        assert!(MemoryBackend::from_snapshot(&bytes).is_err());

        // valid JSON, invalid RGB bytes
        let json = serde_json::to_vec(&InMemoryDb::new()).unwrap();
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&json);
        bytes.extend_from_slice(b"garbage");
        assert!(MemoryBackend::from_snapshot(&bytes).is_err());
    }

    #[test]
    fn snapshot_refuses_open_transactions() {
        use super::MemoryBackend;
        use rgbstd::persistence::TxMode;
        use std::sync::Arc;

        // wallet transaction open
        #[allow(clippy::arc_with_non_send_sync)]
        let backend = Arc::new(MemoryBackend::new());
        let txn = backend.begin_transaction().unwrap();
        assert!(backend.to_snapshot().is_err());
        drop(txn);
        assert!(backend.to_snapshot().is_ok());

        // RGB transaction open
        let backend = MemoryBackend::new();
        {
            let rgb = backend.rgb.lock().unwrap();
            let _ = rgb.begin(TxMode::Read);
        }
        assert!(backend.to_snapshot().is_err());
        backend.rgb.lock().unwrap().rollback();
        assert!(backend.to_snapshot().is_ok());
    }
}
