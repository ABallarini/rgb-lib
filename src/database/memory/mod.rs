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
}

impl MemoryBackend {
    pub(crate) fn new() -> Self {
        Self {
            db: InMemoryDb::new(),
            rgb: Mutex::new(MemRgbStore::default()),
        }
    }

    /// Open one transaction covering both halves. The returned guard restores
    /// both snapshots on drop and releases both on commit.
    pub(crate) fn begin_transaction(self: &Arc<Self>) -> Result<MemoryTxn, Error> {
        self.db.open_tx()?;
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
    backend: Arc<MemoryBackend>,
    db_snapshot: Option<InMemoryDb>,
    rgb_snapshot: Option<RgbSavepoint>,
    on_commit: std::cell::RefCell<Vec<Box<dyn FnOnce()>>>,
}

impl MemoryTxn {
    pub(crate) fn backend(&self) -> &MemoryBackend {
        &self.backend
    }

    pub(crate) fn on_commit(&self, f: impl FnOnce() + 'static) {
        self.on_commit.borrow_mut().push(Box::new(f));
    }

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
            let mut rgb = self
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

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use rgbstd::persistence::{RgbStore, Stock};

    use super::rgb_store::MemRgbStore;
    use crate::RgbStock;
    use crate::database::enums::AssetSchema;
    use crate::utils::BitcoinNetwork;
    use crate::wallet::{setup_db, setup_rgb};

    /// The schemas imported by `setup_rgb` must be the same whether they are
    /// written through SQLite or through the in-memory store.
    #[test]
    fn memory_rgb_store_imports_the_same_schemata_as_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let db = setup_db(dir.path()).unwrap();
        setup_rgb(&db, vec![AssetSchema::Nia], BitcoinNetwork::Regtest).unwrap();

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
        use super::db::{ActiveValue, DbAssetActMod, DbMediaActMod, InMemoryDb};
        use crate::{DbAssetActMod as SqlAssetActMod, DbMediaActMod as SqlMediaActMod};

        let dir = tempfile::tempdir().unwrap();
        let sql_db = setup_db(dir.path()).unwrap();
        let sql_txn = sql_db.begin_transaction().unwrap();
        let sql_asset_idx = sql_txn
            .set_asset(SqlAssetActMod {
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
            .set_media(SqlMediaActMod {
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
        use super::db::{ActiveValue, DbAssetActMod};
        use bdk_wallet::bitcoin::{Txid, hashes::Hash};
        use rgbstd::vm::WitnessOrd;
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
}
