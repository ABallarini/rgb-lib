//! In-memory storage backend spike (Option A).
//!
//! The S05 spike evaluates whether the reference WASM in-memory RGB store
//! can back the same operations as the SQLite store. `rgb_store` is a port
//! of the reference implementation, kept behind `cfg(test)` until the S06
//! decision.

pub(crate) mod db;
pub(crate) mod rgb_store;

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
}
