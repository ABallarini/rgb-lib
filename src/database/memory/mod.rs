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
}
