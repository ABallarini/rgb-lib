pub use sea_orm_migration::prelude::*;

pub use sea_orm_migration::sea_orm::DbBackend;

/// Column for a `u32` field: Postgres reads it only from `INTEGER`, SQLite keeps `BIGINT`.
pub fn unsigned_u32<I>(backend: DbBackend, iden: I) -> ColumnDef
where
    I: IntoIden,
{
    let mut col = ColumnDef::new(iden);
    if backend == DbBackend::Postgres {
        col.integer();
    } else {
        col.big_unsigned();
    };
    col
}

/// Nullable [`unsigned_u32`].
pub fn unsigned_u32_null<I>(backend: DbBackend, iden: I) -> ColumnDef
where
    I: IntoIden,
{
    let mut col = unsigned_u32(backend, iden);
    col.null();
    col
}

mod m20230608_071249_init_db;
mod m20251017_074408_asset_update;
mod m20251105_132121_asset_update;
mod m20251215_124959_backup_info_update;
mod m20260414_134758_add_reserved_txo;
mod m20260625_121819_incoming_rework;
mod m20260727_115821_add_bdk_tables;
mod m20261019_120000_add_transfer_indexes;
mod m20261020_093003_add_pending_witness_indexes;
mod m20261020_111428_reserved_txo_colored;
mod m20261020_141856_add_rgb_storage_tables;
mod m20261020_142324_proxy_v1;
mod m20261020_142840_asset_transfer_transition;
mod m20261020_143313_asset_links;
mod m20261117_104500_asset_reject_list;
mod m20261117_160000_asset_bridge_location;
mod m20261124_120000_consignment_extension;
mod m20261125_120000_invoice_reuse;
mod m20261125_130000_transfer_recipient_id_index;

pub use m20261124_120000_consignment_extension::Migration as ConsignmentExtensionMigration;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230608_071249_init_db::Migration),
            Box::new(m20251017_074408_asset_update::Migration),
            Box::new(m20251105_132121_asset_update::Migration),
            Box::new(m20251215_124959_backup_info_update::Migration),
            Box::new(m20260414_134758_add_reserved_txo::Migration),
            Box::new(m20260625_121819_incoming_rework::Migration),
            Box::new(m20260727_115821_add_bdk_tables::Migration),
            Box::new(m20261019_120000_add_transfer_indexes::Migration),
            Box::new(m20261020_093003_add_pending_witness_indexes::Migration),
            Box::new(m20261020_111428_reserved_txo_colored::Migration),
            Box::new(m20261020_141856_add_rgb_storage_tables::Migration),
            Box::new(m20261020_142324_proxy_v1::Migration),
            Box::new(m20261020_142840_asset_transfer_transition::Migration),
            Box::new(m20261020_143313_asset_links::Migration),
            Box::new(m20261117_104500_asset_reject_list::Migration),
            Box::new(m20261117_160000_asset_bridge_location::Migration),
            Box::new(m20261124_120000_consignment_extension::Migration),
            Box::new(m20261125_120000_invoice_reuse::Migration),
            Box::new(m20261125_130000_transfer_recipient_id_index::Migration),
        ]
    }
}
