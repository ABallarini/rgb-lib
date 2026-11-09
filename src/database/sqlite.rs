//! Native SQLite adapter: connection creation and schema migrations.
//!
//! This is the boundary of the native storage adapter: it owns the `sqlite:` connection string,
//! the pool settings and the migration run, and hands back a database ready for the wallet layer.
//! On `wasm32` there is no filesystem to hold SQLite, so `RgbLibDatabase::new_memory` is used
//! instead and this module is not compiled.

use super::*;

use crate::wallet::core::RGB_LIB_DB_NAME;

/// Open the rgb-lib database inside `wallet_dir`, creating it and running the migrations if needed.
///
/// The pool keeps a single connection: SQLite is single-writer and rgb-lib holds the write
/// transaction open across BDK persist points.
pub(crate) fn open<P: AsRef<Path>>(wallet_dir: P) -> Result<RgbLibDatabase, Error> {
    let db_path = wallet_dir.as_ref().join(RGB_LIB_DB_NAME);
    let display_db_path = adjust_canonicalization(db_path);
    let connection_string = format!("sqlite:{display_db_path}?mode=rwc");
    let mut opt = ConnectOptions::new(connection_string);
    opt.max_connections(1)
        .min_connections(0)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8));
    let db_cnn = block_on(Database::connect(opt));
    let connection = db_cnn?;
    block_on(Migrator::up(&connection, None))?;
    Ok(RgbLibDatabase::new(connection))
}
