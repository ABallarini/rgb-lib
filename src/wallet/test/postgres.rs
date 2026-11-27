//! PostgreSQL wallet tests. They need `RGB_LIB_POSTGRES_URL`
//! (e.g. `postgres://rgb:rgb@localhost:55432/rgbwallet`) and are skipped without it.

use super::*;

use std::sync::atomic::{AtomicU64, Ordering};

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn pg_url() -> Option<String> {
    std::env::var("RGB_LIB_POSTGRES_URL")
        .ok()
        .filter(|url| !url.is_empty())
}

fn schema_name() -> String {
    format!(
        "rgb_lib_test_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn drop_schema(url: &str, schema: &str) {
    let connection = block_on(sea_orm::Database::connect(url)).unwrap();
    block_on(sea_orm::ConnectionTrait::execute_unprepared(
        &connection,
        &format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"),
    ))
    .unwrap();
    block_on(connection.close()).unwrap();
}

fn count_rows(url: &str, schema: &str, table: &str) -> i64 {
    let connection = block_on(sea_orm::Database::connect(url)).unwrap();
    let statement = sea_orm::Statement::from_string(
        sea_orm::DbBackend::Postgres,
        format!("SELECT count(*) AS n FROM \"{schema}\".\"{table}\""),
    );
    let row = block_on(sea_orm::ConnectionTrait::query_one_raw(
        &connection,
        statement,
    ))
    .unwrap()
    .unwrap();
    let count = row.try_get("", "n").unwrap();
    block_on(connection.close()).unwrap();
    count
}

fn wallet_data(data_dir: &str, url: &str, schema: &str) -> WalletData {
    WalletData {
        data_dir: data_dir.to_string(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Postgres(PostgresConfig {
            url: url.to_string(),
            schema: schema.to_string(),
        }),
        address_reuse_vanilla: false,
        address_reuse_colored_auto: false,
        max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
        supported_schemas: AssetSchema::VALUES.to_vec(),
        allow_reckless_schemas: false,
    }
}

#[test]
fn rejects_invalid_config() {
    let data_dir = PrivateDataDir::new();
    let keys = SinglesigKeys::from_keys(
        &generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot),
        None,
    );
    for (url, schema) in [
        (String::new(), "rgb_lib_test".to_string()),
        (
            "postgres://rgb:rgb@localhost/rgbwallet".to_string(),
            String::new(),
        ),
        (
            "postgres://rgb:rgb@localhost/rgbwallet".to_string(),
            "bad; DROP SCHEMA public".to_string(),
        ),
    ] {
        let res = Wallet::new(wallet_data(&data_dir.string(), &url, &schema), keys.clone());
        assert!(
            matches!(res, Err(Error::InvalidPostgresConfig { .. })),
            "expected invalid config for url={url:?} schema={schema:?}"
        );
    }
}

#[test]
fn wallet_lifecycle_in_postgres() {
    let Some(url) = pg_url() else {
        eprintln!("RGB_LIB_POSTGRES_URL not set, skipping");
        return;
    };
    let schema = schema_name();
    drop_schema(&url, &schema);

    let data_dir = PrivateDataDir::new();
    let keys = SinglesigKeys::from_keys(
        &generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot),
        None,
    );
    let wdata = wallet_data(&data_dir.string(), &url, &schema);

    let mut wallet = Wallet::new(wdata.clone(), keys.clone()).unwrap();
    // both BDK and RGB state live in the wallet schema
    assert!(count_rows(&url, &schema, "bdk_wallet") >= 1);
    assert!(count_rows(&url, &schema, "rgb_schema") >= 1);
    let address = wallet.get_address().unwrap();
    assert!(!address.is_empty());
    assert!(
        wallet
            .list_assets(vec![])
            .unwrap()
            .nia
            .unwrap_or_default()
            .is_empty()
    );

    // a second writer on the same schema is rejected by the advisory lock
    match Wallet::new(wdata.clone(), keys.clone()) {
        Err(Error::WalletInUse { schema: s }) => assert_eq!(s, schema),
        Ok(_) => panic!("expected WalletInUse, got a second wallet"),
        Err(e) => panic!("expected WalletInUse, got {e}"),
    }

    let backup_path = data_dir.sub_path("backup.rgb-lib_backup");
    assert!(matches!(
        wallet.backup(&backup_path.to_string_lossy(), "password"),
        Err(Error::DatabaseBackupNotSupported)
    ));

    // the lock is released with the wallet, so it reopens with its state
    drop(wallet);
    let mut wallet = Wallet::new(wdata, keys).unwrap();
    assert!(!wallet.get_address().unwrap().is_empty());
    assert_eq!(
        wallet.get_wallet_data().bitcoin_network,
        BitcoinNetwork::Regtest
    );

    drop(wallet);
    drop_schema(&url, &schema);
}
