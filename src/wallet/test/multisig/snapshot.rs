use super::*;

fn memory_counts(wallet: &MultisigWallet) -> (usize, usize, usize, usize) {
    wallet
        .database()
        .memory_backend()
        .unwrap()
        .counters()
        .counts()
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

#[test]
#[parallel]
fn memory_database_operations_hit_injected_backend() {
    let data_dir = PrivateDataDir::new();
    let wallet = MultisigWallet::new_with_database(
        data_dir.wallet_data(),
        multisig_keys(),
        Some(RgbLibDatabase::new_memory()),
    )
    .unwrap();
    let before = memory_counts(&wallet);

    let wallet_data = wallet.get_wallet_data();
    assert_eq!(wallet_data.bitcoin_network, BitcoinNetwork::Regtest);
    let _descriptors = wallet.get_descriptors();
    let _assets = wallet.list_assets(vec![]).unwrap();

    let (begin, _writes, reads, _bdk) = memory_counts(&wallet);
    assert!(begin > before.0, "no transaction hit the injected backend");
    assert!(reads > before.2, "no asset read hit the injected backend");
}

#[test]
#[parallel]
fn memory_database_restored_operations_hit_injected_backend() {
    let data_dir = PrivateDataDir::new();
    let wallet_data = data_dir.wallet_data();
    let keys = multisig_keys();

    let wallet = MultisigWallet::new_with_database(
        wallet_data.clone(),
        keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .unwrap();
    let snapshot = wallet.snapshot().unwrap().unwrap();
    drop(wallet);

    let restored = MultisigWallet::from_snapshot(&snapshot, wallet_data, keys).unwrap();
    let before = memory_counts(&restored);

    let restored_data = restored.get_wallet_data();
    assert_eq!(restored_data.bitcoin_network, BitcoinNetwork::Regtest);
    let _descriptors = restored.get_descriptors();
    let _assets = restored.list_assets(vec![]).unwrap();

    let (begin, _writes, reads, _bdk) = memory_counts(&restored);
    assert!(begin > before.0, "no transaction hit the restored backend");
    assert!(reads > before.2, "no asset read hit the restored backend");
    assert!(restored.snapshot().unwrap().is_some());
}

#[test]
#[parallel]
fn native_constructor_selects_sqlite() {
    let data_dir = PrivateDataDir::new();
    let wallet = MultisigWallet::new(data_dir.wallet_data(), multisig_keys()).unwrap();
    assert!(wallet.database().memory_backend().is_none());
    assert_eq!(
        wallet.get_wallet_data().bitcoin_network,
        BitcoinNetwork::Regtest
    );
}

#[test]
#[parallel]
fn snapshot_and_restore_memory_success() {
    let data_dir = PrivateDataDir::new();
    let keys_1 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let keys_2 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let multisig_keys = MultisigKeys::new(
        vec![
            Cosigner::from_keys(&keys_1, None),
            Cosigner::from_keys(&keys_2, None),
        ],
        2,
        2,
    );
    let wallet_data = data_dir.wallet_data();

    let wallet = MultisigWallet::new_with_database(
        wallet_data.clone(),
        multisig_keys.clone(),
        Some(RgbLibDatabase::new_memory()),
    )
    .unwrap();

    // construction ran against the injected backend, not SQLite
    assert!(wallet.database().memory_backend().is_some());
    let descriptors = wallet.get_descriptors();
    let assets_before = wallet.list_assets(vec![]).unwrap();

    let snapshot = wallet.snapshot().unwrap().unwrap();
    assert!(!snapshot.is_empty());
    drop(wallet);

    // the files written by the first construction are in the same wallet dir
    let restored =
        MultisigWallet::from_snapshot(&snapshot, wallet_data.clone(), multisig_keys).unwrap();
    assert_eq!(
        restored.get_wallet_data().bitcoin_network,
        wallet_data.bitcoin_network
    );
    assert_eq!(restored.get_descriptors(), descriptors);
    let assets_after = restored.list_assets(vec![]).unwrap();
    assert_eq!(assets_after.nia, assets_before.nia);
    assert_eq!(assets_after.uda, assets_before.uda);
    assert_eq!(assets_after.cfa, assets_before.cfa);
    assert_eq!(assets_after.ifa, assets_before.ifa);
}

#[test]
#[parallel]
fn sqlite_snapshot_is_none() {
    let data_dir = PrivateDataDir::new();
    let keys_1 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let keys_2 = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let multisig_keys = MultisigKeys::new(
        vec![
            Cosigner::from_keys(&keys_1, None),
            Cosigner::from_keys(&keys_2, None),
        ],
        2,
        2,
    );
    let wallet = MultisigWallet::new(data_dir.wallet_data(), multisig_keys).unwrap();
    assert!(wallet.snapshot().unwrap().is_none());
}
