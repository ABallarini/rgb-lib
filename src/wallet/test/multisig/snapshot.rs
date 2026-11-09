use super::*;

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
