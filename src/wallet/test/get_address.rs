use super::*;
use crate::utils::atomic_tmp_path;

#[test]
#[parallel]
fn success() {
    let data_dir = PrivateDataDir::new();
    let mut party = offline_party!(data_dir.wallet(false, None));
    let bak_info_before = party.db_backup_info_opt();
    assert!(bak_info_before.is_none());
    assert_eq!(
        party.wlt().get_wallet_data().data_dir,
        party.wlt_mut().get_wallet_data().data_dir
    );
    let address = party.wallet.get_address().unwrap();
    let bak_info_after = party.db_backup_info();
    assert!(
        bak_info_after
            .last_operation_timestamp
            .parse::<i128>()
            .unwrap()
            > 0
    );
    assert!(!address.is_empty());
}

// A revealed address index must not be lost when the transaction that wrote it rolls back. This
// is the in-process case: the change stays in the in-memory pending buffer and the next persist
// writes it again.
#[test]
#[parallel]
fn reveal_survives_rolled_back_txn() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);

    // reveal an address and write it, then roll the transaction back instead of committing
    let txn = wallet.database().begin_transaction().unwrap();
    let address = wallet.get_new_address().unwrap();
    wallet.persist_bdk(&txn).unwrap();
    drop(txn);

    // the reveal didn't reach the DB
    let txn = wallet.database().begin_transaction().unwrap();
    let changeset = txn.get_bdk_changeset().unwrap();
    txn.commit().unwrap();
    assert!(changeset.indexer.last_revealed.is_empty());

    // ...but it's still pending, so the next commit writes it
    let txn = wallet.database().begin_transaction().unwrap();
    wallet.persist_and_commit(txn).unwrap();

    let txn = wallet.database().begin_transaction().unwrap();
    let changeset = txn.get_bdk_changeset().unwrap();
    txn.commit().unwrap();
    assert!(!changeset.indexer.last_revealed.is_empty());

    // reloading the BDK wallet from the DB gives back the same address
    let reloaded = setup_bdk(
        wallet.database(),
        &*default_files(wallet.get_wallet_dir()),
        wallet.get_wallet_dir(),
        wallet.get_descriptors().colored,
        wallet.get_descriptors().vanilla,
        BitcoinNetwork::Regtest,
    )
    .unwrap();
    assert_eq!(
        reloaded
            .spk_index()
            .last_revealed_index(KeychainKind::External),
        wallet
            .bdk_wallet()
            .spk_index()
            .last_revealed_index(KeychainKind::External),
    );
    assert_eq!(
        reloaded
            .peek_address(
                KeychainKind::External,
                reloaded
                    .spk_index()
                    .last_revealed_index(KeychainKind::External)
                    .unwrap()
            )
            .address,
        address,
    );
}

// A crash after a broadcast must not lose the wallet's view of a TX that is already on the
// network: the pending changes are on disk and are folded back in when the wallet is reloaded.
#[test]
#[parallel]
fn bdk_pending_file_survives_a_crash() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let wallet_dir = wallet.get_wallet_dir();
    let descriptors = wallet.get_descriptors();

    // reveal an address and flush it the way a broadcast does, then lose the transaction
    let txn = wallet.database().begin_transaction().unwrap();
    let address = wallet.get_new_address().unwrap();
    wallet.flush_bdk_pending().unwrap();
    drop(txn);
    assert!(wallet_dir.join(BDK_PENDING_FILE).exists());

    // nothing reached the DB
    let txn = wallet.database().begin_transaction().unwrap();
    assert!(
        txn.get_bdk_changeset()
            .unwrap()
            .indexer
            .last_revealed
            .is_empty()
    );
    txn.commit().unwrap();

    // reloading the BDK wallet (as a restart would) recovers the reveal from the file
    let reloaded = setup_bdk(
        wallet.database(),
        &*default_files(&wallet_dir),
        &wallet_dir,
        descriptors.colored,
        descriptors.vanilla,
        BitcoinNetwork::Regtest,
    )
    .unwrap();

    let index = reloaded
        .spk_index()
        .last_revealed_index(KeychainKind::External)
        .expect("the revealed index must have survived");
    assert_eq!(
        reloaded.peek_address(KeychainKind::External, index).address,
        address
    );
    // the file is dropped once its contents are durably in the DB
    assert!(!wallet_dir.join(BDK_PENDING_FILE).exists());
}

// Recovery of the pending file happens while the wallet is being built, not at some later commit:
// a fresh instance must see the recovered state immediately, before any operation of its own.
#[test]
#[parallel]
fn recovered_pending_is_visible_right_after_load() {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let data_dir = PrivateDataDir::new();

    // a wallet that revealed an address, flushed it as a broadcast does, then died
    let (wallet_dir, address) = {
        let mut wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
        let txn = wallet.database().begin_transaction().unwrap();
        let address = wallet.get_new_address().unwrap();
        wallet.flush_bdk_pending().unwrap();
        drop(txn);
        (wallet.get_wallet_dir(), address)
    };
    assert!(wallet_dir.join(BDK_PENDING_FILE).exists());

    // restart: no commit of our own, just construction
    let wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    assert_eq!(wallet.get_wallet_dir(), wallet_dir);

    let index = wallet
        .bdk_wallet()
        .spk_index()
        .last_revealed_index(KeychainKind::External)
        .expect("the recovered index must be visible immediately after load");
    assert_eq!(
        wallet
            .bdk_wallet()
            .peek_address(KeychainKind::External, index)
            .address,
        address
    );
    // and it is already durable, so the file is gone
    assert!(!wallet_dir.join(BDK_PENDING_FILE).exists());
}

// A crash between the temporary write and the rename leaves the newest changes in the .tmp file
// only: they must still be recovered, and must not be silently truncated by the next flush.
#[test]
#[parallel]
fn pending_tmp_file_left_by_a_crash_is_recovered() {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let data_dir = PrivateDataDir::new();

    let (wallet_dir, address) = {
        let mut wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
        let txn = wallet.database().begin_transaction().unwrap();
        let address = wallet.get_new_address().unwrap();
        wallet.flush_bdk_pending().unwrap();
        drop(txn);
        (wallet.get_wallet_dir(), address)
    };

    // simulate the crash: the write and fsync completed, the rename did not
    let pending = wallet_dir.join(BDK_PENDING_FILE);
    let tmp = atomic_tmp_path(&pending).unwrap();
    fs::rename(&pending, &tmp).unwrap();
    assert!(!pending.exists() && tmp.exists());

    // restart: the reveal is recovered from the temporary file alone
    let wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    assert_eq!(wallet.get_wallet_dir(), wallet_dir);
    let index = wallet
        .bdk_wallet()
        .spk_index()
        .last_revealed_index(KeychainKind::External)
        .expect("the index written to the temporary file must have survived");
    assert_eq!(
        wallet
            .bdk_wallet()
            .peek_address(KeychainKind::External, index)
            .address,
        address
    );
    assert!(!tmp.exists());
}

// A crash can leave both the previous `bdk_pending.json` and a newer, fully written temporary
// file. The loader folds them in oldest first, so the newer one wins, and removes both once their
// contents are in the DB. No crash-recovery file may survive a successful load.
#[test]
#[parallel]
fn newer_tmp_file_wins_over_a_stale_pending_file() {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let data_dir = PrivateDataDir::new();

    let (wallet_dir, older_address, newer_address) = {
        let mut wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
        let txn = wallet.database().begin_transaction().unwrap();
        let pending = wallet.get_wallet_dir().join(BDK_PENDING_FILE);
        let older_address = wallet.get_new_address().unwrap();
        wallet.flush_bdk_pending().unwrap();
        let older_bytes = fs::read(&pending).unwrap();
        let newer_address = wallet.get_new_address().unwrap();
        wallet.flush_bdk_pending().unwrap();
        let newer_bytes = fs::read(&pending).unwrap();
        drop(txn);
        // simulate the interrupted rename: the old file is still in place, the new write is whole
        // but still under the temporary name
        fs::write(&pending, &older_bytes).unwrap();
        fs::write(atomic_tmp_path(&pending).unwrap(), &newer_bytes).unwrap();
        (wallet.get_wallet_dir(), older_address, newer_address)
    };

    let wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    assert_eq!(wallet.get_wallet_dir(), wallet_dir);
    let index = wallet
        .bdk_wallet()
        .spk_index()
        .last_revealed_index(KeychainKind::External)
        .expect("the newer changeset must have been recovered");
    assert_eq!(
        wallet
            .bdk_wallet()
            .peek_address(KeychainKind::External, index)
            .address,
        newer_address
    );
    // the older state is a prefix of the newer one, so the older address is still there
    assert_eq!(
        wallet
            .bdk_wallet()
            .peek_address(KeychainKind::External, 0)
            .address,
        older_address
    );

    // both crash-recovery files are gone now that their contents are in the DB
    assert_eq!(pending_files(&wallet_dir), Vec::<String>::new());
}

// A file that does not parse was still being written when the crash happened: its contents were
// never complete, so the wallet opens without them rather than refusing to open at all. The
// unreadable file is dropped like a recovered one.
#[test]
#[parallel]
fn corrupt_pending_file_is_dropped_instead_of_blocking_the_wallet() {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let data_dir = PrivateDataDir::new();

    let wallet_dir = {
        let wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
        wallet.get_wallet_dir()
    };
    let pending = wallet_dir.join(BDK_PENDING_FILE);
    fs::write(&pending, b"{\"totally\":\"not a changeset\"}").unwrap();
    assert!(pending.exists());

    let wallet = data_dir.wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    assert_eq!(wallet.get_wallet_dir(), wallet_dir);
    // the wallet is usable and its DB never took the junk in
    let txn = wallet.database().begin_transaction().unwrap();
    assert!(
        txn.get_bdk_changeset()
            .unwrap()
            .indexer
            .last_revealed
            .is_empty()
    );
    txn.commit().unwrap();
    wallet.bdk_wallet().peek_address(KeychainKind::External, 0);
    assert_eq!(pending_files(&wallet_dir), Vec::<String>::new());
}

/// The BDK crash-recovery files present in a wallet directory: the pending changeset and its
/// temporary sibling.
fn pending_files(wallet_dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(wallet_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.contains(BDK_PENDING_FILE))
        .collect();
    found.sort();
    found
}
