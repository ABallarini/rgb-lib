//! Wallet backups: an encrypted, Zstd-compressed ZIP archive of the wallet state.
//!
//! The format is fixed: an outer ZIP holds `backup.pub_data` (the JSON scrypt/nonce/version
//! metadata) and `backup.enc` (the wallet archive encrypted with XChaCha20Poly1305, one chunk per
//! 239-byte plaintext block). The key is derived from the password with scrypt.
//!
//! The archive assembly, encryption and decryption are byte-oriented and shared by every target:
//! [`create_backup_bytes`] produces the archive, [`restore_backup_bytes`] decrypts and unpacks it,
//! and [`backup_info_bytes`] reads its public metadata. The native path-writing entry points are
//! thin wrappers over them. On wasm the same outer format carries the wallet snapshot envelope,
//! because a browser wallet keeps its database and files in memory instead of a wallet directory.

use super::*;

const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239; // 255 max, leaving 16 for the checksum
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;
const BACKUP_VERSION: u8 = 1;
const BACKUP_PUB_DATA_FILE: &str = "backup.pub_data";
const BACKUP_ENCRYPTED_FILE: &str = "backup.enc";
// wasm: the wallet state is its snapshot envelope, stored under the wallet fingerprint so the
// archive keeps the native layout's leading directory entry
#[cfg(target_arch = "wasm32")]
const WASM_BACKUP_SNAPSHOT_FILE: &str = "wallet_snapshot";

/// Backups on wasm are byte-oriented: these entry points take or return paths and a filesystem, so
/// they keep reporting that explicitly. Use the byte API instead.
#[cfg(target_arch = "wasm32")]
fn backup_unsupported(operation: &str) -> Error {
    Error::Internal {
        details: format!(
            "{operation} is not supported on wasm32: it takes a filesystem path; use the byte \
             backup API instead"
        ),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScryptParams {
    log_n: u8,
    r: u32,
    p: u32,
    len: usize,
}

impl ScryptParams {
    pub(crate) fn new(log_n: Option<u8>, r: Option<u32>, p: Option<u32>) -> ScryptParams {
        ScryptParams {
            log_n: log_n.unwrap_or(Params::RECOMMENDED_LOG_N),
            r: r.unwrap_or(Params::RECOMMENDED_R),
            p: p.unwrap_or(Params::RECOMMENDED_P),
            len: BACKUP_KEY_LENGTH,
        }
    }
}

impl Default for ScryptParams {
    fn default() -> ScryptParams {
        ScryptParams::new(None, None, None)
    }
}

impl TryInto<Params> for ScryptParams {
    type Error = Error;

    fn try_into(self: ScryptParams) -> Result<Params, Error> {
        Params::new_with_output_len(self.log_n, self.r, self.p, self.len).map_err(|e| {
            Error::Internal {
                details: format!("invalid params {e}"),
            }
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BackupPubData {
    scrypt_params: ScryptParams,
    salt: String,
    nonce: String,
    pub(crate) version: u8,
}

impl BackupPubData {
    fn nonce(&self) -> Result<[u8; BACKUP_NONCE_LENGTH], InternalError> {
        let nonce_bytes = self.nonce.as_bytes();
        nonce_bytes[0..BACKUP_NONCE_LENGTH]
            .try_into()
            .map_err(|_| InternalError::Unexpected)
    }
}

/// The public metadata of a backup archive: its format version and the scrypt parameters needed to
/// derive the key. It holds no password and no secret.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    /// Backup format version.
    pub version: u8,
    /// scrypt parameters the backup payload was encrypted with.
    pub scrypt_params: ScryptParams,
}

/// One entry of a backup archive: a file with its bytes, or a directory when `bytes` is `None`.
pub(crate) struct BackupEntry {
    name: String,
    bytes: Option<Vec<u8>>,
}

impl BackupEntry {
    fn file(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            bytes: Some(bytes.into()),
        }
    }

    fn dir(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bytes: None,
        }
    }
}

/// A decrypted and unpacked backup: the wallet fingerprint from its leading archive entry and the
/// contained files and directories.
pub struct RestoredBackup {
    pub(crate) fingerprint: String,
    pub(crate) entries: Vec<RestoredEntry>,
}

pub(crate) struct RestoredEntry {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Option<Vec<u8>>,
}

impl RestoredBackup {
    /// The wallet fingerprint the backup was taken from.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The wallet snapshot envelope carried by a browser backup, for
    /// [`Wallet::from_snapshot`](crate::wallet::Wallet::from_snapshot).
    #[cfg(target_arch = "wasm32")]
    pub fn wallet_snapshot(&self) -> Result<Vec<u8>, Error> {
        self.entries
            .iter()
            .find(|entry| {
                entry.bytes.is_some()
                    && entry.path.file_name().and_then(|name| name.to_str())
                        == Some(WASM_BACKUP_SNAPSHOT_FILE)
            })
            .and_then(|entry| entry.bytes.clone())
            .ok_or_else(|| Error::Internal {
                details: "the backup carries no browser wallet snapshot".to_string(),
            })
    }
}

pub trait WalletBackup: WalletCore {
    /// For now setting the scrypt params is done only for testing purposes,
    /// a few details should be refined before allowing to set this in the public API:
    /// - Which parameters should we allow users to change? Should we set sensible minimums?
    /// - Can we guarantee old backups can always be recovered in the future?
    fn backup_customize(
        &self,
        backup_path: &str,
        password: &str,
        scrypt_params: Option<ScryptParams>,
    ) -> Result<(), Error> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (backup_path, password, scrypt_params);
            Err(backup_unsupported("a wallet backup"))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.with_backup_info(|| self.backup_raw(backup_path, password, scrypt_params))
        }
    }

    /// Create an encrypted backup and return its bytes, without touching the filesystem.
    ///
    /// It carries the same archive and encryption format as the native file backup: on native the
    /// inner archive is the wallet directory, on wasm it is the in-memory wallet snapshot envelope.
    fn backup_bytes(&self, password: &str) -> Result<Vec<u8>, Error> {
        self.with_backup_info(|| self.backup_bytes_impl(password))
    }

    /// Mark the backup as done when the operation succeeds, or restore the previous backup
    /// bookkeeping when it fails.
    fn with_backup_info<T>(&self, backup: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let txn = self.database().begin_transaction()?;
        let prev_backup_info = self.update_backup_info(&txn, true)?;
        txn.commit()?;
        match backup() {
            Ok(value) => Ok(value),
            Err(e) => {
                error!(self.logger(), "Error during backup: {e:?}");
                let txn = self.database().begin_transaction()?;
                if let Some(prev_backup_info) = prev_backup_info {
                    let mut prev_backup_info: DbBackupInfoActMod = prev_backup_info.into();
                    txn.update_backup_info(&mut prev_backup_info)?;
                } else {
                    txn.del_backup_info()?;
                }
                txn.commit()?;
                Err(e)
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn backup_raw(
        &self,
        backup_path: &str,
        password: &str,
        scrypt_params: Option<ScryptParams>,
    ) -> Result<(), Error> {
        info!(self.logger(), "starting backup...");
        self.write_backup_file(backup_path, password, scrypt_params)?;
        info!(self.logger(), "backup completed");
        Ok(())
    }

    /// Write a file backup and return the exact bytes written, so a caller can prove the file and
    /// the byte path agree.
    #[cfg(not(target_arch = "wasm32"))]
    fn write_backup_file(
        &self,
        backup_path: &str,
        password: &str,
        scrypt_params: Option<ScryptParams>,
    ) -> Result<Vec<u8>, Error> {
        let backup_file = PathBuf::from(&backup_path);
        if backup_file.exists() {
            Err(Error::FileAlreadyExists {
                path: backup_path.to_string(),
            })?;
        }
        let parent = get_parent_path(&backup_file)?;
        // the old tempdir-in-parent setup created a missing parent as a side effect
        fs::create_dir_all(parent)?;
        let bytes = wallet_backup_bytes(self.wallet_dir(), password, scrypt_params, self.logger())?;
        let mut file = fs::File::create(&backup_file)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(bytes)
    }

    /// Native: the inner archive is the wallet directory.
    #[cfg(not(target_arch = "wasm32"))]
    fn backup_bytes_impl(&self, password: &str) -> Result<Vec<u8>, Error> {
        wallet_backup_bytes(self.wallet_dir(), password, None, self.logger())
    }

    /// wasm: the inner archive is the wallet snapshot envelope, under the wallet fingerprint.
    /// Implemented per wallet type, where the inherent snapshot method and identity are available.
    #[cfg(target_arch = "wasm32")]
    fn backup_bytes_impl(&self, password: &str) -> Result<Vec<u8>, Error>;

    fn get_backup_info(&self, txn: &DbTxn) -> Result<bool, Error> {
        Ok(if let Some(backup_info) = txn.get_backup_info()? {
            backup_info
                .last_operation_timestamp
                .parse::<i128>()
                .unwrap()
                > backup_info.last_backup_timestamp.parse::<i128>().unwrap()
        } else {
            false
        })
    }

    fn update_backup_info_with_op_idx(
        &self,
        txn: &DbTxn,
        doing_backup: bool,
        last_processed_operation_idx: Option<i32>,
    ) -> Result<Option<DbBackupInfo>, Error> {
        let now = ActiveValue::Set(now().unix_timestamp_nanos().to_string());
        let last_processed_operation_idx = if last_processed_operation_idx.is_some() {
            ActiveValue::Set(last_processed_operation_idx)
        } else {
            ActiveValue::NotSet
        };
        Ok(if let Some(backup_info) = txn.get_backup_info()? {
            let prev_backup_info = backup_info.clone();
            let mut backup_info: DbBackupInfoActMod = backup_info.into();
            if doing_backup {
                backup_info.last_backup_timestamp = now;
            } else {
                backup_info.last_operation_timestamp = now;
            }
            backup_info.last_processed_operation_idx = last_processed_operation_idx;
            txn.update_backup_info(&mut backup_info)?;
            Some(prev_backup_info)
        } else {
            let (last_backup_timestamp, last_operation_timestamp) = if doing_backup {
                (now, ActiveValue::Set(s!("0")))
            } else {
                (ActiveValue::Set(s!("0")), now)
            };
            let backup_info = DbBackupInfoActMod {
                last_backup_timestamp,
                last_operation_timestamp,
                last_processed_operation_idx,
                ..Default::default()
            };
            txn.set_backup_info(backup_info)?;
            None
        })
    }

    fn update_backup_info(
        &self,
        txn: &DbTxn,
        doing_backup: bool,
    ) -> Result<Option<DbBackupInfo>, Error> {
        self.update_backup_info_with_op_idx(txn, doing_backup, None)
    }
}

/// Build a backup archive from `entries` with the fixed backup format.
///
/// The result is the complete outer ZIP: `backup.pub_data` with a fresh salt and nonce, and
/// `backup.enc` holding the Zstd-compressed `entries` archive encrypted for `password`.
pub(crate) fn create_backup_bytes(
    entries: &[BackupEntry],
    password: &str,
    scrypt_params: Option<ScryptParams>,
    logger: &Logger,
) -> Result<Vec<u8>, Error> {
    let scrypt_params = scrypt_params.unwrap_or_default();
    let salt: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    let str_params = serde_json::to_string(&scrypt_params).map_err(InternalError::from)?;
    debug!(logger, "using generated scrypt params: {}", str_params);
    let nonce: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(BACKUP_NONCE_LENGTH)
        .map(char::from)
        .collect();
    debug!(logger, "using generated nonce: {}", &nonce);
    let backup_pub_data = BackupPubData {
        scrypt_params,
        salt,
        nonce,
        version: BACKUP_VERSION,
    };

    debug!(logger, "zipping {} entries", entries.len());
    let zip = zip_entries(entries, logger)?;
    let encrypted = encrypt_bytes(&zip, password, &backup_pub_data)?;
    let pub_data = serde_json::to_vec(&backup_pub_data).map_err(InternalError::from)?;
    zip_entries(
        &[
            BackupEntry::file(BACKUP_ENCRYPTED_FILE, encrypted),
            BackupEntry::file(BACKUP_PUB_DATA_FILE, pub_data),
        ],
        logger,
    )
}

/// Native wallet backup: archive the wallet directory and wrap it in the backup format.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn wallet_backup_bytes(
    wallet_dir: &PathBuf,
    password: &str,
    scrypt_params: Option<ScryptParams>,
    logger: &Logger,
) -> Result<Vec<u8>, Error> {
    let entries = wallet_entries(wallet_dir, true, logger)?;
    create_backup_bytes(&entries, password, scrypt_params, logger)
}

/// wasm wallet backup: carry the wallet snapshot envelope in the same outer archive format.
#[cfg(target_arch = "wasm32")]
pub(crate) fn wasm_backup_bytes(
    fingerprint: &str,
    snapshot: Vec<u8>,
    password: &str,
    logger: &Logger,
) -> Result<Vec<u8>, Error> {
    let entries = [
        BackupEntry::dir(fingerprint),
        BackupEntry::file(
            format!("{fingerprint}/{WASM_BACKUP_SNAPSHOT_FILE}"),
            snapshot,
        ),
    ];
    create_backup_bytes(&entries, password, None, logger)
}

/// Restore a backup from bytes: decrypt it and unpack the wallet archive.
///
/// The wallet fingerprint comes from the archive's leading entry, as in the native restore. The
/// returned files are not written anywhere; the caller applies them to its storage (a directory on
/// native, the wallet snapshot on wasm).
pub fn restore_backup_bytes(bytes: &[u8], password: &str) -> Result<RestoredBackup, Error> {
    restore_backup_bytes_labeled(bytes, password, None)
}

fn restore_backup_bytes_labeled(
    bytes: &[u8],
    password: &str,
    path_label: Option<&str>,
) -> Result<RestoredBackup, Error> {
    let (backup_pub_data, encrypted) = backup_parts(bytes, path_label)?;
    if backup_pub_data.version != BACKUP_VERSION {
        return Err(Error::UnsupportedBackupVersion {
            version: backup_pub_data.version.to_string(),
        });
    }
    let zip = decrypt_bytes(&encrypted, password, &backup_pub_data)?;
    unzip_in_memory(&zip, path_label)
}

/// Read the public metadata of a backup without its password.
pub fn backup_info_bytes(bytes: &[u8]) -> Result<BackupInfo, Error> {
    let (backup_pub_data, _) = backup_parts(bytes, None)?;
    Ok(BackupInfo {
        version: backup_pub_data.version,
        scrypt_params: backup_pub_data.scrypt_params,
    })
}

/// Restore a backup from the given file and password to the provided target directory.
pub fn restore_backup(backup_path: &str, password: &str, target_dir: &str) -> Result<(), Error> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (backup_path, password, target_dir);
        Err(backup_unsupported("restoring a wallet backup"))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // setup
        fs::create_dir_all(target_dir)?;
        let log_dir = Path::new(&target_dir);
        let log_name = format!("restore_{}", now().unix_timestamp());
        let (logger, _logger_guard) = setup_logger(log_dir, Some(&log_name))?;
        info!(logger, "starting restore...");
        let backup_file = PathBuf::from(backup_path);
        let bytes = fs::read(&backup_file).map_err(|_| Error::InvalidFilePath {
            file_path: backup_path.to_string(),
        })?;
        let target_dir_path = PathBuf::from(&target_dir);

        // decrypt and unpack the given backup
        info!(logger, "decrypting and unzipping {:?}", backup_file);
        let restored = restore_backup_bytes_labeled(&bytes, password, Some(backup_path))?;

        // check the target wallet directory doesn't already exist
        let fingerprint = restored.fingerprint.clone();
        let wallet_dir = target_dir_path.join(fingerprint);
        if wallet_dir.exists() {
            return Err(Error::WalletDirAlreadyExists {
                path: wallet_dir.to_string_lossy().to_string(),
            });
        }

        // restore files
        info!(
            logger,
            "unzipping the wallet archive to {:?}", &target_dir_path
        );
        write_restored_entries(&restored.entries, &target_dir_path, &logger)?;

        info!(logger, "restore completed");
        Ok(())
    }
}

/// Write an archive of `entries` into a ZIP, Zstd-compressing every file.
fn zip_entries(entries: &[BackupEntry], logger: &Logger) -> Result<Vec<u8>, Error> {
    let mut zip = ZipWriter::new(io::Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
    for entry in entries {
        match &entry.bytes {
            Some(bytes) => {
                debug!(
                    logger,
                    "adding file {:?} ({} bytes)",
                    entry.name,
                    bytes.len()
                );
                zip.start_file(&entry.name, options)
                    .map_err(InternalError::from)?;
                zip.write_all(bytes)?;
            }
            None => {
                debug!(logger, "adding directory {:?}", entry.name);
                zip.add_directory(&entry.name, options)
                    .map_err(InternalError::from)?;
            }
        }
    }
    Ok(zip
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(InternalError::from)?)
}

fn invalid_archive(path_label: Option<&str>, error: impl std::fmt::Display) -> Error {
    match path_label {
        Some(path) => Error::InvalidFilePath {
            file_path: path.to_string(),
        },
        None => Error::Internal {
            details: format!("invalid backup archive: {error}"),
        },
    }
}

/// Split the outer archive into its public metadata and encrypted payload.
fn backup_parts(bytes: &[u8], path_label: Option<&str>) -> Result<(BackupPubData, Vec<u8>), Error> {
    let mut archive =
        ZipArchive::new(io::Cursor::new(bytes)).map_err(|e| invalid_archive(path_label, e))?;
    let mut pub_data = None;
    let mut encrypted = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(InternalError::from)?;
        let name = entry.name().map_err(InternalError::from)?;
        match name.as_ref() {
            BACKUP_PUB_DATA_FILE => {
                let mut json = String::new();
                entry.read_to_string(&mut json)?;
                pub_data = Some(serde_json::from_str(json.as_str()).map_err(InternalError::from)?);
            }
            BACKUP_ENCRYPTED_FILE => {
                let mut payload = Vec::new();
                entry.read_to_end(&mut payload)?;
                encrypted = Some(payload);
            }
            _ => {}
        }
    }
    let pub_data = pub_data.ok_or_else(|| Error::Internal {
        details: "invalid backup archive: no backup metadata".to_string(),
    })?;
    let encrypted = encrypted.ok_or_else(|| Error::Internal {
        details: "invalid backup archive: no encrypted payload".to_string(),
    })?;
    Ok((pub_data, encrypted))
}

/// Unpack a wallet archive from memory, rejecting entries that escape its root.
fn unzip_in_memory(bytes: &[u8], path_label: Option<&str>) -> Result<RestoredBackup, Error> {
    let mut archive =
        ZipArchive::new(io::Cursor::new(bytes)).map_err(|e| invalid_archive(path_label, e))?;
    let fingerprint = archive
        .name_for_index(0)
        .transpose()
        .map_err(InternalError::from)?
        .unwrap_or_default()
        .to_string()
        .replace("/", "");
    let mut entries = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(InternalError::from)?;
        let Some(path) = entry.enclosed_name() else {
            continue;
        };
        let is_dir = entry.is_dir();
        let bytes = if is_dir {
            None
        } else {
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;
            Some(contents)
        };
        entries.push(RestoredEntry { path, bytes });
    }
    Ok(RestoredBackup {
        fingerprint,
        entries,
    })
}

/// Native: write the unpacked archive to a directory, creating parents as the ZIP extractor did.
#[cfg(not(target_arch = "wasm32"))]
fn write_restored_entries(
    entries: &[RestoredEntry],
    path_out: &Path,
    logger: &Logger,
) -> Result<(), Error> {
    for entry in entries {
        let outpath = path_out.join(&entry.path);
        match &entry.bytes {
            Some(bytes) => {
                debug!(
                    logger,
                    "extracting file to {} ({} bytes)",
                    outpath.display(),
                    bytes.len()
                );
                if let Some(parent) = outpath.parent()
                    && !parent.exists()
                {
                    debug!(logger, "creating parent dir {}", parent.display());
                    fs::create_dir_all(parent)?;
                }
                fs::write(&outpath, bytes)?;
            }
            None => {
                debug!(logger, "creating directory {}", outpath.display());
                fs::create_dir_all(&outpath)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn get_parent_path(file: &Path) -> Result<PathBuf, Error> {
    if let Some(parent) = file.parent() {
        Ok(parent.to_path_buf())
    } else {
        Err(Error::IO {
            details: "provided file path has no parent".to_string(),
        })
    }
}

/// Native: collect the wallet directory entries exactly as the archive has always stored them.
///
/// The root directory is skipped when `keep_last_path_component` is false; with it true the wallet
/// directory's own name becomes the leading entry, which is where the fingerprint comes from.
#[cfg(not(target_arch = "wasm32"))]
fn wallet_entries(
    path_in: &PathBuf,
    keep_last_path_component: bool,
    logger: &Logger,
) -> Result<Vec<BackupEntry>, Error> {
    let prefix = if keep_last_path_component {
        if let Some(parent) = path_in.parent() {
            parent
        } else {
            return Err(Error::Internal {
                details: "no parent directory".to_string(),
            });
        }
    } else {
        path_in
    };
    let mut entries = Vec::new();
    // a legacy RGB store migration that crashed between retiring the legacy store and deleting it
    // can leave the retired copy behind: skip its whole subtree, the DB holds its data
    let entry_iterator = WalkDir::new(path_in)
        .into_iter()
        .filter_entry(|e| !e.path().ends_with(RGB_RUNTIME_DELETING_DIR));
    for entry in entry_iterator {
        let entry = entry.map_err(std::io::Error::from)?;
        let path = entry.path();
        let name = path.strip_prefix(prefix).map_err(InternalError::from)?;
        let name_str = name.to_str().ok_or(InternalError::Unexpected)?;
        if path.is_file() {
            if path.ends_with(LOG_FILE) {
                continue;
            }; // skip log file
            debug!(logger, "adding file {path:?} as {name:?}");
            entries.push(BackupEntry::file(name_str, fs::read(path)?));
        } else if !name.as_os_str().is_empty() {
            debug!(logger, "adding directory {path:?} as {name:?}");
            entries.push(BackupEntry::dir(name_str));
        }
    }
    Ok(entries)
}

/// Test-only: replace the version recorded in a backup's public metadata.
#[cfg(test)]
pub(crate) fn rewrite_backup_version(bytes: &[u8], version: u8) -> Result<Vec<u8>, Error> {
    let (mut pub_data, encrypted) = backup_parts(bytes, None)?;
    pub_data.version = version;
    let json = serde_json::to_vec(&pub_data).map_err(InternalError::from)?;
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    zip_entries(
        &[
            BackupEntry::file(BACKUP_ENCRYPTED_FILE, encrypted),
            BackupEntry::file(BACKUP_PUB_DATA_FILE, json),
        ],
        &logger,
    )
}

fn get_cypher_secrets(password: &str, backup_pub_data: &BackupPubData) -> Result<Key, Error> {
    // hash password using scrypt with the provided salt
    let password_bytes = password.as_bytes();
    let salt = Salt::from_b64(&backup_pub_data.salt).map_err(InternalError::from)?;
    let params = backup_pub_data.scrypt_params.clone().try_into()?;
    let mut hash = [0u8; BACKUP_KEY_LENGTH];
    crate::executor::cpu_executor()
        .scrypt(password_bytes, salt.as_ref(), &params, &mut hash)
        .map_err(|_| Error::Internal {
            details: s!("failed to derive backup encryption key"),
        })?;

    // get key from password hash
    let key =
        Key::try_from(hash.as_slice()).expect("scrypt output length matches XChaCha20 key size");

    Ok(key)
}

fn stream_be32_nonce(
    prefix: &[u8; BACKUP_NONCE_LENGTH],
    position: u32,
    last_block: bool,
) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..BACKUP_NONCE_LENGTH].copy_from_slice(prefix);
    nonce[BACKUP_NONCE_LENGTH..(BACKUP_NONCE_LENGTH + 4)].copy_from_slice(&position.to_be_bytes());
    nonce[BACKUP_NONCE_LENGTH + 4] = u8::from(last_block);
    nonce.into()
}

fn encrypt_bytes(
    cleartext: &[u8],
    password: &str,
    backup_pub_data: &BackupPubData,
) -> Result<Vec<u8>, Error> {
    let key = get_cypher_secrets(password, backup_pub_data)?;

    // - XChacha20Poly1305 is fast and requires no special hardware
    // - the payload is encrypted chunk-by-chunk to bound the memory each AEAD operation needs
    let aead = XChaCha20Poly1305::new(&key);
    let nonce_prefix = backup_pub_data.nonce()?;
    let mut position: u32 = 0;
    let mut chunks = cleartext.chunks(BACKUP_BUFFER_LEN_ENCRYPT);
    let mut encrypted = Vec::with_capacity(cleartext.len() + cleartext.len() / 128 + 16);
    loop {
        let chunk = chunks.next().unwrap_or(&[]);
        let is_last = chunk.len() != BACKUP_BUFFER_LEN_ENCRYPT;
        if !is_last && position == u32::MAX {
            return Err(Error::Internal {
                details: s!("backup file too large"),
            });
        }

        let nonce = stream_be32_nonce(&nonce_prefix, position, is_last);
        let ciphertext = aead
            .encrypt(&nonce, chunk)
            .expect("chunk size is within XChaCha20Poly1305 limits");
        encrypted.extend_from_slice(&ciphertext);

        if is_last {
            break;
        }
        position += 1;
    }

    Ok(encrypted)
}

fn decrypt_bytes(
    ciphertext: &[u8],
    password: &str,
    backup_pub_data: &BackupPubData,
) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    let key = get_cypher_secrets(password, backup_pub_data)?;

    let aead = XChaCha20Poly1305::new(&key);
    let nonce_prefix = backup_pub_data.nonce()?;
    let mut position: u32 = 0;
    let mut cleartext = Vec::with_capacity(ciphertext.len());
    let mut offset = 0;
    loop {
        let remaining = ciphertext.len() - offset;
        let chunk_len = remaining.min(BACKUP_BUFFER_LEN_DECRYPT);
        let is_last = chunk_len != BACKUP_BUFFER_LEN_DECRYPT;
        if !is_last && position == u32::MAX {
            return Err(Error::Internal {
                details: s!("backup file too large"),
            });
        }
        let nonce = stream_be32_nonce(&nonce_prefix, position, is_last);
        let chunk = &ciphertext[offset..offset + chunk_len];
        let plain = aead
            .decrypt(&nonce, chunk)
            .map_err(|_| Error::WrongPassword)?;
        cleartext.extend_from_slice(&plain);

        if is_last {
            break;
        }
        offset += chunk_len;
        position += 1;
    }

    Ok(cleartext)
}

// The native ZIP helpers only exist off wasm; the byte path is covered by the browser suite.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn logger() -> Logger {
        slog::Logger::root(slog::Discard, slog::o!())
    }

    fn fixture() -> Vec<BackupEntry> {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        vec![
            BackupEntry::dir("wallet-fingerprint"),
            BackupEntry::dir("wallet-fingerprint/nested"),
            BackupEntry::dir("wallet-fingerprint/nested/empty"),
            BackupEntry::file("wallet-fingerprint/nested/payload", payload),
        ]
    }

    #[test]
    fn byte_backup_round_trip_and_info() {
        let entries = fixture();
        // cheap params keep the test fast; the restore reads them from the archive
        let params = ScryptParams::new(Some(4), Some(1), Some(1));
        let bytes = create_backup_bytes(&entries, "password", Some(params), &logger()).unwrap();

        let info = backup_info_bytes(&bytes).unwrap();
        assert_eq!(info.version, BACKUP_VERSION);
        assert_eq!(info.scrypt_params.log_n, 4);

        let restored = restore_backup_bytes(&bytes, "password").unwrap();
        assert_eq!(restored.fingerprint(), "wallet-fingerprint");
        let payload = restored
            .entries
            .iter()
            .find(|e| e.path.to_string_lossy() == "wallet-fingerprint/nested/payload")
            .and_then(|e| e.bytes.clone())
            .unwrap();
        assert_eq!(
            payload,
            (0..10_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        );

        assert!(matches!(
            restore_backup_bytes(&bytes, "wrong"),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn zip_entries_missing_source() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("missing");
        let result = wallet_entries(&source, false, &logger());
        assert!(matches!(result, Err(Error::IO { details }) if details.contains("missing")));
    }

    #[cfg(unix)]
    #[test]
    fn zip_entries_unreadable_directory() {
        // Restore permissions on every exit path so TempDir can clean up, including on panics.
        struct RestorePermissions<'a>(&'a Path, fs::Permissions);

        impl Drop for RestorePermissions<'_> {
            fn drop(&mut self) {
                let _ = fs::set_permissions(self.0, self.1.clone());
            }
        }

        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("source");
        let unreadable = source.join("unreadable");
        fs::create_dir_all(&unreadable).unwrap();
        fs::write(unreadable.join("contents"), b"must not be silently omitted").unwrap();
        let permissions = fs::metadata(&unreadable).unwrap().permissions();
        let _guard = RestorePermissions(&unreadable, permissions);
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        // Permission bits are not enforced for privileged users (root or CAP_DAC_OVERRIDE).
        if fs::read_dir(&unreadable).is_ok() {
            return;
        }

        let result = wallet_entries(&source, false, &logger());
        assert!(matches!(result, Err(Error::IO { details }) if details.contains("unreadable")));
    }

    #[test]
    fn zip_zstd_round_trip() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("wallet-fingerprint");
        fs::create_dir_all(source.join("nested/empty")).unwrap();
        // larger than one encryption chunk, so it gets written in multiple chunks
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(source.join("nested/payload"), &payload).unwrap();
        fs::write(source.join(LOG_FILE), b"must not be archived").unwrap();

        let entries = wallet_entries(&source, true, &logger()).unwrap();
        let archive_bytes = zip_entries(&entries, &logger()).unwrap();

        // archive contains the wallet dir (empty dirs included), without the log file
        {
            let mut archive = ZipArchive::new(io::Cursor::new(&archive_bytes)).unwrap();
            let mut names = archive
                .file_names()
                .map(|n| n.unwrap().into_owned())
                .collect::<Vec<_>>();
            names.sort();
            assert_eq!(
                names,
                [
                    "wallet-fingerprint/",
                    "wallet-fingerprint/nested/",
                    "wallet-fingerprint/nested/empty/",
                    "wallet-fingerprint/nested/payload",
                ]
            );
            let entry = archive
                .by_name("wallet-fingerprint/nested/payload")
                .unwrap();
            assert_eq!(entry.compression(), zip::CompressionMethod::Zstd);
        }

        let restored = unzip_in_memory(&archive_bytes, None).unwrap();
        assert_eq!(restored.fingerprint, "wallet-fingerprint");
        let output = tempdir.path().join("restored");
        write_restored_entries(&restored.entries, &output, &logger()).unwrap();
        assert_eq!(
            fs::read(output.join("wallet-fingerprint/nested/payload")).unwrap(),
            payload
        );
        assert!(output.join("wallet-fingerprint/nested/empty").is_dir());
        assert!(!output.join("wallet-fingerprint").join(LOG_FILE).exists());
    }

    #[test]
    fn unzip_stays_inside_output_dir() {
        let entries = [
            BackupEntry::file("../escaped", "../escaped"),
            BackupEntry::file("safe/../../escaped_nested", "safe/../../escaped_nested"),
            BackupEntry::file("/absolute", "/absolute"),
            BackupEntry::file("safe/file", "safe/file"),
        ];
        let archive_bytes = zip_entries(&entries, &logger()).unwrap();

        let tempdir = tempfile::tempdir().unwrap();
        let restored = unzip_in_memory(&archive_bytes, None).unwrap();
        let output = tempdir.path().join("restored");
        write_restored_entries(&restored.entries, &output, &logger()).unwrap();

        // entries escaping the output dir are skipped
        assert!(!tempdir.path().join("escaped").exists());
        assert!(!tempdir.path().join("escaped_nested").exists());
        // absolute paths are made relative to the output dir
        assert_eq!(fs::read(output.join("absolute")).unwrap(), b"/absolute");
        assert_eq!(fs::read(output.join("safe/file")).unwrap(), b"safe/file");
    }
}
