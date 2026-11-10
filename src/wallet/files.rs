//! Wallet-relative file/blob storage.
//!
//! This module defines the narrow storage interface the wallet needs, so that the same wallet
//! code can run over a native directory and, later, over a browser backend. Every wallet holds
//! one adapter ([`WalletFiles`] behind an `Arc`) and routes its wallet-relative file operations
//! through it, so a browser backend can be injected without touching the call sites.
//!
//! # Logical keys
//!
//! A [`WalletPath`] is a normalized, `/`-separated key relative to the wallet directory. It never
//! contains an absolute path, a `..` component, a backslash, a drive colon in its first component
//! or a NUL byte. `./` and repeated/trailing separators are normalized away.
//!
//! # Browser backend
//!
//! [`WasmFiles`] (wasm only) holds the same keys in memory: a `BTreeMap` of blobs and a
//! `BTreeSet` of logical directories, with no filesystem calls. Its contents travel in the wallet
//! snapshot, so the next [`Wallet::flush`](crate::wallet::Wallet::flush) makes them durable. Native
//! builds compile neither the adapter nor the snapshot files section.
//!
//! # Native layout preserved by [`NativeFiles`]
//!
//! `NativeFiles::new(wallet_dir)` maps every key to `wallet_dir` joined with the key components,
//! exactly as the current call sites build their paths:
//!
//! - `wallet_manifest.json`: [`WalletManifest`](crate::wallet::WalletManifest)
//! - `bdk_pending.json` and `bdk_pending.json`'s `.<name>.tmp` sibling: the BDK crash-recovery
//!   changeset
//! - `assets/<asset_id>`: issued contract/consignment files
//! - `media_files/<digest>`: media blobs
//! - `transfers/<transfer_id>/...`: PSBTs, fasciae, transfer data, consignments and receive
//!   metadata/validated copies
//! - `hub_ops/<file_id>`: multisig hub download cache (native only)
//! - `rgb/` and `rgb.deleting/`: legacy RGB store input/retirement (native-only migration)
//!
//! # Not in this interface
//!
//! - Logs are append-only native file drains (`utils::setup_logger`); wasm has no log file. The
//!   interface has no append operation.
//! - Backups are byte-oriented (`backup.rs`): the archive is built and read in memory, so wasm uses
//!   the same format with the wallet snapshot as the payload. Only the native path-based entry
//!   points touch absolute paths, temporary directories and permission bits.
//! - The legacy BDK file store is a path-based BDK store, so its import is compiled out on wasm
//!   rather than routed through this adapter. The legacy RGB store import stays native as well; on
//!   wasm and in builds without its feature, finding `rgb/` in the adapter is an explicit error.
//! - Files supplied by the host (media to send, PSBT/consignment paths in the public API) are
//!   absolute host paths, not wallet-relative data. The portable layer will read/write them as
//!   bytes at the boundary in S21 rather than adding a host-path operation here.
//!
//! # Errors
//!
//! Invalid keys map to [`Error::InvalidFilePath`] and I/O failures to [`Error::IO`]. The browser
//! adapter reports a missing blob as `NotFound` in the same crate error, so callers do not need to
//! know which backend they run on.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(target_arch = "wasm32")]
use std::sync::Mutex;

/// A normalized, wallet-relative logical path.
///
/// Declared `pub` only because the public wallet traits use it in their default-method
/// signatures; the `files` module itself is `pub(crate)`, so it stays unreachable from outside
/// the crate and no API is added.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletPath(String);

impl WalletPath {
    /// Validate and normalize a wallet-relative key.
    ///
    /// Rejects empty keys, absolute paths, `..` components, backslashes, NUL bytes and a colon in
    /// the first component (a drive or stream prefix). Accepts and normalizes `.` components,
    /// repeated separators and trailing separators. A colon in a later component is allowed so the
    /// issued-contract file keeps its native name `assets/rgb:<asset id>`.
    pub(crate) fn new(path: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidFilePath {
            file_path: path.to_string(),
        };
        if path.is_empty() || path.starts_with('/') || path.contains(['\\', '\0']) {
            return Err(invalid());
        }
        let mut parts = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => continue,
                ".." => return Err(invalid()),
                part => parts.push(part),
            }
        }
        let Some(first) = parts.first() else {
            return Err(invalid());
        };
        // a colon in the first component can name a drive ("C:/wallet") or a stream, so it stays
        // rejected; later components stay inside the wallet root
        if first.contains(':') {
            return Err(invalid());
        }
        Ok(Self(parts.join("/")))
    }

    /// The normalized key, always `/`-separated.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Append one relative segment, validating the resulting key.
    pub(crate) fn join(&self, segment: &str) -> Result<Self, Error> {
        Self::new(&format!("{self}/{segment}"))
    }

    /// Build a key from `segments` joined with `/`.
    pub(crate) fn from_segments(segments: &[&str]) -> Result<Self, Error> {
        Self::new(&segments.join("/"))
    }

    /// Build a key from a path relative to the wallet root.
    ///
    /// The reverse of [`NativeFiles::resolve`]: every component must be a plain name, so a key
    /// built from a wallet-rooted path can never escape it.
    pub(crate) fn from_relative(relative: &Path) -> Result<Self, Error> {
        let mut key = String::new();
        for component in relative.components() {
            let std::path::Component::Normal(part) = component else {
                return Err(Error::Internal {
                    details: format!("invalid wallet-relative path {relative:?}"),
                });
            };
            let part = part.to_str().ok_or_else(|| Error::Internal {
                details: format!("non-UTF-8 wallet-relative path {relative:?}"),
            })?;
            if !key.is_empty() {
                key.push('/');
            }
            key.push_str(part);
        }
        Self::new(&key)
    }

    /// The temporary sibling `atomic_write` stages this key in, before renaming it into place.
    ///
    /// A loader uses it to recover a file left behind by a crash between the write and the
    /// rename. Mirrors [`atomic_tmp_path`](crate::utils::atomic_tmp_path).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn tmp_sibling(&self) -> Result<Self, Error> {
        let name = match self.0.rsplit_once('/') {
            Some((dir, name)) => format!("{dir}/.{name}.tmp"),
            None => format!(".{}.tmp", self.0),
        };
        Self::new(&name)
    }
}

impl fmt::Display for WalletPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The owned contents of the browser adapter: blobs keyed by [`WalletPath`] plus the set of
/// logical directories.
///
/// Directories are only keys that exist in this set, never POSIX entries: a name is a directory
/// because a wallet operation registered it, not because anything is stored under it. The state is
/// what travels in a wasm wallet snapshot, so [`encode`](Self::encode) and [`decode`](Self::decode)
/// are the on-the-wire format and every decoded key is re-validated by [`WalletPath::new`].
///
/// Declared `pub` only because the public wallet traits use it in their default-method signatures;
/// the `files` module itself is `pub(crate)`, so it stays unreachable from outside the crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasmFilesState {
    pub(crate) files: BTreeMap<WalletPath, Vec<u8>>,
    pub(crate) dirs: BTreeSet<WalletPath>,
}

impl WasmFilesState {
    /// Whether the adapter holds nothing, not even a directory.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty()
    }

    /// Encode to the deterministic layout stored in a wasm wallet snapshot.
    ///
    /// `u32 directory count`, then each directory key, then `u32 file count`, then each file as
    /// key and bytes, every length a little-endian `u32`. Keys come from `BTreeMap`/`BTreeSet`
    /// order, so the same state always encodes to the same bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        put_len(&mut out, self.dirs.len())?;
        for dir in &self.dirs {
            put_bytes(&mut out, dir.as_str().as_bytes())?;
        }
        put_len(&mut out, self.files.len())?;
        for (key, bytes) in &self.files {
            put_bytes(&mut out, key.as_str().as_bytes())?;
            put_bytes(&mut out, bytes)?;
        }
        Ok(out)
    }

    /// Decode [`encode`](Self::encode) output.
    ///
    /// Every key goes through [`WalletPath::new`], so a snapshot cannot introduce an absolute key,
    /// a `..` component, a backslash, a NUL or a drive colon in the first component; such a section
    /// is rejected with [`Error::InvalidFilePath`]. Trailing bytes are rejected as a corrupt
    /// section.
    #[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let mut dirs = BTreeSet::new();
        for _ in 0..reader.u32()? {
            dirs.insert(WalletPath::new(reader.string()?)?);
        }
        let mut files = BTreeMap::new();
        for _ in 0..reader.u32()? {
            let key = WalletPath::new(reader.string()?)?;
            let data = reader.bytes()?.to_vec();
            files.insert(key, data);
        }
        if !reader.done() {
            return Err(corrupt("trailing bytes after the last file"));
        }
        Ok(Self { files, dirs })
    }
}

fn corrupt(details: &str) -> Error {
    Error::Internal {
        details: format!("corrupt wallet files section: {details}"),
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    let len = u32::try_from(len)
        .map_err(|_| corrupt("the adapter holds more entries than a snapshot can carry"))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Bounds-checked cursor over an encoded [`WasmFilesState`].
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.bytes.len() {
            return Err(corrupt("a length runs past the end of the section"));
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("take returned four bytes"),
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<&'a str, Error> {
        std::str::from_utf8(self.bytes()?).map_err(|_| corrupt("a key is not UTF-8"))
    }

    fn done(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The wallet's file/blob operations, over wallet-relative keys.
///
/// Implementations must be shareable: a wallet hands the adapter to database commit callbacks, so
/// a slow native write can be deferred until the transaction that depends on it has committed.
///
/// Only operations that current call sites need are declared. Metadata helpers (`len`, `is_file`)
/// and `copy` are omitted: no current call site needs them through a portable abstraction, and
/// external blob sources stay host paths.
///
/// Declared `pub` only because the public wallet traits use it in their default-method signatures;
/// the `files` module itself is `pub(crate)`, so it stays unreachable from outside the crate.
pub trait WalletFiles: Send + Sync {
    /// Read a whole file. Used by the manifest, the BDK pending changeset, transfer data/PSBTs,
    /// consignments, media hashing and the legacy RGB migration.
    fn read(&self, path: &WalletPath) -> Result<Vec<u8>, Error>;

    /// Create or truncate a file and write all bytes. Used where a non-atomic write is enough;
    /// durable wallet data uses [`atomic_write`](Self::atomic_write).
    #[allow(dead_code)]
    fn write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error>;

    /// Write all bytes through a temporary sibling and an atomic rename, creating parent
    /// directories. Used by the manifest, BDK pending changeset, transfer data/PSBTs,
    /// consignments, fasciae and media blobs. On native it is `utils::atomic_write`, so it keeps
    /// the current `.<file>.tmp` name and fsync/rename semantics.
    fn atomic_write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error>;

    /// Whether a key exists. Used for the manifest, media deduplication, consignments, transfer
    /// directories, the hub cache and legacy-store detection.
    fn exists(&self, path: &WalletPath) -> Result<bool, Error>;

    /// Remove a file. Idempotent: a missing key is not an error. Used for BDK crash-recovery
    /// files after commit, media/consignment cleanup and the hub cache.
    fn remove(&self, path: &WalletPath) -> Result<(), Error>;

    /// List every regular file under a directory key, recursively, sorted by key. Symlinks are
    /// skipped. Used by the legacy RGB migration and native backup/cleanup walks.
    fn list(&self, dir: &WalletPath) -> Result<Vec<WalletPath>, Error>;

    /// Create a directory and its parents. Used for `assets/`, `media_files/`, transfer/asset
    /// transfer directories and `hub_ops/`.
    fn create_dir_all(&self, dir: &WalletPath) -> Result<(), Error>;

    /// Remove a directory and its contents, idempotently. Used to reset a transfer directory
    /// before reuse and to sweep the retired legacy RGB store.
    fn remove_dir_all(&self, dir: &WalletPath) -> Result<(), Error>;

    /// Rename a file or directory within the wallet. Used when a transfer directory is renamed to
    /// its TXID and when the legacy RGB store is retired. The target's parent must exist, matching
    /// `fs::rename` and every current call site. No cross-device fallback: keys are under one
    /// wallet root.
    fn rename(&self, from: &WalletPath, to: &WalletPath) -> Result<(), Error>;

    /// The adapter's owned blob state, when it keeps its files in memory.
    ///
    /// Only the browser adapter returns `Some`. The native adapter returns `None`: its files live
    /// in the wallet directory and travel with it, so a native snapshot never carries a files
    /// section and its bytes stay unchanged.
    fn snapshot_state(&self) -> Option<WasmFilesState> {
        None
    }

    /// Replace the adapter's owned blob state with the one restored from a wallet snapshot.
    ///
    /// The default is a no-op: a native adapter owns no in-memory state to replace.
    fn restore_snapshot_state(&self, _state: WasmFilesState) {}
}

/// Native directory adapter rooted at the wallet directory.
///
/// Resolves keys by pushing each `/`-separated component onto the root, which reproduces the
/// existing `wallet_dir.join(...)` layout on every platform.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct NativeFiles {
    root: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeFiles {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, path: &WalletPath) -> PathBuf {
        let mut resolved = self.root.clone();
        for component in path.as_str().split('/') {
            resolved.push(component);
        }
        resolved
    }

    fn relative_key(&self, path: &Path) -> Result<WalletPath, Error> {
        let relative = path.strip_prefix(&self.root).map_err(|e| Error::Internal {
            details: format!("cannot make {path:?} relative to the wallet dir: {e}"),
        })?;
        WalletPath::from_relative(relative)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl WalletFiles for NativeFiles {
    fn read(&self, path: &WalletPath) -> Result<Vec<u8>, Error> {
        Ok(fs::read(self.resolve(path))?)
    }

    fn write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        fs::write(self.resolve(path), bytes)?;
        Ok(())
    }

    fn atomic_write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        atomic_write(&self.resolve(path), bytes)
    }

    fn exists(&self, path: &WalletPath) -> Result<bool, Error> {
        Ok(self.resolve(path).exists())
    }

    fn remove(&self, path: &WalletPath) -> Result<(), Error> {
        remove_if_present(&self.resolve(path))
    }

    fn list(&self, dir: &WalletPath) -> Result<Vec<WalletPath>, Error> {
        let mut pending = vec![self.resolve(dir)];
        let mut files = Vec::new();
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                // same decision as the legacy migration walk: never follow a symlink
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if file_type.is_dir() {
                    pending.push(path);
                } else if file_type.is_file() {
                    files.push(self.relative_key(&path)?);
                }
            }
        }
        files.sort();
        Ok(files)
    }

    fn create_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        fs::create_dir_all(self.resolve(dir))?;
        Ok(())
    }

    fn remove_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        match fs::remove_dir_all(self.resolve(dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn rename(&self, from: &WalletPath, to: &WalletPath) -> Result<(), Error> {
        fs::rename(self.resolve(from), self.resolve(to))?;
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn remove_if_present(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The adapter a wallet uses on the target it was built for.
///
/// Native wallets get the directory adapter rooted at their wallet directory. A wasm wallet has no
/// filesystem: blobs live in [`WasmFiles`], are kept in memory, and travel with the wallet
/// snapshot, so they are durable once [`Wallet::flush`](crate::wallet::Wallet::flush) commits.
pub(crate) fn default_files(root: impl Into<PathBuf>) -> Arc<dyn WalletFiles> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Arc::new(NativeFiles::new(root))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = root;
        Arc::new(WasmFiles::new())
    }
}

/// Browser blob storage: wallet files held in memory, restored from and serialized into the wallet
/// snapshot.
///
/// The browser has no filesystem, so nothing here touches one. Keys are [`WalletPath`]s and
/// directories are entries in a set, never POSIX entries: a directory exists because a wallet
/// operation registered it.
///
/// # Atomicity
///
/// There is no temporary-file concept. [`write`](WalletFiles::write) and
/// [`atomic_write`](WalletFiles::atomic_write) both replace the blob in one step: the map either
/// holds the new bytes or the old ones, never a mix. The atomic unit a host can observe is the
/// snapshot flush, which stores every blob plus the database and BDK state in one IndexedDB
/// transaction; a crash before that commit keeps the previous flushed state.
///
/// # Namespace
///
/// Every key is a [`WalletPath`], so an absolute path, a `..` component, a backslash, a NUL, a
/// colon in the first component or a drive prefix cannot name anything in the adapter, and no
/// operation can reach outside the wallet's key space. The same validation runs again when a
/// snapshot's files section is decoded.
#[cfg(target_arch = "wasm32")]
pub(crate) struct WasmFiles {
    state: Mutex<WasmFilesState>,
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmFiles {
    fn default() -> Self {
        Self {
            state: Mutex::new(WasmFilesState::default()),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl WasmFiles {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WasmFilesState> {
        self.state
            .lock()
            .expect("the files state is never poisoned")
    }

    fn is_under(path: &WalletPath, dir: &WalletPath) -> bool {
        path.as_str()
            .strip_prefix(dir.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Register a directory and every ancestor, as `create_dir_all` would on disk.
    fn register_dirs(state: &mut WasmFilesState, dir: &WalletPath) -> Result<(), Error> {
        let mut key = String::new();
        for part in dir.as_str().split('/') {
            if !key.is_empty() {
                key.push('/');
            }
            key.push_str(part);
            state.dirs.insert(WalletPath::new(&key)?);
        }
        Ok(())
    }

    /// Register the directories a file key lives in, without making the file a directory.
    fn register_parents(state: &mut WasmFilesState, path: &WalletPath) -> Result<(), Error> {
        let mut parts = path.as_str().split('/').collect::<Vec<_>>();
        parts.pop();
        if !parts.is_empty() {
            Self::register_dirs(state, &WalletPath::new(&parts.join("/"))?)?;
        }
        Ok(())
    }

    fn missing(path: &WalletPath) -> Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such wallet file: {path}"),
        )
        .into()
    }

    fn store(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        let mut state = self.lock();
        Self::register_parents(&mut state, path)?;
        state.files.insert(path.clone(), bytes.to_vec());
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl WalletFiles for WasmFiles {
    fn read(&self, path: &WalletPath) -> Result<Vec<u8>, Error> {
        self.lock()
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| Self::missing(path))
    }

    fn write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        self.store(path, bytes)
    }

    fn atomic_write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
        // no temporary file: the insert is the whole write, see the type docs
        self.store(path, bytes)
    }

    fn exists(&self, path: &WalletPath) -> Result<bool, Error> {
        let state = self.lock();
        Ok(state.files.contains_key(path) || state.dirs.contains(path))
    }

    fn remove(&self, path: &WalletPath) -> Result<(), Error> {
        self.lock().files.remove(path);
        Ok(())
    }

    fn list(&self, dir: &WalletPath) -> Result<Vec<WalletPath>, Error> {
        // a directory that was never registered holds no files, so an empty list mirrors the
        // logical contents rather than reporting a POSIX `ENOENT`
        Ok(self
            .lock()
            .files
            .keys()
            .filter(|key| Self::is_under(key, dir))
            .cloned()
            .collect())
    }

    fn create_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        Self::register_dirs(&mut self.lock(), dir)
    }

    fn remove_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
        let mut state = self.lock();
        state.files.retain(|key, _| !Self::is_under(key, dir));
        state
            .dirs
            .retain(|key| key != dir && !Self::is_under(key, dir));
        Ok(())
    }

    fn rename(&self, from: &WalletPath, to: &WalletPath) -> Result<(), Error> {
        let mut state = self.lock();
        if let Some(bytes) = state.files.remove(from) {
            Self::register_parents(&mut state, to)?;
            state.files.insert(to.clone(), bytes);
            return Ok(());
        }
        if !state.dirs.contains(from) {
            // match `fs::rename`, which fails for a missing source
            return Err(Self::missing(from));
        }
        let rebase = |key: &WalletPath| -> Result<WalletPath, Error> {
            let suffix = key
                .as_str()
                .strip_prefix(from.as_str())
                .expect("is_under checked the prefix");
            WalletPath::new(&format!("{to}{suffix}"))
        };
        let files = state
            .files
            .iter()
            .filter(|(key, _)| Self::is_under(key, from))
            .map(|(key, bytes)| Ok((rebase(key)?, bytes.clone())))
            .collect::<Result<Vec<_>, Error>>()?;
        let dirs = state
            .dirs
            .iter()
            .filter(|key| Self::is_under(key, from))
            .map(rebase)
            .collect::<Result<Vec<_>, Error>>()?;
        state.files.retain(|key, _| !Self::is_under(key, from));
        state
            .dirs
            .retain(|key| key != from && !Self::is_under(key, from));
        Self::register_dirs(&mut state, to)?;
        for (key, bytes) in files {
            state.files.insert(key, bytes);
        }
        for dir in dirs {
            state.dirs.insert(dir);
        }
        Ok(())
    }

    fn snapshot_state(&self) -> Option<WasmFilesState> {
        Some(self.lock().clone())
    }

    fn restore_snapshot_state(&self, state: WasmFilesState) {
        *self.lock() = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    #[test]
    fn wallet_path_normalizes() {
        for (input, expected) in [
            ("wallet_manifest.json", "wallet_manifest.json"),
            ("./assets//rgb_asset", "assets/rgb_asset"),
            (
                "transfers/txid/./unsigned.psbt",
                "transfers/txid/unsigned.psbt",
            ),
            ("media_files/abc123/", "media_files/abc123"),
            (
                "./assets/rgb:2sKqy6Lz-8xMBo7E",
                "assets/rgb:2sKqy6Lz-8xMBo7E",
            ),
            ("a///b//c", "a/b/c"),
        ] {
            assert_eq!(WalletPath::new(input).unwrap().as_str(), expected);
        }
        let base = WalletPath::new("transfers").unwrap();
        assert_eq!(
            base.join("./txid/../x").unwrap_err(),
            Error::InvalidFilePath {
                file_path: "transfers/./txid/../x".to_string(),
            }
        );
        assert_eq!(
            base.join("txid/files").unwrap().as_str(),
            "transfers/txid/files"
        );
        assert_eq!(
            base.join("..").unwrap_err(),
            Error::InvalidFilePath {
                file_path: "transfers/..".to_string(),
            }
        );
    }

    #[test]
    fn wallet_path_rejects_escapes_and_host_paths() {
        for input in [
            "",
            ".",
            "..",
            "/absolute",
            "//server/share",
            "a/../b",
            "a/../../b",
            "a\\b",
            "C:/wallet",
            "asset:name",
            "nul\0byte",
        ] {
            assert!(
                matches!(WalletPath::new(input), Err(Error::InvalidFilePath { .. })),
                "expected {input:?} to be rejected"
            );
        }
    }

    #[test]
    fn wallet_path_derives_relative_keys_and_tmp_siblings() {
        assert_eq!(
            WalletPath::from_relative(Path::new("transfers/txid/unsigned.psbt"))
                .unwrap()
                .as_str(),
            "transfers/txid/unsigned.psbt"
        );
        for invalid in ["/abs", "../x", "a/../../b"] {
            assert!(WalletPath::from_relative(Path::new(invalid)).is_err());
        }
        assert_eq!(
            WalletPath::new("bdk_pending.json")
                .unwrap()
                .tmp_sibling()
                .unwrap()
                .as_str(),
            ".bdk_pending.json.tmp"
        );
        assert_eq!(
            WalletPath::new("transfers/txid/unsigned.psbt")
                .unwrap()
                .tmp_sibling()
                .unwrap()
                .as_str(),
            "transfers/txid/.unsigned.psbt.tmp"
        );
    }

    /// Minimal in-memory backend: proves the interface is usable through `&dyn WalletFiles`.
    ///
    /// A `Mutex` rather than a `RefCell`: the trait is shareable, since a wallet hands the adapter
    /// to database commit callbacks.
    #[derive(Default)]
    struct MemoryFiles {
        files: Mutex<BTreeMap<WalletPath, Vec<u8>>>,
        dirs: Mutex<BTreeSet<WalletPath>>,
    }

    impl MemoryFiles {
        fn key(path: &str) -> WalletPath {
            WalletPath::new(path).unwrap()
        }

        fn is_dir(&self, path: &WalletPath) -> bool {
            self.dirs.lock().unwrap().contains(path)
        }

        fn is_under(path: &WalletPath, dir: &WalletPath) -> bool {
            path.as_str()
                .strip_prefix(dir.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        }

        fn remove_tree(&self, dir: &WalletPath) {
            self.files
                .lock()
                .unwrap()
                .retain(|key, _| !Self::is_under(key, dir));
            self.dirs
                .lock()
                .unwrap()
                .retain(|key| !Self::is_under(key, dir));
            self.dirs.lock().unwrap().remove(dir);
        }
    }

    impl WalletFiles for MemoryFiles {
        fn read(&self, path: &WalletPath) -> Result<Vec<u8>, Error> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| Error::InvalidFilePath {
                    file_path: path.to_string(),
                })
        }

        fn write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
            self.files
                .lock()
                .unwrap()
                .insert(path.clone(), bytes.to_vec());
            Ok(())
        }

        fn atomic_write(&self, path: &WalletPath, bytes: &[u8]) -> Result<(), Error> {
            self.write(path, bytes)
        }

        fn exists(&self, path: &WalletPath) -> Result<bool, Error> {
            Ok(self.files.lock().unwrap().contains_key(path) || self.is_dir(path))
        }

        fn remove(&self, path: &WalletPath) -> Result<(), Error> {
            self.files.lock().unwrap().remove(path);
            Ok(())
        }

        fn list(&self, dir: &WalletPath) -> Result<Vec<WalletPath>, Error> {
            Ok(self
                .files
                .lock()
                .unwrap()
                .keys()
                .filter(|key| Self::is_under(key, dir))
                .cloned()
                .collect())
        }

        fn create_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
            self.dirs.lock().unwrap().insert(dir.clone());
            Ok(())
        }

        fn remove_dir_all(&self, dir: &WalletPath) -> Result<(), Error> {
            self.remove_tree(dir);
            Ok(())
        }

        fn rename(&self, from: &WalletPath, to: &WalletPath) -> Result<(), Error> {
            let removed = self.files.lock().unwrap().remove(from);
            if let Some(bytes) = removed {
                self.files.lock().unwrap().insert(to.clone(), bytes);
                return Ok(());
            }
            if !self.dirs.lock().unwrap().contains(from) {
                return Ok(());
            }
            let moved = self
                .files
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| Self::is_under(key, from))
                .map(|(key, bytes)| {
                    let suffix = key.as_str().strip_prefix(from.as_str()).unwrap();
                    (
                        WalletPath::new(&format!("{to}{suffix}")).unwrap(),
                        bytes.clone(),
                    )
                })
                .collect::<Vec<_>>();
            self.remove_tree(from);
            for (key, bytes) in moved {
                self.files.lock().unwrap().insert(key, bytes);
            }
            self.dirs.lock().unwrap().insert(to.clone());
            Ok(())
        }
    }

    fn exercise(files: &dyn WalletFiles) -> Result<(), Error> {
        let root = MemoryFiles::key("transfers/txid");
        files.create_dir_all(&root)?;
        let data = MemoryFiles::key("transfers/txid/transfer_data.txt");
        files.atomic_write(&data, b"hello")?;
        files.atomic_write(&data, b"world")?;
        assert_eq!(files.read(&data)?, b"world");
        assert!(files.exists(&root)?);
        assert_eq!(files.list(&root)?, vec![data.clone()]);
        files.remove(&data)?;
        assert!(!files.exists(&data)?);
        files.remove(&data)?;
        files.write(&data, b"again")?;
        files.rename(&data, &MemoryFiles::key("transfers/txid/renamed"))?;
        assert!(!files.exists(&data)?);
        files.remove_dir_all(&root)?;
        assert!(!files.exists(&root)?);
        Ok(())
    }

    #[test]
    fn trait_is_object_safe_with_memory_backend() {
        let files = MemoryFiles::default();
        exercise(&files).unwrap();
    }

    #[test]
    fn wasm_files_state_round_trips() {
        let key = WalletPath::new("media_files/abc123").unwrap();
        let state = WasmFilesState {
            files: BTreeMap::from([(key.clone(), b"media".to_vec())]),
            dirs: BTreeSet::from([WalletPath::new("media_files").unwrap()]),
        };
        let encoded = state.encode().unwrap();
        assert_eq!(WasmFilesState::decode(&encoded).unwrap(), state);
        // deterministic: the same state always encodes to the same bytes
        assert_eq!(state.encode().unwrap(), encoded);
        assert!(!state.is_empty());
        assert!(WasmFilesState::default().is_empty());
    }

    /// Encode a files section from raw key names, to feed keys a `WalletPath` would reject.
    fn raw_files_section(keys: &[&str]) -> Vec<u8> {
        let mut out = 0u32.to_le_bytes().to_vec();
        out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for key in keys {
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.push(b'x');
        }
        out
    }

    #[test]
    fn wasm_files_state_rejects_escaped_keys() {
        for key in ["/absolute", "../escape", "a\\b", "a\0b", "a:b"] {
            let encoded = raw_files_section(&[key]);
            assert!(
                matches!(
                    WasmFilesState::decode(&encoded),
                    Err(Error::InvalidFilePath { .. })
                ),
                "expected {key:?} to be rejected"
            );
        }
    }

    #[test]
    fn wasm_files_state_rejects_trailing_bytes() {
        let mut encoded = raw_files_section(&[]);
        encoded.push(0);
        assert!(matches!(
            WasmFilesState::decode(&encoded),
            Err(Error::Internal { .. })
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_adapter_owns_no_snapshot_state() {
        let dir = tempfile::tempdir().unwrap();
        assert!(NativeFiles::new(dir.path()).snapshot_state().is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_adapter_preserves_wallet_layout() {
        let dir = tempfile::tempdir().unwrap();
        let files = NativeFiles::new(dir.path());

        let manifest = WalletPath::new("wallet_manifest.json").unwrap();
        files.atomic_write(&manifest, b"{}").unwrap();
        assert!(dir.path().join("wallet_manifest.json").is_file());

        let media = WalletPath::new("media_files/abc123").unwrap();
        files.atomic_write(&media, b"media").unwrap();
        assert!(dir.path().join("media_files").join("abc123").is_file());

        files
            .create_dir_all(&WalletPath::new("transfers/txid/asset").unwrap())
            .unwrap();
        let transfer_data = WalletPath::new("transfers/txid/asset/transfer_data.txt").unwrap();
        files.write(&transfer_data, b"data").unwrap();
        assert_eq!(
            dir.path()
                .join("transfers")
                .join("txid")
                .join("asset")
                .join("transfer_data.txt")
                .is_file(),
            true
        );
        assert_eq!(
            files.list(&WalletPath::new("transfers").unwrap()).unwrap(),
            vec![transfer_data.clone()]
        );

        let renamed = WalletPath::new("transfers/final/asset/transfer_data.txt").unwrap();
        files
            .create_dir_all(&WalletPath::new("transfers/final/asset").unwrap())
            .unwrap();
        files.rename(&transfer_data, &renamed).unwrap();
        assert!(
            dir.path()
                .join("transfers/final/asset/transfer_data.txt")
                .is_file()
        );

        files.remove(&renamed).unwrap();
        files.remove(&renamed).unwrap();
        files
            .remove_dir_all(&WalletPath::new("transfers").unwrap())
            .unwrap();
        assert!(!dir.path().join("transfers").exists());
    }
}
