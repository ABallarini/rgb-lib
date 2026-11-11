//! Browser durable persistence for the in-memory backend; native builds use SQLite and do not use
//! this module.
//!
//! The wallet over the in-memory backend serializes its whole state with
//! [`Wallet::snapshot`](crate::wallet::Wallet::snapshot); the browser has no filesystem to write
//! those bytes to, so this module stores them in IndexedDB. One database (`rgb-lib`, version 1)
//! holds a single object store (`snapshots`) mapping the wallet id to a [`SnapshotRecord`]: the
//! snapshot bytes, the id of the writer that produced them and a monotonic sequence number. The
//! wallet id is the object store key: saving the same id replaces the previous record. Records
//! written before the guard existed are a bare `Uint8Array`; they still load, as sequence `0` with
//! writer `legacy`, and the first guarded save migrates them to the record shape.
//!
//! Only the wallet id, the snapshot and the writer id are written. The snapshot excludes the
//! mnemonic and the signing keys (see `Wallet::snapshot`) but is still sensitive: it carries the
//! proxy operation secret keys and RGB secret seals needed to finish pending transfers, together
//! with the wallet's browser blobs. It is stored as plain bytes, not encrypted at rest, so the host
//! must treat the IndexedDB origin as private wallet storage. One write makes the database, BDK and
//! file state durable together. Errors surface as [`Error::Internal`] with the JS failure message
//! and never with a value.
//!
//! # Host lifecycle
//!
//! The wallet owns every in-memory change until the host flushes it. On wasm32
//! [`Wallet::flush`](crate::wallet::Wallet::flush) and
//! [`MultisigWallet::flush`](crate::wallet::MultisigWallet::flush) serialize the wallet with
//! `snapshot` and delegate the write to [`save_snapshot`]. The wasm bindings instead track the
//! writer id and sequence and call [`save_snapshot_record`], so a stale instance cannot clobber a
//! newer snapshot. Flush is the only durable-write boundary, and its future resolves once the
//! IndexedDB transaction commits. Native builds expose no flush method: their SQLite backend writes
//! every change itself, so a native flush would be a no-op.
//!
//! Restoring is asynchronous, so the host loads the snapshot first and only then constructs the
//! wallet with `from_snapshot`; constructors are synchronous and cannot await IndexedDB. Delete the
//! entry when the host deletes the wallet.
//!
//! ```ignore
//! # // wasm32-only example: it cannot compile or run in a native doctest.
//! # async fn host_flow(wallet_data: WalletData, keys: SinglesigKeys) -> Result<(), Error> {
//! let wallet_id = keys.master_fingerprint.clone();
//! let restored = match load_snapshot(&wallet_id).await? {
//!     Some(bytes) => Wallet::from_snapshot(&bytes, wallet_data.clone(), keys)?,
//!     None => Wallet::new(wallet_data, keys)?,
//! };
//! // ... use the wallet ...
//! restored.flush(&wallet_id).await?;
//! // when the wallet is deleted
//! delete_snapshot(&wallet_id).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Crash and concurrency semantics
//!
//! Changes made after the last flush are lost if the wallet goes away without another flush. A
//! flush error leaves the in-memory wallet usable, so the host can retry.
//!
//! [`save_snapshot_record`] is a compare-and-swap: inside one read-write transaction it reads the
//! stored sequence and refuses to write when the stored sequence is greater than the caller's
//! expected one, so a stale instance cannot overwrite a newer snapshot. The error names the stored
//! sequence and its writer. Two instances that load the same record may both write at that
//! sequence: the first commits `sequence + 1` and the second is rejected. A different writer at an
//! equal sequence is accepted, because it may be a new tab that loaded the latest state.
//!
//! A write is a single IndexedDB read-write transaction, so it either commits whole or not at all.
//! When it fails or aborts, the transaction rolls back and the previously committed snapshot stays
//! intact: a crash mid-write can lose the newest unflushed changes, never the whole wallet.
//! [`save_snapshot`] remains the unversioned, last-committed-write-wins compatibility entry point;
//! do not use it for a wallet that also flushes through the guard.
//!
//! A snapshot that cannot be decoded is an error, never a fresh wallet. [`load_snapshot`] returns
//! the bytes it finds and `Wallet::from_snapshot` validates the envelope and the manifest, so the
//! host must surface the error instead of falling back to `Wallet::new`. The stored value stays
//! untouched, so the host can diagnose or overwrite it.
//!
//! The wallet id is the key, so the caller passes the same id to every call.
//! `save_snapshot` waits for the IndexedDB transaction to commit before it returns.

use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, IdbDatabase, IdbRequest, IdbTransaction, IdbTransactionMode};

use crate::Error;

const DB_NAME: &str = "rgb-lib";
const DB_VERSION: u32 = 1;
const STORE_NAME: &str = "snapshots";
/// Writer id of a snapshot stored as a bare `Uint8Array`, before the guard existed.
const LEGACY_WRITER: &str = "legacy";

/// A stored snapshot with the identity of the writer that produced it.
///
/// `sequence` is monotonic per wallet id: [`save_snapshot_record`] refuses to write unless the
/// caller's expected sequence is at least the stored one. A legacy `Uint8Array` loads as
/// `writer = "legacy"` and `sequence = 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRecord {
    /// The snapshot bytes, as produced by
    /// [`Wallet::snapshot`](crate::wallet::Wallet::snapshot).
    pub bytes: Vec<u8>,
    /// The id of the instance that wrote this record; `legacy` for a pre-guard value.
    pub writer: String,
    /// The number of successful guarded writes that produced this record.
    pub sequence: u64,
}

/// Generate a random writer id: 16 lowercase hex characters from the crate CSPRNG.
///
/// Not secret; it only tells two wallet instances apart in a stale-write error.
pub fn new_writer_id() -> String {
    let bytes: [u8; 8] = rand::random();
    hex::encode(bytes)
}

/// Test-only failure injection for the browser scenarios; never compiled outside `cfg(test)`.
///
/// `Unavailable` fails before any transaction starts, `WriteFailed` writes the value and then
/// fails without committing, and `AbortBeforeCommit` aborts the transaction after the write so the
/// explicit abort path is exercised. All three must leave the previous committed snapshot intact.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InjectedFailure {
    Unavailable,
    WriteFailed,
    AbortBeforeCommit,
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAILURE: std::cell::Cell<Option<InjectedFailure>> =
        const { std::cell::Cell::new(None) };
}

/// Set or clear the test-only failure injection for this thread; not compiled in production builds.
#[cfg(test)]
pub(crate) fn set_injected_failure(failure: Option<InjectedFailure>) {
    INJECTED_FAILURE.with(|injected| injected.set(failure));
}

#[cfg(test)]
fn injected_failure() -> Option<InjectedFailure> {
    INJECTED_FAILURE.with(|injected| injected.get())
}

fn internal(details: impl Into<String>) -> Error {
    Error::Internal {
        details: details.into(),
    }
}

/// Describe a JS failure without handing on the JS value itself, which can carry a stack.
fn js_error(context: &str, error: JsValue) -> Error {
    let message = if let Some(dom) = error.dyn_ref::<DomException>() {
        format!("{} ({})", dom.message(), dom.name())
    } else if let Some(err) = error.dyn_ref::<js_sys::Error>() {
        String::from(err.message())
    } else {
        error.as_string().unwrap_or_else(|| format!("{error:?}"))
    };
    internal(format!("{context}: {message}"))
}

fn indexed_db() -> Result<web_sys::IdbFactory, Error> {
    let window =
        web_sys::window().ok_or_else(|| internal("no window: not running in a browser"))?;
    window
        .indexed_db()
        .map_err(|e| js_error("cannot access IndexedDB", e))?
        .ok_or_else(|| internal("IndexedDB is not available"))
}

async fn open() -> Result<IdbDatabase, Error> {
    let request = indexed_db()?
        .open_with_u32(DB_NAME, DB_VERSION)
        .map_err(|e| js_error("cannot open the rgb-lib database", e))?;

    // the only upgrade path is 0 -> 1, where the store cannot exist yet
    let upgrade_request = request.clone();
    let on_upgrade = Closure::once(move || {
        if let Ok(value) = upgrade_request.result()
            && let Ok(db) = value.dyn_into::<IdbDatabase>()
        {
            let _ = db.create_object_store(STORE_NAME);
        }
    });
    request.set_onupgradeneeded(Some(on_upgrade.into_js_value().unchecked_ref()));

    let value = request_future(&request)
        .await
        .map_err(|e| js_error("cannot open the rgb-lib database", e))?;
    value
        .dyn_into::<IdbDatabase>()
        .map_err(|_| internal("the rgb-lib database handle is not an IdbDatabase"))
}

/// Resolve with the request result when it succeeds, reject with its JS error otherwise.
fn request_future(request: &IdbRequest) -> JsFuture {
    let request = request.clone();
    let promise = js_sys::Promise::new(&mut move |resolve, reject| {
        let success_request = request.clone();
        let success_reject = reject.clone();
        let on_success = Closure::once(move || match success_request.result() {
            Ok(value) => {
                let _ = resolve.call1(&JsValue::NULL, &value);
            }
            Err(error) => {
                let _ = success_reject.call1(&JsValue::NULL, &error);
            }
        });
        request.set_onsuccess(Some(on_success.into_js_value().unchecked_ref()));

        let error_request = request.clone();
        let on_error = Closure::once(move || {
            let error = error_request
                .error()
                .ok()
                .flatten()
                .map(JsValue::from)
                .unwrap_or_else(|| JsValue::from_str("IndexedDB request failed"));
            let _ = reject.call1(&JsValue::NULL, &error);
        });
        request.set_onerror(Some(on_error.into_js_value().unchecked_ref()));
    });
    JsFuture::from(promise)
}

/// Resolve once the transaction commits, reject if it errors or aborts.
///
/// The handlers are attached before any request is issued, so a transaction that completes as
/// soon as its last request succeeds cannot fire the event before it is observed.
fn transaction_future(transaction: &IdbTransaction) -> JsFuture {
    let transaction = transaction.clone();
    let promise = js_sys::Promise::new(&mut move |resolve, reject| {
        let on_complete = Closure::once(move || {
            let _ = resolve.call0(&JsValue::NULL);
        });
        transaction.set_oncomplete(Some(on_complete.into_js_value().unchecked_ref()));

        let error_transaction = transaction.clone();
        let abort_reject = reject.clone();
        let on_abort = Closure::once(move || {
            let error = error_transaction
                .error()
                .map(JsValue::from)
                .unwrap_or_else(|| JsValue::from_str("IndexedDB transaction aborted"));
            let _ = abort_reject.call1(&JsValue::NULL, &error);
        });
        transaction.set_onabort(Some(on_abort.into_js_value().unchecked_ref()));

        let error_transaction = transaction.clone();
        let error_reject = reject.clone();
        let on_error = Closure::once(move || {
            let error = error_transaction
                .error()
                .map(JsValue::from)
                .unwrap_or_else(|| JsValue::from_str("IndexedDB transaction failed"));
            let _ = error_reject.call1(&JsValue::NULL, &error);
        });
        transaction.set_onerror(Some(on_error.into_js_value().unchecked_ref()));
    });
    JsFuture::from(promise)
}

/// Store the snapshot bytes under the wallet id as a bare `Uint8Array`, replacing any previous
/// value.
///
/// This is the unversioned compatibility entry point: it does not read or bump a sequence, so two
/// overlapping writes are serialized by IndexedDB and the last committed write wins. Use
/// [`save_snapshot_record`] when a stale instance must not overwrite a newer snapshot.
///
/// Asynchronous: it resolves once the IndexedDB transaction commits, so the bytes are durable when
/// the future completes. `wallet_id` is the object store key, so saving the same id overwrites the
/// stored value. The bytes are the output of
/// [`Wallet::snapshot`](crate::wallet::Wallet::snapshot) and carry no secret material. Errors are
/// returned as [`Error::Internal`] with the JS failure message.
pub async fn save_snapshot(wallet_id: &str, bytes: &[u8]) -> Result<(), Error> {
    #[cfg(test)]
    if injected_failure() == Some(InjectedFailure::Unavailable) {
        return Err(internal("injected failure: IndexedDB is unavailable"));
    }
    let db = open().await?;
    let result = write(&db, wallet_id, bytes).await;
    db.close();
    result
}

/// Store the snapshot under the wallet id and bump its writer sequence, refusing a stale write.
///
/// Inside one read-write IndexedDB transaction this reads the stored record; when its `sequence`
/// is greater than `expected_sequence` it aborts with an error naming the stored sequence and its
/// writer. A missing record and a legacy `Uint8Array` value both count as sequence `0`, so the
/// first guarded save migrates a legacy value to the record shape. Otherwise it writes
/// `{ bytes, writer, sequence: expected_sequence + 1 }`, waits for the commit, and returns the new
/// sequence. A different `writer` at an equal sequence is accepted: it may be a new instance that
/// loaded the latest state. `writer` is a non-secret id from [`new_writer_id`].
///
/// Errors are returned as [`Error::Internal`] with the JS failure message. A failed or aborted
/// write leaves the previous record intact.
pub async fn save_snapshot_record(
    wallet_id: &str,
    bytes: &[u8],
    writer: &str,
    expected_sequence: u64,
) -> Result<u64, Error> {
    #[cfg(test)]
    if injected_failure() == Some(InjectedFailure::Unavailable) {
        return Err(internal("injected failure: IndexedDB is unavailable"));
    }
    let db = open().await?;
    let result = write_record(&db, wallet_id, bytes, writer, expected_sequence).await;
    db.close();
    result
}

/// Return the snapshot stored under the wallet id, if any.
///
/// Asynchronous: the host awaits it before constructing the wallet, because wallet constructors
/// are synchronous and cannot wait for IndexedDB. `wallet_id` is the object store key; `None`
/// means no snapshot has been saved for it yet. Both a guarded record and a legacy `Uint8Array`
/// yield their bytes. The returned bytes can be passed to
/// [`Wallet::from_snapshot`](crate::wallet::Wallet::from_snapshot). Errors are returned as
/// [`Error::Internal`] with the JS failure message.
pub async fn load_snapshot(wallet_id: &str) -> Result<Option<Vec<u8>>, Error> {
    Ok(load_snapshot_record(wallet_id)
        .await?
        .map(|record| record.bytes))
}

/// Return the stored record under the wallet id, with its writer and sequence.
///
/// A record saved by [`save_snapshot_record`] keeps its writer and sequence. A legacy
/// `Uint8Array` value, or no value, loads as writer `legacy` and sequence `0`. Acknowledge the
/// returned sequence and pass it as `expected_sequence` to the next [`save_snapshot_record`]
/// call; a fresh [`load_snapshot_record`] is the way a stale instance recovers. Errors are
/// returned as [`Error::Internal`] with the JS failure message.
pub async fn load_snapshot_record(wallet_id: &str) -> Result<Option<SnapshotRecord>, Error> {
    #[cfg(test)]
    if injected_failure() == Some(InjectedFailure::Unavailable) {
        return Err(internal("injected failure: IndexedDB is unavailable"));
    }
    let db = open().await?;
    let result = read(&db, wallet_id).await;
    db.close();
    result
}

/// Remove the snapshot stored under the wallet id; missing entries are not an error.
///
/// Asynchronous: call it when the host deletes the wallet. `wallet_id` is the object store key,
/// and deleting an id that has no snapshot succeeds. Errors are returned as [`Error::Internal`]
/// with the JS failure message.
pub async fn delete_snapshot(wallet_id: &str) -> Result<(), Error> {
    #[cfg(test)]
    if injected_failure() == Some(InjectedFailure::Unavailable) {
        return Err(internal("injected failure: IndexedDB is unavailable"));
    }
    let db = open().await?;
    let result = remove(&db, wallet_id).await;
    db.close();
    result
}

async fn write(db: &IdbDatabase, wallet_id: &str, bytes: &[u8]) -> Result<(), Error> {
    let transaction = db
        .transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)
        .map_err(|e| js_error("cannot start the snapshot write", e))?;
    let committed = transaction_future(&transaction);

    let written = async {
        let store = transaction
            .object_store(STORE_NAME)
            .map_err(|e| js_error("cannot open the snapshots store", e))?;
        let array = js_sys::Uint8Array::from(bytes);
        let request = store
            .put_with_key(&array, &JsValue::from_str(wallet_id))
            .map_err(|e| js_error("cannot write the snapshot", e))?;
        request_future(&request)
            .await
            .map_err(|e| js_error("cannot write the snapshot", e))?;
        // test-only: fail after the put so the transaction rolls back. `WriteFailed` leaves the
        // abort to the caller's error path, `AbortBeforeCommit` aborts here to exercise it directly.
        #[cfg(test)]
        match injected_failure() {
            Some(InjectedFailure::WriteFailed) => {
                return Err(internal("injected failure: the snapshot write failed"));
            }
            Some(InjectedFailure::AbortBeforeCommit) => {
                let _ = transaction.abort();
                return Err(internal(
                    "injected failure: the snapshot write aborted before commit",
                ));
            }
            _ => {}
        }
        Ok::<(), Error>(())
    }
    .await;

    match written {
        Ok(()) => committed
            .await
            .map(|_| ())
            .map_err(|e| js_error("cannot commit the snapshot", e)),
        Err(error) => {
            // the request failed, so the transaction would roll back anyway; abort it explicitly
            // so it stops holding its locks
            let _ = transaction.abort();
            Err(error)
        }
    }
}

async fn write_record(
    db: &IdbDatabase,
    wallet_id: &str,
    bytes: &[u8],
    writer: &str,
    expected_sequence: u64,
) -> Result<u64, Error> {
    let transaction = db
        .transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)
        .map_err(|e| js_error("cannot start the snapshot write", e))?;
    let committed = transaction_future(&transaction);

    let written = async {
        let store = transaction
            .object_store(STORE_NAME)
            .map_err(|e| js_error("cannot open the snapshots store", e))?;
        let stored = read_store(&store, wallet_id).await?;
        let stored_sequence = stored.as_ref().map(|record| record.sequence).unwrap_or(0);
        if stored_sequence > expected_sequence {
            let stored_writer = stored
                .as_ref()
                .map(|record| record.writer.as_str())
                .unwrap_or(LEGACY_WRITER);
            return Err(internal(format!(
                "stale snapshot write rejected: the stored sequence is {stored_sequence}, written by {stored_writer}; reload the wallet before flushing"
            )));
        }
        let sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| internal("the snapshot sequence cannot be incremented"))?;
        let record = record_object(bytes, writer, sequence)?;
        let request = store
            .put_with_key(record.as_ref(), &JsValue::from_str(wallet_id))
            .map_err(|e| js_error("cannot write the snapshot", e))?;
        request_future(&request)
            .await
            .map_err(|e| js_error("cannot write the snapshot", e))?;
        // test-only: fail after the put so the transaction rolls back, as for the legacy write
        #[cfg(test)]
        match injected_failure() {
            Some(InjectedFailure::WriteFailed) => {
                return Err(internal("injected failure: the snapshot write failed"));
            }
            Some(InjectedFailure::AbortBeforeCommit) => {
                let _ = transaction.abort();
                return Err(internal(
                    "injected failure: the snapshot write aborted before commit",
                ));
            }
            _ => {}
        }
        Ok::<u64, Error>(sequence)
    }
    .await;

    match written {
        Ok(sequence) => committed
            .await
            .map(|_| sequence)
            .map_err(|e| js_error("cannot commit the snapshot", e)),
        Err(error) => {
            let _ = transaction.abort();
            Err(error)
        }
    }
}

/// Build the value stored for a guarded snapshot.
fn record_object(bytes: &[u8], writer: &str, sequence: u64) -> Result<js_sys::Object, Error> {
    let object = js_sys::Object::new();
    let set = |key: &str, value: &JsValue| {
        js_sys::Reflect::set(object.as_ref(), &JsValue::from_str(key), value)
            .map(|_| ())
            .map_err(|e| js_error("cannot build the snapshot record", e))
    };
    set("bytes", &js_sys::Uint8Array::from(bytes))?;
    set("writer", &JsValue::from_str(writer))?;
    set("sequence", &JsValue::from_f64(sequence as f64))?;
    Ok(object)
}

/// Decode a stored value: absent, a legacy `Uint8Array`, or a guarded record.
fn decode_record(value: JsValue) -> Result<Option<SnapshotRecord>, Error> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if value.is_instance_of::<js_sys::Uint8Array>() {
        let bytes = value.unchecked_into::<js_sys::Uint8Array>().to_vec();
        return Ok(Some(SnapshotRecord {
            bytes,
            writer: LEGACY_WRITER.to_string(),
            sequence: 0,
        }));
    }
    if !value.is_object() {
        return Err(internal(
            "the stored snapshot is neither bytes nor a snapshot record",
        ));
    }
    let bytes = js_sys::Reflect::get(&value, &JsValue::from_str("bytes"))
        .map_err(|e| js_error("cannot read the stored snapshot", e))?;
    if !bytes.is_instance_of::<js_sys::Uint8Array>() {
        return Err(internal("the stored snapshot record has no bytes"));
    }
    let bytes = bytes.unchecked_into::<js_sys::Uint8Array>().to_vec();
    let writer = js_sys::Reflect::get(&value, &JsValue::from_str("writer"))
        .map_err(|e| js_error("cannot read the stored snapshot", e))?
        .as_string()
        .ok_or_else(|| internal("the stored snapshot record has no writer"))?;
    let sequence = js_sys::Reflect::get(&value, &JsValue::from_str("sequence"))
        .map_err(|e| js_error("cannot read the stored snapshot", e))?;
    let sequence = sequence
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .filter(|value| *value <= 9_007_199_254_740_991.0)
        .ok_or_else(|| internal("the stored snapshot record has an invalid sequence"))?
        as u64;
    Ok(Some(SnapshotRecord {
        bytes,
        writer,
        sequence,
    }))
}

/// Read and decode the value of one key from an open store, inside the caller's transaction.
async fn read_store(
    store: &web_sys::IdbObjectStore,
    wallet_id: &str,
) -> Result<Option<SnapshotRecord>, Error> {
    let request = store
        .get(&JsValue::from_str(wallet_id))
        .map_err(|e| js_error("cannot read the snapshot", e))?;
    let value = request_future(&request)
        .await
        .map_err(|e| js_error("cannot read the snapshot", e))?;
    decode_record(value)
}

async fn read(db: &IdbDatabase, wallet_id: &str) -> Result<Option<SnapshotRecord>, Error> {
    let transaction = db
        .transaction_with_str(STORE_NAME)
        .map_err(|e| js_error("cannot start the snapshot read", e))?;

    let loaded = async {
        let store = transaction
            .object_store(STORE_NAME)
            .map_err(|e| js_error("cannot open the snapshots store", e))?;
        read_store(&store, wallet_id).await
    }
    .await;

    if loaded.is_err() {
        let _ = transaction.abort();
    }
    loaded
}

async fn remove(db: &IdbDatabase, wallet_id: &str) -> Result<(), Error> {
    let transaction = db
        .transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)
        .map_err(|e| js_error("cannot start the snapshot delete", e))?;
    let committed = transaction_future(&transaction);

    let deleted = async {
        let store = transaction
            .object_store(STORE_NAME)
            .map_err(|e| js_error("cannot open the snapshots store", e))?;
        let request = store
            .delete(&JsValue::from_str(wallet_id))
            .map_err(|e| js_error("cannot delete the snapshot", e))?;
        request_future(&request)
            .await
            .map_err(|e| js_error("cannot delete the snapshot", e))?;
        Ok::<(), Error>(())
    }
    .await;

    match deleted {
        Ok(()) => committed
            .await
            .map(|_| ())
            .map_err(|e| js_error("cannot commit the snapshot delete", e)),
        Err(error) => {
            let _ = transaction.abort();
            Err(error)
        }
    }
}
