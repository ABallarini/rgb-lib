//! Browser durable persistence for the in-memory backend; native builds use SQLite and do not use
//! this module.
//!
//! The wallet over the in-memory backend serializes its whole state with
//! [`Wallet::snapshot`](crate::wallet::Wallet::snapshot); the browser has no filesystem to write
//! those bytes to, so this module stores them in IndexedDB. One database (`rgb-lib`, version 1)
//! holds a single object store (`snapshots`) mapping the wallet id to the snapshot bytes. The
//! wallet id is the object store key: saving the same id replaces the previous snapshot.
//!
//! Only the wallet id and the snapshot are written: the snapshot excludes the mnemonic and the
//! signing keys (see `Wallet::snapshot`), so the stored value carries no secret material.
//! Errors surface as [`Error::Internal`] with the JS failure message and never with a value.
//!
//! # Host lifecycle
//!
//! The wallet owns every in-memory change until the host flushes it. On wasm32
//! [`Wallet::flush`](crate::wallet::Wallet::flush) and
//! [`MultisigWallet::flush`](crate::wallet::MultisigWallet::flush) serialize the wallet with
//! `snapshot` and delegate the write to [`save_snapshot`]. Flush is the only durable-write
//! boundary, and its future resolves once the IndexedDB transaction commits. Native builds expose
//! no flush method: their SQLite backend writes every change itself, so a native flush would be a
//! no-op.
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
//! The last flushed snapshot wins: changes made after the last flush are lost if the wallet goes
//! away without another flush. A flush error leaves the in-memory wallet usable, so the host can
//! retry. Two overlapping flushes for the same wallet id have no ordering guarantee: keep one
//! writer per wallet id.
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

/// Store the snapshot bytes under the wallet id, replacing any previous value.
///
/// Asynchronous: it resolves once the IndexedDB transaction commits, so the bytes are durable when
/// the future completes. `wallet_id` is the object store key, so saving the same id overwrites the
/// stored snapshot. The bytes are the output of [`Wallet::snapshot`](crate::wallet::Wallet::snapshot)
/// and carry no secret material. Errors are returned as [`Error::Internal`] with the JS failure
/// message.
///
/// Call this only on an explicit flush boundary, never concurrently for the same wallet id: two
/// overlapping writes for one id have no ordering guarantee.
pub async fn save_snapshot(wallet_id: &str, bytes: &[u8]) -> Result<(), Error> {
    let db = open().await?;
    let result = write(&db, wallet_id, bytes).await;
    db.close();
    result
}

/// Return the snapshot stored under the wallet id, if any.
///
/// Asynchronous: the host awaits it before constructing the wallet, because wallet constructors
/// are synchronous and cannot wait for IndexedDB. `wallet_id` is the object store key; `None`
/// means no snapshot has been saved for it yet. The returned bytes can be passed to
/// [`Wallet::from_snapshot`](crate::wallet::Wallet::from_snapshot). Errors are returned as
/// [`Error::Internal`] with the JS failure message.
pub async fn load_snapshot(wallet_id: &str) -> Result<Option<Vec<u8>>, Error> {
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

async fn read(db: &IdbDatabase, wallet_id: &str) -> Result<Option<Vec<u8>>, Error> {
    let transaction = db
        .transaction_with_str(STORE_NAME)
        .map_err(|e| js_error("cannot start the snapshot read", e))?;

    let loaded = async {
        let store = transaction
            .object_store(STORE_NAME)
            .map_err(|e| js_error("cannot open the snapshots store", e))?;
        let request = store
            .get(&JsValue::from_str(wallet_id))
            .map_err(|e| js_error("cannot read the snapshot", e))?;
        let value = request_future(&request)
            .await
            .map_err(|e| js_error("cannot read the snapshot", e))?;
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }
        let array = value
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| internal("the stored snapshot is not a Uint8Array"))?;
        Ok(Some(array.to_vec()))
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
