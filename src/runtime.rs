//! The crate's single blocking runtime boundary.
//!
//! The SQLite driver (`sea-orm`'s `runtime-tokio-rustls`) drives its connection pool on a Tokio
//! runtime, while rgb-lib's database API is synchronous. This module is the only place in the
//! crate that owns a runtime: every synchronous database path reaches it through `block_on`, so
//! the runtime flavour, its lifetime and the re-entrancy rule live in one place.
//!
//! What is kept, unchanged from the `utils::block_on` this came from:
//!
//! - one multi-threaded runtime for the whole process, created on first use and shared. Database
//!   calls happen once per wallet operation, so a runtime per call would spawn and tear down a
//!   thread pool per query;
//! - the call completes before it returns: this is not a background dispatch and it is safe to
//!   call again straight after;
//! - re-entrancy: when the calling thread already drives a Tokio runtime (a caller's own native
//!   bridge, or a test), the future runs on a scoped thread against the shared runtime. Blocking
//!   the caller's runtime thread from inside it would panic or deadlock, so it is left free, and
//!   the scoped thread joins before `block_on` returns;
//! - a panic while driving the future reaches the caller as a panic, as before.
//!
//! # wasm32
//!
//! There is no blocking runtime on wasm32 and there must be none: the browser has one thread and a
//! storage future only completes while the event loop runs, so blocking would deadlock the page.
//! This module compiles empty on that target, so `block_on` does not exist there and a wasm caller
//! that tries to block on a browser future fails to build instead of hanging at run time. The wasm
//! wallet reaches storage through the `async` API in `wallet::persistence` instead.

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use std::sync::LazyLock;
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use tokio::runtime::{Handle, Runtime};

// sea-orm with runtime-tokio-rustls needs a tokio runtime for connection pool management
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
static TOKIO_RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("failed to create the runtime"));

/// Block on a future to completion on the shared runtime, spawning a scoped thread if already
/// inside a Tokio runtime.
///
/// Native only: on wasm32 this function does not exist.
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if Handle::try_current().is_ok() {
        // avoid blocking the Tokio runtime thread; spawn a new thread
        std::thread::scope(|s| {
            s.spawn(|| TOKIO_RUNTIME.block_on(future))
                .join()
                .expect("rgb-lib block_on thread panicked")
        })
    } else {
        TOKIO_RUNTIME.block_on(future)
    }
}

// The blocking runtime is gated on `sqlite` and never on wasm32. Assert the enabling condition
// here too, at the boundary: if the gate above is ever widened to wasm32 this build fails instead
// of shipping a runtime that would block the browser's only thread.
#[cfg(target_arch = "wasm32")]
const _: () = assert!(!cfg!(all(feature = "sqlite", not(target_arch = "wasm32"))));

// The test build needs the runtime half, which only exists for native `sqlite` builds. The wasm32
// browser test build compiles this module empty, so these tests are left out there.
#[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// A representative caller: one database-shaped call that completes with a value or an error.
    async fn call(fail: bool) -> Result<u32, std::io::Error> {
        if fail {
            Err(std::io::Error::other("connection closed"))
        } else {
            Ok(42)
        }
    }

    /// The abstraction drives a call exactly like a dedicated runtime, on both the success and the
    /// error path, so routing a caller through it cannot change what that caller sees.
    #[test]
    fn block_on_matches_a_dedicated_runtime() {
        let dedicated = Runtime::new().unwrap();
        let expected_ok = dedicated.block_on(call(false)).unwrap();
        let expected_err = dedicated.block_on(call(true)).unwrap_err().to_string();

        assert_eq!(block_on(call(false)).unwrap(), expected_ok);
        assert_eq!(block_on(call(true)).unwrap_err().to_string(), expected_err);
    }

    /// Source-audit pin for the wasm32 port: the browser has one thread, so any thread-creating or
    /// blocking path that can be reached there would panic or freeze the page. Every occurrence of
    /// such a token in non-test source must be listed below with the gate that keeps wasm32 out, so
    /// a new path fails here until it is reviewed.
    #[test]
    fn no_thread_path_is_reachable_on_wasm32() {
        // split so this audit does not match its own token list
        let tokens = [
            concat!("thread::", "spawn"),
            concat!("thread::", "scope"),
            concat!("Builder::new().", "spawn"),
            concat!("tokio::", "spawn"),
            concat!("spawn_", "blocking"),
            concat!("slog_async::Async::", "new"),
            concat!("sle", "ep("),
        ];
        // reviewed allowlist: file relative to `src/` -> occurrences and why wasm32 never sees it
        let reviewed: &[(&str, usize)] = &[
            // the native-only re-entrancy thread; the gate above also fails the wasm build
            ("runtime.rs", 1),
            // test-only mock electrum server, `cfg(all(test, feature = "_online"))`
            ("wallet/indexer.rs", 1),
            // native `slog_async` drain, plus a test-only mock electrum server
            ("utils.rs", 2),
            // browser retry backoff: the async client's `Sleeper::sleep` resolves a `setTimeout`
            // promise, so nothing blocks the page; wasm32-only module
            ("wallet/indexer_async.rs", 1),
        ];

        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);

        let mut actual = Vec::new();
        for file in files {
            let relative = file
                .strip_prefix(&src)
                .expect("source file under src")
                .to_string_lossy()
                .replace('\\', "/");
            // the browser lifecycle tests live in `test_wasm.rs` and `wallet/test/`; they are not
            // part of the wasm wallet build, which compiles the library without `cfg(test)`
            if relative == "wallet/test_wasm.rs" || relative.starts_with("wallet/test/") {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("read source file");
            let count = tokens
                .iter()
                .map(|t| text.matches(t).count())
                .sum::<usize>();
            if count > 0 {
                actual.push((relative, count));
            }
        }
        actual.sort();

        let mut expected: Vec<(String, usize)> = reviewed
            .iter()
            .map(|(path, count)| (path.to_string(), *count))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            actual, expected,
            "thread or blocking path changed: review it for wasm32 and update the allowlist"
        );
    }

    fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_files(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
}
