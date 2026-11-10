//! The crate's narrow boundary for CPU-bound, expensive operations.
//!
//! Only two operations in this crate are expensive enough to be worth a boundary: the scrypt key
//! derivation of wallet backups and the proof of work a proxy may demand before accepting a
//! consignment. Both are bounded by their inputs, but their cost is large: scrypt's is set by its
//! params (the default needs 128 MiB and takes a noticeable fraction of a second) and the proof of
//! work's by the difficulty the remote proxy asks for. They are the only work a browser binding
//! could want to run off the page's only thread.
//!
//! The boundary is operation-specific on purpose. A Web Worker cannot carry a closure, so a
//! worker-backed implementation must serialize named calls, not arbitrary jobs; there is no job
//! system here. The default implementation runs both operations inline on the calling thread,
//! exactly as the crate did before this module existed, and a Worker is never required: operations
//! that are small and bounded keep running inline.

use std::sync::{Arc, OnceLock};

use scrypt::Params;

/// The crate's expensive operations, one method per operation.
///
/// A binding that wants a Web Worker supplies an implementation of this trait; without one the
/// inline default below is used.
pub(crate) trait CpuExecutor: Send + Sync {
    /// Derive a key with scrypt, with the same result and error as [`scrypt::scrypt`].
    fn scrypt(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &Params,
        output: &mut [u8],
    ) -> Result<(), scrypt::errors::InvalidOutputLen>;

    /// Find a proof-of-work nonce, with the same result as
    /// [`solve_pow`](crate::encryption::solve_pow).
    #[cfg(feature = "_online")]
    fn proof_of_work(&self, transfer_id: &str, pow_timestamp: &str, difficulty: u32) -> String;
}

/// Runs every operation inline, on the calling thread.
pub(crate) struct InlineCpuExecutor;

impl CpuExecutor for InlineCpuExecutor {
    fn scrypt(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &Params,
        output: &mut [u8],
    ) -> Result<(), scrypt::errors::InvalidOutputLen> {
        scrypt::scrypt(password, salt, params, output)
    }

    #[cfg(feature = "_online")]
    fn proof_of_work(&self, transfer_id: &str, pow_timestamp: &str, difficulty: u32) -> String {
        crate::encryption::solve_pow(transfer_id, pow_timestamp, difficulty)
    }
}

static INLINE: InlineCpuExecutor = InlineCpuExecutor;
static INSTALLED: OnceLock<Arc<dyn CpuExecutor>> = OnceLock::new();

/// The executor to use: the one a binding installed, or the inline default.
pub(crate) fn cpu_executor() -> &'static dyn CpuExecutor {
    match INSTALLED.get() {
        Some(executor) => executor.as_ref(),
        None => &INLINE,
    }
}

/// Install a binding-provided executor, e.g. one that posts work to a Web Worker.
///
/// The first install wins and must happen before the first expensive operation. Nothing in this
/// crate installs one: no in-crate caller needs off-thread execution, so the seam is open for a
/// host binding and the default stays inline.
#[allow(dead_code)] // the host binding's entry point; no in-crate caller yet
pub(crate) fn install_cpu_executor(executor: Arc<dyn CpuExecutor>) {
    let _ = INSTALLED.set(executor);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap params (log_n 4) keep the scrypt tests fast; the boundary must not change the result.
    fn params() -> Params {
        Params::new(4, 1, 1).expect("valid params")
    }

    #[test]
    fn inline_scrypt_matches_the_crate_function() {
        let params = params();
        let mut expected = [0u8; 32];
        let mut actual = [0u8; 32];
        scrypt::scrypt(b"password", b"salt", &params, &mut expected).unwrap();
        InlineCpuExecutor
            .scrypt(b"password", b"salt", &params, &mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn inline_scrypt_returns_the_same_error() {
        let params = params();
        // scrypt rejects an empty output; the boundary must surface the same error
        assert!(scrypt::scrypt(b"password", b"salt", &params, &mut []).is_err());
        assert!(
            InlineCpuExecutor
                .scrypt(b"password", b"salt", &params, &mut [])
                .is_err()
        );
    }

    #[test]
    #[cfg(feature = "_online")]
    fn inline_proof_of_work_matches_solve_pow() {
        for difficulty in [0, 8] {
            assert_eq!(
                InlineCpuExecutor.proof_of_work("tid", "123", difficulty),
                crate::encryption::solve_pow("tid", "123", difficulty)
            );
        }
    }

    /// The boundary is object-safe and injectable: a binding can supply its own implementation
    /// behind `Arc<dyn CpuExecutor>` without the crate knowing what it does.
    #[test]
    fn boundary_takes_an_arc_trait_object() {
        struct Counting(std::sync::atomic::AtomicUsize);

        impl CpuExecutor for Counting {
            fn scrypt(
                &self,
                password: &[u8],
                salt: &[u8],
                params: &Params,
                output: &mut [u8],
            ) -> Result<(), scrypt::errors::InvalidOutputLen> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                InlineCpuExecutor.scrypt(password, salt, params, output)
            }

            #[cfg(feature = "_online")]
            fn proof_of_work(
                &self,
                transfer_id: &str,
                pow_timestamp: &str,
                difficulty: u32,
            ) -> String {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                InlineCpuExecutor.proof_of_work(transfer_id, pow_timestamp, difficulty)
            }
        }

        let executor = Counting(std::sync::atomic::AtomicUsize::new(0));
        let dynamic: Arc<dyn CpuExecutor> = Arc::new(executor);
        let mut out = [0u8; 32];
        dynamic.scrypt(b"p", b"s", &params(), &mut out).unwrap();
        assert_eq!(out, {
            let mut expected = [0u8; 32];
            scrypt::scrypt(b"p", b"s", &params(), &mut expected).unwrap();
            expected
        });
    }

    /// Without an installed executor the crate runs the inline default, which needs no worker.
    #[test]
    fn unset_seam_uses_the_inline_default() {
        let mut out = [0u8; 32];
        cpu_executor()
            .scrypt(b"p", b"s", &params(), &mut out)
            .unwrap();
        assert_ne!(out, [0u8; 32]);
    }
}
