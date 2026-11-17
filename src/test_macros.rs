//! Test-only macros shared by every `#[cfg(test)]` module.
//!
//! The assertion lives here rather than in a wallet test helper so that the wasm32 test build,
//! which does not compile `wallet::test`, still has it.

/// Panic if the given expression doesn't match the provided pattern, logging the unexpected result
#[macro_export]
macro_rules! assert_matches {
    ($expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {{
        #[allow(unreachable_patterns)]
        match $expression {
            $pattern $(if $guard)? => {},
            _ => {
                panic!("received unexpected result: {}", format!("{:?}", $expression));
            }
        }
    }};
}
