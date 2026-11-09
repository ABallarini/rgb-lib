#!/bin/bash
# Fail-fast gate for the WASM portability work.
#
# Runs the checks that must stay green for every step, including the wallet
# build for wasm32, which compiles over the in-memory backend (no SQLite/Tokio).
# The wasm wallet build treats rustc warnings as errors and the native and wasm
# wallet builds must stay clippy-clean.
# The browser lifecycle test needs Chrome and a wasm-bindgen test runner, so it
# runs in the `wasm_browser_lifecycle` CI job instead of here.
set -e

CWD=$(dirname "${0}")
cd "${CWD}/.."

_run() {
    echo "+ $*"
    "$@"
}

# Treat rustc warnings as errors for the step: the wasm wallet build must stay warning-free.
_run_deny_warnings() {
    echo "+ RUSTFLAGS='-D warnings' $*"
    RUSTFLAGS="-D warnings" "$@"
}

_run rustup target add wasm32-unknown-unknown
_run cargo fmt --all -- --check
_run cargo check --lib --all-features
_run cargo clippy --lib --all-features -- -D warnings
_run cargo test --lib --no-default-features --features wallet
_run cargo check --lib --target wasm32-unknown-unknown --no-default-features
_run_deny_warnings cargo check --lib --target wasm32-unknown-unknown --no-default-features --features wallet
_run cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features wallet -- -D warnings
