#!/bin/bash
# Fail-fast gate for the WASM portability work.
#
# Runs the checks that must stay green for every step, including the wallet
# build for wasm32, which compiles over the in-memory backend (no SQLite/Tokio).
# The browser lifecycle test needs Chrome and a wasm-bindgen test runner, so it
# runs in the `wasm_browser_lifecycle` CI job instead of here.
set -e

CWD=$(dirname "${0}")
cd "${CWD}/.."

_run() {
    echo "+ $*"
    "$@"
}

_run rustup target add wasm32-unknown-unknown
_run cargo fmt --all -- --check
_run cargo check --lib --all-features
_run cargo test --lib --no-default-features --features wallet
_run cargo check --lib --target wasm32-unknown-unknown --no-default-features
_run cargo check --lib --target wasm32-unknown-unknown --no-default-features --features wallet
