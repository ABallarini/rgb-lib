#!/bin/bash
# Fail-fast gate for the WASM portability work.
#
# Runs the checks that must stay green for every step. The wallet build for
# wasm32 is not included here until it is genuinely green; the baseline script
# runs it as a separate, clearly labelled informational check.
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
