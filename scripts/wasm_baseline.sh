#!/bin/bash
# Print the toolchain versions and run the WASM portability baseline.
#
# The gate runs first and fails fast. The wallet build for wasm32 is then run
# as an informational check: it is expected to fail at this baseline and its
# failure must not be recorded as a passing check.
set -e

CWD=$(dirname "${0}")
cd "${CWD}/.."

echo "== toolchain =="
rustc --version
cargo --version
rustup --version
rustup target list --installed
echo

./scripts/wasm_gate.sh
echo

echo "== informational: wallet on wasm32 (expected to fail at this baseline) =="
if cargo check --lib --target wasm32-unknown-unknown --no-default-features --features wallet; then
    echo "RESULT: pass"
else
    echo "RESULT: fail (known baseline blocker, see WASM_PROGRESS.md)"
fi
