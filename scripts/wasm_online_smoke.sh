#!/bin/bash
# Opt-in browser online smoke test for the wasm wallet.
#
# It runs `regtest_esplora_online_smoke` (src/wallet/test_wasm_online.rs) in headless Chrome
# through `wasm-bindgen-test-runner`, against a controlled regtest Esplora endpoint. Every request
# is read-only: no broadcast, no spend, no mainnet.
#
# What is proven: the async `EsploraTransport` and `EsploraResolver` reach a real Esplora over the
# browser `fetch` backend (tip height, tip/block-1 hash, header, block-1 coinbase TX, confirmations,
# fee-estimate mapping, witness/chain-net resolution). When `RGB_REGTEST_PROXY_URL` is set, one
# read-only proxy call (`server.info`) is proven too.
#
# What is NOT proven: the wallet online flow. On wasm, `go_online`, `OnlineOptions`, sync and
# transfers still live behind the native-only `_online` feature; `esplora_async` does not enable it.
# The test asserts that gate instead of faking an end-to-end flow. Wiring the transport into
# `WalletOnline` is a later step.
#
# Controlled environment (a fresh regtest chain has only genesis, so mine first):
#
#   bitcoind -regtest -fallbackfee=0.0002 -txindex -daemon
#   bitcoin-cli -regtest -generate 101        # funds + height > 0
#   # start an Esplora-compatible indexer for regtest, e.g. electrs or the Esplora image,
#   # and point ESPLORA_URL at it (default http://127.0.0.1:3002)
#
# Usage:
#   export RGB_REGTEST_ESPLORA_URL=http://127.0.0.1:3002
#   export RGB_REGTEST_PROXY_URL=http://127.0.0.1:3000   # optional
#   bash scripts/wasm_online_smoke.sh
#
# Requirements: rust with the wasm32-unknown-unknown target, `wasm-bindgen-test-runner` matching
# the wasm-bindgen version in Cargo.lock, and a Chrome/chromedriver pair. CI adds these in the
# `wasm_browser_lifecycle` job; this script deliberately does not change required CI (S41 decides).
set -euo pipefail

cd "$(dirname "${0}")/.."

ESPLORA_URL="${RGB_REGTEST_ESPLORA_URL:-}"
PROXY_URL="${RGB_REGTEST_PROXY_URL:-}"

if [[ -z "${ESPLORA_URL}" ]]; then
    echo "RGB_REGTEST_ESPLORA_URL is not set; nothing to smoke against." >&2
    echo "See the header of this script for the regtest setup." >&2
    exit 2
fi

for tool in wasm-bindgen-test-runner chromedriver; do
    command -v "${tool}" >/dev/null || {
        echo "missing ${tool}; install it (see the CI job) before running this smoke." >&2
        exit 2
    }
done

height=$(curl -fsS --max-time 10 "${ESPLORA_URL}/blocks/tip/height")
if [[ ! "${height}" =~ ^[0-9]+$ ]] || (( height < 1 )); then
    echo "Esplora at ${ESPLORA_URL} reports tip height '${height}'; mine at least one block." >&2
    exit 2
fi

export RGB_REGTEST_ESPLORA_URL="${ESPLORA_URL}"
if [[ -n "${PROXY_URL}" ]]; then
    export RGB_REGTEST_PROXY_URL="${PROXY_URL}"
fi
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_TEST_TIMEOUT=300

# The env vars are compile-time: touch the test so a baked-in URL from an old build cannot win.
touch src/wallet/test_wasm_online.rs

cargo test --lib --target wasm32-unknown-unknown --no-default-features \
    --features wallet,esplora_async -- regtest_esplora_online_smoke
