#!/bin/bash
# Opt-in browser online smoke test for the wasm wallet.
#
# It runs `regtest_esplora_online_smoke` (src/wallet/test_wasm_online.rs) in headless Chrome
# through `wasm-bindgen-test-runner`, against a controlled regtest Esplora endpoint. Every request
# is read-only: no broadcast, no spend, no mainnet.
#
# What is proven: the async `EsploraTransport` and `EsploraResolver` reach a real Esplora over the
# browser `fetch` backend (tip height, tip/block-1 hash, header, block-1 coinbase TX, confirmations,
# fee-estimate mapping, witness/chain-net resolution). The wallet's online steps are proven too:
# `Wallet::sync_async` full-scans both BDK keychains through the transport, persists the update in
# the wallet database (a snapshot restore sees it), and answers `tip_height_async` and
# `fee_estimation_async`. When `RGB_REGTEST_PROXY_URL` is set, one read-only proxy call
# (`server.info`) is proven too. When `RGB_REGTEST_MNEMONIC` is set, the scan must see funding of
# that mnemonic's first internal receive address.
#
# `regtest_proxy_receive_smoke` additionally runs when `RGB_REGTEST_PROXY_URL`,
# `RGB_REGTEST_MNEMONIC` and `RGB_REGTEST_TRANSFER_ID` are set: it runs `sync_online_async` and
# `receive_transfer_async` against a real pending proxy transfer prepared by the harness, asserts
# the second receive is idempotent, and checks the recorded ACK and the transfer status. Preparing
# the transfer needs the native sender flow (the browser cannot reserve a proxy invoice yet):
# create a proxy receive on a native wallet with these keys and send to it. Without that setup the
# test returns early.
#
# What is NOT proven: transfers, send, proxy invoice reservation, media upload and hub
# coordination. Those still live behind the native-only `_online` feature; `esplora_async` does not
# enable it, and the regression test still asserts that gate.
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
#   export RGB_REGTEST_MNEMONIC="..."                    # optional: fund its first internal address
#   export RGB_REGTEST_TRANSFER_ID="..."                 # optional: a pending proxy transfer for it
#   bash scripts/wasm_online_smoke.sh
#
# `RGB_REGTEST_MNEMONIC` makes the funded-balance assertion real. Create a wallet from it, take the
# first address from `getAddress()` (the vanilla/internal receive address) and send regtest BTC to
# it before running. Without the variable that assertion is skipped, so the smoke still proves the
# scan, the persisted state, the tip and the fee estimate on an unfunded wallet. The same mnemonic
# plus `RGB_REGTEST_TRANSFER_ID` makes the receive smoke real: the named proxy transfer must be
# pending for an invoice of that wallet.
#
# Requirements: rust with the wasm32-unknown-unknown target, `wasm-bindgen-test-runner` matching
# the wasm-bindgen version in Cargo.lock, and a Chrome/chromedriver pair. CI adds these in the
# `wasm_browser_lifecycle` job; this script deliberately does not change required CI (S41 decides).
set -euo pipefail

cd "$(dirname "${0}")/.."

ESPLORA_URL="${RGB_REGTEST_ESPLORA_URL:-}"
PROXY_URL="${RGB_REGTEST_PROXY_URL:-}"
FUNDED_MNEMONIC="${RGB_REGTEST_MNEMONIC:-}"

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
if [[ -n "${FUNDED_MNEMONIC}" ]]; then
    export RGB_REGTEST_MNEMONIC="${FUNDED_MNEMONIC}"
fi
TRANSFER_ID="${RGB_REGTEST_TRANSFER_ID:-}"
if [[ -n "${TRANSFER_ID}" ]]; then
    export RGB_REGTEST_TRANSFER_ID="${TRANSFER_ID}"
fi
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_TEST_TIMEOUT=300

# The env vars are compile-time: touch the test so a baked-in URL from an old build cannot win.
touch src/wallet/test_wasm_online.rs

cargo test --lib --target wasm32-unknown-unknown --no-default-features \
    --features wallet,esplora_async -- regtest_
