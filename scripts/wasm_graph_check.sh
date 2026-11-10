#!/bin/bash
# Fail-fast dependency-graph gate for the wasm32 wallet builds.
#
# Resolves the graph that actually applies to `wasm32-unknown-unknown` for the two
# browser feature sets and fails if a crate that cannot work in a browser appears:
# no `mio` (epoll sockets), no `libsqlite3-sys` (native C SQLite), no `ring`
# (native assembly), no native TLS backend, no blocking HTTP client, no Tokio or
# hyper runtime and no native socket indexer. The wallet build must also leave a
# wasm artifact behind and that artifact must not reference a native import.
#
# `--self-test` feeds a synthetic forbidden graph line through the same check and
# asserts it fails, so the detection itself is tested.
set -euo pipefail

CWD=$(dirname "${0}")
cd "${CWD}/.."

TARGET="wasm32-unknown-unknown"
ARTIFACT="target/${TARGET}/debug/librgb_lib.rlib"

# Crates that cannot run in a browser, matched against the start of a
# `cargo tree --prefix none` entry ("name vX.Y.Z"). Native TLS is listed by its
# backend crates: the browser has no socket stack, so all of them are forbidden.
FORBIDDEN=(
    mio
    libsqlite3-sys
    sqlx-sqlite
    sqlx-core
    ring
    native-tls
    openssl
    openssl-sys
    rustls
    tokio-rustls
    hyper-rustls
    minreq
    tokio
    hyper
    bdk_electrum
    bdk_bitcoind_rpc
)

# Allowed even though the name looks native, each with its reason. Keep in sync
# with Cargo.toml when the browser dependency set changes.
cat <<'EOF'
allowed dependencies (and why they are safe on wasm32):
  getrandom 0.2/0.3/0.4   browser entropy through the `js`/`wasm_js` backends that the `wallet`
                          feature enables; no OS entropy source is linked
  js-sys, wasm-bindgen,   browser APIs (IndexedDB snapshot store, fetch, timers); they compile to
  wasm-bindgen-futures,   wasm imports of the host, not to native code
  web-sys
  reqwest 0.12.28         only the `fetch` backend is compiled (`reqwest_fetch`); the blocking,
                          TLS and socket features are never enabled on wasm32
  secp256k1-sys,          C sources compiled by `cc` to wasm objects; no host library is linked
  zstd-sys
EOF
echo

# assert_clean <label>: reads a `cargo tree` graph on stdin, fails on a forbidden crate.
assert_clean() {
    local label=$1 line name failed=0
    while IFS= read -r line; do
        for name in "${FORBIDDEN[@]}"; do
            case "${line}" in
                "${name} v"*) echo "FAIL: forbidden crate '${name}' in the wasm graph for ${label}"; failed=1 ;;
            esac
        done
    done
    ((failed == 0)) || return 1
    echo "ok: no forbidden crate in the wasm graph for ${label}"
}

graph() {
    cargo tree --target "${TARGET}" --no-default-features --features "$1" -e normal --prefix none
}

# check_graph <features>: resolve the real graph and assert it is clean.
check_graph() {
    local features=$1 resolved
    resolved=$(graph "${features}")
    [[ -n "${resolved}" ]] || { echo "FAIL: empty dependency graph for ${features}"; return 1; }
    printf '%s\n' "${resolved}" | assert_clean "${features}"
}

# check_artifact: the built wasm artifact must exist and reference no native import.
#
# `cargo build --lib` emits an rlib (this crate has no cdylib target), so there is
# no linked wasm module to read an import section from, and no wasm inspector
# (wasm-objdump/wasm-tools) is installed. The strongest check available is the
# graph plus a scan of the archive bytes: the crate's own wasm objects live there,
# so a native import module or symbol would show up as a string.
check_artifact() {
    local size name
    [[ -f "${ARTIFACT}" ]] || { echo "FAIL: no wasm artifact at ${ARTIFACT}"; return 1; }
    size=$(stat -c%s "${ARTIFACT}")
    if ((size < 1000000)); then
        echo "FAIL: wasm artifact ${ARTIFACT} is only ${size} bytes, expected a populated rlib"
        return 1
    fi
    echo "ok: wasm artifact ${ARTIFACT} exists (${size} bytes)"
    for name in wasi_snapshot_preview1 libsqlite3 mio_sys tokio hyper; do
        if grep -qa "${name}" "${ARTIFACT}"; then
            echo "FAIL: '${name}' referenced in ${ARTIFACT}"
            return 1
        fi
    done
    echo "ok: no native import string in ${ARTIFACT}"
}

if [[ "${1:-}" == "--self-test" ]]; then
    if printf 'mio v1.1.0\n' | assert_clean "self-test (synthetic forbidden line)"; then
        echo "FAIL: checker accepted a synthetic forbidden line"
        exit 1
    fi
    echo "ok: checker rejects a synthetic forbidden line"
    exit 0
fi

check_graph wallet
check_graph wallet,esplora_async

echo "+ cargo build --lib --target ${TARGET} --no-default-features --features wallet,esplora_async"
cargo build --lib --target "${TARGET}" --no-default-features --features wallet,esplora_async
check_artifact
