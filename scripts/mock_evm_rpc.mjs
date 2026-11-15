#!/usr/bin/env node
// Mock EVM JSON-RPC node for the browser BFA claim transport test.
//
// Dependency-free: plain Node HTTP, no anvil, no docker, no network. It answers the handful of
// methods `EvmFetchClient` uses so `src/wallet/test_wasm_bfa.rs` can prove the real browser
// `fetch` transport (CORS preflight included) end to end.
//
// Fixed chain state:
//
// - `eth_chainId`                     31337 (override with `?chain_id=<id>` on the RPC URL)
// - `eth_blockNumber`                 19
// - `eth_getBlockByNumber("finalized")` 15
// - `eth_call` `getFundsInBlock` (0x2ce06e2d)  a per-lock word, keyed by the requested amount
// - `eth_call` `circulatingSupply` (0x9358928b) 1000
// - `eth_call` `length()` (0x1f7b6d32)          2
// - `eth_call` `entries()` (0x17b937e6)         one rejected and one allowed opout
//
// `getFundsInBlock` returns the block plus one, zero meaning "no record" (see
// `decode_funds_in_block`), so the test can drive the three lock statuses from the amount:
//
// - 100 -> included in block 17  (Confirmed for a claim committing to block 18)
// - 200 -> no record             (Pending  for a claim committing to block 30)
// - any other amount -> no record
// - 300 -> included in block 21  (Expired   for a claim committing to block 18)
//
// Control endpoints (GET, never counted as JSON-RPC calls):
//
// - `/__health`  `{"ok":true}` once the server listens
// - `/__count`   `{"count":N}` JSON-RPC requests served since the last reset
// - `/__calls`   `{"count":N,"calls":[...]}` exact request order; each entry is the method, plus
//                 the selector and block tag for `eth_call` and the tag for
//                 `eth_getBlockByNumber`, e.g. `eth_call:0x2ce06e2d:0xf`
// - `/__reset`   `{"ok":true}` clears the counter and the call log
//
// Any other POST is treated as JSON-RPC, whatever its path. `?fail=<status>` on the RPC URL makes
// every JSON-RPC request fail with that HTTP status, to exercise the error mapping and prove the
// URL (which may carry an API key) never reaches an error message.
//
// Usage:
//
//   node scripts/mock_evm_rpc.mjs --port 18545
//   curl -s http://127.0.0.1:18545/__health
//
// `--host` defaults to 127.0.0.1.

import http from 'node:http';

const args = process.argv.slice(2);
function argValue(name, fallback) {
    const index = args.indexOf(name);
    return index === -1 || index === args.length - 1 ? fallback : args[index + 1];
}

const PORT = Number(argValue('--port', '18545'));
const HOST = argValue('--host', '127.0.0.1');

/** Body cap: a JSON-RPC request is a few hundred bytes. */
const MAX_BODY_BYTES = 64 * 1024;

const CHAIN_ID = 31337;
const LATEST_BLOCK = 19;
const FINALIZED_BLOCK = 15;
const CIRCULATING_SUPPLY = 1000;

const FUNDS_IN_BLOCK_SELECTOR = '0x2ce06e2d';
const CIRCULATING_SUPPLY_SELECTOR = '0x9358928b';
const REJECT_LIST_LENGTH_SELECTOR = '0x1f7b6d32';
const REJECT_LIST_ENTRIES_SELECTOR = '0x17b937e6';

/** Amount (as a decimal string) -> block the lock was included in. Missing means no record. */
const LOCK_BLOCKS = new Map([
    ['100', 17n],
    ['300', 21n],
]);

/** The two reject list entries the contract serves: the first is rejected, the second allowed. */
const REJECT_LIST_ENTRIES = [
    { op: '44'.repeat(32), ty: 4000n, no: 7n, reject: true },
    { op: '55'.repeat(32), ty: 4000n, no: 8n, reject: false },
];

const CORS_HEADERS = {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    // Chrome sends this on a preflight from a page asking for a local address
    'access-control-allow-private-network': 'true',
};

let count = 0;
let calls = [];

/** A 32-byte ABI word. */
function word(value) {
    return value.toString(16).padStart(64, '0');
}

function hexQuantity(value) {
    return `0x${value.toString(16)}`;
}

function sendJson(res, status, body) {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        ...CORS_HEADERS,
    });
    res.end(payload);
}

/** The mock's `eth_call` answers, by selector. The state it reports does not depend on the block
 * tag the call asks about: `/__calls` records the tag so the test can assert which one was used. */
function ethCall(call) {
    const data = typeof call?.data === 'string' ? call.data.toLowerCase() : '';
    const selector = data.slice(0, 10);
    const body = data.slice(10);
    switch (selector) {
        case FUNDS_IN_BLOCK_SELECTOR: {
            // (uint256 lockId, uint256 amount): the amount is the second word
            if (body.length < 128) {
                return word(0n);
            }
            const amount = BigInt(`0x${body.slice(64, 128)}`).toString();
            const block = LOCK_BLOCKS.get(amount);
            // the record is the block plus one, zero meaning there's none
            return `0x${word(block === undefined ? 0n : block + 1n)}`;
        }
        case CIRCULATING_SUPPLY_SELECTOR:
            return `0x${word(BigInt(CIRCULATING_SUPPLY))}`;
        case REJECT_LIST_LENGTH_SELECTOR:
            return `0x${word(BigInt(REJECT_LIST_ENTRIES.length))}`;
        case REJECT_LIST_ENTRIES_SELECTOR: {
            const words = [word(32n), word(BigInt(REJECT_LIST_ENTRIES.length))];
            for (const entry of REJECT_LIST_ENTRIES) {
                words.push(
                    entry.op.padStart(64, '0'),
                    word(entry.ty),
                    word(entry.no),
                    word(entry.reject ? 1n : 0n),
                );
            }
            return `0x${words.join('')}`;
        }
        default:
            return null;
    }
}

/** The label recorded in `/__calls` for one request. */
function label(method, params) {
    if (method === 'eth_call') {
        const data = typeof params[0]?.data === 'string' ? params[0].data : '';
        return `eth_call:${data.slice(0, 10).toLowerCase()}:${params[1]}`;
    }
    if (method === 'eth_getBlockByNumber') {
        return `eth_getBlockByNumber:${params[0]}`;
    }
    return method;
}

/** Handle one JSON-RPC request, returning `{result}` or `{error}`. */
function dispatch(request, url) {
    const method = request.method;
    const params = Array.isArray(request.params) ? request.params : [];
    count += 1;
    calls.push(label(method, params));
    console.log(`jsonrpc ${calls[calls.length - 1]}`);

    switch (method) {
        case 'eth_chainId': {
            const requested = Number(url.searchParams.get('chain_id') ?? CHAIN_ID);
            const chainId = Number.isSafeInteger(requested) && requested >= 0 ? requested : CHAIN_ID;
            return { result: hexQuantity(chainId) };
        }
        case 'eth_blockNumber':
            return { result: hexQuantity(LATEST_BLOCK) };
        case 'eth_getBlockByNumber': {
            const tag = params[0];
            if (tag === 'finalized') {
                return { result: { number: hexQuantity(FINALIZED_BLOCK) } };
            }
            if (tag === 'latest') {
                return { result: { number: hexQuantity(LATEST_BLOCK) } };
            }
            if (typeof tag === 'string' && /^0x[0-9a-f]+$/i.test(tag)) {
                return { result: { number: tag } };
            }
            return { result: null };
        }
        case 'eth_call': {
            const result = ethCall(params[0]);
            if (result === null) {
                return {
                    error: {
                        code: 3,
                        message: 'execution reverted: unknown selector in the mock',
                    },
                };
            }
            return { result };
        }
        default:
            return { error: { code: -32601, message: `method ${method} not found` } };
    }
}

function handleRpc(req, res, url) {
    let body = '';
    let bytes = 0;
    let refused = false;
    req.on('data', (chunk) => {
        if (refused) {
            return;
        }
        bytes += chunk.length;
        if (bytes > MAX_BODY_BYTES) {
            refused = true;
            sendJson(res, 413, { error: { code: -32600, message: 'request body too large' } });
            req.destroy();
            return;
        }
        body += chunk;
    });
    req.on('end', () => {
        if (refused) {
            return;
        }
        let request;
        try {
            request = JSON.parse(body);
        } catch {
            sendJson(res, 400, {
                jsonrpc: '2.0',
                id: null,
                error: { code: -32700, message: 'parse error' },
            });
            return;
        }
        const id = request && request.id !== undefined ? request.id : null;
        const answer = dispatch(request, url);
        if (answer.error) {
            sendJson(res, 200, { jsonrpc: '2.0', id, error: answer.error });
            return;
        }
        sendJson(res, 200, { jsonrpc: '2.0', id, result: answer.result });
    });
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host ?? `${HOST}:${PORT}`}`);

    if (req.method === 'OPTIONS') {
        res.writeHead(204, CORS_HEADERS);
        res.end();
        return;
    }

    switch (url.pathname) {
        case '/__health':
            sendJson(res, 200, { ok: true });
            return;
        case '/__count':
            sendJson(res, 200, { count });
            return;
        case '/__calls':
            sendJson(res, 200, { count, calls });
            return;
        case '/__reset':
            count = 0;
            calls = [];
            sendJson(res, 200, { ok: true });
            return;
        default:
            break;
    }

    if (req.method !== 'POST') {
        sendJson(res, 405, { error: { code: -32600, message: 'use POST for JSON-RPC' } });
        return;
    }

    const fail = Number(url.searchParams.get('fail') ?? 0);
    if (Number.isInteger(fail) && fail >= 400 && fail <= 599) {
        // a failing endpoint must still be a well-formed HTTP answer: the client maps the status
        req.resume();
        req.on('end', () => {
            sendJson(res, fail, { error: { code: -32000, message: 'mock failure' } });
        });
        return;
    }

    handleRpc(req, res, url);
});

server.listen(PORT, HOST, () => {
    console.log(`mock EVM JSON-RPC listening on http://${HOST}:${PORT}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
        server.close(() => process.exit(0));
    });
}
