// Node smoke test for the generated bindings: create, offline reads, address, out-of-band receive,
// snapshot, restore, keys, watch-only, the hub-free multisig subset, invoice parsing,
// consignment validation and the offline proxy health-check rejection.
//
// Run it against the `nodejs` target bundle:
//   wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
//   node bindings/wasm/smoke/smoke.cjs
//
// IndexedDB does not exist in Node, so `flush()`/`load()` (the browser durable path) are not
// exercised here; `npm run browser` and `demo/index.html` cover them in a real browser.

// Node 18 exposes Web Crypto only behind `--experimental-global-webcrypto`; the wasm random source
// and the backup key derivation need it. Node 19+ has it on `globalThis` already.
if (!globalThis.crypto) globalThis.crypto = require("node:crypto").webcrypto;

const assert = require("node:assert/strict");
const {
  RgbLibWallet,
  RgbLibMultisigWallet,
  WasmInvoice,
  backupInfo,
  checkProxyUrl,
  generateKeys,
  restoreKeys,
  validateConsignmentOffchain,
} = require("../pkg-node/rgb_lib_wasm.js");

// BIP39 test vector phrase; regtest keeps the addresses local.
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NETWORK = "regtest";

// A deterministic regtest invoice: NIA asset, blinded UTXO recipient, assignment, expiry, public
// key, encryption preference, one transport endpoint and an unknown query parameter.
const PUBLIC_KEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const INVOICE =
  "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E/" +
  "RWhwUfTMpuP2Zfx1~j4nswCANGeJrYOqDcKelaMV4zU/ae/" +
  "bcrt:utxob:tjVmHbI2-U0_umHn-bU4cmP6-l3VW00H-ewoi2uz-XZG6O3i-wUFBW" +
  `?assignment_name=assetOwner&expiry=1700000000&pk=${PUBLIC_KEY}&enc=1` +
  "&endpoints=rpc://proxy.example.com&foo=bar";

// The core `SinglesigKeys` shape, with no mnemonic: what a watch-only host stores.
function watchOnlyKeys(keys) {
  return {
    account_xpub_vanilla: keys.account_xpub_vanilla,
    account_xpub_colored: keys.account_xpub_colored,
    vanilla_keychain: null,
    master_fingerprint: keys.master_fingerprint,
    mnemonic: null,
    witness_version: keys.witness_version,
  };
}

// The core `Cosigner` shape, built from the public fields of a generated key set.
function cosigner(keys) {
  return {
    account_xpub_vanilla: keys.account_xpub_vanilla,
    account_xpub_colored: keys.account_xpub_colored,
    vanilla_keychain: null,
    master_fingerprint: keys.master_fingerprint,
  };
}

async function main() {
  const wallet = RgbLibWallet.create("smoke", MNEMONIC, NETWORK);
  const id = wallet.id();
  assert.match(id, /^[0-9a-f]{8}$/, `unexpected wallet id '${id}'`);
  assert.equal(wallet.name(), "smoke");

  const firstAddress = wallet.getAddress();
  assert.ok(firstAddress.startsWith("bcrt1"), `unexpected address '${firstAddress}'`);

  // offline reads from a fresh wallet: no chain access, so balances and lists are empty
  const btc = JSON.parse(wallet.getBtcBalance());
  assert.equal(btc.vanilla.settled, 0);
  assert.equal(btc.colored.settled, 0);
  assert.deepEqual(JSON.parse(wallet.listAssets()), {
    nia: [],
    uda: [],
    cfa: [],
    ifa: [],
  });
  assert.deepEqual(JSON.parse(wallet.listTransfers()), []);
  assert.deepEqual(JSON.parse(wallet.listUnspents(false)), []);
  assert.deepEqual(JSON.parse(wallet.listTransactions()), []);
  assert.equal(wallet.deleteTransfers(undefined, false), false);

  const walletData = JSON.parse(wallet.getWalletData());
  assert.equal(walletData.bitcoin_network, "Regtest");
  assert.equal(walletData.max_allocations_per_utxo, 5);

  // out-of-band witness receive: no transport endpoint, no proxy reservation, witness script
  // recipient, so a fresh wallet with no colored UTXO can create it
  const expiration = Math.floor(Date.now() / 1000) + 3600;
  const receive = JSON.parse(wallet.witnessReceive(null, '{"Fungible":1000}', BigInt(expiration), 1, "optional"));
  assert.ok(receive.invoice.startsWith("rgb:"), `unexpected invoice '${receive.invoice}'`);
  assert.ok(receive.recipient_id.startsWith("bcrt:wvout:"), `unexpected recipient '${receive.recipient_id}'`);
  assert.equal(receive.expiration_timestamp, expiration);
  assert.ok(Number.isInteger(receive.batch_transfer_idx) && receive.batch_transfer_idx >= 0);
  assert.match(receive.public_key, /^[0-9a-f]{64}$/);
  assert.equal(receive.invoice.includes("endpoints="), false);

  // out-of-band blind receive needs a colored UTXO: the core error surfaces, nothing is faked
  assert.throws(
    () => wallet.blindReceive(null, '{"Fungible":1000}', BigInt(expiration), 1, null),
    /cannot create the blind receive/,
  );
  assert.throws(
    () => wallet.witnessReceive(null, "not json", BigInt(expiration), 1, null),
    /cannot parse the assignment/,
  );
  assert.throws(
    () => wallet.witnessReceive(null, '"Any"', BigInt(expiration), 1, "sometimes"),
    /unsupported encryption/,
  );

  // the snapshot carries the database and BDK state, never the mnemonic
  const snapshot = wallet.snapshot();
  assert.ok(snapshot.length > 0, "empty snapshot");
  assert.equal(Buffer.from(snapshot).includes(Buffer.from(MNEMONIC)), false);

  // the restored wallet keeps the revealed-address index: it must not hand out the address above
  const restored = RgbLibWallet.restore("smoke", snapshot, MNEMONIC, NETWORK);
  assert.equal(restored.id(), id);
  const nextAddress = restored.getAddress();
  assert.notEqual(nextAddress, firstAddress);

  // a snapshot restored with other keys is an error, never a fresh wallet
  assert.throws(
    () => RgbLibWallet.restore("smoke", snapshot, OTHER_MNEMONIC, NETWORK),
    /cannot restore the wallet/,
  );

  // encrypted backup: bytes out, public metadata, restore through the shared snapshot path
  const backupPassword = "smoke backup password";
  const backup = wallet.backup(backupPassword);
  assert.ok(backup.length > 0, "empty backup");
  assert.equal(Buffer.from(backup).includes(Buffer.from(MNEMONIC)), false);
  const info = JSON.parse(backupInfo(backup));
  assert.equal(info.version, 1);
  assert.ok(info.scrypt_params.log_n > 0, "missing scrypt parameters");
  const fromBackup = RgbLibWallet.create("smoke", MNEMONIC, NETWORK);
  fromBackup.restoreBackup(backup, backupPassword);
  assert.equal(fromBackup.id(), id);
  assert.throws(
    () => fromBackup.restoreBackup(backup, "wrong password"),
    /cannot restore the backup/,
  );

  // key errors never echo the phrase
  assert.throws(
    () => RgbLibWallet.create("bad", `${MNEMONIC} notaword`, NETWORK),
    (e) => !String(e).includes("notaword"),
  );

  // generateKeys/restoreKeys return the core `Keys` JSON and round trip
  const generated = JSON.parse(generateKeys(NETWORK));
  assert.equal(generated.mnemonic.split(" ").length, 12);
  assert.equal(generated.witness_version, "Taproot");
  assert.match(generated.master_fingerprint, /^[0-9a-f]{8}$/);
  const restoredKeys = JSON.parse(restoreKeys(NETWORK, generated.mnemonic));
  assert.equal(restoredKeys.xpub, generated.xpub);
  assert.equal(restoredKeys.master_fingerprint, generated.master_fingerprint);
  assert.equal(restoredKeys.account_xpub_vanilla, generated.account_xpub_vanilla);
  assert.equal(restoredKeys.account_xpub_colored, generated.account_xpub_colored);

  // a bad phrase is a fixed sanitized error, never the phrase back
  assert.throws(
    () => restoreKeys(NETWORK, `${generated.mnemonic} notaword`),
    (e) =>
      /invalid mnemonic phrase/.test(String(e)) && !String(e).includes("notaword"),
  );

  // watch-only: public keys only, addresses, snapshot and restore, no signing keys
  const publicKeys = watchOnlyKeys(generated);
  const watchOnly = RgbLibWallet.createWatchOnly("watch-only", JSON.stringify(publicKeys), NETWORK);
  assert.equal(watchOnly.id(), generated.master_fingerprint);
  const watchOnlyAddress = watchOnly.getAddress();
  assert.ok(watchOnlyAddress.startsWith("bcrt1"), `unexpected address '${watchOnlyAddress}'`);
  const watchOnlySnapshot = watchOnly.snapshot();
  assert.ok(watchOnlySnapshot.length > 0, "empty watch-only snapshot");
  assert.equal(
    Buffer.from(watchOnlySnapshot).includes(Buffer.from(generated.mnemonic)),
    false,
  );
  const watchOnlyRestored = RgbLibWallet.restoreWatchOnly(
    "watch-only",
    watchOnlySnapshot,
    JSON.stringify(publicKeys),
    NETWORK,
  );
  assert.equal(watchOnlyRestored.id(), watchOnly.id());
  assert.notEqual(watchOnlyRestored.getAddress(), watchOnlyAddress);
  // a phrase in the keys is refused, never silently used or dropped
  assert.throws(
    () =>
      RgbLibWallet.createWatchOnly(
        "watch-only",
        JSON.stringify({ ...publicKeys, mnemonic: MNEMONIC }),
        NETWORK,
      ),
    /must not contain a mnemonic/,
  );

  // multisig, hub-free: construction, id, descriptors, descriptor-derived addresses, snapshot
  const multisigKeys = {
    cosigners: [cosigner(generated), cosigner(JSON.parse(generateKeys(NETWORK)))],
    threshold_colored: 2,
    threshold_vanilla: 2,
  };
  const multisig = RgbLibMultisigWallet.create(
    "multisig",
    JSON.stringify(multisigKeys),
    NETWORK,
  );
  const multisigId = multisig.id();
  assert.match(multisigId, /^[0-9a-f]{8}$/, `unexpected multisig id '${multisigId}'`);
  assert.equal(JSON.parse(multisig.getWalletData()).bitcoin_network, "Regtest");
  const descriptors = JSON.parse(multisig.getDescriptors());
  assert.ok(descriptors.colored.includes("multi_a(2,"), "colored descriptor is not 2-of-2");
  assert.ok(descriptors.vanilla.includes("multi_a(2,"), "vanilla descriptor is not 2-of-2");
  const multisigAddress = multisig.getAddress(0);
  assert.ok(multisigAddress.startsWith("bcrt1"), `unexpected address '${multisigAddress}'`);
  assert.equal(multisig.getAddress(0), multisigAddress, "address derivation is not deterministic");
  const multisigSnapshot = multisig.snapshot();
  assert.ok(multisigSnapshot.length > 0, "empty multisig snapshot");
  const multisigRestored = RgbLibMultisigWallet.restore(
    "multisig",
    multisigSnapshot,
    JSON.stringify(multisigKeys),
    NETWORK,
  );
  assert.equal(multisigRestored.id(), multisigId);
  assert.deepEqual(JSON.parse(multisigRestored.getDescriptors()), descriptors);
  assert.deepEqual(JSON.parse(multisigRestored.getKeys()), multisigKeys);
  assert.equal(multisigRestored.getAddress(0), multisigAddress);

  // invoice parsing: the core `InvoiceData` shape, network checked, invalid input sanitized
  const invoice = WasmInvoice.parse(INVOICE, NETWORK);
  assert.equal(invoice.invoiceString(), INVOICE);
  const invoiceData = JSON.parse(invoice.invoiceData());
  assert.deepEqual(invoiceData, {
    recipient_id:
      "bcrt:utxob:tjVmHbI2-U0_umHn-bU4cmP6-l3VW00H-ewoi2uz-XZG6O3i-wUFBW",
    asset_schema: "Nia",
    asset_id: "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E",
    assignment: { Fungible: 1 },
    assignment_name: "assetOwner",
    network: "Regtest",
    expiration_timestamp: 1700000000,
    transport_endpoints: ["rpc://proxy.example.com"],
    public_key: PUBLIC_KEY,
    encryption: "Optional",
    unknown_query_params: { foo: "bar" },
  });
  assert.throws(() => WasmInvoice.parse("not an invoice", NETWORK), /cannot parse the invoice/);
  assert.throws(
    () => WasmInvoice.parse(INVOICE, "mainnet"),
    /not for the given network/,
  );

  // consignment validation: the invalid path is covered offline. No valid consignment fixture
  // exists in the tree and producing one needs a funded regtest wallet, so the valid path is not
  // exercised here; the core `validate_consignment_offchain` has no network access either way.
  assert.throws(
    () =>
      validateConsignmentOffchain(
        Uint8Array.from([1, 2, 3]),
        "00".repeat(32),
        NETWORK,
      ),
    /cannot validate the consignment/,
  );

  // proxy health check: an invalid endpoint is rejected by the shared transport-endpoint parser
  // before any request, so this needs no live proxy and makes no network call
  await assert.rejects(
    checkProxyUrl("not-a-url"),
    /cannot check the proxy URL: Invalid transport endpoint/,
  );
  await assert.rejects(
    checkProxyUrl("http://"),
    /cannot check the proxy URL: Invalid transport endpoint/,
  );

  console.log(`wallet id: ${id}`);
  console.log(`address: ${firstAddress}`);
  console.log(`restored address: ${nextAddress}`);
  console.log(`snapshot: ${snapshot.length} bytes, restored from bytes alone`);
  console.log(`backup: ${backup.length} bytes, restored with a password`);
  console.log(`keys: ${generated.master_fingerprint}, restored from the mnemonic`);
  console.log(`watch-only: ${watchOnly.id()}, address: ${watchOnlyAddress}`);
  console.log(`witness receive: ${receive.recipient_id}, batch ${receive.batch_transfer_idx}`);
  console.log(`multisig id: ${multisigId}, address: ${multisigAddress}`);
  console.log(`invoice: ${invoiceData.asset_id}, network: ${invoiceData.network}`);
  console.log("consignment validation: invalid bytes rejected");
  console.log("proxy check: invalid URL rejected without network");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
