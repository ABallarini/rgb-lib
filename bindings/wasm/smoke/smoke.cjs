// Node smoke test for the generated bindings: create, address, snapshot, restore.
//
// Run it against the `nodejs` target bundle:
//   wasm-pack build bindings/wasm --target nodejs --out-dir pkg-node
//   node bindings/wasm/smoke/smoke.cjs
//
// IndexedDB does not exist in Node, so `flush()`/`load()` (the browser durable path) are not
// exercised here; `npm run browser` and `demo/index.html` cover them in a real browser.

const assert = require("node:assert/strict");
const { RgbLibWallet } = require("../pkg-node/rgb_lib_wasm.js");

// BIP39 test vector phrase; regtest keeps the addresses local.
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NETWORK = "regtest";

function main() {
  const wallet = RgbLibWallet.create("smoke", MNEMONIC, NETWORK);
  const id = wallet.id();
  assert.match(id, /^[0-9a-f]{8}$/, `unexpected wallet id '${id}'`);
  assert.equal(wallet.name(), "smoke");

  const firstAddress = wallet.getAddress();
  assert.ok(firstAddress.startsWith("bcrt1"), `unexpected address '${firstAddress}'`);

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

  // key errors never echo the phrase
  assert.throws(
    () => RgbLibWallet.create("bad", `${MNEMONIC} notaword`, NETWORK),
    (e) => !String(e).includes("notaword"),
  );

  console.log(`wallet id: ${id}`);
  console.log(`address: ${firstAddress}`);
  console.log(`restored address: ${nextAddress}`);
  console.log(`snapshot: ${snapshot.length} bytes, restored from bytes alone`);
}

main();
