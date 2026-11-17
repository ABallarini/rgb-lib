// Browser demo: the same crate, the browser durable path.
//
// Serves both as the consume example and as the check that `load()`/`flush()` work against
// IndexedDB in a real browser.

import init, { RgbLibWallet } from "../pkg/rgb_lib_wasm.js";

// BIP39 test vector phrase. Never use this one for real funds.
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NAME = "demo";
const NETWORK = "regtest";

const logElement = document.getElementById("log");
const log = (message) => {
  logElement.textContent += `${message}\n`;
};

await init();

// One call on startup: restores the snapshot stored under NAME, or creates a fresh wallet.
const wallet = await RgbLibWallet.load(NAME, MNEMONIC, NETWORK);
log(`wallet id: ${wallet.id()}`);

document.getElementById("address").addEventListener("click", () => {
  log(`address: ${wallet.getAddress()}`);
});

document.getElementById("flush").addEventListener("click", async () => {
  log(`snapshot: ${wallet.snapshot().length} bytes`);
  await wallet.flush();
  log("flushed to IndexedDB");
});
