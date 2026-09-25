#!/usr/bin/env node
/**
 * Runs one `wasm32-wasip1` module under Node's built-in WASI host, for
 * issue #772's cross-runtime qualification of the shadow evidence scorer.
 *
 *     node scripts/wasi-run.mjs <module.wasm> [args...]
 *
 * It is also a Cargo runner: with
 * `CARGO_TARGET_WASM32_WASIP1_RUNNER="node scripts/wasi-run.mjs"`,
 * `cargo test --target wasm32-wasip1` and `cargo run --target wasm32-wasip1`
 * execute the compiled module here, on V8's WebAssembly engine (the engine
 * the browser artifact and the Node WebAssembly fallback run on), with no
 * extra tool to install or pin.
 *
 * The module sees the host's standard input, output and error, and this
 * repository's root preopened at its own absolute path, so the absolute
 * paths a test or example derives from `CARGO_MANIFEST_DIR` at compile time
 * (the conformance fixtures, the scoring artifact) resolve unchanged, and
 * nothing outside the checkout is visible. No environment variable is
 * passed through. The process exits with the module's exit code.
 */
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { WASI } from "node:wasi";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const [modulePath, ...args] = process.argv.slice(2);
if (!modulePath) {
  console.error("usage: node scripts/wasi-run.mjs <module.wasm> [args...]");
  process.exit(2);
}

const wasi = new WASI({
  version: "preview1",
  args: [modulePath, ...args],
  env: {},
  preopens: { [REPO_ROOT]: REPO_ROOT },
  returnOnExit: true,
});
const module = await WebAssembly.compile(await readFile(modulePath));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
process.exitCode = wasi.start(instance);
