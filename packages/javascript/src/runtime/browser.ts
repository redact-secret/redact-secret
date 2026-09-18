/**
 * The browser adapter: the `wasm-bindgen` build, normalized to the internal
 * binding contract (`decision-define-runtime-bindings`).
 *
 * The package's `imports` map reaches this module under the `browser`
 * condition and by default. It imports nothing from `node:` and touches no
 * Node global, so a bundle produced for the browser resolves only this file,
 * `./wasm-binding.js`, and the WebAssembly artifact it loads — never
 * `./browser-common.js` or its artifact (see `./wasm-binding.js`'s module
 * comment on why the two profile loaders never import each other).
 *
 * There are two distinct setup steps behind one `await initialize()`: the
 * generated `init()` that fetches and instantiates the `.wasm` binary, and the
 * binding's own idempotent `initialize()` that builds the detector registry.
 * Wrapping both is exactly this adapter's job.
 *
 * `bindings/wasm` exports a real `createIncrementalSanitizer`
 * (`decision-define-runtime-bindings`): it builds a bounded
 * `IncrementalSanitizer` session, wrapping the same core session
 * `bindings/node` and `bindings/python` wrap, with an explicit
 * `accepting`/`finalized`/`aborted`/`failed` lifecycle and absolute UTF-16
 * ranges converted chunk by chunk. `./web-stream` reaches it through this
 * same binding.
 */

import type { NativeBinding } from "../native.js";
import {
  assertWasmModuleShape,
  createBindingFromWasmModule,
  type WasmModule,
} from "./wasm-binding.js";

export * from "./wasm-binding.js";

/**
 * Loads the WebAssembly artifact published in lockstep with this package.
 *
 * The specifier is a literal so a bundler can resolve and include the glue and
 * the `.wasm` binary it references, and the import is dynamic so nothing is
 * fetched until a caller awaits `initialize()`.
 */
async function loadWasmModule(): Promise<WasmModule> {
  const module = (await import(
    "@redact-secret/wasm"
  )) as unknown as Partial<WasmModule>;
  assertWasmModuleShape(module);
  return module;
}

export const loadNativeBinding = async (): Promise<NativeBinding> => {
  const wasm = await loadWasmModule();
  await wasm.default();
  return createBindingFromWasmModule(wasm);
};
