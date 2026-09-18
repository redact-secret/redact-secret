/**
 * The browser `common`-profile adapter: the `wasm-bindgen` build published
 * under `@redact-secret/wasm`'s `common` subpath, normalized to the internal
 * binding contract the same way `runtime/browser.ts` normalizes the full
 * artifact (`decision-define-runtime-bindings`,
 * `decision-define-detector-profile-and-pack-contract`).
 *
 * The package's `imports` map reaches this module only under the
 * `#native-common` condition, resolved by `@redact-secret/core/common`. Its
 * own `loadWasmModule` is not factored together with `runtime/browser.ts`'s:
 * each keeps a literal dynamic-import specifier so a bundler can statically
 * discover and include the right `.wasm` artifact for whichever entry point a
 * consumer imports. Both import their shared normalization from
 * `./wasm-binding.js` rather than from each other — importing `./browser.js`
 * here would pull its `full`-profile literal `import("@redact-secret/wasm")`
 * into any bundle that resolves this module, defeating the point of a
 * separate `common` entry (see `./wasm-binding.js`'s module comment).
 */

import type { NativeBinding } from "../native.js";
import {
  assertWasmModuleShape,
  createBindingFromWasmModule,
  type WasmModule,
} from "./wasm-binding.js";

/**
 * Loads the `common`-profile WebAssembly artifact published in lockstep with
 * this package, under `@redact-secret/wasm`'s `common` subpath export.
 *
 * The specifier is a literal so a bundler can resolve and include the glue and
 * the `.wasm` binary it references, and the import is dynamic so nothing is
 * fetched until a caller awaits `initialize()`.
 */
async function loadWasmModule(): Promise<WasmModule> {
  const module = (await import(
    "@redact-secret/wasm/common"
  )) as unknown as Partial<WasmModule>;
  assertWasmModuleShape(module);
  return module;
}

export const loadNativeBinding = async (): Promise<NativeBinding> => {
  const wasm = await loadWasmModule();
  await wasm.default();
  return createBindingFromWasmModule(wasm);
};
