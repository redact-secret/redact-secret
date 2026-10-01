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

import type { NativeBindingLoader } from "../native.js";
import { assertWasmModuleShape, createBindingFromWasmModule, type WasmModule } from "./wasm-binding.js";

/**
 * Loads the `common`-profile WebAssembly artifact published in lockstep with
 * this package, under `@redact-secret/wasm`'s `common` subpath export, or,
 * only when the first `initialize()` carries a PII selection, its `pii`
 * build under the `common/pii` subpath (issue #937).
 *
 * Each specifier is a literal so a bundler can resolve and include the glue
 * and the `.wasm` binary it references, and each import is dynamic so
 * nothing is fetched until a caller awaits `initialize()`, and the `pii`
 * build is never fetched unless PII is selected.
 */
async function loadWasmModule(pii: boolean): Promise<WasmModule> {
  const module = (pii
    ? await import("@redact-secret/wasm/common/pii")
    : await import("@redact-secret/wasm/common")) as unknown as Partial<WasmModule>;
  assertWasmModuleShape(module);
  return module;
}

export const loadNativeBinding: NativeBindingLoader = async ({ pii }) => {
  const wasm = await loadWasmModule(pii);
  await wasm.default();
  return createBindingFromWasmModule(wasm);
};
