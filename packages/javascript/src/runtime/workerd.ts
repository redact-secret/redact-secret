/**
 * The Cloudflare Workers adapter: the same `wasm-bindgen` build
 * `runtime/browser.ts` loads, instantiated from a bundler-compiled
 * `WebAssembly.Module` instead of the generated glue's `import.meta.url`-
 * relative `fetch` (`decision-verify-edge-runtimes`).
 *
 * The package's `imports` map reaches this module only under the `workerd`
 * condition, which `wrangler`'s bundler sets ahead of the generic `browser`
 * condition `runtime/browser.ts` would otherwise resolve to. `import.meta.url`
 * is `undefined` inside a real `workerd` module worker — verified against a
 * real `wrangler dev` sandbox while implementing this decision — so the
 * generated glue's own no-argument `default()` throws `Invalid URL` before
 * ever reaching the network; it never gets the chance to fail on the fetch
 * itself, since `workerd`'s `fetch()` cannot load a same-origin module
 * specifier anyway.
 *
 * This adapter sidesteps both failures by importing the `.wasm` binary
 * through its own literal specifier: `workerd`'s bundler applies its
 * `CompiledWasm` module rule to any `.wasm`-extension import by default
 * (verified against the same sandbox), resolving it to an already-compiled
 * `WebAssembly.Module` rather than fetching bytes. Passing that module as
 * `default({ module_or_path: <module> })` instantiates synchronously with no
 * `fetch` involved at all — the same documented calling convention
 * `runtime/node.ts`'s WebAssembly fallback uses for bytes read from disk.
 *
 * Like `runtime/browser.ts`, both imports are dynamic so nothing is compiled
 * until a caller awaits `initialize()`, and both specifiers are literals so
 * the bundler can discover and include them statically.
 */

import type { NativeBinding } from "../native.js";
import {
  assertWasmModuleShape,
  createBindingFromWasmModule,
  type WasmModule,
} from "./wasm-binding.js";

export * from "./wasm-binding.js";

async function loadCompiledWasmModule(): Promise<
  readonly [WasmModule, object]
> {
  const [module, artifact] = await Promise.all([
    import("@redact-secret/wasm") as unknown as Promise<Partial<WasmModule>>,
    import(
      "@redact-secret/wasm/redact_secret_wasm_bg.wasm"
    ) as unknown as Promise<{ default: object }>,
  ]);
  assertWasmModuleShape(module);
  return [module, artifact.default];
}

export const loadNativeBinding = async (): Promise<NativeBinding> => {
  const [wasm, compiled] = await loadCompiledWasmModule();
  await wasm.default({ module_or_path: compiled });
  return createBindingFromWasmModule(wasm);
};
