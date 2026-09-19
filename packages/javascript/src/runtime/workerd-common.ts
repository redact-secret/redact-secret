/**
 * The Cloudflare Workers `common`-profile adapter: as `runtime/workerd.ts`
 * instantiates the `full`-profile artifact from a bundler-compiled
 * `WebAssembly.Module`, this instantiates the `common`-profile one
 * `runtime/browser-common.ts` loads (`decision-verify-edge-runtimes`,
 * `decision-define-detector-profile-and-pack-contract`).
 *
 * The package's `imports` map reaches this module only under the
 * `#native-common` condition object's `workerd` key. Its own
 * `loadCompiledWasmModule` is not factored together with
 * `runtime/workerd.ts`'s, for the same reason `runtime/browser.ts` and
 * `runtime/browser-common.ts` each keep their own: a literal dynamic-import
 * specifier per profile is what lets a bundler discover and include only the
 * one `.wasm` artifact the entry point a consumer imported actually needs.
 */

import type { NativeBinding } from "../native.js";
import {
  assertWasmModuleShape,
  createBindingFromWasmModule,
  type WasmModule,
} from "./wasm-binding.js";

async function loadCompiledWasmModule(): Promise<
  readonly [WasmModule, object]
> {
  const [module, artifact] = await Promise.all([
    import(
      "@redact-secret/wasm/common"
    ) as unknown as Promise<Partial<WasmModule>>,
    import(
      "@redact-secret/wasm/redact_secret_wasm_common_bg.wasm"
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
