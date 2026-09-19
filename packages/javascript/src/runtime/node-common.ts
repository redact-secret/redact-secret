/**
 * The Node.js `common`-profile adapter: the same N-API native addon
 * `runtime/node.ts` loads, normalized through its `common`-profile exports
 * instead of its full-profile ones (`decision-define-runtime-bindings`,
 * `decision-define-detector-profile-and-pack-contract`), with the same
 * WebAssembly fallback `runtime/node.ts` falls back to, against the
 * `common`-profile artifact (`decision-add-node-wasm-fallback`).
 *
 * The package's `imports` map reaches this module only under the `#native-common`
 * condition, resolved by `@redact-secret/core/common`.
 */

import {
  createBindingFromCommonAddon,
  loadCommonAddon,
  loadWasmFallback,
} from "./node.js";
import type { NativeBinding } from "../native.js";

export const loadNativeBinding = async (): Promise<NativeBinding> => {
  try {
    return createBindingFromCommonAddon(loadCommonAddon());
  } catch {
    return loadWasmFallback("common");
  }
};
