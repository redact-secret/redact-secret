import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { loadNativeBinding, loadWasmFallback } from "../src/runtime/node.js";

/**
 * `runtime/node.ts`'s WebAssembly fallback
 * (`decision-add-node-wasm-fallback`), exercised against the real module
 * rather than a double. `@redact-secret/wasm` is not installed in a source
 * checkout (it is generated and published in lockstep,
 * `runtime/browser.ts`'s own module comment), so both of these calls take
 * the fallback's real failure path — the same path a consumer would hit on
 * a host missing that dependency entirely — without needing to fake
 * anything. `scripts/qualify-node-wasm-fallback.mjs` covers the success
 * path against the real built artifact, which cannot exist in this
 * checkout.
 */
describe("Node WebAssembly fallback: unavailable artifact", () => {
  it("fails with INITIALIZATION_FAILED, not a raw import error, when the wasm package cannot be resolved", async () => {
    await expect(loadWasmFallback("full")).rejects.toThrowError(
      new SecretScanError("INITIALIZATION_FAILED"),
    );
  });

  it("fails the same way for the common profile", async () => {
    await expect(loadWasmFallback("common")).rejects.toThrowError(
      new SecretScanError("INITIALIZATION_FAILED"),
    );
  });

  it("still fails with INITIALIZATION_FAILED end to end when both the addon and the fallback are unavailable", async () => {
    // In this checkout the addon is never built and the wasm package is
    // never installed, so `loadNativeBinding` exercises exactly the
    // "nothing at all is usable" host this fallback does not change the
    // outcome for: it must still fail cleanly, not throw a different error
    // or hang.
    await expect(loadNativeBinding()).rejects.toThrowError(
      new SecretScanError("INITIALIZATION_FAILED"),
    );
  });
});
