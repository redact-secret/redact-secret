/**
 * `IncrementalLimits` accepts `max*Bytes` as additive aliases of the
 * deprecated `max*CodeUnits` names (issue #1184). Both spellings hold UTF-8
 * byte ceilings. The public wrapper resolves them once, before any binding
 * call, so the Node addon shape (`createFakeBinding`) and the WebAssembly
 * shape (`createWasmShapedBinding`, positional arguments) are both checked.
 */

import { describe, expect, it } from "vitest";

import { createRedactSecretRuntime } from "../src/runtime.js";
import type { IncrementalLimits } from "../src/types.js";
import { createFakeBinding } from "./fake-binding.js";
import { createWasmShapedBinding } from "./wasm-shaped-binding.js";

const LEGACY = {
  maxInputCodeUnits: 1_024,
  maxBufferedCodeUnits: 384,
  maxTokenCodeUnits: 128,
  maxMultilineCodeUnits: 256,
};
const BYTES = {
  maxInputBytes: 1_024,
  maxBufferedBytes: 384,
  maxTokenBytes: 128,
  maxMultilineBytes: 256,
};
const RESOLVED = [1_024, 384, 128, 256];
const BYTE_KEYS = Object.keys(BYTES) as (keyof typeof BYTES)[];

async function nodeRuntime() {
  const binding = createFakeBinding();
  const runtime = createRedactSecretRuntime(async () => binding, "full");
  await runtime.initialize();
  return { binding, runtime };
}

const invalidLimits = expect.objectContaining({ name: "SecretScanError", code: "INVALID_LIMITS" });

describe("incremental limit aliases: Node addon shape", () => {
  it("leaves the deprecated names unchanged", async () => {
    const { binding, runtime } = await nodeRuntime();
    runtime.createIncrementalSanitizer({ limits: LEGACY });
    expect(binding.lastIncrementalLimits).toEqual(LEGACY);
  });

  it("accepts the byte names and hands the binding the same values under its one shape", async () => {
    const { binding, runtime } = await nodeRuntime();
    runtime.createIncrementalSanitizer({ limits: BYTES });
    expect(binding.lastIncrementalLimits).toEqual(LEGACY);
  });

  it("accepts the two spellings mixed across different limits", async () => {
    const { binding, runtime } = await nodeRuntime();
    runtime.createIncrementalSanitizer({
      limits: {
        maxInputBytes: 1_024,
        maxBufferedCodeUnits: 384,
        maxTokenBytes: 128,
        maxMultilineCodeUnits: 256,
      },
    });
    expect(binding.lastIncrementalLimits).toEqual(LEGACY);
  });

  it("accepts both spellings of one limit when they agree", async () => {
    const { binding, runtime } = await nodeRuntime();
    runtime.createIncrementalSanitizer({ limits: { ...LEGACY, ...BYTES } });
    expect(binding.lastIncrementalLimits).toEqual(LEGACY);
  });

  it("treats an explicitly undefined alias as not given", async () => {
    const { binding, runtime } = await nodeRuntime();
    runtime.createIncrementalSanitizer({
      limits: { ...BYTES, maxInputCodeUnits: undefined } as unknown as IncrementalLimits,
    });
    expect(binding.lastIncrementalLimits).toEqual(LEGACY);
  });

  it.each(BYTE_KEYS)("rejects %s conflicting with its deprecated alias instead of guessing", async (key) => {
    const { binding, runtime } = await nodeRuntime();
    const legacyKey = key.replace("Bytes", "CodeUnits") as keyof typeof LEGACY;
    expect(() =>
      runtime.createIncrementalSanitizer({
        limits: { ...LEGACY, [key]: LEGACY[legacyKey] + 1 } as unknown as IncrementalLimits,
      }),
    ).toThrowError(invalidLimits);
    expect(binding.calls).toEqual(["initialize"]);
  });

  it.each(BYTE_KEYS)("rejects a limit given under neither spelling (%s omitted)", async (key) => {
    const { runtime } = await nodeRuntime();
    const { [key]: _omitted, ...rest } = BYTES;
    expect(() => runtime.createIncrementalSanitizer({ limits: rest as unknown as IncrementalLimits })).toThrowError(
      invalidLimits,
    );
  });

  it.each([-1, 1.5, 2 ** 32, Number.NaN, "8"])(
    "validates a byte name's value %s like the old name's",
    async (value) => {
      const { runtime } = await nodeRuntime();
      for (const key of BYTE_KEYS) {
        expect(() =>
          runtime.createIncrementalSanitizer({ limits: { ...BYTES, [key]: value } as unknown as IncrementalLimits }),
        ).toThrowError(invalidLimits);
      }
    },
  );

  it("validates the alias even when the byte name is valid", async () => {
    const { runtime } = await nodeRuntime();
    expect(() =>
      runtime.createIncrementalSanitizer({ limits: { ...BYTES, maxInputCodeUnits: -1 } as IncrementalLimits }),
    ).toThrowError(invalidLimits);
  });
});

describe("incremental limit aliases: WebAssembly shape", () => {
  async function wasmRuntime() {
    const wasm = createWasmShapedBinding();
    const runtime = createRedactSecretRuntime(wasm.load, "full");
    await runtime.initialize();
    return { wasm, runtime };
  }

  it("forwards the old names positionally, unchanged", async () => {
    const { wasm, runtime } = await wasmRuntime();
    runtime.createIncrementalSanitizer({ limits: LEGACY });
    expect(wasm.lastIncrementalLimits).toEqual(RESOLVED);
  });

  it("forwards the byte names as the same four positional values", async () => {
    const { wasm, runtime } = await wasmRuntime();
    runtime.createIncrementalSanitizer({ limits: BYTES });
    expect(wasm.lastIncrementalLimits).toEqual(RESOLVED);
  });

  it("rejects a conflicting pair before the WebAssembly call", async () => {
    const { wasm, runtime } = await wasmRuntime();
    expect(() =>
      runtime.createIncrementalSanitizer({ limits: { ...LEGACY, maxTokenBytes: 129 } as IncrementalLimits }),
    ).toThrowError(invalidLimits);
    expect(wasm.lastIncrementalLimits).toBeUndefined();
  });
});
