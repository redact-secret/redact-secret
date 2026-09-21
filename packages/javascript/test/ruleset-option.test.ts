/**
 * The `ruleset` option on `scan`/`scanAndRedact` (issue #495,
 * `decision-define-declarative-detector-ruleset-contract`): conversion from
 * a public `Uint8Array`/`string` to the `Uint8Array` every binding accepts,
 * and that it reaches the binding as the documented fourth argument.
 */

import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import { createFakeBinding } from "./fake-binding.js";

describe("ruleset option", () => {
  it("passes Uint8Array bytes through to the binding unchanged", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    const ruleset = new TextEncoder().encode("ruleset-revision: 1\n");
    runtime.scan("input", { ruleset });

    expect(binding.lastRuleset).toBe(ruleset);
  });

  it("encodes a string ruleset as UTF-8 bytes", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    const text = "ruleset-revision: 1\ndetector: acme-token\n";
    runtime.scan("input", { ruleset: text });

    expect(binding.lastRuleset).toEqual(new TextEncoder().encode(text));
  });

  it("is omitted from the native call when not given", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    runtime.scan("input");

    expect(binding.lastRuleset).toBeUndefined();
  });

  it("threads through scanAndRedact the same way as scan", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    const ruleset = new TextEncoder().encode("ruleset-revision: 1\n");
    runtime.scanAndRedact("input", { ruleset });

    expect(binding.lastRuleset).toBe(ruleset);
  });

  it("rejects a ruleset that is neither a Uint8Array nor a string", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    expect(() =>
      runtime.scan("input", {
        // @ts-expect-error exercising a caller-supplied malformed option
        ruleset: 12345,
      }),
    ).toThrow(SecretScanError);
    try {
      runtime.scan("input", {
        // @ts-expect-error exercising a caller-supplied malformed option
        ruleset: 12345,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(SecretScanError);
      expect((error as SecretScanError).code).toBe("INVALID_OPTIONS");
    }
  });

  it("surfaces INVALID_RULESET when the binding rejects the ruleset", async () => {
    const binding = createFakeBinding({
      throwOnScan: Object.assign(new Error("rejected"), {
        code: "INVALID_RULESET",
      }),
    });
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    try {
      runtime.scan("input", { ruleset: "ruleset-revision: 2\n" });
      throw new Error("expected scan to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SecretScanError);
      expect((error as SecretScanError).code).toBe("INVALID_RULESET");
    }
  });
});
