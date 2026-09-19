/**
 * The N-API addon binding's own adapter contract (`runtime/node.ts`).
 *
 * Every test here runs against `createBindingFromAddon` — the same
 * normalization `runtime/node.ts` applies to the real per-platform addon
 * (`@redact-secret/node-<platform>`), exercised here against a plain
 * object double instead of the compiled addon, which is not present in a
 * source checkout.
 */

import { describe, expect, it } from "vitest";

import type {
  NativeFinding,
  NativeFormatterCallback,
} from "../src/native.js";
import {
  createBindingFromAddon,
  createBindingFromCommonAddon,
} from "../src/runtime/node.js";
import { sampleFinding } from "./fake-binding.js";

const LIMITS = {
  maxInputCodeUnits: 1_024,
  maxBufferedCodeUnits: 384,
  maxTokenCodeUnits: 128,
  maxMultilineCodeUnits: 256,
};

describe("Node addon binding: createIncrementalSanitizer", () => {
  it("delegates to the required addon's own export", () => {
    const calls: string[] = [];
    const binding = createBindingFromAddon({
      version: () => "0.0.0-test",
      profile: () => "full",
      initialize: () => {},
      scan: () => [],
      redact: (input) => input,
      scanAndRedact: (input) => ({ findings: [], redacted: input }),
      createIncrementalSanitizer: (options) => {
        calls.push(`createIncrementalSanitizer:${options.limits.maxInputCodeUnits}`);
        return {
          state: "accepting",
          append: (chunk) => ({ text: chunk, findings: [] }),
          finalize: () => ({ text: "", findings: [sampleFinding] }),
          abort: () => {},
        };
      },
    });

    const session = binding.createIncrementalSanitizer({ limits: LIMITS });

    expect(calls).toEqual([`createIncrementalSanitizer:${LIMITS.maxInputCodeUnits}`]);
    expect(session.finalize()).toEqual({ text: "", findings: [sampleFinding] });
  });
});

describe("Node addon binding: scanAndRedact result shape", () => {
  it("renames the addon's redacted field to the contract's text", () => {
    const binding = createBindingFromAddon({
      version: () => "0.0.0-test",
      profile: () => "full",
      initialize: () => {},
      scan: () => [],
      redact: (input) => input,
      scanAndRedact: () => ({ findings: [sampleFinding], redacted: "<SECRET_1>" }),
      createIncrementalSanitizer: () => ({
        state: "accepting",
        append: (chunk) => ({ text: chunk, findings: [] }),
        finalize: () => ({ text: "", findings: [] }),
        abort: () => {},
      }),
    });

    expect(
      binding.scanAndRedact("input", undefined, undefined, undefined),
    ).toEqual({
      text: "<SECRET_1>",
      findings: [sampleFinding],
    });
  });
});

describe("Node addon binding: createBindingFromCommonAddon", () => {
  it("routes every operation through the addon's *Common exports", () => {
    const calls: string[] = [];
    const binding = createBindingFromCommonAddon({
      version: () => "0.0.0-test",
      profileCommon: () => "common",
      initializeCommon: () => {
        calls.push("initializeCommon");
      },
      scanCommon: () => {
        calls.push("scanCommon");
        return [];
      },
      redact: (input) => {
        calls.push("redact");
        return input;
      },
      scanAndRedactCommon: (input) => {
        calls.push("scanAndRedactCommon");
        return { findings: [sampleFinding], redacted: input };
      },
      createIncrementalSanitizerCommon: (options) => {
        calls.push(
          `createIncrementalSanitizerCommon:${options.limits.maxInputCodeUnits}`,
        );
        return {
          state: "accepting",
          append: (chunk) => ({ text: chunk, findings: [] }),
          finalize: () => ({ text: "", findings: [sampleFinding] }),
          abort: () => {},
        };
      },
    });

    expect(binding.version()).toBe("0.0.0-test");
    expect(binding.profile()).toBe("common");
    binding.initialize();
    expect(binding.scan("input", undefined, undefined)).toEqual([]);
    expect(binding.redact("input", [], undefined, undefined)).toBe("input");
    expect(
      binding.scanAndRedact("input", undefined, undefined, undefined),
    ).toEqual({
      text: "input",
      findings: [sampleFinding],
    });
    binding.createIncrementalSanitizer({ limits: LIMITS });

    expect(calls).toEqual([
      "initializeCommon",
      "scanCommon",
      "redact",
      "scanAndRedactCommon",
      `createIncrementalSanitizerCommon:${LIMITS.maxInputCodeUnits}`,
    ]);
  });

  it("renames the addon's redacted field to the contract's text", () => {
    const binding = createBindingFromCommonAddon({
      version: () => "0.0.0-test",
      profileCommon: () => "common",
      initializeCommon: () => {},
      scanCommon: () => [],
      redact: (input) => input,
      scanAndRedactCommon: () => ({
        findings: [sampleFinding],
        redacted: "<SECRET_1>",
      }),
      createIncrementalSanitizerCommon: () => ({
        state: "accepting",
        append: (chunk) => ({ text: chunk, findings: [] }),
        finalize: () => ({ text: "", findings: [] }),
        abort: () => {},
      }),
    });

    expect(
      binding.scanAndRedact("input", undefined, undefined, undefined),
    ).toEqual({
      text: "<SECRET_1>",
      findings: [sampleFinding],
    });
  });

  it("shares the same redact export as the full-profile binding", () => {
    const calls: string[] = [];
    const redact = (
      input: string,
      findings: readonly NativeFinding[],
      formatter?: NativeFormatterCallback,
    ) => {
      calls.push(
        `redact:${input}:${findings.length}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      return input;
    };

    const fullBinding = createBindingFromAddon({
      version: () => "0.0.0-test",
      profile: () => "full",
      initialize: () => {},
      scan: () => [],
      redact,
      scanAndRedact: (input) => ({ findings: [], redacted: input }),
      createIncrementalSanitizer: () => ({
        state: "accepting",
        append: (chunk) => ({ text: chunk, findings: [] }),
        finalize: () => ({ text: "", findings: [] }),
        abort: () => {},
      }),
    });
    const commonBinding = createBindingFromCommonAddon({
      version: () => "0.0.0-test",
      profileCommon: () => "common",
      initializeCommon: () => {},
      scanCommon: () => [],
      redact,
      scanAndRedactCommon: (input) => ({ findings: [], redacted: input }),
      createIncrementalSanitizerCommon: () => ({
        state: "accepting",
        append: (chunk) => ({ text: chunk, findings: [] }),
        finalize: () => ({ text: "", findings: [] }),
        abort: () => {},
      }),
    });

    fullBinding.redact("api_key=x", [sampleFinding], undefined, undefined);
    commonBinding.redact("api_key=x", [sampleFinding], undefined, undefined);

    // Both bindings called the exact same `redact` function, not a
    // per-profile copy of it.
    expect(calls).toEqual([
      "redact:api_key=x:1:builtin",
      "redact:api_key=x:1:builtin",
    ]);
  });
});
