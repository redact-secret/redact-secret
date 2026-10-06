/**
 * `compareActionPolicies` (issue #1220,
 * `decision-explain-and-compare-action-policies-over-one-detection-pass`):
 * what the public wrapper validates and forwards, how it shapes what a binding
 * returns, and that nothing resembling an incremental or stream comparison is
 * accepted. Detection, evaluation, the digest and the comparison itself belong
 * to the Rust core and run in the real-artifact qualification
 * (`scripts/lib/action-policy-compare-reference.mjs`), not here.
 */

import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import type { NativeActionComparison } from "../src/native.js";
import { decodeComparison } from "../src/runtime/wasm-binding.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import type { ActionPolicyDocument, CompareActionPoliciesOptions } from "../src/types.js";
import { VERSION } from "../src/version.js";
import { createFakeBinding, emptyNativeComparison } from "./fake-binding.js";
import { createWasmShapedBinding, encodeComparison } from "./wasm-shaped-binding.js";

const DOCUMENT: ActionPolicyDocument = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [{ id: "warn-jwt", match: { type: ["jwt"] }, action: "warn" }],
};
const DOCUMENT_TEXT =
  '{"actionPolicyRevision":1,"base":"default","rules":[{"id":"warn-jwt","match":{"type":["jwt"]},"action":"warn"}]}';
const DIGEST = "8d7435054449cc35e59598f47e5c2a586d7bf751748f5b6867453f3dad667786";

/** A comparison of three sides over two findings, covering every shape a field takes. */
const RICH: NativeActionComparison = {
  detection: {
    activationIdentity: "credentials=full;selectors=off;families=;vocabulary=pii-context/v2",
    profile: "full",
    detectorCount: 42,
  },
  sides: [
    { kind: "default", redact: 1, block: 0, warn: 1, allow: 0 },
    { kind: "action-policy", documentSha256: DIGEST, redact: 0, block: 0, warn: 1, allow: 1 },
    { kind: "callback", documentSha256: null, redact: 0, block: 0, warn: 2, allow: 0 },
  ],
  changedCount: 2,
  findings: [
    {
      id: "finding-1",
      type: "github_token",
      detector: "github-token",
      confidence: "high",
      obfuscation: "none",
      start: 8,
      end: 48,
      differs: true,
      decisions: [
        { action: "redact", basis: "default-policy", ruleId: null, ruleIndex: null },
        { action: "allow", basis: "rule", ruleId: "allow-github", ruleIndex: 1 },
        { action: "warn", basis: "callback" },
      ],
    },
    {
      id: "finding-2",
      type: "jwt",
      detector: "jwt",
      confidence: "medium",
      obfuscation: "invisible-characters",
      start: 60,
      end: 90,
      differs: true,
      decisions: [
        { action: "warn", basis: "default-policy" },
        { action: "warn", basis: "rule-default", ruleId: "keep-jwt", ruleIndex: 0 },
        { action: "warn", basis: "callback", ruleId: null, ruleIndex: null },
      ],
    },
  ],
};

async function ready(options: Parameters<typeof createFakeBinding>[0] = {}) {
  const binding = createFakeBinding(options);
  const runtime = createRedactSecretRuntime(async () => binding, "full");
  await runtime.initialize();
  return { binding, runtime };
}

function codeOf(call: () => unknown): string | undefined {
  try {
    call();
  } catch (error) {
    expect(error).toBeInstanceOf(SecretScanError);
    return (error as SecretScanError).code;
  }
  return undefined;
}

const ONE = [{ kind: "default" }] as const;

describe("compareActionPolicies: validation before any native call", () => {
  it("needs a successful initialize like every other operation", () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding(), "full");

    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: ONE }))).toBe("NOT_INITIALIZED");
  });

  it("takes exactly one string, so a chunk, bytes or an iterable is INVALID_INPUT", async () => {
    const { binding, runtime } = await ready();

    for (const input of [["a", "b"], new Uint8Array([1]), 7, undefined, (async function* () {})()]) {
      expect(codeOf(() => runtime.compareActionPolicies(input as never, { policies: ONE }))).toBe("INVALID_INPUT");
    }
    expect(codeOf(() => runtime.compareActionPolicies("a\uD800", { policies: ONE }))).toBe("UNPAIRED_SURROGATE");
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("requires one to four sides", async () => {
    const { binding, runtime } = await ready();
    const side = { kind: "default" } as const;

    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: [] }))).toBe("INVALID_OPTIONS");
    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: [side, side, side, side, side] }))).toBe(
      "INVALID_OPTIONS",
    );
    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: undefined } as never))).toBe("INVALID_OPTIONS");
    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: "default" } as never))).toBe("INVALID_OPTIONS");
    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: new Array(2) } as never))).toBe(
      "INVALID_OPTIONS",
    );
    expect(codeOf(() => runtime.compareActionPolicies("x", undefined as never))).toBe("INVALID_OPTIONS");
    expect(codeOf(() => runtime.compareActionPolicies("x", [] as never))).toBe("INVALID_OPTIONS");
    expect(binding.calls).toEqual(["initialize"]);

    for (const count of [1, 2, 3, 4]) {
      runtime.compareActionPolicies("x", { policies: Array.from({ length: count }, () => side) });
    }
    expect(binding.calls.filter((call) => call.startsWith("compareActionPolicies"))).toHaveLength(4);
  });

  it("closes the side kinds and refuses a field of another kind, so nothing is silently ignored", async () => {
    const { binding, runtime } = await ready();
    const evaluate = () => "warn" as const;
    const bad: unknown[] = [
      { kind: "session" },
      { kind: "incremental" },
      { kind: "stream" },
      {},
      null,
      "default",
      { kind: "default", actionPolicy: DOCUMENT },
      { kind: "default", policy: { evaluate } },
      { kind: "default", incremental: true },
      { kind: "action-policy" },
      { kind: "action-policy", actionPolicy: DOCUMENT, policy: { evaluate } },
      { kind: "callback" },
      { kind: "callback", policy: { evaluate }, actionPolicy: DOCUMENT },
      { kind: "callback", policy: {} },
      { kind: "callback", policy: evaluate },
    ];

    for (const side of bad) {
      expect(
        codeOf(() => runtime.compareActionPolicies("x", { policies: [side] } as never)),
        JSON.stringify(side),
      ).toBe("INVALID_OPTIONS");
    }
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("refuses an option that could be mistaken for incremental or stream support", async () => {
    const { binding, runtime } = await ready();

    for (const extra of [
      { incremental: true },
      { stream: true },
      { chunks: ["a"] },
      { session: {} },
      { policy: { evaluate: () => "warn" } },
      { actionPolicy: DOCUMENT },
      { placeholderFormatter: () => "<X>" },
      { limits: { maxInputBytes: 10, maxFindings: 10, maxBufferedBytes: 10 } },
      { limits: { maxInputBytes: 10, maxFindings: 10, maxTokenBytes: 5 } },
    ]) {
      expect(
        codeOf(() => runtime.compareActionPolicies("x", { policies: ONE, ...extra } as never)),
        JSON.stringify(extra),
      ).toBe("INVALID_OPTIONS");
    }
    expect(
      codeOf(() => runtime.compareActionPolicies("x", { policies: ONE, limits: { maxInputBytes: 10 } } as never)),
    ).toBe("INVALID_OPTIONS");
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("reuses the whole-input limit and ruleset validation of scan", async () => {
    const { binding, runtime } = await ready();

    expect(
      codeOf(() =>
        runtime.compareActionPolicies("x", { policies: ONE, limits: { maxInputBytes: -1, maxFindings: 1 } }),
      ),
    ).toBe("INVALID_LIMITS");
    expect(
      codeOf(() =>
        runtime.compareActionPolicies("x", { policies: ONE, limits: { maxInputBytes: 1.5, maxFindings: 1 } }),
      ),
    ).toBe("INVALID_LIMITS");
    expect(codeOf(() => runtime.compareActionPolicies("x", { policies: ONE, ruleset: 7 as never }))).toBe(
      "INVALID_OPTIONS",
    );
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("reports a document the way scan does: INVALID_ACTION_POLICY for an unserializable object, INVALID_OPTIONS for another kind", async () => {
    const { binding, runtime } = await ready();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    expect(
      codeOf(() =>
        runtime.compareActionPolicies("x", { policies: [{ kind: "action-policy", actionPolicy: cyclic as never }] }),
      ),
    ).toBe("INVALID_ACTION_POLICY");
    expect(
      codeOf(() =>
        runtime.compareActionPolicies("x", { policies: [{ kind: "action-policy", actionPolicy: 7 as never }] }),
      ),
    ).toBe("INVALID_OPTIONS");
    expect(binding.calls).toEqual(["initialize"]);
  });
});

describe("compareActionPolicies: what reaches the binding", () => {
  it("forwards the sides in order, with each document as the exact bytes the core will hash", async () => {
    const { binding, runtime } = await ready();
    const bytes = new TextEncoder().encode(DOCUMENT_TEXT);

    runtime.compareActionPolicies("x", {
      policies: [
        { kind: "default" },
        { kind: "action-policy", actionPolicy: DOCUMENT },
        { kind: "action-policy", actionPolicy: DOCUMENT_TEXT },
        { kind: "action-policy", actionPolicy: bytes },
      ],
    });
    const sides = binding.lastCompare?.sides ?? [];

    expect(sides.map((side) => side.kind)).toEqual(["default", "action-policy", "action-policy", "action-policy"]);
    const documents = sides.flatMap((side) => (side.kind === "action-policy" ? [side.document] : []));
    expect(documents.map((document) => new TextDecoder().decode(document))).toEqual([
      DOCUMENT_TEXT,
      DOCUMENT_TEXT,
      DOCUMENT_TEXT,
    ]);
    expect(documents[2]).toBe(bytes);
  });

  it("does not let a later mutation of an object policy change what was sent", async () => {
    const { binding, runtime } = await ready();
    const mutable = { actionPolicyRevision: 1, base: "default", rules: [] as unknown[] };

    runtime.compareActionPolicies("x", { policies: [{ kind: "action-policy", actionPolicy: mutable as never }] });
    const side = binding.lastCompare?.sides[0];
    mutable.rules.push({ id: "late" });

    expect(side?.kind === "action-policy" && new TextDecoder().decode(side.document)).toBe(
      '{"actionPolicyRevision":1,"base":"default","rules":[]}',
    );
  });

  it("adapts a callback to the safe metadata and calls it as the binding calls it", async () => {
    const { binding, runtime } = await ready();
    const seen: unknown[] = [];

    runtime.compareActionPolicies("x", {
      policies: [
        {
          kind: "callback",
          policy: {
            evaluate: (finding, context) => {
              seen.push([finding, context]);
              return "warn";
            },
          },
        },
      ],
    });
    const side = binding.lastCompare?.sides[0];
    if (side?.kind !== "callback") throw new Error("expected a callback side");
    const returned = side.callback(
      {
        id: "finding-1",
        type: "jwt",
        detector: "jwt",
        confidence: "high",
        obfuscation: "none",
        start: 1,
        end: 2,
        extra: "leak",
      } as never,
      { findingIndex: 0, findingCount: 1 },
    );

    expect(returned).toBe("warn");
    const [finding, context] = seen[0] as [Record<string, unknown>, unknown];
    expect(Object.keys(finding).sort()).toEqual([
      "confidence",
      "detector",
      "end",
      "id",
      "obfuscation",
      "start",
      "type",
    ]);
    expect(Object.isFrozen(finding)).toBe(true);
    expect(context).toEqual({ findingIndex: 0, findingCount: 1 });
  });

  it("forwards limits and a ruleset as scan does, and nothing else", async () => {
    const { binding, runtime } = await ready();

    runtime.compareActionPolicies("x", {
      policies: ONE,
      limits: { maxInputBytes: 100, maxFindings: 5 },
      ruleset: "ruleset-revision: 1\n",
    });
    expect(binding.lastCompare?.limits).toEqual({ maxInputBytes: 100, maxFindings: 5 });
    expect(new TextDecoder().decode(binding.lastCompare?.ruleset)).toBe("ruleset-revision: 1\n");

    runtime.compareActionPolicies("x", { policies: ONE });
    expect(binding.lastCompare?.limits).toBeUndefined();
    expect(binding.lastCompare?.ruleset).toBeUndefined();
  });

  it("never touches the enforcement paths", async () => {
    const { binding, runtime } = await ready();

    runtime.compareActionPolicies("x", { policies: ONE });

    expect(binding.calls).toEqual(["initialize", "compareActionPolicies:x:default"]);
  });
});

describe("compareActionPolicies: the result", () => {
  it("is frozen plain data with the CLI's field names, labels and self-description", async () => {
    const { runtime } = await ready({ comparison: RICH });

    const result = runtime.compareActionPolicies("x", { policies: [...ONE, ...ONE, ...ONE] });

    expect(result).toEqual({
      version: VERSION,
      rangeUnit: "utf16-code-units",
      mode: "preview",
      enforced: false,
      detection: { activationIdentity: RICH.detection.activationIdentity, profile: "full", detectorCount: 42 },
      policies: [
        {
          label: "baseline",
          kind: "default",
          documentSha256: null,
          counts: { redact: 1, block: 0, warn: 1, allow: 0 },
        },
        {
          label: "candidate-1",
          kind: "action-policy",
          documentSha256: DIGEST,
          counts: { redact: 0, block: 0, warn: 1, allow: 1 },
        },
        {
          label: "candidate-2",
          kind: "callback",
          documentSha256: null,
          counts: { redact: 0, block: 0, warn: 2, allow: 0 },
        },
      ],
      findingCount: 2,
      changedCount: 2,
      findings: [
        {
          id: "finding-1",
          type: "github_token",
          detector: "github-token",
          confidence: "high",
          obfuscation: "none",
          start: 8,
          end: 48,
          differs: true,
          decisions: [
            { action: "redact", basis: "default-policy", ruleId: null, ruleIndex: null },
            { action: "allow", basis: "rule", ruleId: "allow-github", ruleIndex: 1 },
            { action: "warn", basis: "callback", ruleId: null, ruleIndex: null },
          ],
        },
        {
          id: "finding-2",
          type: "jwt",
          detector: "jwt",
          confidence: "medium",
          obfuscation: "invisible-characters",
          start: 60,
          end: 90,
          differs: true,
          decisions: [
            { action: "warn", basis: "default-policy", ruleId: null, ruleIndex: null },
            { action: "warn", basis: "rule-default", ruleId: "keep-jwt", ruleIndex: 0 },
            { action: "warn", basis: "callback", ruleId: null, ruleIndex: null },
          ],
        },
      ],
    });
  });

  it("is frozen all the way down and survives a structured clone and JSON unchanged", async () => {
    const { runtime } = await ready({ comparison: RICH });

    const result = runtime.compareActionPolicies("x", { policies: ONE });
    const frozen = (value: unknown): boolean =>
      typeof value !== "object" || value === null || (Object.isFrozen(value) && Object.values(value).every(frozen));

    expect(frozen(result)).toBe(true);
    expect(structuredClone(result)).toEqual(result);
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
  });

  it("carries only the documented keys: no text, no value, no score", async () => {
    const { runtime } = await ready({ comparison: RICH });

    const result = runtime.compareActionPolicies("x", { policies: ONE });

    expect(Object.keys(result).sort()).toEqual([
      "changedCount",
      "detection",
      "enforced",
      "findingCount",
      "findings",
      "mode",
      "policies",
      "rangeUnit",
      "version",
    ]);
    expect(Object.keys(result.findings[0] ?? {}).sort()).toEqual([
      "confidence",
      "decisions",
      "detector",
      "differs",
      "end",
      "id",
      "obfuscation",
      "start",
      "type",
    ]);
    expect(Object.keys(result.policies[0] ?? {}).sort()).toEqual(["counts", "documentSha256", "kind", "label"]);
  });

  it("reports an empty comparison with its detection identity and no findings", async () => {
    const { runtime } = await ready();

    const result = runtime.compareActionPolicies("x", { policies: ONE });

    expect(result.findings).toEqual([]);
    expect(result.findingCount).toBe(0);
    expect(result.changedCount).toBe(0);
    expect(result.policies).toHaveLength(emptyNativeComparison.sides.length);
  });
});

describe("compareActionPolicies: failures", () => {
  it("passes a binding's fixed code through and replaces anything else with DETECTOR_FAILURE", async () => {
    for (const [thrown, code] of [
      [Object.assign(new Error("boom"), { code: "POLICY_FAILURE" }), "POLICY_FAILURE"],
      [Object.assign(new Error("boom"), { code: "INVALID_POLICY_ACTION" }), "INVALID_POLICY_ACTION"],
      [Object.assign(new Error("boom"), { code: "INPUT_LIMIT_EXCEEDED" }), "INPUT_LIMIT_EXCEEDED"],
      [Object.assign(new Error("boom"), { code: "FINDING_LIMIT_EXCEEDED" }), "FINDING_LIMIT_EXCEEDED"],
      [Object.assign(new Error("boom"), { code: "INVALID_ACTION_POLICY" }), "INVALID_ACTION_POLICY"],
      [Object.assign(new Error("boom"), { code: "INVALID_OPTIONS" }), "INVALID_OPTIONS"],
      [new Error("host text that could echo the input"), "DETECTOR_FAILURE"],
    ] as const) {
      const { runtime } = await ready({ throwOnCompare: thrown });

      let caught: unknown;
      try {
        runtime.compareActionPolicies("x", { policies: ONE });
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(SecretScanError);
      expect((caught as SecretScanError).code).toBe(code);
      expect((caught as Error).message).not.toContain("boom");
      expect((caught as Error).message).not.toContain("echo");
    }
  });
});

describe("compareActionPolicies: the WebAssembly flat layout", () => {
  it("round-trips every shape of field through the decoder", () => {
    expect(decodeComparison(encodeComparison(RICH))).toEqual({
      detection: RICH.detection,
      sides: RICH.sides.map((side) => ({ ...side, documentSha256: side.documentSha256 ?? null })),
      changedCount: 2,
      findings: RICH.findings.map((finding) => ({
        ...finding,
        decisions: finding.decisions.map((decision) => ({
          ...decision,
          ruleId: decision.ruleId ?? null,
          ruleIndex: decision.ruleIndex ?? null,
        })),
      })),
    });
  });

  it("fails closed on a layout that is the wrong length or the wrong kind", () => {
    const flat = encodeComparison(RICH);

    for (const broken of [
      flat.slice(0, -1),
      [...flat, "extra"],
      [7, ...flat.slice(1)],
      flat.map((value, index) => (index === 3 ? "3" : value)),
      [],
    ]) {
      expect(codeOf(() => decodeComparison(broken))).toBe("INITIALIZATION_FAILED");
    }
  });

  it("gives the same public result whichever runtime shape the binding has", async () => {
    const wasm = createWasmShapedBinding({ comparison: RICH });
    const wasmRuntime = createRedactSecretRuntime(wasm.load, "full");
    await wasmRuntime.initialize();
    const { runtime: addonRuntime } = await ready({ comparison: RICH });
    const options: CompareActionPoliciesOptions = { policies: [...ONE, ...ONE, ...ONE] };

    expect(wasmRuntime.compareActionPolicies("x", options)).toEqual(addonRuntime.compareActionPolicies("x", options));
  });

  it("flattens a callback's metadata the way a scan callback sees it, once per finding per side", async () => {
    const wasm = createWasmShapedBinding({
      findings: [
        {
          id: "finding-1",
          type: "jwt",
          detector: "jwt",
          confidence: "high",
          action: "redact",
          obfuscation: "none",
          range: { start: 2, end: 9 },
          start: 2,
          end: 9,
        },
      ],
    });
    const runtime = createRedactSecretRuntime(wasm.load, "full");
    await runtime.initialize();
    const seen: unknown[] = [];

    runtime.compareActionPolicies("x", {
      policies: [
        {
          kind: "callback",
          policy: {
            evaluate: (finding, context) => {
              seen.push([finding.start, finding.end, context]);
              return "warn";
            },
          },
        },
      ],
    });

    expect(seen).toEqual([[2, 9, { findingIndex: 0, findingCount: 1 }]]);
    expect(wasm.lastCompareArguments?.slice(1, 4)).toEqual([["callback"], [], 1]);
  });
});
