/**
 * The `actionPolicy` option and the `defaultPolicy` export (issue #1219,
 * `decision-define-the-versioned-declarative-action-policy-and-default-overlay`):
 * conversion of the public input forms to the document bytes every binding
 * accepts, where the bytes reach the binding, the host-level misuse codes,
 * and `defaultPolicy`'s delegation. Parsing, validation and evaluation belong
 * to the Rust core and run in the real-artifact qualification
 * (`scripts/lib/action-policy-reference.mjs`), not here.
 */

import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import type { ActionPolicyDocument, DetectedSecretFinding } from "../src/types.js";
import { createFakeBinding } from "./fake-binding.js";
import { createWasmShapedBinding } from "./wasm-shaped-binding.js";

const LIMITS = {
  maxInputCodeUnits: 1_024,
  maxBufferedCodeUnits: 384,
  maxTokenCodeUnits: 128,
  maxMultilineCodeUnits: 256,
};

const DOCUMENT: ActionPolicyDocument = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [{ id: "warn-jwt", match: { type: ["jwt"] }, action: "warn" }],
};
const DOCUMENT_TEXT =
  '{"actionPolicyRevision":1,"base":"default","rules":[{"id":"warn-jwt","match":{"type":["jwt"]},"action":"warn"}]}';

const FINDING: DetectedSecretFinding = {
  id: "finding-1",
  type: "jwt",
  detector: "jwt",
  confidence: "medium",
  obfuscation: "none",
  start: 0,
  end: 10,
};

async function ready() {
  const binding = createFakeBinding();
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

describe("actionPolicy option", () => {
  it("serializes a plain object once, compactly, in member order", async () => {
    const { binding, runtime } = await ready();

    runtime.scan("input", { actionPolicy: DOCUMENT });

    expect(new TextDecoder().decode(binding.lastActionPolicy)).toBe(DOCUMENT_TEXT);
  });

  it("encodes text as UTF-8 bytes and passes bytes through unchanged", async () => {
    const { binding, runtime } = await ready();

    runtime.scan("input", { actionPolicy: DOCUMENT_TEXT });
    expect(binding.lastActionPolicy).toEqual(new TextEncoder().encode(DOCUMENT_TEXT));

    const bytes = new TextEncoder().encode(DOCUMENT_TEXT);
    runtime.scan("input", { actionPolicy: bytes });
    expect(binding.lastActionPolicy).toBe(bytes);
  });

  it("reaches the binding from scanAndRedact as well, and is absent when not given", async () => {
    const { binding, runtime } = await ready();

    runtime.scanAndRedact("input", { actionPolicy: DOCUMENT });
    expect(new TextDecoder().decode(binding.lastActionPolicy)).toBe(DOCUMENT_TEXT);

    runtime.scanAndRedact("input");
    expect(binding.lastActionPolicy).toBeUndefined();
    runtime.scan("input");
    expect(binding.lastActionPolicy).toBeUndefined();
  });

  it("does not let a later mutation of the object change what was sent", async () => {
    const { binding, runtime } = await ready();
    const mutable = { actionPolicyRevision: 1, base: "default", rules: [] as unknown[] };

    runtime.scan("input", { actionPolicy: mutable as unknown as ActionPolicyDocument });
    const sent = new TextDecoder().decode(binding.lastActionPolicy);
    mutable.rules.push({ id: "late" });

    expect(sent).toBe('{"actionPolicyRevision":1,"base":"default","rules":[]}');
  });

  it("rejects a callback policy and an action policy together as INVALID_OPTIONS, before any native call", async () => {
    const { binding, runtime } = await ready();
    const policy = { evaluate: () => "redact" as const };

    expect(codeOf(() => runtime.scan("input", { policy, actionPolicy: DOCUMENT }))).toBe("INVALID_OPTIONS");
    expect(codeOf(() => runtime.scanAndRedact("input", { policy, actionPolicy: DOCUMENT_TEXT }))).toBe(
      "INVALID_OPTIONS",
    );
    expect(
      codeOf(() => runtime.createIncrementalSanitizer({ limits: LIMITS, policy, actionPolicy: DOCUMENT } as never)),
    ).toBe("INVALID_OPTIONS");
    // Not even a document that would be rejected is serialized or sent.
    expect(codeOf(() => runtime.scan("input", { policy, actionPolicy: new Uint8Array([1]) }))).toBe("INVALID_OPTIONS");
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("reports a serializer failure or a value with no JSON form as INVALID_ACTION_POLICY", async () => {
    const { binding, runtime } = await ready();
    const cyclic: Record<string, unknown> = { actionPolicyRevision: 1 };
    cyclic.self = cyclic;
    const withBigInt = { actionPolicyRevision: 1n };
    const throwing = {
      toJSON() {
        throw new Error("SYNTHETIC_REVOKED_SERIALIZER_FAILURE");
      },
    };
    const noJsonForm = { toJSON: () => undefined };

    for (const value of [cyclic, withBigInt, throwing, noJsonForm]) {
      expect(codeOf(() => runtime.scan("input", { actionPolicy: value as never }))).toBe("INVALID_ACTION_POLICY");
    }
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("rejects an option of any other kind as INVALID_OPTIONS", async () => {
    const { runtime } = await ready();

    for (const value of [12345, true, null, () => DOCUMENT_TEXT, Symbol("policy")]) {
      expect(codeOf(() => runtime.scan("input", { actionPolicy: value as never }))).toBe("INVALID_OPTIONS");
    }
  });

  it("surfaces the binding's INVALID_ACTION_POLICY as a code with its one fixed message", async () => {
    const binding = createFakeBinding({
      throwOnScan: Object.assign(new Error("The supplied action policy is invalid. (INVALID_ACTION, rule 3)"), {
        code: "INVALID_ACTION_POLICY",
      }),
    });
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    try {
      runtime.scan("input", { actionPolicy: DOCUMENT });
      throw new Error("expected scan to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SecretScanError);
      expect((error as SecretScanError).code).toBe("INVALID_ACTION_POLICY");
      expect((error as SecretScanError).message).toBe("The supplied action policy is invalid.");
    }
  });
});

describe("actionPolicy option on incremental sessions", () => {
  it("is serialized at construction and bound to the session", async () => {
    const { binding, runtime } = await ready();
    const mutable = { actionPolicyRevision: 1, base: "default", rules: [] as unknown[] };

    const session = runtime.createIncrementalSanitizer({
      limits: LIMITS,
      actionPolicy: mutable as unknown as ActionPolicyDocument,
    });
    mutable.rules.push({ id: "late" });

    expect(new TextDecoder().decode(binding.lastIncrementalOptions?.actionPolicy)).toBe(
      '{"actionPolicyRevision":1,"base":"default","rules":[]}',
    );
    expect(session.state).toBe("accepting");
  });

  it("is absent from the native options when not given", async () => {
    const { binding, runtime } = await ready();

    runtime.createIncrementalSanitizer({ limits: LIMITS });

    expect(binding.lastIncrementalOptions).toBeDefined();
    expect(Object.hasOwn(binding.lastIncrementalOptions ?? {}, "actionPolicy")).toBe(false);
  });

  it("rejects a value of an unsupported kind as INVALID_OPTIONS and a cyclic one as INVALID_ACTION_POLICY", async () => {
    const { runtime } = await ready();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    expect(codeOf(() => runtime.createIncrementalSanitizer({ limits: LIMITS, actionPolicy: 7 as never }))).toBe(
      "INVALID_OPTIONS",
    );
    expect(codeOf(() => runtime.createIncrementalSanitizer({ limits: LIMITS, actionPolicy: cyclic as never }))).toBe(
      "INVALID_ACTION_POLICY",
    );
  });
});

describe("actionPolicy option through the WebAssembly binding shape", () => {
  it("passes the bytes as the trailing argument of scan, scanAndRedact and createIncrementalSanitizer", async () => {
    const shaped = createWasmShapedBinding();
    const runtime = createRedactSecretRuntime(shaped.load, "full");
    await runtime.initialize();
    const bytes = new TextEncoder().encode(DOCUMENT_TEXT);

    runtime.scan("input", { actionPolicy: bytes });
    expect(shaped.lastActionPolicy).toBe(bytes);

    runtime.scanAndRedact("input", { actionPolicy: bytes });
    expect(shaped.lastActionPolicy).toBe(bytes);

    runtime.scan("input");
    expect(shaped.lastActionPolicy).toBeUndefined();

    runtime.createIncrementalSanitizer({ limits: LIMITS, actionPolicy: bytes });
    expect(shaped.lastActionPolicy).toBe(bytes);
  });

  it("flattens the finding metadata into the positional defaultPolicy arguments", async () => {
    const shaped = createWasmShapedBinding();
    const binding = await shaped.load({ pii: false });

    expect(binding.defaultPolicy(FINDING)).toBe("redact");
    expect(shaped.lastDefaultPolicyArguments).toEqual(["finding-1", "jwt", "jwt", "medium", "none", 0, 10]);
  });
});

describe("defaultPolicy", () => {
  it("delegates to the binding's core evaluation and returns its action", async () => {
    const binding = {
      ...createFakeBinding(),
      defaultPolicy: (finding: DetectedSecretFinding) => (finding.type === "private_key" ? "block" : "warn"),
    };
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    expect(runtime.defaultPolicy.evaluate({ ...FINDING, type: "private_key" })).toBe("block");
    expect(runtime.defaultPolicy.evaluate(FINDING)).toBe("warn");
  });

  it("is usable detached, as a whole-input policy and as an incremental policy, and is frozen", async () => {
    const { runtime } = await ready();
    const { evaluate } = runtime.defaultPolicy;

    expect(evaluate(FINDING)).toBe("redact");
    expect(Object.isFrozen(runtime.defaultPolicy)).toBe(true);
    expect(() => runtime.scan("input", { policy: runtime.defaultPolicy })).not.toThrow();
    expect(() => runtime.createIncrementalSanitizer({ limits: LIMITS, policy: runtime.defaultPolicy })).not.toThrow();
  });

  it("requires initialization like every other operation", () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding(), "full");

    expect(codeOf(() => runtime.defaultPolicy.evaluate(FINDING))).toBe("NOT_INITIALIZED");
  });

  it("rejects malformed metadata as INVALID_FINDINGS before it reaches the binding", async () => {
    const { binding, runtime } = await ready();
    const evaluate = (value: unknown) => runtime.defaultPolicy.evaluate(value as never);

    for (const value of [
      undefined,
      null,
      "jwt",
      { ...FINDING, type: 1 },
      { ...FINDING, confidence: undefined },
      { ...FINDING, start: -1 },
      { ...FINDING, end: 1.5 },
      { ...FINDING, end: 2 ** 32 },
      { ...FINDING, start: "0" },
    ]) {
      expect(codeOf(() => evaluate(value))).toBe("INVALID_FINDINGS");
    }
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("maps a binding failure to a fixed SecretScanError, never the binding's text", async () => {
    const binding = {
      ...createFakeBinding(),
      defaultPolicy: () => {
        throw new Error("SYNTHETIC_REVOKED_BINDING_TEXT");
      },
    };
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();

    try {
      runtime.defaultPolicy.evaluate(FINDING);
      throw new Error("expected evaluate to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SecretScanError);
      expect((error as SecretScanError).code).toBe("INVALID_FINDINGS");
      expect((error as SecretScanError).message).not.toContain("SYNTHETIC");
    }
  });
});
