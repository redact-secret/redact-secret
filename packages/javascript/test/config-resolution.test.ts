import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { canonicalJson } from "../src/manifest.js";
import type { NativeBinding } from "../src/native.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import { VERSION } from "../src/version.js";
import { createFakeBinding } from "./fake-binding.js";

/**
 * The runtime side of `resolveConfig`/`describeConfig` and detector selection
 * (issue #1251). The Rust core owns the truth table, the snapshot and the
 * ownership; this package only forwards, parses, checks and freezes. These
 * tests use a recorded binding double, so they pin the plumbing: what is
 * forwarded and when, what is copied, what is frozen, which fixed codes
 * surface, and that nothing is called when it must not be. The table itself
 * runs against the real artifacts (`real-binding-config.test.ts`, the addon
 * smoke test and the Rust suite) from one shared fixture.
 */

const sha256 = (text: string): string => `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;

const MANIFEST_BODY = {
  artifact: { kind: "node-addon", pii: true, variant: "full" },
  bounds: {
    actionPolicyBytes: 65_536,
    detectorIdsMax: 256,
    diagnosticsMax: 256,
    limits: { maxFindings: 50_000, maxInputBytes: 67_108_864 },
  },
  capabilities: {
    actionPolicy: { revisions: [1] },
    detectorSelection: true,
    incremental: true,
    ruleset: { revisions: [1] },
  },
  composition: { id: null, kind: "standard", profile: "full" },
  defaults: {
    actionPolicy: "artifact-default",
    detection: "all-included",
    limits: "artifact-default",
    pii: { selectors: [] },
    schema: "build-defaults/v1",
  },
  detectors: [{ aliases: [], id: "jwt", pack: "common", types: ["jwt"] }],
  notIncluded: [],
  pii: { available: true, families: [] },
  product: "redact-secret",
  schema: "artifact-manifest/v1",
  sourceRevision: null,
  typeVocabulary: { builtInTypes: "declared", complete: false, dynamicSources: ["custom-detector", "pii", "ruleset"] },
  version: VERSION,
};
const MANIFEST_DIGEST = sha256(canonicalJson(MANIFEST_BODY));
const MANIFEST_TEXT = JSON.stringify({ ...MANIFEST_BODY, digest: MANIFEST_DIGEST });

/** A contract-shaped `config-resolution/v1` document. */
function resolutionText(
  options: { ok?: boolean; manifestDigest?: string; digest?: string; marker?: string; schema?: string } = {},
): string {
  const ok = options.ok ?? true;
  const digest = options.digest ?? sha256(`snapshot${options.marker ?? ""}`);
  return JSON.stringify({
    schema: options.schema ?? "config-resolution/v1",
    diagnostics: {
      schema: "config-diagnostics/v1",
      items: ok ? [] : [{ code: "UNKNOWN_DETECTOR_ID", id: null, path: "detection.include[0]", severity: "error" }],
      truncated: false,
    },
    ok,
    snapshot: ok
      ? {
          schema: "config-snapshot/v1",
          artifact: { manifestDigest: options.manifestDigest ?? MANIFEST_DIGEST },
          detection: { enabled: ["jwt"], disabled: [], enabledCount: 1 },
          detectionDigest: sha256("detection"),
          digest,
        }
      : null,
  });
}

interface ResolveCall {
  readonly config: string | undefined;
  readonly ruleset: Uint8Array | undefined;
  readonly actionPolicy: Uint8Array | undefined;
  readonly callback: boolean;
  readonly disclose: boolean;
}

interface Recorded {
  readonly binding: ReturnType<typeof createFakeBinding> & NativeBinding;
  readonly resolveCalls: ResolveCall[];
  readonly initializeCalls: Array<{ pii: readonly string[] | undefined; detection: string | undefined }>;
}

/** A binding double that reports a manifest and resolves with `answer`. */
function recorded(
  options: { answer?: (call: ResolveCall) => string; withResolve?: boolean; onInitialize?: () => void } = {},
): Recorded {
  const base = createFakeBinding();
  const resolveCalls: ResolveCall[] = [];
  const initializeCalls: Recorded["initializeCalls"] = [];
  const originalInitialize = base.initialize.bind(base);
  const binding = Object.assign(base, {
    artifactManifest: () => MANIFEST_TEXT,
    initialize: (pii?: readonly string[], detection?: string) => {
      initializeCalls.push({ pii, detection });
      options.onInitialize?.();
      originalInitialize(pii);
    },
    ...(options.withResolve === false
      ? {}
      : {
          resolveConfig: (
            config: string | undefined,
            ruleset: Uint8Array | undefined,
            actionPolicy: Uint8Array | undefined,
            callback: boolean,
            disclose: boolean,
          ) => {
            const call = { config, ruleset, actionPolicy, callback, disclose };
            resolveCalls.push(call);
            return (options.answer ?? (() => resolutionText()))(call);
          },
        }),
  }) as Recorded["binding"];
  return { binding, resolveCalls, initializeCalls };
}

async function initialized(
  double: Recorded,
  initializeOptions?: Parameters<ReturnType<typeof createRedactSecretRuntime>["initialize"]>[0],
) {
  const runtime = createRedactSecretRuntime(async () => double.binding, "full");
  await runtime.initialize(initializeOptions);
  return runtime;
}

describe("resolveConfig", () => {
  it("is refused before initialize and reaches no binding", () => {
    const double = recorded();
    const runtime = createRedactSecretRuntime(async () => double.binding, "full");

    expect(() => runtime.resolveConfig()).toThrowError(expect.objectContaining({ code: "NOT_INITIALIZED" }));
    expect(() => runtime.describeConfig()).toThrowError(expect.objectContaining({ code: "NOT_INITIALIZED" }));
    expect(double.binding.calls).toEqual([]);
    expect(double.resolveCalls).toEqual([]);
  });

  it("forwards only the data members as compact JSON and the two documents as their exact bytes", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    double.resolveCalls.length = 0;
    const policy = { actionPolicyRevision: 1, base: "default", rules: [] } as const;

    runtime.resolveConfig({
      detection: { include: ["jwt"] },
      pii: ["pii:global"],
      limits: { maxFindings: 5 },
      ruleset: "ruleset-revision: 1\n",
      actionPolicy: policy,
    });

    expect(double.resolveCalls).toHaveLength(1);
    const [call] = double.resolveCalls;
    expect(call?.config).toBe('{"detection":{"include":["jwt"]},"pii":["pii:global"],"limits":{"maxFindings":5}}');
    expect(new TextDecoder().decode(call?.ruleset)).toBe("ruleset-revision: 1\n");
    // The policy document is serialized once, exactly as a call would, so
    // the identity the core reports is the digest of these bytes.
    expect(new TextDecoder().decode(call?.actionPolicy)).toBe(JSON.stringify(policy));
    expect(call?.callback).toBe(false);
    expect(call?.disclose).toBe(false);
  });

  it("passes text and bytes through unchanged and records a callback without calling it", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    double.resolveCalls.length = 0;
    const bytes = new TextEncoder().encode('{"actionPolicyRevision":1,"base":"default","rules":[]}');
    let called = 0;

    runtime.resolveConfig(
      { actionPolicy: bytes },
      {
        discloseRulesetIdentity: true,
      },
    );
    runtime.resolveConfig(undefined, {
      policy: {
        evaluate: () => {
          called += 1;
          return "redact";
        },
      },
    });

    expect(double.resolveCalls[0]?.actionPolicy).toBe(bytes);
    expect(double.resolveCalls[0]?.disclose).toBe(true);
    expect(double.resolveCalls[1]?.config).toBeUndefined();
    expect(double.resolveCalls[1]?.callback).toBe(true);
    expect(called).toBe(0);
  });

  it("returns a deeply frozen result bound to the artifact manifest", async () => {
    const double = recorded();
    const runtime = await initialized(double);

    const resolution = runtime.resolveConfig({ detection: { exclude: ["jwt"] } });

    expect(resolution.ok).toBe(true);
    expect(resolution.snapshot?.schema).toBe("config-snapshot/v1");
    expect(Object.isFrozen(resolution)).toBe(true);
    expect(Object.isFrozen(resolution.snapshot)).toBe(true);
    expect(Object.isFrozen(resolution.snapshot?.detection.enabled)).toBe(true);
    expect(Object.isFrozen(resolution.diagnostics.items)).toBe(true);
    expect(() => {
      (resolution as { ok: boolean }).ok = false;
    }).toThrow();
  });

  it("reports an invalid request as data, with no snapshot, and never throws for it", async () => {
    const double = recorded({ answer: () => resolutionText({ ok: false }) });
    const runtime = await initialized(double);

    const resolution = runtime.resolveConfig({ detection: { include: ["no-such-detector"] } });

    expect(resolution.ok).toBe(false);
    expect(resolution.snapshot).toBeNull();
    expect(resolution.diagnostics.items[0]).toEqual({
      code: "UNKNOWN_DETECTOR_ID",
      id: null,
      path: "detection.include[0]",
      severity: "error",
    });
  });

  it("does not change what a later resolution or a later call sees when the caller mutates its data", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    double.resolveCalls.length = 0;
    const config = { detection: { include: ["jwt"] }, limits: { maxFindings: 5 } };

    const first = runtime.resolveConfig(config);
    config.detection.include.push("private-key");
    config.limits.maxFindings = 1;
    const second = runtime.resolveConfig({ detection: { include: ["jwt"] }, limits: { maxFindings: 5 } });

    // The text a binding received was copied when the call was made.
    expect(double.resolveCalls[0]?.config).toBe('{"detection":{"include":["jwt"]},"limits":{"maxFindings":5}}');
    expect(second).toEqual(first);
    expect(Object.isFrozen(first)).toBe(true);
  });

  it("rejects host-shape mistakes as INVALID_OPTIONS before reaching the binding", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    double.resolveCalls.length = 0;
    const bad: Array<() => unknown> = [
      () => runtime.resolveConfig("detection" as never),
      () => runtime.resolveConfig([] as never),
      () => runtime.resolveConfig(new (class Config {})() as never),
      () => runtime.resolveConfig({}, "options" as never),
      () => runtime.resolveConfig({}, { surprise: true } as never),
      () => runtime.resolveConfig({}, { discloseRulesetIdentity: "yes" } as never),
      () => runtime.resolveConfig({}, { policy: {} as never }),
      () => runtime.resolveConfig({ ruleset: 5 as never }),
      () => runtime.resolveConfig({ actionPolicy: 5 as never }),
    ];
    for (const attempt of bad) {
      expect(attempt).toThrowError(expect.objectContaining({ name: "SecretScanError", code: "INVALID_OPTIONS" }));
    }
    expect(double.resolveCalls).toEqual([]);
  });

  it("fails with the fixed initialization error for an artifact without the export, a foreign manifest or a bad document", async () => {
    const marker = "SYNTHETIC-DOCUMENT-CONTENT";
    const cases: Array<[string, Recorded]> = [
      ["no export", recorded({ withResolve: false })],
      ["other manifest", recorded({ answer: () => resolutionText({ manifestDigest: sha256("other") }) })],
      ["other schema", recorded({ answer: () => resolutionText({ schema: "config-resolution/v2" }) })],
      ["bad digest", recorded({ answer: () => resolutionText({ digest: marker }) })],
      ["not json", recorded({ answer: () => marker })],
      [
        "throws",
        recorded({
          answer: () => {
            throw new Error(marker);
          },
        }),
      ],
    ];
    for (const [name, double] of cases) {
      const runtime = await initialized(double);
      let thrown: unknown;
      try {
        runtime.resolveConfig();
      } catch (error) {
        thrown = error;
      }
      expect(thrown, name).toBeInstanceOf(SecretScanError);
      expect((thrown as SecretScanError).code, name).toBe("INITIALIZATION_FAILED");
      expect(JSON.stringify(thrown), name).not.toContain(marker);
      expect((thrown as Error).message, name).not.toContain(marker);
      // Absent is not fatal for the rest of the surface.
      expect(runtime.scan("SYNTHETIC_REVOKED_VALUE"), name).toEqual([]);
    }
  });
});

describe("describeConfig and status().configuration", () => {
  it("describes the owner's configuration, input-free, from the one resolution made at initialize", async () => {
    const double = recorded({
      answer: (call) => resolutionText({ marker: call.config ?? "" }),
    });
    const runtime = await initialized(double, { pii: ["pii:global"], detection: { exclude: ["jwt"] } });
    const calls = [...double.resolveCalls];

    const snapshot = runtime.describeConfig();

    // One resolution, of the detection and PII the owner was initialized with.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.config).toBe('{"detection":{"exclude":["jwt"]},"pii":["pii:global"]}');
    expect(calls[0]?.ruleset).toBeUndefined();
    expect(calls[0]?.actionPolicy).toBeUndefined();
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(runtime.describeConfig()).toBe(snapshot);
    expect(runtime.status().configuration).toBe(snapshot.digest);
    // Observation asked nothing more of the binding and changed nothing.
    expect(double.resolveCalls).toHaveLength(1);
    expect(double.initializeCalls).toHaveLength(1);
  });

  it("is null before initialize and when the artifact reports no configuration", async () => {
    const double = recorded({ withResolve: false });
    const runtime = createRedactSecretRuntime(async () => double.binding, "full");
    expect(runtime.status().configuration).toBeNull();
    await runtime.initialize();
    expect(runtime.status().configuration).toBeNull();
    expect(() => runtime.describeConfig()).toThrowError(expect.objectContaining({ code: "INITIALIZATION_FAILED" }));
  });

  it("keeps the first configuration across a rejected or conflicting initialize", async () => {
    let failNext = false;
    const double = recorded({
      answer: (call) => resolutionText({ marker: call.config ?? "" }),
      onInitialize: () => {
        if (failNext) throw Object.assign(new Error("x"), { code: "DETECTION_CONFIG_CONFLICT" });
      },
    });
    const runtime = await initialized(double, { detection: { include: ["jwt"] } });
    const snapshot = runtime.describeConfig();

    failNext = true;
    await expect(runtime.initialize({ detection: { exclude: ["jwt"] } })).rejects.toMatchObject({
      code: "DETECTION_CONFIG_CONFLICT",
    });

    expect(runtime.describeConfig()).toBe(snapshot);
    expect(runtime.status().configuration).toBe(snapshot.digest);
    expect(runtime.status().initialized).toBe(true);
  });
});

describe("initialize({ detection })", () => {
  it("forwards a copy of the selection as JSON text, made when the call was made", async () => {
    const double = recorded();
    const include = ["jwt", "private-key"];
    const attempt = createRedactSecretRuntime(async () => double.binding, "full").initialize({
      detection: { include },
    });
    include.push("github-token");
    await attempt;

    expect(double.initializeCalls).toHaveLength(1);
    expect(double.initializeCalls[0]?.detection).toBe('{"include":["jwt","private-key"]}');
  });

  it("forwards no detection when none is given, as before", async () => {
    const double = recorded();
    await initialized(double, { pii: ["pii"] });
    expect(double.initializeCalls[0]?.detection).toBeUndefined();
    expect(double.initializeCalls[0]?.pii).toEqual(["pii"]);
  });

  it("rejects a detection that is not a plain object as INVALID_OPTIONS and loads nothing", async () => {
    for (const detection of [[], "jwt", 5, null, new (class Selection {})()]) {
      const double = recorded();
      let loads = 0;
      const runtime = createRedactSecretRuntime(async () => {
        loads += 1;
        return double.binding;
      }, "full");
      await expect(runtime.initialize({ detection: detection as never })).rejects.toMatchObject({
        code: "INVALID_OPTIONS",
      });
      expect(loads).toBe(0);
    }
    const double = recorded();
    const runtime = createRedactSecretRuntime(async () => double.binding, "full");
    await expect(runtime.initialize({ surprise: true } as never)).rejects.toMatchObject({ code: "INVALID_OPTIONS" });
  });

  it("surfaces the core's fixed codes, without a message that echoes the selection", async () => {
    const marker = "synthetic-detector-marker";
    for (const code of ["INVALID_DETECTION_CONFIG", "DETECTION_CONFIG_CONFLICT", "EMPTY_DETECTION_SET"] as const) {
      const double = recorded({
        onInitialize: () => {
          throw Object.assign(new Error(`${marker} (UNKNOWN_DETECTOR_ID, id 0)`), { code });
        },
      });
      const runtime = createRedactSecretRuntime(async () => double.binding, "full");
      const attempt = runtime.initialize({ detection: { include: [marker] } });
      await expect(attempt).rejects.toBeInstanceOf(SecretScanError);
      await expect(attempt).rejects.toMatchObject({ code });
      await attempt.catch((error: Error) => {
        expect(error.message).not.toContain(marker);
      });
      expect(runtime.status().initialized).toBe(false);
    }
  });

  it("shares one load between identical requests and asks the binding again only when the request differs", async () => {
    const double = recorded();
    const runtime = createRedactSecretRuntime(async () => double.binding, "full");

    await Promise.all([
      runtime.initialize({ detection: { include: ["jwt"] } }),
      runtime.initialize({ detection: { include: ["jwt"] } }),
    ]);
    await runtime.initialize({ detection: { include: ["jwt"] } });
    expect(double.initializeCalls).toHaveLength(1);

    // A different spelling reaches the binding, which decides whether it is
    // equivalent (idempotent) or a conflict; this package does not guess.
    await runtime.initialize({ detection: { include: ["jwt", "private-key"] } });
    expect(double.initializeCalls).toHaveLength(2);
  });

  it("is a rejected request, not a no-op, for an addon that cannot take a selection", async () => {
    const { createBindingFromAddon } = await import("../src/runtime/node.js");
    const binding = createBindingFromAddon({
      version: () => VERSION,
      defaultPolicy: () => "redact",
      compareActionPolicies: () => {
        throw new Error("unused");
      },
      profile: () => "full",
      initialize: () => {},
      initializePii: () => {},
      scan: () => [],
      redact: (input) => input,
      scanAndRedact: (input) => ({ findings: [], redacted: input }),
      createIncrementalSanitizer: () => {
        throw new Error("unused");
      },
    });
    expect(() => binding.initialize([], '{"include":["jwt"]}')).toThrowError(
      expect.objectContaining({ code: "INVALID_DETECTION_CONFIG" }),
    );
    // Without a selection the legacy path is untouched.
    expect(() => binding.initialize([])).not.toThrow();
  });
});

describe("detection is never a per-call argument", () => {
  it("rejects a detection key on every call surface instead of ignoring it", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    const before = [...double.binding.calls];
    const attempts: Array<() => unknown> = [
      () => runtime.scan("SYNTHETIC_REVOKED_VALUE", { detection: { include: ["jwt"] } } as never),
      () => runtime.scan("SYNTHETIC_REVOKED_VALUE", { detection: undefined } as never),
      () => runtime.scanAndRedact("SYNTHETIC_REVOKED_VALUE", { detection: {} } as never),
      () => runtime.redact("SYNTHETIC_REVOKED_VALUE", [], { detection: {} } as never),
      () =>
        runtime.createIncrementalSanitizer({
          limits: { maxInputBytes: 1024, maxBufferedBytes: 384, maxTokenBytes: 128, maxMultilineBytes: 256 },
          detection: {},
        } as never),
      () => runtime.compareActionPolicies("x", { policies: [{ kind: "default" }], detection: {} } as never),
    ];
    for (const attempt of attempts) {
      expect(attempt).toThrowError(expect.objectContaining({ code: "INVALID_OPTIONS" }));
    }
    expect(double.binding.calls).toEqual(before);
  });

  it("leaves a call without the key exactly as before", async () => {
    const double = recorded();
    const runtime = await initialized(double);
    expect(runtime.scan("SYNTHETIC_REVOKED_VALUE", {})).toEqual([]);
    expect(runtime.scan("SYNTHETIC_REVOKED_VALUE")).toEqual([]);
    expect(runtime.scanAndRedact("SYNTHETIC_REVOKED_VALUE", {}).text).toBe("<SECRET_1>");
  });
});
