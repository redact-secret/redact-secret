import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { canonicalJson } from "../src/manifest.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import type { ArtifactManifest } from "../src/types.js";
import { VERSION } from "../src/version.js";
import { createFakeBinding } from "./fake-binding.js";

/**
 * The runtime side of `artifact-manifest/v1` (issue #1250). The Rust core
 * generates the document; the package only parses, checks and freezes it.
 * These tests use a recorded binding double that reports a hand-built,
 * contract-shaped document, plus the shared canonical-JSON fixture every
 * surface runs. There is deliberately no detector table here: the real
 * artifact's composition is checked by the Rust drift tests and by the
 * installed-artifact tests below when a built artifact is present.
 */

const FIXTURE = JSON.parse(
  readFileSync(new URL("../../../conformance/fixtures/artifact-manifest-v1.json", import.meta.url), "utf8"),
) as {
  manifest: { members: string[] };
  cases: Array<{ name: string; input: unknown; canonical: string; sha256: string }>;
};

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

/** A contract-shaped manifest for `variant`, with a correct digest unless told otherwise. */
function manifestText(
  options: {
    variant?: string;
    version?: string;
    schema?: string;
    digest?: string;
    extra?: Record<string, unknown>;
  } = {},
): string {
  const body: Record<string, unknown> = {
    artifact: { kind: "node-addon", pii: true, variant: options.variant ?? "full" },
    bounds: {
      actionPolicyBytes: 65_536,
      detectorIdsMax: 256,
      diagnosticsMax: 256,
      limits: { maxFindings: 50_000, maxInputBytes: 67_108_864 },
    },
    capabilities: {
      actionPolicy: { revisions: [1] },
      detectorSelection: false,
      incremental: true,
      ruleset: { revisions: [1] },
    },
    composition: { id: null, kind: "standard", profile: options.variant ?? "full" },
    defaults: {
      actionPolicy: "artifact-default",
      detection: "all-included",
      limits: "artifact-default",
      pii: { selectors: [] },
      schema: "build-defaults/v1",
    },
    detectors: [{ aliases: [], id: "jwt", pack: "common", types: ["jwt"] }],
    notIncluded: [],
    pii: { available: true, families: ["pii:global:email"] },
    product: "redact-secret",
    schema: options.schema ?? "artifact-manifest/v1",
    sourceRevision: null,
    typeVocabulary: {
      builtInTypes: "declared",
      complete: false,
      dynamicSources: ["custom-detector", "pii", "ruleset"],
    },
    version: options.version ?? VERSION,
    ...options.extra,
  };
  const digest = options.digest ?? `sha256:${sha256(canonicalJson(body))}`;
  // `schema` first, then the rest in bytewise order, as the core emits it.
  const { schema, ...rest } = canonicalDocument({ ...body, digest });
  return JSON.stringify({ schema, ...rest });
}

function canonicalDocument(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(canonicalJson(value)) as Record<string, unknown>;
}

function bindingReporting(text: string, profile: "full" | "common" = "full") {
  return Object.assign(createFakeBinding({ profile }), { artifactManifest: () => text });
}

describe("canonical JSON (shared fixture)", () => {
  it("renders every fixture case exactly and hashes it to the recorded digest", () => {
    expect(FIXTURE.cases.length).toBeGreaterThan(0);
    for (const fixtureCase of FIXTURE.cases) {
      expect(canonicalJson(fixtureCase.input), fixtureCase.name).toBe(fixtureCase.canonical);
      expect(sha256(canonicalJson(fixtureCase.input)), fixtureCase.name).toBe(fixtureCase.sha256);
    }
  });

  it("states the manifest member set the core emits", () => {
    const text = manifestText();
    expect(Object.keys(JSON.parse(text) as object)[0]).toBe("schema");
    expect(Object.keys(JSON.parse(text) as object).sort()).toEqual(FIXTURE.manifest.members);
  });
});

describe("artifactManifest()", () => {
  it("is refused before initialize and does not touch the binding", () => {
    const binding = bindingReporting(manifestText());
    const runtime = createRedactSecretRuntime(async () => binding, "full");

    expect(() => runtime.artifactManifest()).toThrowError(expect.objectContaining({ code: "NOT_INITIALIZED" }));
    expect(binding.calls).toEqual([]);
  });

  it("returns the loaded artifact's frozen manifest after initialize, without extra binding calls", async () => {
    const text = manifestText();
    const binding = bindingReporting(text);
    const runtime = createRedactSecretRuntime(async () => binding, "full");
    await runtime.initialize();
    const callsAfterInitialize = [...binding.calls];

    const manifest: ArtifactManifest = runtime.artifactManifest();

    expect(manifest).toEqual(JSON.parse(text));
    expect(manifest.schema).toBe("artifact-manifest/v1");
    expect(manifest.version).toBe(VERSION);
    expect(manifest.artifact.variant).toBe("full");
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest.detectors)).toBe(true);
    expect(Object.isFrozen(manifest.detectors[0])).toBe(true);
    expect(Object.isFrozen(manifest.pii.families)).toBe(true);
    expect(runtime.artifactManifest()).toBe(manifest);
    expect(binding.calls).toEqual(callsAfterInitialize);
    expect(runtime.status().initialized).toBe(true);
  });

  it("reads the manifest before the binding is initialized, so a bad one never activates anything", async () => {
    const binding = bindingReporting(manifestText({ version: "0.0.0-other" }));
    const runtime = createRedactSecretRuntime(async () => binding, "full");

    await expect(runtime.initialize({ pii: ["pii"] })).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
    expect(binding.calls).not.toContain("initialize");
    expect(runtime.status().initialized).toBe(false);
  });

  it("fails with the fixed initialization error for a missing manifest export", async () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding(), "full");
    await runtime.initialize();

    expect(() => runtime.artifactManifest()).toThrowError(
      expect.objectContaining({ name: "SecretScanError", code: "INITIALIZATION_FAILED" }),
    );
    // Absent is not fatal for the rest of the surface.
    expect(runtime.scan("SYNTHETIC_REVOKED_VALUE")).toEqual([]);
  });

  it("rejects a document of another schema, version, variant or digest, echoing none of it", async () => {
    const marker = "SYNTHETIC-DOCUMENT-CONTENT";
    const wrongDigest = `sha256:${"0".repeat(64)}`;
    const cases: Array<[string, string, "full" | "common"]> = [
      ["schema", manifestText({ schema: "artifact-manifest/v2" }), "full"],
      ["version", manifestText({ version: "9.9.9" }), "full"],
      ["variant", manifestText({ variant: "common" }), "full"],
      ["profile entry", manifestText({ variant: "full" }), "common"],
      ["digest value", manifestText({ digest: wrongDigest }), "full"],
      ["digest format", manifestText({ digest: marker }), "full"],
      [
        "content under a valid-looking digest",
        manifestText({ extra: { product: marker } }).replace(marker, `${marker}x`),
        "full",
      ],
      ["not json", marker, "full"],
      ["not an object", JSON.stringify([marker]), "full"],
    ];
    for (const [name, text, profile] of cases) {
      const runtime = createRedactSecretRuntime(async () => bindingReporting(text, profile), profile);
      const attempt = runtime.initialize();
      await expect(attempt, name).rejects.toBeInstanceOf(SecretScanError);
      await expect(attempt, name).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
      await attempt.catch((error: Error) => {
        expect(error.message).not.toContain(marker);
        expect(JSON.stringify(error)).not.toContain(marker);
      });
      expect(runtime.status().initialized, name).toBe(false);
    }
  });

  it("does not retry a successful load and keeps one manifest across equivalent initialize calls", async () => {
    let loads = 0;
    const binding = bindingReporting(manifestText());
    const runtime = createRedactSecretRuntime(async () => {
      loads += 1;
      return binding;
    }, "full");
    await Promise.all([runtime.initialize(), runtime.initialize()]);
    const first = runtime.artifactManifest();
    await runtime.initialize();

    expect(loads).toBe(1);
    expect(runtime.artifactManifest()).toBe(first);
  });
});

describe("a custom composition manifest (issue #1253)", () => {
  const CUSTOM_ID = `custom:${"a".repeat(64)}`;
  const custom = (composition: unknown = { id: CUSTOM_ID, kind: "custom", profile: "custom" }): string =>
    manifestText({ variant: "custom", extra: { composition } });

  it("is accepted by the custom wrapper only, with its composition identity", async () => {
    const runtime = createRedactSecretRuntime(async () => bindingReporting(custom(), "custom" as "full"), "custom");
    await runtime.initialize();
    expect(runtime.artifactManifest().artifact.variant).toBe("custom");
    expect(runtime.artifactManifest().composition).toEqual({ id: CUSTOM_ID, kind: "custom", profile: "custom" });
    expect(runtime.status().profile).toBe("custom");
  });

  it("is refused by the standard entry points, and a standard manifest by the custom wrapper", async () => {
    for (const profile of ["full", "common"] as const) {
      const runtime = createRedactSecretRuntime(async () => bindingReporting(custom(), profile), profile);
      await expect(runtime.initialize()).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
    }
    const standard = createRedactSecretRuntime(
      async () => bindingReporting(manifestText(), "custom" as "full"),
      "custom",
    );
    await expect(standard.initialize()).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
  });

  it("refuses a custom document without a well-formed composition identity or with the wrong kind", async () => {
    for (const composition of [
      { id: null, kind: "custom", profile: "custom" },
      { id: "custom:short", kind: "custom", profile: "custom" },
      { id: CUSTOM_ID, kind: "standard", profile: "custom" },
      { id: CUSTOM_ID, kind: "custom", profile: "full" },
      "custom",
    ]) {
      const runtime = createRedactSecretRuntime(
        async () => bindingReporting(custom(composition), "custom" as "full"),
        "custom",
      );
      await expect(runtime.initialize()).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
    }
  });
});
