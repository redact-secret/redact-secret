import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getManifestDigest as selectedDigest } from "#manifest-digest";

import { assertManifestDigest, canonicalJson, parseArtifactManifest } from "../src/manifest.js";
import { getManifestDigest as nodeDigest } from "../src/runtime/manifest-digest-node.js";
import { getManifestDigest as webDigest } from "../src/runtime/manifest-digest-web.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import { VERSION } from "../src/version.js";
import { createFakeBinding } from "./fake-binding.js";

vi.mock("#manifest-digest", () => ({ getManifestDigest: vi.fn() }));
vi.mock("node:module", async (original) => {
  const actual = await original<typeof import("node:module")>();
  return { ...actual, createRequire: vi.fn(actual.createRequire) };
});

const bytes = (text: string) => new TextEncoder().encode(text);
const fixture = JSON.parse(
  readFileSync(new URL("../../../conformance/fixtures/artifact-manifest-v1.json", import.meta.url), "utf8"),
) as { cases: Array<{ input: unknown; canonical: string; sha256: string }> };

function document(profile: "full" | "common" = "full") {
  const body = {
    schema: "artifact-manifest/v1",
    version: VERSION,
    artifact: { variant: profile },
    composition: { id: null, kind: "standard", profile },
    detectors: [],
  };
  const digest = `sha256:${createHash("sha256").update(canonicalJson(body)).digest("hex")}`;
  return JSON.stringify({ ...body, digest });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(selectedDigest).mockImplementation(nodeDigest);
});
afterEach(() => vi.unstubAllGlobals());

describe("private manifest digest providers", () => {
  it("acquires the Node provider without loading crypto, then hashes every canonical fixture", () => {
    const hash = nodeDigest();
    expect(nodeModule.createRequire).not.toHaveBeenCalled();
    for (const row of fixture.cases) {
      expect(canonicalJson(row.input)).toBe(row.canonical);
      expect(hash(bytes(row.canonical))).toBe(row.sha256);
    }
    expect(nodeModule.createRequire).toHaveBeenCalledTimes(fixture.cases.length);
  });

  it("keeps Web Crypto canonical digests identical", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const hash = webDigest();
    expect(hash).toBeTypeOf("function");
    for (const row of fixture.cases) expect(await hash?.(bytes(row.canonical))).toBe(row.sha256);
  });

  it("retains the Web provider's early no-subtle compatibility", async () => {
    vi.stubGlobal("crypto", undefined);
    expect(webDigest()).toBeUndefined();
    vi.mocked(selectedDigest).mockImplementation(webDigest);
    const manifest = parseArtifactManifest(document(), "full");
    await expect(assertManifestDigest(manifest)).resolves.toBeUndefined();
  });

  it.each(["full", "common"] as const)(
    "verifies and rejects tampering on Node %s without global crypto",
    async (profile) => {
      vi.stubGlobal("crypto", undefined);
      const text = document(profile);
      const binding = Object.assign(createFakeBinding({ profile }), { artifactManifest: () => text });
      const runtime = createRedactSecretRuntime(async () => binding, profile);
      await runtime.initialize();
      expect(runtime.status().initialized).toBe(true);

      const forged = Object.assign(createFakeBinding({ profile }), {
        artifactManifest: () => text.replace('"detectors":[]', '"detectors":[{"id":"synthetic"}]'),
      });
      const rejected = createRedactSecretRuntime(async () => forged, profile);
      await expect(rejected.initialize()).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
      expect(forged.calls).not.toContain("initialize");
      expect(rejected.status().initialized).toBe(false);
    },
  );

  it.each(["acquire", "sync", "async", "malformed"])(
    "fails closed on %s provider failure and permits a valid retry",
    async (failure) => {
      const marker = "SYNTHETIC_PROVIDER_FAILURE";
      const binding = Object.assign(createFakeBinding(), { artifactManifest: () => document() });
      const runtime = createRedactSecretRuntime(async () => binding, "full");
      vi.mocked(selectedDigest).mockImplementation(() => {
        if (failure === "acquire") throw new Error(marker);
        if (failure === "sync")
          return () => {
            throw new Error(marker);
          };
        if (failure === "async")
          return async () => {
            throw new Error(marker);
          };
        return () => marker;
      });
      const attempt = runtime.initialize();
      await expect(attempt).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
      await attempt.catch((error: Error) => expect(error.message).not.toContain(marker));
      expect(binding.calls).not.toContain("initialize");
      expect(runtime.status().initialized).toBe(false);
      vi.mocked(selectedDigest).mockImplementation(nodeDigest);
      await runtime.initialize();
      expect(runtime.status().initialized).toBe(true);
    },
  );

  it("captures the expected digest before an asynchronous provider can mutate it", async () => {
    const valid = parseArtifactManifest(document(), "full");
    const mutable = { ...valid, digest: `sha256:${"0".repeat(64)}` };
    vi.mocked(selectedDigest).mockReturnValue(async () => {
      mutable.digest = valid.digest;
      return valid.digest.slice("sha256:".length);
    });
    await expect(assertManifestDigest(mutable)).rejects.toMatchObject({ code: "INITIALIZATION_FAILED" });
  });

  it("maps a Web Crypto digest rejection to the same fixed error", async () => {
    vi.stubGlobal("crypto", {
      subtle: {
        digest: async () => {
          throw new Error("SYNTHETIC_WEB_FAILURE");
        },
      },
    });
    vi.mocked(selectedDigest).mockImplementation(webDigest);
    await expect(assertManifestDigest(parseArtifactManifest(document(), "full"))).rejects.toMatchObject({
      code: "INITIALIZATION_FAILED",
    });
  });
});
