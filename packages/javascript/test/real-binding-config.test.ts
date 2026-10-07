import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { describe, expect, it } from "vitest";

/**
 * Detector selection and configuration resolution against the real, built
 * artifacts (issue #1251): the N-API addon and the WebAssembly artifacts, both
 * profiles, through the compiled package.
 *
 * The Rust core owns the truth table, the snapshot and the ownership; this is
 * the proof that every shipped JavaScript surface reports what the core
 * decides, from the one shared fixture (`conformance/fixtures/runtime-config-v1.json`),
 * with no table of its own. Each scenario runs in its own Worker, so each one
 * starts from a fresh native owner (the registry, PII activation and detector
 * selection are thread-local) and may exercise the one-shot initialization.
 *
 * An artifact that has not been built (`bindings/node` addon, `npm run
 * wasm:build`, `npm run wasm:build:common`) is skipped, as the addon and the
 * WebAssembly artifact are not part of a source checkout. CI builds both.
 */

const ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const WORKER = fileURLToPath(new URL("./helpers/config-worker.mjs", import.meta.url));
const DIST = resolve(ROOT, "packages/javascript/dist/runtime.js");

type Artifact = "addon" | "wasm";
type Profile = "full" | "common";

function available(artifact: Artifact, profile: Profile): boolean {
  if (!existsSync(DIST)) return false;
  if (artifact === "addon") {
    const loader = resolve(ROOT, "bindings/node/index.js");
    const binaries = ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-arm64-gnu", "win32-x64-msvc"];
    return (
      existsSync(loader) &&
      binaries.some((name) => existsSync(resolve(ROOT, `bindings/node/redact-secret.${name}.node`)))
    );
  }
  const [directory, name] =
    profile === "common" ? ["pkg-common", "redact_secret_wasm_common"] : ["pkg", "redact_secret_wasm"];
  return existsSync(resolve(ROOT, `bindings/wasm/${directory}/${name}_bg.wasm`));
}

function scenario<T = Record<string, unknown>>(artifact: Artifact, profile: Profile, name: string): Promise<T> {
  return new Promise((resolvePromise, reject) => {
    const worker = new Worker(WORKER, { workerData: { artifact, profile, scenario: name, root: ROOT } });
    worker.once("message", (message: { ok: boolean; result?: T; error?: string }) => {
      void worker.terminate();
      if (message.ok) resolvePromise(message.result as T);
      else reject(new Error(message.error));
    });
    worker.once("error", reject);
  });
}

const SURFACES: ReadonlyArray<[Artifact, Profile]> = [
  ["addon", "full"],
  ["addon", "common"],
  ["wasm", "full"],
  ["wasm", "common"],
];

for (const [artifact, profile] of SURFACES) {
  describe.skipIf(!available(artifact, profile))(`${artifact} ${profile}: configuration`, () => {
    it("runs the shared truth table and agrees with the manifest it reports", async () => {
      const result = await scenario<{ ran: number; failures: string[] }>(artifact, profile, "fixture");
      expect(result.failures).toEqual([]);
      expect(result.ran).toBeGreaterThanOrEqual(30);
    });

    it("compares configurations from the shared cases, with nothing but safe metadata in the result", async () => {
      const result = await scenario<{ ran: number; failures: string[]; leaks: string[] }>(artifact, profile, "compare");
      expect(result.failures).toEqual([]);
      expect(result.leaks).toEqual([]);
      expect(result.ran).toBeGreaterThanOrEqual(profile === "full" ? 13 : 11);
    });

    it("keeps a comparison independent of the owner, discloses callbacks and refuses malformed calls", async () => {
      const result = await scenario<Record<string, unknown>>(artifact, profile, "compareContract");
      // Independent passes: the baseline finds the provider token the owner's narrow selection cannot.
      if (profile === "full") expect(result.wideDetectors).toEqual(["github-token"]);
      expect(result.narrowDetectors).not.toContain("github-token");
      expect(result.ownerUnchanged).toBe(true);
      expect(result.preview).toEqual(["preview", false, "input", "configuration-comparison/v1", "utf16-code-units"]);
      expect(result.noCallbacks).toEqual([]);
      // A callback is called once per finding of each scanned side, side by side; the failed
      // third side (nothing enabled) never calls it.
      expect(result.callbackLog).toEqual(["jwt#0", "jwt#0"]);
      expect(result.callbackSides).toEqual([0, 1, 2]);
      expect(result.callbackKinds).toEqual([
        ["callback", null],
        ["callback", null],
        ["callback", null],
      ]);
      expect(result.callbackStatus).toEqual(["scanned", "scanned", "error"]);
      expect(result.callbackActions).toEqual([["warn"], ["warn"], []]);
      expect(result.throwing).toBe("POLICY_FAILURE");
      expect(result.badAction).toBe("INVALID_POLICY_ACTION");
      expect(result.badDocument).toBe("INVALID_ACTION_POLICY");
      expect(result.badDocumentWithCallback).toBe("INVALID_OPTIONS");
      expect(result.callbackCallsAfterRejection).toBe(0);
      for (const key of ["zero", "five", "unknownKey", "notObject", "notArray", "missing"]) {
        expect(result[key], key).toBe("INVALID_OPTIONS");
      }
      expect(result.notString).toBe("INVALID_INPUT");
      // PII an artifact without the PII runtime cannot build is an unsupported side, never ignored.
      expect(result.pii).toEqual(
        artifact === "wasm"
          ? ["unsupported", "PII_SELECTOR_UNAVAILABLE", true, "scanned", [], null, false]
          : ["scanned", null, false, "scanned", ["pii-domain"], ["added"], false],
      );
      // The shared policy applies to a side without its own; a side's own replaces it.
      expect(result.shared).toEqual([["allow"], ["redact"]]);
      expect(result.sharedDigests).toEqual([true, true]);
      expect(result.sharedDigestsDiffer).toBe(true);
    });

    it("leaves a legacy initialize untouched: every included detector, default origin, one digest", async () => {
      const result = await scenario<{
        mode: string;
        enabledCount: number;
        compiledCount: number;
        manifestDetectors: number;
        origins: string;
        keyed: string[];
        sessionText: string;
        status: { initialized: boolean; configuration: string | null };
        digestIsStatus: boolean;
      }>(artifact, profile, "legacy");
      expect(result.mode).toBe("all-included");
      expect(result.enabledCount).toBe(result.manifestDetectors);
      expect(result.compiledCount).toBe(result.manifestDetectors);
      expect(result.origins).toBe("artifact-default");
      expect(result.status.initialized).toBe(true);
      expect(result.status.configuration).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(result.digestIsStatus).toBe(true);
      // The standard behavior, as before: the provider token is found on
      // `full`, and the placeholder replaces the same span in a session.
      if (profile === "full") expect(result.keyed).toEqual(["github-token"]);
      expect(result.sessionText.startsWith("API_KEY=")).toBe(true);
      if (profile === "full") expect(result.sessionText).toBe("API_KEY=<SECRET_1>");
    });

    it("fixes the owner's selection, applies it everywhere, and refuses every change", async () => {
      const result = await scenario<{
        enabled: string[];
        disabledCount: number;
        mode: string;
        origin: string;
        overlap: boolean;
        keyed: string[];
        scanWithRuleset: string[];
        sessionText: string;
        frozen: boolean;
        idempotent: string;
        conflicts: string[];
        previewMode: string;
        previewEnabledCount: number;
        unchanged: boolean;
        keyedAfter: string[];
        perCall: string;
      }>(artifact, profile, "owner");
      // Canonical order, and the caller's later mutation of its array changed nothing.
      expect(result.enabled).toEqual(["private-key", "jwt"]);
      expect(result.mode).toBe("include");
      expect(result.origin).toBe("runtime");
      expect(result.disabledCount).toBeGreaterThan(0);
      expect(result.overlap).toBe(true);
      expect(result.frozen).toBe(true);
      // The provider detector is off, so it finds nothing here: scan, the
      // cached ruleset path and a session all use the owner's selection.
      expect(result.keyed).not.toContain("github-token");
      expect(result.scanWithRuleset).not.toContain("github-token");
      expect(result.sessionText).toBe("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000");
      expect(result.idempotent).toBe("ok");
      expect(result.conflicts).toEqual([
        "DETECTION_CONFIG_CONFLICT",
        "DETECTION_CONFIG_CONFLICT",
        "DETECTION_CONFIG_CONFLICT",
        "DETECTION_CONFIG_CONFLICT",
      ]);
      // A preview resolves another selection without touching the owner.
      expect(result.previewMode).toBe("exclude");
      expect(result.previewEnabledCount).toBeGreaterThan(0);
      expect(result.unchanged).toBe(true);
      expect(result.keyedAfter).toEqual(result.keyed);
      expect(result.perCall).toBe("INVALID_OPTIONS");
    });

    it("rejects every bad selection with a fixed code, caches nothing, and still takes a valid one", async () => {
      const result = await scenario<Record<string, unknown>>(artifact, profile, "rejected");
      expect(result.unknown).toBe("INVALID_DETECTION_CONFIG");
      expect(result.duplicate).toBe("INVALID_DETECTION_CONFIG");
      expect(result.conflict).toBe("INVALID_DETECTION_CONFIG");
      expect(result.family).toBe("INVALID_DETECTION_CONFIG");
      expect(result.adapter).toBe("INVALID_DETECTION_CONFIG");
      expect(result.empty).toBe("EMPTY_DETECTION_SET");
      if (profile === "common") expect(result.notIncluded).toBe("INVALID_DETECTION_CONFIG");
      for (const key of Object.keys(result).filter((name) => name.endsWith("Initialized"))) {
        expect(result[key], key).toBe(false);
      }
      expect(result.valid).toBe("ok");
      expect(result.enabled).toEqual(["jwt"]);
    });
  });
}

describe("built artifacts", () => {
  it("are reported, so a skipped suite is visible rather than silent", () => {
    const present = SURFACES.filter(([artifact, profile]) => available(artifact, profile)).map(
      ([artifact, profile]) => `${artifact}:${profile}`,
    );
    expect(Array.isArray(present)).toBe(true);
    if (process.env.REDACT_SECRET_REQUIRE_BUILT_ARTIFACTS === "1") {
      expect(present).toEqual(SURFACES.map(([artifact, profile]) => `${artifact}:${profile}`));
    }
  });
});
