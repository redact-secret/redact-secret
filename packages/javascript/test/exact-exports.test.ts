import { describe, expect, it } from "vitest";

/**
 * The published runtime surface, in full.
 *
 * Adding a name here is a public API change; the list exists so that one
 * cannot happen by accident. Detector construction, registries, entropy
 * helpers, and every internal module are absent by design: built-in detectors
 * run in Rust and custom detector callbacks are not part of the first stable
 * API (`decision-define-runtime-bindings`).
 */
const PUBLIC_RUNTIME_EXPORTS = [
  "PROFILE",
  "RANGE_UNIT",
  "SecretScanError",
  "VERSION",
  "createIncrementalSanitizer",
  "defaultPlaceholderFormatter",
  "initialize",
  "redact",
  "scan",
  "scanAndRedact",
  "typedPlaceholderFormatter",
];

/**
 * Each stream adapter subpath, in full. Both re-export `SecretScanError` so a
 * consumer of one adapter can catch its failures without also importing the
 * root, and neither adds an error type of its own. The `common` counterparts
 * export the exact same names as their `full` sibling — only which runtime
 * `create*StreamSanitizer` opens differs.
 */
const PUBLIC_ADAPTER_EXPORTS = {
  "@redact-secret/core/node-stream": [
    "NodeStreamSanitizer",
    "SecretScanError",
    "createNodeStreamSanitizer",
  ],
  "@redact-secret/core/web-stream": [
    "SecretScanError",
    "WebStreamSanitizer",
    "createWebStreamSanitizer",
  ],
  "@redact-secret/core/common/node-stream": [
    "NodeStreamSanitizer",
    "SecretScanError",
    "createNodeStreamSanitizer",
  ],
  "@redact-secret/core/common/web-stream": [
    "SecretScanError",
    "WebStreamSanitizer",
    "createWebStreamSanitizer",
  ],
};

describe("exact exports", () => {
  it("exposes only the reviewed root runtime values", async () => {
    const publicApi = await import("@redact-secret/core");

    expect(Object.keys(publicApi).sort()).toEqual(PUBLIC_RUNTIME_EXPORTS);
  });

  it("states its range unit, its lockstep product version, and its profile", async () => {
    const { PROFILE, RANGE_UNIT, VERSION } = await import("@redact-secret/core");
    const manifest = await import("../package.json", { with: { type: "json" } });

    expect(RANGE_UNIT).toBe("utf16-code-units");
    expect(VERSION).toBe(manifest.default.version);
    expect(PROFILE).toBe("full");
  });

  it("exposes the same public shape from the common profile entry, differing only in PROFILE", async () => {
    const fullApi = await import("@redact-secret/core");
    const commonApi = await import("@redact-secret/core/common");

    expect(Object.keys(commonApi).sort()).toEqual(Object.keys(fullApi).sort());
    expect(commonApi.PROFILE).toBe("common");
    expect(fullApi.PROFILE).toBe("full");
  });

  it("exposes only the reviewed values on each stream adapter subpath", async () => {
    for (const [subpath, expected] of Object.entries(PUBLIC_ADAPTER_EXPORTS)) {
      const adapter = await import(subpath);

      expect(Object.keys(adapter).sort(), subpath).toEqual(expected);
    }
  });

  it("keeps every documented internal module unreachable", async () => {
    for (const subpath of [
      "@redact-secret/core/native",
      "@redact-secret/core/runtime",
      "@redact-secret/core/session",
      "@redact-secret/core/session-common",
      "@redact-secret/core/adapters/shared",
      "@redact-secret/core/adapters/node-stream-core",
      "@redact-secret/core/adapters/web-stream-core",
      "@redact-secret/core/dist/index.js",
      "@redact-secret/core/runtime/node",
      "@redact-secret/core/runtime/node-common",
      "@redact-secret/core/runtime/browser-common",
    ]) {
      await expect(import(subpath)).rejects.toThrowError(
        /is not exported|ERR_PACKAGE_PATH_NOT_EXPORTED|Cannot find/,
      );
    }
  });
});
