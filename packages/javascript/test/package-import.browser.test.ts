import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** The artifacts a browser build resolves lazily, at `initialize()` time. */
const EXTERNAL_ARTIFACTS = ["@redact-secret/wasm", "@redact-secret/wasm/common"];

async function bundleForBrowser(contents: string): Promise<string> {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "browser",
    external: EXTERNAL_ARTIFACTS,
    stdin: {
      contents,
      loader: "js",
      resolveDir: PACKAGE_ROOT,
      sourcefile: "browser-consumer.js",
    },
    write: false,
  });

  expect(result.errors).toEqual([]);
  expect(result.outputFiles).toHaveLength(1);
  const output = result.outputFiles[0]?.text;
  expect(output).toBeDefined();
  return output ?? "";
}

describe("browser package import", () => {
  it("bundles and evaluates the package entry point", async () => {
    const output = await bundleForBrowser(
      [
        'import * as api from "@redact-secret/core";',
        "globalThis.secretScanExports = Object.keys(api).sort();",
        "globalThis.secretScanRangeUnit = api.RANGE_UNIT;",
      ].join("\n"),
    );

    await import(
      `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );
    const globals = globalThis as typeof globalThis & {
      secretScanExports?: readonly string[];
      secretScanRangeUnit?: string;
    };

    expect(globals.secretScanExports).toEqual([
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
    ]);
    expect(globals.secretScanRangeUnit).toBe("utf16-code-units");
  });

  it("bundles and evaluates the common-profile entry point", async () => {
    const output = await bundleForBrowser(
      [
        'import * as api from "@redact-secret/core/common";',
        "globalThis.secretScanCommonExports = Object.keys(api).sort();",
        "globalThis.secretScanCommonProfile = api.PROFILE;",
      ].join("\n"),
    );

    await import(
      `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );
    const globals = globalThis as typeof globalThis & {
      secretScanCommonExports?: readonly string[];
      secretScanCommonProfile?: string;
    };

    expect(globals.secretScanCommonExports).toEqual([
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
    ]);
    expect(globals.secretScanCommonProfile).toBe("common");
  });

  it("bundles the Web adapter without resolving a Node-only module", async () => {
    const output = await bundleForBrowser(
      [
        'import { createWebStreamSanitizer, WebStreamSanitizer } from "@redact-secret/core/web-stream";',
        "globalThis.secretScanWebStream = [",
        "  typeof createWebStreamSanitizer,",
        "  WebStreamSanitizer.prototype instanceof TransformStream,",
        "];",
      ].join("\n"),
    );

    await import(
      `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );
    const globals = globalThis as typeof globalThis & {
      secretScanWebStream?: readonly unknown[];
    };

    expect(globals.secretScanWebStream).toEqual(["function", true]);
    expect(output).not.toContain("node:stream");
    expect(output).not.toContain("require(");
  });

  it("bundles the common-profile Web adapter without the full runtime or its artifact", async () => {
    const output = await bundleForBrowser(
      [
        'import { createWebStreamSanitizer, WebStreamSanitizer } from "@redact-secret/core/common/web-stream";',
        "globalThis.secretScanCommonWebStream = [",
        "  typeof createWebStreamSanitizer,",
        "  WebStreamSanitizer.prototype instanceof TransformStream,",
        "];",
      ].join("\n"),
    );

    await import(
      `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );
    const globals = globalThis as typeof globalThis & {
      secretScanCommonWebStream?: readonly unknown[];
    };

    expect(globals.secretScanCommonWebStream).toEqual(["function", true]);
    expect(output).not.toContain("node:stream");
    expect(output).not.toContain("require(");
    // The issue #416 assertion: a `/common` browser bundle with streams
    // never references the `full` artifact specifier, only its own.
    expect(output).not.toContain('import("@redact-secret/wasm")');
  });

  it("refuses synchronous operations before initialize succeeds", async () => {
    const output = await bundleForBrowser(
      [
        'import { scan, SecretScanError } from "@redact-secret/core";',
        "try { scan('API_KEY=SYNTHETIC_REVOKED_VALUE'); }",
        "catch (error) {",
        "  globalThis.secretScanBrowserError = {",
        "    isSecretScanError: error instanceof SecretScanError,",
        "    code: error.code,",
        "    message: error.message,",
        "  };",
        "}",
      ].join("\n"),
    );

    await import(
      `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );

    expect(
      (globalThis as typeof globalThis & { secretScanBrowserError?: unknown })
        .secretScanBrowserError,
    ).toEqual({
      isSecretScanError: true,
      code: "NOT_INITIALIZED",
      message:
        "redact-secret is not initialized; await initialize() before this call.",
    });
  });
});
