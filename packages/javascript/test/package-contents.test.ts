import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const REPOSITORY_ROOT = join(PACKAGE_ROOT, "..", "..");

interface PackFile {
  readonly path: string;
}

interface PackResult {
  readonly name: string;
  readonly version: string;
  readonly files: readonly PackFile[];
}

/**
 * Packs `packages/javascript` itself: whatever `npm pack` would publish from
 * this exact directory, with nothing pre-populated. `LICENSE` and `dist` must
 * already be real, tracked or built files here for either to appear below.
 */
function pack(): PackResult {
  const output = execFileSync(
    process.platform === "win32" ? "npm.cmd" : "npm",
    ["pack", "--dry-run", "--json"],
    { cwd: PACKAGE_ROOT, encoding: "utf8" },
  );
  const [result] = JSON.parse(output) as PackResult[];
  if (result === undefined) throw new Error("npm pack produced no result");
  return result;
}

describe("package contents", () => {
  it("publishes the runtime, the declarations, and the documentation", () => {
    const result = pack();
    const paths = result.files.map(({ path }) => path);

    expect(result.name).toBe("@redact-secret/core");
    expect(paths).toContain("package.json");
    expect(paths).toContain("README.md");
    expect(paths).toContain("LICENSE");
    expect(paths).toContain("dist/index.js");
    expect(paths).toContain("dist/index.d.ts");
    expect(paths).toContain("dist/common.js");
    expect(paths).toContain("dist/common.d.ts");
    expect(paths).toContain("dist/runtime/node.js");
    expect(paths).toContain("dist/runtime/browser.js");
    expect(paths).toContain("dist/runtime/node-common.js");
    expect(paths).toContain("dist/runtime/browser-common.js");
    expect(paths).toContain("dist/adapters/node-stream.js");
    expect(paths).toContain("dist/adapters/node-stream.d.ts");
    expect(paths).toContain("dist/adapters/web-stream.js");
    expect(paths).toContain("dist/adapters/web-stream.d.ts");
    expect(paths).toContain("dist/adapters/node-stream-common.js");
    expect(paths).toContain("dist/adapters/node-stream-common.d.ts");
    expect(paths).toContain("dist/adapters/web-stream-common.js");
    expect(paths).toContain("dist/adapters/web-stream-common.d.ts");
  });

  it("publishes nothing from the repository around it", () => {
    const paths = pack().files.map(({ path }) => path);

    for (const prefix of [
      "src/",
      "test/",
      "crates/",
      "bindings/",
      "conformance/",
      ".github/",
      "_notes/",
    ]) {
      expect(paths.some((path) => path.startsWith(prefix))).toBe(false);
    }
    expect(paths.some((path) => path.endsWith(".map"))).toBe(false);
    expect(paths.some((path) => path.endsWith("tsconfig.json"))).toBe(false);
  });

  it("carries the shared product version in every place that states it", () => {
    const result = pack();
    const workspaceManifest = JSON.parse(
      readFileSync(join(REPOSITORY_ROOT, "package.json"), "utf8"),
    ) as { version: string };
    const declaredVersion = readFileSync(
      join(PACKAGE_ROOT, "dist", "version.js"),
      "utf8",
    );

    expect(result.version).toBe(workspaceManifest.version);
    expect(declaredVersion).toContain(`"${workspaceManifest.version}"`);
  });

  it("exposes the reviewed public subpaths and no internal ones", () => {
    const manifest = JSON.parse(
      readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"),
    ) as { exports: Record<string, unknown>; imports: Record<string, unknown> };

    // The root API, its `common`-profile sibling, plus the two stream
    // adapters and their `common`-profile counterparts. Each adapter is its
    // own subpath so that resolving the Web one never reaches `node:stream`.
    expect(Object.keys(manifest.exports).sort()).toEqual([
      ".",
      "./common",
      "./common/node-stream",
      "./common/web-stream",
      "./node-stream",
      "./package.json",
      "./web-stream",
    ]);
    // `#native`/`#native-common` are subpath *imports*: how this package
    // selects its own runtime adapter for each profile, and are not
    // reachable from outside.
    expect(Object.keys(manifest.imports).sort()).toEqual([
      "#native",
      "#native-common",
    ]);
  });

  it("keeps the Web adapter free of Node-only modules", () => {
    for (const file of [
      "web-stream.js",
      "web-stream.d.ts",
      "web-stream-core.js",
      "web-stream-core.d.ts",
      "web-stream-common.js",
      "web-stream-common.d.ts",
      "shared.js",
      "shared.d.ts",
    ]) {
      const source = readFileSync(
        join(PACKAGE_ROOT, "dist", "adapters", file),
        "utf8",
      );

      expect(source, file).not.toMatch(/from\s+["']node:/);
    }
  });

  it("keeps implementation details out of the published declarations", () => {
    const declarations =
      readFileSync(join(PACKAGE_ROOT, "dist", "index.d.ts"), "utf8") +
      readFileSync(join(PACKAGE_ROOT, "dist", "common.d.ts"), "utf8");

    for (const internal of [
      "#native",
      "#native-common",
      "NATIVE_HANDLE",
      "NativeBinding",
      "createRedactSecretRuntime",
      "INCREMENTAL_LOOKAROUND",
      "SecretDetector",
      "DetectorRegistry",
    ]) {
      expect(declarations).not.toContain(internal);
    }
  });
});
