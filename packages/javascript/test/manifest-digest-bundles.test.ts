import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const { bundleEntry } = (await import(
  fileURLToPath(new URL("../../../scripts/build-custom-artifact.mjs", import.meta.url))
)) as { bundleEntry(options: { distDir: string }): string };

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const dist = `${packageRoot}dist`;

async function bundle(contents: string, conditions: string[], alias?: Record<string, string>) {
  return build({
    stdin: { contents, resolveDir: packageRoot, loader: "js" },
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    conditions,
    external: ["node:*", "@redact-secret/wasm", "@redact-secret/wasm/*"],
    ...(alias === undefined ? {} : { alias }),
    metafile: true,
    plugins: [
      {
        name: "custom-glue-double",
        setup(api) {
          api.onResolve({ filter: /^\.\/redact_secret_wasm_custom\.js$/ }, (args) => ({
            path: args.path,
            external: true,
          }));
        },
      },
    ],
  });
}

function expectWeb(result: Awaited<ReturnType<typeof bundle>>) {
  const inputs = Object.keys(result.metafile?.inputs ?? {});
  expect(inputs.some((p) => p.endsWith("manifest-digest-web.js"))).toBe(true);
  expect(inputs.some((p) => p.endsWith("manifest-digest-node.js"))).toBe(false);
  expect(result.outputFiles?.[0]?.text).not.toContain("#manifest-digest");
  expect(result.outputFiles?.[0]?.text).not.toMatch(/(?:from|import\()\s*["']node:/);
}

describe("private digest condition routing", () => {
  it.each([["browser"], ["workerd"], ["workerd", "node"], []])("keeps %j on Web Crypto", async (...conditions) => {
    expectWeb(await bundle('export { getManifestDigest } from "#manifest-digest";', conditions));
  });

  it.each([["node"], ["browser", "node"]])(
    "selects Node hashing for %j with Node precedence outside workerd",
    async (...conditions) => {
      const result = await bundle('export { getManifestDigest } from "#manifest-digest";', conditions);
      expect(Object.keys(result.metafile?.inputs ?? {}).some((p) => p.endsWith("manifest-digest-node.js"))).toBe(true);
      expect(Object.keys(result.metafile?.inputs ?? {}).some((p) => p.endsWith("manifest-digest-web.js"))).toBe(false);
    },
  );

  it.each(["index", "common"])(
    "keeps browser %s consumers and their explicit native alias free of Node modules",
    async (entry) => {
      const common = entry === "common";
      expectWeb(
        await bundle(`export * from "./dist/${entry}.js";`, ["browser"], {
          [common ? "#native-common" : "#native"]: `${dist}/runtime/browser${common ? "-common" : ""}.js`,
        }),
      );
    },
  );

  it.each([
    { label: "neutral default", conditions: [] },
    { label: "browser", conditions: ["browser"] },
    { label: "workerd", conditions: ["workerd"] },
  ])("keeps directly bundled custom $label wrappers on Web Crypto", async ({ conditions }) => {
    expectWeb(await bundle(bundleEntry({ distDir: dist }), conditions));
  });
});
