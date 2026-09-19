import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));

const ROOT_CONSUMER =
  'import { initialize, scanAndRedact } from "@redact-secret/core"; globalThis.secretScanEntry = [initialize, scanAndRedact];';

const WEB_STREAM_CONSUMER =
  'import { createWebStreamSanitizer } from "@redact-secret/core/web-stream"; globalThis.secretScanEntry = [createWebStreamSanitizer];';

const COMMON_WEB_STREAM_CONSUMER =
  'import { createWebStreamSanitizer } from "@redact-secret/core/common/web-stream"; globalThis.secretScanEntry = [createWebStreamSanitizer];';

const COMMON_NODE_STREAM_CONSUMER =
  'import { createNodeStreamSanitizer } from "@redact-secret/core/common/node-stream"; globalThis.secretScanEntry = [createNodeStreamSanitizer];';

/**
 * The Node addon is one of eight `optionalDependencies`, selected at runtime
 * by `process.platform`/`process.arch` and, on Linux, detected libc
 * (`runtime/node.ts`), so unlike the
 * wasm glue below it is never a statically resolvable specifier for a
 * bundler to see — nothing here needs to mark it external.
 */
async function bundle(
  platform: "browser" | "node",
  contents: string = ROOT_CONSUMER,
  conditions?: readonly string[],
) {
  const result = await build({
    bundle: true,
    format: "esm",
    metafile: true,
    platform,
    ...(conditions === undefined ? {} : { conditions: [...conditions] }),
    external: [
      "@redact-secret/wasm",
      "@redact-secret/wasm/common",
      "@redact-secret/wasm/redact_secret_wasm_bg.wasm",
      "@redact-secret/wasm/redact_secret_wasm_common_bg.wasm",
    ],
    stdin: {
      contents,
      loader: "js",
      resolveDir: PACKAGE_ROOT,
      sourcefile: `${platform}-consumer.js`,
    },
    write: false,
  });

  expect(result.errors).toEqual([]);
  return {
    inputs: Object.keys(result.metafile.inputs),
    output: result.outputFiles[0]?.text ?? "",
  };
}

/** The exact esbuild resolve conditions `wrangler`'s bundler applies, per
 * `decision-add-node-wasm-fallback`'s own research and confirmed while
 * implementing `decision-verify-edge-runtimes` against a real `wrangler dev`
 * sandbox. */
const WORKERD_CONDITIONS = ["workerd", "worker", "browser", "import"];

describe("bundler conditions", () => {
  it("routes a browser build through the WebAssembly adapter only", async () => {
    const { inputs, output } = await bundle("browser");

    expect(inputs.some((path) => path.endsWith("dist/runtime/browser.js"))).toBe(
      true,
    );
    expect(inputs.some((path) => path.endsWith("dist/runtime/node.js"))).toBe(
      false,
    );
    expect(inputs.some((path) => path.startsWith("node:"))).toBe(false);
    expect(output).not.toContain("node:module");
    expect(output).not.toContain("createRequire");
  });

  it("routes a Node build through the N-API adapter only", async () => {
    const { inputs } = await bundle("node");

    expect(inputs.some((path) => path.endsWith("dist/runtime/node.js"))).toBe(
      true,
    );
    expect(inputs.some((path) => path.endsWith("dist/runtime/browser.js"))).toBe(
      false,
    );
  });

  it("does not statically inline the WebAssembly fallback into a Node build (decision-add-node-wasm-fallback)", async () => {
    const { output } = await bundle("node");

    // The fallback's `import()` specifier is a lookup into a map, not a
    // string literal at the call site, so a bundler that only follows
    // literal specifiers cannot discover or inline the browser-oriented
    // glue and `.wasm` binary here.
    expect(output).not.toContain('import("@redact-secret/wasm")');
    expect(output).not.toContain('import("@redact-secret/wasm/common")');
  });

  it("routes the Web adapter through the WebAssembly adapter only", async () => {
    const { inputs, output } = await bundle("browser", WEB_STREAM_CONSUMER);

    expect(
      inputs.some((path) => path.endsWith("dist/adapters/web-stream.js")),
    ).toBe(true);
    expect(inputs.some((path) => path.endsWith("dist/runtime/browser.js"))).toBe(
      true,
    );
    expect(inputs.some((path) => path.endsWith("dist/runtime/node.js"))).toBe(
      false,
    );
    expect(
      inputs.some((path) => path.endsWith("dist/adapters/node-stream.js")),
    ).toBe(false);
    expect(inputs.some((path) => path.startsWith("node:"))).toBe(false);
    expect(output).not.toContain("node:stream");
  });

  it("bundles the Node adapter for Node, and only there", async () => {
    const { inputs } = await bundle(
      "node",
      'import { createNodeStreamSanitizer } from "@redact-secret/core/node-stream"; globalThis.secretScanEntry = [createNodeStreamSanitizer];',
    );

    expect(
      inputs.some((path) => path.endsWith("dist/adapters/node-stream.js")),
    ).toBe(true);
    expect(inputs.some((path) => path.endsWith("dist/runtime/node.js"))).toBe(
      true,
    );
  });

  it("routes a /common Web adapter build through the common WebAssembly adapter only", async () => {
    const { inputs, output } = await bundle("browser", COMMON_WEB_STREAM_CONSUMER);

    expect(
      inputs.some((path) => path.endsWith("dist/adapters/web-stream-common.js")),
    ).toBe(true);
    expect(
      inputs.some((path) => path.endsWith("dist/adapters/web-stream-core.js")),
    ).toBe(true);
    expect(
      inputs.some((path) => path.endsWith("dist/runtime/browser-common.js")),
    ).toBe(true);
    // The whole point of a `/common` subpath: it never reaches the `full`
    // runtime loader or the root `@redact-secret/wasm` artifact specifier.
    expect(inputs.some((path) => path.endsWith("dist/runtime/browser.js"))).toBe(
      false,
    );
    expect(inputs.some((path) => path.endsWith("dist/adapters/web-stream.js"))).toBe(
      false,
    );
    expect(inputs.some((path) => path.startsWith("node:"))).toBe(false);
    expect(output).not.toContain('import("@redact-secret/wasm")');
    expect(output).toContain('import("@redact-secret/wasm/common")');
  });

  it("bundles the /common Node adapter for Node, through node-stream-common only", async () => {
    const { inputs } = await bundle("node", COMMON_NODE_STREAM_CONSUMER);

    expect(
      inputs.some((path) => path.endsWith("dist/adapters/node-stream-common.js")),
    ).toBe(true);
    expect(
      inputs.some((path) => path.endsWith("dist/adapters/node-stream-core.js")),
    ).toBe(true);
    expect(inputs.some((path) => path.endsWith("dist/runtime/node-common.js"))).toBe(
      true,
    );
    // Unlike the browser WASM artifacts, one compiled Node addon serves both
    // profiles (`runtime/node-common.ts` imports `runtime/node.ts` directly),
    // so `dist/runtime/node.js` legitimately appears here too; only the
    // adapter's own factory module differs by profile.
    expect(inputs.some((path) => path.endsWith("dist/adapters/node-stream.js"))).toBe(
      false,
    );
  });

  it("keeps the platform artifacts out of the module graph until initialize", async () => {
    const { output } = await bundle("browser");

    // The WebAssembly artifact is reached through a dynamic import, so a
    // bundle that never calls initialize() never loads it.
    expect(output).toContain('import("@redact-secret/wasm")');
  });

  it("routes a Cloudflare Workers build through the workerd adapter, not browser or node (decision-verify-edge-runtimes)", async () => {
    const { inputs, output } = await bundle(
      "browser",
      ROOT_CONSUMER,
      WORKERD_CONDITIONS,
    );

    expect(
      inputs.some((path) => path.endsWith("dist/runtime/workerd.js")),
    ).toBe(true);
    expect(inputs.some((path) => path.endsWith("dist/runtime/browser.js"))).toBe(
      false,
    );
    expect(inputs.some((path) => path.endsWith("dist/runtime/node.js"))).toBe(
      false,
    );
    // The `.wasm` binary is imported by its own literal specifier, the same
    // way the browser adapter's `@redact-secret/wasm` specifier stays
    // discoverable to a bundler.
    expect(output).toContain('"@redact-secret/wasm/redact_secret_wasm_bg.wasm"');
  });

  it("routes a /common Cloudflare Workers build through the workerd-common adapter only", async () => {
    const { inputs, output } = await bundle(
      "browser",
      COMMON_WEB_STREAM_CONSUMER,
      WORKERD_CONDITIONS,
    );

    expect(
      inputs.some((path) => path.endsWith("dist/runtime/workerd-common.js")),
    ).toBe(true);
    expect(
      inputs.some((path) => path.endsWith("dist/runtime/browser-common.js")),
    ).toBe(false);
    expect(
      inputs.some((path) => path.endsWith("dist/runtime/workerd.js")),
    ).toBe(false);
    expect(output).toContain(
      '"@redact-secret/wasm/redact_secret_wasm_common_bg.wasm"',
    );
  });
});
