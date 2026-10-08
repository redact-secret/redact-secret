import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

import { startWrangler, stopWrangler } from "../qualify-workerd-artifact.mjs";
import { REPO_ROOT } from "./candidate-install.mjs";
import { assertNoSecret, LIMITS, PROBES } from "./configuration-journeys.mjs";
import { copyRedactWasm } from "./esbuild-redact-wasm.mjs";

const COMPATIBILITY_DATE = "2026-10-01";
const PROBE_MODULE = fileURLToPath(new URL("./custom-runtime-probes.mjs", import.meta.url));

export function renderCustomRuntimeConsumer(expected, workers = false) {
  return [
    'import * as api from "./vendor/redact/index.js";',
    `import { qualifyCustomRuntime } from ${JSON.stringify(PROBE_MODULE)};`,
    ...(workers
      ? [
          'import { initSync } from "./vendor/redact/redact_secret_wasm_custom.js";',
          'import module from "./vendor/redact/redact_secret_wasm_custom_bg.wasm";',
          // Workers supplies a precompiled module. The generated glue caches it,
          // so the unmodified wrapper's initialize() never compiles fetched bytes.
          "initSync({ module });",
        ]
      : []),
    `const expected = ${JSON.stringify(expected)};`,
    workers
      ? "export default { async fetch() { return Response.json(await qualifyCustomRuntime(api, expected)); } };"
      : "window.__customRuntimeResult = qualifyCustomRuntime(api, expected);",
  ].join("\n");
}

async function listen(server) {
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((done) => server.close(done));
}

/** Runs the same vendored custom bytes in Chromium and local workerd. */
export async function qualifyCustomRuntimes({ project, row }) {
  const expected = {
    manifest: JSON.parse(row.manifest.manifestJson),
    enabled: row.defaults.enabled,
    scans: row.defaults.scans,
    probes: PROBES,
    limits: LIMITS,
    excluded: row.known.notIncluded[0],
  };
  assert(expected.excluded, "custom runtime ceiling control is vacuous");
  const outfile = join(project, "bundled", "custom-browser", "runtime.mjs");
  const entry = join(project, "custom-runtime-browser.mjs");
  await writeFile(entry, renderCustomRuntimeConsumer(expected));
  await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "esm",
    platform: "browser",
    plugins: [copyRedactWasm({ artifactDir: join(project, "vendor", "redact") })],
    logLevel: "error",
  });
  const server = createServer(async (request, response) => {
    const files = {
      "/runtime.mjs": ["runtime.mjs", "text/javascript"],
      "/redact_secret_wasm_custom_bg.wasm": ["redact_secret_wasm_custom_bg.wasm", "application/wasm"],
    };
    try {
      if (request.url === "/") {
        response.setHeader("Content-Type", "text/html");
        response.end('<script type="module" src="/runtime.mjs"></script>');
      } else if (Object.hasOwn(files, request.url)) {
        const [file, mime] = files[request.url];
        response.setHeader("Content-Type", mime);
        response.end(await readFile(join(project, "bundled", "custom-browser", file)));
      } else {
        response.statusCode = 404;
        response.end();
      }
    } catch {
      response.statusCode = 500;
      response.end();
    }
  });
  let browser;
  let chromium;
  try {
    const port = await listen(server);
    const playwright = await import("playwright");
    browser = await playwright.chromium.launch();
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${port}/`);
    await page.waitForFunction(() => window.__customRuntimeResult !== undefined, { timeout: 30_000 });
    chromium = await page.evaluate(() => window.__customRuntimeResult);
    assertNoSecret("custom/chromium", chromium);
    chromium = { ...chromium, runtime: "chromium", version: browser.version(), executed: true };
  } finally {
    await browser?.close();
    await close(server);
  }

  const lock = JSON.parse(await readFile(join(REPO_ROOT, "package-lock.json"), "utf8"));
  const wranglerBin =
    process.env.REDACT_SECRET_WRANGLER_BIN ?? join(REPO_ROOT, "node_modules/wrangler/bin/wrangler.js");
  const wrangler = JSON.parse(await readFile(resolve(wranglerBin, "../../package.json"), "utf8"));
  assert.equal(wrangler.version, lock.packages["node_modules/wrangler"].version, "Wrangler differs from lockfile");
  await writeFile(join(project, "worker.mjs"), renderCustomRuntimeConsumer(expected, true));
  await writeFile(
    join(project, "wrangler.toml"),
    `name = "redact-secret-custom-qualification"\nmain = "worker.mjs"\ncompatibility_date = "${COMPATIBILITY_DATE}"\n` +
      '\n[[rules]]\ntype = "CompiledWasm"\nglobs = ["**/*.wasm"]\nfallthrough = true\n',
  );
  const portProbe = createServer();
  const port = await listen(portProbe);
  await close(portProbe);
  const child = await startWrangler(project, port);
  let workerd;
  try {
    const response = await fetch(`http://127.0.0.1:${port}/`);
    assert(response.ok, "custom workerd checks failed");
    workerd = await response.json();
    assertNoSecret("custom/workerd", workerd);
    workerd = {
      ...workerd,
      runtime: "cloudflare-workers",
      wranglerVersion: wrangler.version,
      compatibilityDate: COMPATIBILITY_DATE,
      mode: "local workerd",
      executed: true,
    };
  } finally {
    await stopWrangler(child);
  }
  const identity = {
    manifestDigest: row.manifest.manifestDigest,
    compositionId: row.manifest.compositionId,
    binarySha256: row.binarySha256,
  };
  return { chromium: { ...chromium, ...identity }, workerd: { ...workerd, ...identity } };
}
