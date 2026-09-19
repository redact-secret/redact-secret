/**
 * Qualifies the browser WebAssembly artifact in a real engine.
 *
 * The artifact is served over HTTP from a temporary directory — with
 * `application/wasm` on the binary, which streaming instantiation requires —
 * and two pages run in each engine against that one artifact. Nothing is
 * stubbed; the engine fetches and instantiates the same `.wasm` a consumer
 * would.
 *
 * `scripts/browser-harness.mjs` drives the artifact through its own exports:
 * the lifecycle gate, the canonical conformance corpus, the UTF-16 range
 * conversion, redaction, and the sanitized error contract
 * (`decision-govern-cross-language-conformance`).
 * `scripts/browser-package-harness.mjs`, bundled the way a consumer bundles
 * it, drives the published `@redact-secret/core` public API — including the
 * Web `TransformStream` adapter's byte-partition, Unicode, malformed-input,
 * backpressure, cancellation, and error-propagation behavior — on top of the
 * same artifact.
 *
 * Chromium, Firefox, and WebKit are the supported engines, declared in
 * `[workspace.metadata.redact-secret] browser-engines`, and
 * `scripts/check-artifact-matrix.py` keeps this list and the workflow
 * matrix in agreement. Usage:
 *
 *     node scripts/qualify-browser-artifact.mjs --engine chromium
 *     node scripts/qualify-browser-artifact.mjs            # every engine
 *
 * `--artifact-dir` (also accepted as `--wasm-dir`) points at a build other
 * than the default `bindings/wasm/pkg`.
 *
 * `--detector-profile common` qualifies the `common` artifact
 * (`npm run wasm:build:common`, default directory `bindings/wasm/pkg-common`)
 * instead (`decision-define-detector-profile-and-pack-contract`): both pages
 * run against the reviewed
 * `conformance/fixtures/common-profile-expectations.json`. The artifact page
 * must report the `common` profile and only `common` detector ids; the
 * package page drives the opt-in `@redact-secret/core/common` entry
 * (`scripts/browser-package-harness-common.mjs`) on the same artifact,
 * instead of the default entry the `full` package page drives.
 *
 * Every corpus input is synthetic or explicitly revoked, and no diagnostic
 * this script prints carries an input, a matched value, or a placeholder.
 */

import { createServer } from "node:http";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { fullDetectorIds } from "./lib/full-detector-ids.mjs";
import { DETECTOR_PROFILES as WASM_PROFILES } from "./lib/detector-profiles.mjs";

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPTS_DIR, "..");
const FIXTURES_DIR = join(REPO_ROOT, "conformance", "fixtures");
/**
 * This script's own view of `./lib/detector-profiles.mjs`'s shared table:
 * the glue and binary the page loads, and the default build directory,
 * resolved to an absolute path. Both profiles serve every page in `PAGES` —
 * there is no per-profile page selection.
 */
const DETECTOR_PROFILES = Object.fromEntries(
  Object.entries(WASM_PROFILES).map(([key, wasmProfile]) => [
    key,
    {
      glue: wasmProfile.glue,
      binary: wasmProfile.binary,
      defaultArtifactDir: join(REPO_ROOT, wasmProfile.relativeDir),
      buildCommand: wasmProfile.buildCommand,
    },
  ]),
);
const COMMON_EXPECTATIONS = "common-profile-expectations.json";
const PACKAGE_ENTRY = join(REPO_ROOT, "packages", "javascript", "dist", "index.js");
const PACKAGE_COMMON_ENTRY = join(REPO_ROOT, "packages", "javascript", "dist", "common.js");
const PACKAGE_WEB_STREAM_ENTRY = join(
  REPO_ROOT,
  "packages",
  "javascript",
  "dist",
  "adapters",
  "web-stream.js",
);

/** The engines this artifact is qualified in, in the order they run. */
const ENGINES = ["chromium", "firefox", "webkit"];


const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};

/**
 * The two pages each engine loads, in order: the artifact through its own
 * exports, then the published package on top of the same artifact. They run
 * in separate pages because each drives a fresh module instance through the
 * same one-time initialization gate.
 */
const PAGES = [
  { name: "artifact", file: "artifact.html", module: "./browser-harness.mjs" },
  { name: "package", file: "package.html", module: "./package-harness.js" },
];

function renderPage(module) {
  return `<!doctype html>
<meta charset="utf-8">
<title>redact-secret browser qualification</title>
<script type="module">
  import { qualify } from "${module}";
  const fixtures = await (await fetch("./fixtures.json")).json();
  try {
    globalThis.__qualification = await qualify(fixtures);
  } catch (error) {
    globalThis.__qualification = {
      ok: false,
      failures: 1,
      checks: [{ name: "harness", ok: false, detail: String(error) }],
    };
  }
</script>
`;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { engines: [], artifactDir: undefined, detectorProfile: "full" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--engine") {
      index += 1;
      const value = argv[index];
      if (value === undefined || !ENGINES.includes(value)) {
        fail(`--engine must be one of ${ENGINES.join(", ")}`);
      }
      options.engines.push(value);
    } else if (argument === "--artifact-dir" || argument === "--wasm-dir") {
      index += 1;
      const value = argv[index];
      if (value === undefined) fail(`${argument} requires a directory`);
      options.artifactDir = resolve(REPO_ROOT, value);
    } else if (argument === "--detector-profile") {
      index += 1;
      const value = argv[index];
      if (!Object.hasOwn(DETECTOR_PROFILES, value ?? "")) {
        fail(`--detector-profile must be one of ${Object.keys(DETECTOR_PROFILES).join(", ")}`);
      }
      options.detectorProfile = value;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  if (options.engines.length === 0) options.engines = [...ENGINES];
  options.artifactDir ??= DETECTOR_PROFILES[options.detectorProfile].defaultArtifactDir;
  return options;
}

function loadCorpus(name) {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, name), "utf8"));
}

/**
 * The fixture payload the page fetches: the canonical corpora reduced to the
 * fields the harness asserts on, plus the version, profile, and detector ids
 * the artifact must report. For `common`, each expectation is replaced by
 * its reviewed `common` expectation, matched by fixture id.
 */
function buildFixtures(detectorProfile) {
  const synchronous = loadCorpus("synchronous-corpus.json");
  if (synchronous.offsetUnit !== "utf8-byte") {
    fail(
      `synchronous-corpus.json: offsetUnit is ${synchronous.offsetUnit}, not utf8-byte`,
    );
  }
  // "not-yet-evaluated" fixtures carry no expectation and document a
  // future gap, not a current behavioral contract.
  let fixtures = synchronous.fixtures
    .filter((fixture) => fixture.support !== "not-yet-evaluated")
    .map(({ id, input, expected }) => ({ id, input, expected }));
  let detectors = fullDetectorIds();

  if (detectorProfile === "common") {
    const common = loadCorpus(COMMON_EXPECTATIONS);
    if (common.profile !== "common" || common.offsetUnit !== "utf8-byte") {
      fail(`${COMMON_EXPECTATIONS}: not a utf8-byte common expectation set`);
    }
    const expectations = new Map(common.fixtures.map(({ id, expected }) => [id, expected]));
    if (expectations.size !== fixtures.length) {
      fail(
        `${COMMON_EXPECTATIONS} covers ${expectations.size} fixtures, the corpus ` +
          `evaluates ${fixtures.length}; regenerate it (see its Rust test)`,
      );
    }
    fixtures = fixtures.map((fixture) => {
      const expected = expectations.get(fixture.id);
      if (expected === undefined) fail(`${COMMON_EXPECTATIONS}: no entry for ${fixture.id}`);
      return { ...fixture, expected };
    });
    detectors = common.detectors;
  }

  return {
    version: JSON.parse(
      readFileSync(join(REPO_ROOT, "packages/javascript/package.json"), "utf8"),
    ).version,
    profile: detectorProfile,
    detectors,
    synchronous: fixtures,
  };
}

/**
 * Bundles the package harness for the browser.
 *
 * The package resolves its runtime through its own `imports` map, so the
 * `browser` condition has to be the one a bundler applies — that is what
 * selects `dist/runtime/browser.js` (or, for `common`,
 * `dist/runtime/browser-common.js`) over the Node adapter — and the artifact
 * specifier is aliased to the glue being served, so the bundle loads the same
 * `.wasm` the artifact page does. `import.meta.url` inside the generated glue
 * survives bundling, and the output sits beside the binary, so the module's
 * own `default()` fetches it exactly as a deployed consumer would.
 *
 * `common` bundles a different entry point (`browser-package-harness-common.mjs`,
 * importing `@redact-secret/core/common`) and aliases the `/common` specifiers
 * instead of the root ones, so the bundle never pulls in the `full` package
 * entry or the `full` `.wasm`.
 */
async function bundlePackageHarness(artifactDir, outFile, detectorProfile) {
  const { build } = await import("esbuild");
  const glue = DETECTOR_PROFILES[detectorProfile].glue;
  const entry =
    detectorProfile === "common"
      ? join(SCRIPTS_DIR, "browser-package-harness-common.mjs")
      : join(SCRIPTS_DIR, "browser-package-harness.mjs");
  const alias =
    detectorProfile === "common"
      ? {
          // No `@redact-secret/core/web-stream` alias: the common harness
          // does not import it (see its own module comment — that adapter
          // is not profile-aware yet).
          "@redact-secret/core/common": PACKAGE_COMMON_ENTRY,
          "@redact-secret/wasm/common": join(artifactDir, glue),
        }
      : {
          "@redact-secret/core": PACKAGE_ENTRY,
          "@redact-secret/core/web-stream": PACKAGE_WEB_STREAM_ENTRY,
          "@redact-secret/wasm": join(artifactDir, glue),
        };
  const result = await build({
    entryPoints: [entry],
    outfile: outFile,
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["browser", "import"],
    alias,
    logLevel: "silent",
  });
  if (result.errors.length > 0) {
    fail(`bundling the package harness failed: ${JSON.stringify(result.errors)}`);
  }
}

async function stageServeDirectory(artifactDir, detectorProfile, pages) {
  const profile = DETECTOR_PROFILES[detectorProfile];
  const requiredEntries =
    detectorProfile === "common"
      ? [PACKAGE_COMMON_ENTRY]
      : [PACKAGE_ENTRY, PACKAGE_WEB_STREAM_ENTRY];
  for (const entry of requiredEntries) {
    if (!existsSync(entry)) {
      fail(`${entry}: missing; build the package with \`npm run js:build\``);
    }
  }
  const directory = mkdtempSync(join(tmpdir(), "redact-secret-browser-"));
  for (const name of [profile.glue, profile.binary]) {
    try {
      copyFileSync(join(artifactDir, name), join(directory, name));
    } catch {
      rmSync(directory, { recursive: true, force: true });
      fail(
        `${join(artifactDir, name)}: missing; build it with ` +
          `\`${profile.buildCommand}\``,
      );
    }
  }
  writeFileSync(
    join(directory, "artifact.js"),
    `export * from "./${profile.glue}";\nexport { default } from "./${profile.glue}";\n`,
  );
  copyFileSync(
    join(SCRIPTS_DIR, "browser-harness.mjs"),
    join(directory, "browser-harness.mjs"),
  );
  await bundlePackageHarness(
    artifactDir,
    join(directory, "package-harness.js"),
    detectorProfile,
  );
  for (const { file, module } of pages) {
    writeFileSync(join(directory, file), renderPage(module));
  }
  writeFileSync(
    join(directory, "fixtures.json"),
    JSON.stringify(buildFixtures(detectorProfile)),
  );
  return directory;
}

async function serve(directory) {
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const name = path.slice(1);
    // Only the staged files are reachable: a name with a separator or a
    // parent reference never becomes a path.
    if (name.includes("/") || name.includes("\\") || name.includes("..")) {
      response.writeHead(404).end();
      return;
    }
    let body;
    try {
      body = readFileSync(join(directory, name));
    } catch {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      "content-type": CONTENT_TYPES[extname(name)] ?? "application/octet-stream",
      "content-length": String(body.byteLength),
    });
    response.end(body);
  });
  await new Promise((resolveListening) => {
    server.listen(0, "127.0.0.1", resolveListening);
  });
  const { port } = server.address();
  return { server, origin: `http://127.0.0.1:${port}` };
}

/**
 * Runs every page once in one engine. Each page gets its own tab, because
 * each drives a fresh module instance through the one-time initialization
 * gate its first check asserts.
 */
async function runEngine(playwright, engine, origin, pages) {
  const browser = await playwright[engine].launch();
  const runs = [];
  try {
    for (const { name, file } of pages) {
      const diagnostics = [];
      const tab = await browser.newPage();
      tab.on("pageerror", (error) => diagnostics.push(`pageerror: ${error.message}`));
      tab.on("console", (message) => {
        if (message.type() === "error") diagnostics.push(`console: ${message.text()}`);
      });
      await tab.goto(`${origin}/${file}`, { waitUntil: "load" });
      await tab.waitForFunction(
        () => globalThis.__qualification !== undefined,
        undefined,
        { timeout: 120_000 },
      );
      runs.push({
        page: name,
        report: await tab.evaluate(() => globalThis.__qualification),
        diagnostics,
      });
      await tab.close();
    }
  } finally {
    await browser.close();
  }
  return runs;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));

  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    fail(
      "playwright is not installed; run `npm ci` and " +
        "`npx playwright install --with-deps chromium firefox webkit`",
    );
    return;
  }

  const directory = await stageServeDirectory(
    options.artifactDir,
    options.detectorProfile,
    PAGES,
  );
  const { server, origin } = await serve(directory);
  let failed = 0;
  try {
    for (const engine of options.engines) {
      const started = Date.now();
      let runs;
      try {
        runs = await runEngine(playwright, engine, origin, PAGES);
      } catch (error) {
        failed += 1;
        console.error(`${engine}: FAILED to run — ${error.message}`);
        continue;
      }
      let passed = 0;
      let engineFailed = false;
      for (const { page: name, report, diagnostics } of runs) {
        for (const entry of report.checks) {
          console.log(
            `${entry.ok ? "ok" : "not ok"} - ${engine} · ${name} · ${entry.name}`,
          );
          if (!entry.ok) console.error(`    ${entry.detail}`);
        }
        for (const line of diagnostics) console.error(`    ${engine}: ${line}`);
        passed += report.checks.length;
        if (!report.ok) {
          engineFailed = true;
          console.error(`${engine} · ${name}: ${report.failures} check(s) FAILED`);
        }
      }
      const seconds = ((Date.now() - started) / 1000).toFixed(1);
      if (engineFailed) {
        failed += 1;
        console.error(`${engine}: FAILED\n`);
      } else {
        console.log(`${engine}: ${passed} check(s) passed in ${seconds}s\n`);
      }
    }
  } finally {
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }

  if (failed > 0) {
    console.error(`browser qualification FAILED in ${failed} engine(s)`);
    process.exit(1);
  }
  console.log(`browser qualification passed in ${options.engines.join(", ")}`);
}

await main();
