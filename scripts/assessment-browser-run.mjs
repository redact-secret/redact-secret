/**
 * Evaluates the real, installed `@redact-secret/core` package against the
 * real browser WebAssembly artifact, in a real engine, against
 * `assessment/fixtures/accuracy-corpus.json`, and emits a conforming
 * `AssessmentResult` for the `"browser-wasm"` surface, plus a Markdown
 * report.
 *
 * Structured the same way `scripts/qualify-browser-artifact.mjs` qualifies
 * the artifact: the artifact is served over HTTP from a temporary directory
 * (`application/wasm` on the binary, which streaming instantiation
 * requires) and `scripts/assessment-browser-harness.mjs`, bundled with the
 * published package aliased to the real artifact, runs in a real page.
 * Nothing is stubbed — the engine fetches and instantiates the same `.wasm`
 * a consumer would.
 *
 * This expects the package already built (`npm run js:build`) and the
 * artifact already built (`npm run wasm:build`); it does no building of its
 * own, so a missing artifact fails loudly rather than being silently worked
 * around.
 *
 * Usage:
 *
 *     node scripts/assessment-browser-run.mjs
 *     node scripts/assessment-browser-run.mjs --engine firefox
 *     node scripts/assessment-browser-run.mjs --json-out out/browser.json --markdown-out out/browser.md
 *
 * Every fixture in the corpus is synthetic or explicitly revoked, and
 * nothing this script prints or writes carries a fixture's `input` or a
 * matched value.
 */

import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAndEmitAccuracyResult, loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import {
  accuracyCorpusHash,
  gitCommit,
  hostCpu,
  hostOs,
  loadAccuracyCorpus,
  REPO_ROOT,
  readPackageVersion,
} from "./lib/assessment-provenance.mjs";

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const JS_PACKAGE_DIR = join(REPO_ROOT, "packages", "javascript");
const PACKAGE_ENTRY = join(JS_PACKAGE_DIR, "dist", "index.js");
const DEFAULT_ARTIFACT_DIR = join(REPO_ROOT, "bindings", "wasm", "pkg");
const WASM_PACKAGE_JSON = join(REPO_ROOT, "bindings", "wasm", "npm", "package.json");
const ARTIFACT_FILES = ["redact_secret_wasm.js", "redact_secret_wasm_bg.wasm"];
const ENGINES = ["chromium", "firefox", "webkit"];
const PROFILE_ID = "accuracy-corpus";

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = {
    engine: "chromium",
    artifactDir: DEFAULT_ARTIFACT_DIR,
    jsonOut: undefined,
    markdownOut: undefined,
    mismatchesOut: undefined,
    strict: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--engine") {
      const value = argv[(index += 1)];
      if (value === undefined || !ENGINES.includes(value)) {
        fail(`--engine must be one of ${ENGINES.join(", ")}`);
      }
      options.engine = value;
    } else if (argument === "--artifact-dir") {
      options.artifactDir = argv[(index += 1)];
    } else if (argument === "--json-out") {
      options.jsonOut = argv[(index += 1)];
    } else if (argument === "--markdown-out") {
      options.markdownOut = argv[(index += 1)];
    } else if (argument === "--mismatches-out") {
      options.mismatchesOut = argv[(index += 1)];
    } else if (argument === "--strict") {
      options.strict = true;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function renderPage() {
  return `<!doctype html>
<meta charset="utf-8">
<title>redact-secret accuracy assessment</title>
<script type="module">
  import { assess } from "./assessment-harness.js";
  const fixtures = await (await fetch("./fixtures.json")).json();
  try {
    globalThis.__assessment = { ok: true, ...(await assess(fixtures)) };
  } catch (error) {
    globalThis.__assessment = { ok: false, error: String(error) };
  }
</script>
`;
}

async function bundleHarness(artifactDir, outFile) {
  const { build } = await import("esbuild");
  const result = await build({
    entryPoints: [join(SCRIPTS_DIR, "assessment-browser-harness.mjs")],
    outfile: outFile,
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["browser", "import"],
    alias: {
      "@redact-secret/core": PACKAGE_ENTRY,
      "@redact-secret/wasm": join(artifactDir, "redact_secret_wasm.js"),
      // Named by the facade's PII-only dynamic import (#937); this PII-off
      // harness never fetches it.
      "@redact-secret/wasm/pii": join(artifactDir, "redact_secret_wasm_pii.js"),
    },
    logLevel: "silent",
  });
  if (result.errors.length > 0) {
    fail(`bundling the assessment harness failed: ${JSON.stringify(result.errors)}`);
  }
}

async function stageServeDirectory(artifactDir, fixtures) {
  if (!existsSync(PACKAGE_ENTRY)) {
    fail(`${PACKAGE_ENTRY}: missing; build the package with \`npm run js:build\` first`);
  }
  const directory = mkdtempSync(join(tmpdir(), "redact-secret-assessment-"));
  for (const name of ARTIFACT_FILES) {
    try {
      copyFileSync(join(artifactDir, name), join(directory, name));
    } catch {
      rmSync(directory, { recursive: true, force: true });
      fail(`${join(artifactDir, name)}: missing; build it with \`npm run wasm:build\` first`);
    }
  }
  await bundleHarness(artifactDir, join(directory, "assessment-harness.js"));
  writeFileSync(join(directory, "index.html"), renderPage());
  writeFileSync(join(directory, "fixtures.json"), JSON.stringify(fixtures));
  return directory;
}

async function serve(directory) {
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const name = path === "/" ? "index.html" : path.slice(1);
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
  await new Promise((resolveListening) => server.listen(0, "127.0.0.1", resolveListening));
  const { port } = server.address();
  return { server, origin: `http://127.0.0.1:${port}` };
}

async function runInEngine(playwright, engine, origin) {
  const browser = await playwright[engine].launch();
  const diagnostics = [];
  try {
    const version = browser.version();
    const page = await browser.newPage();
    page.on("pageerror", (error) => diagnostics.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error") diagnostics.push(`console: ${message.text()}`);
    });
    await page.goto(`${origin}/index.html`, { waitUntil: "load" });
    await page.waitForFunction(() => globalThis.__assessment !== undefined, undefined, {
      timeout: 120_000,
    });
    const report = await page.evaluate(() => globalThis.__assessment);
    return { version, report, diagnostics };
  } finally {
    await browser.close();
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const jsonOut = options.jsonOut ?? "-";

  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    fail(
      "playwright is not installed; run `npm ci` and " + "`npx playwright install --with-deps chromium firefox webkit`",
    );
    return;
  }

  const schema = await loadAssessmentSchema();
  const corpus = loadAccuracyCorpus();
  if (corpus.offsetUnit !== "utf8-byte") {
    fail(`accuracy-corpus.json: unexpected offsetUnit ${corpus.offsetUnit}`);
  }
  const fixtures = schema.validateAssessmentFixtures(corpus.fixtures);
  if (fixtures.length !== corpus.fixtureCount || fixtures.length === 0) {
    fail(`accuracy-corpus.json: expected ${corpus.fixtureCount} fixture(s), found ${fixtures.length}`);
  }

  const directory = await stageServeDirectory(options.artifactDir, fixtures);
  const { server, origin } = await serve(directory);
  let outcome;
  try {
    outcome = await runInEngine(playwright, options.engine, origin);
  } catch (error) {
    server.close();
    rmSync(directory, { recursive: true, force: true });
    fail(
      `browser accuracy evaluation FAILED before completing — ${error instanceof Error ? error.message : String(error)}`,
    );
    return;
  }
  server.close();
  rmSync(directory, { recursive: true, force: true });

  for (const line of outcome.diagnostics) console.error(`    ${options.engine}: ${line}`);
  if (!outcome.report.ok) {
    fail(`browser accuracy evaluation FAILED before completing — ${outcome.report.error}`);
    return;
  }
  const { metrics, mismatches, fixturesEvaluated } = outcome.report;
  if (fixturesEvaluated !== fixtures.length) {
    fail(`evaluated ${fixturesEvaluated} of ${fixtures.length} fixtures`);
  }

  const provenance = {
    commit: gitCommit(),
    artifactIdentity: `@redact-secret/wasm@${readPackageVersion(WASM_PACKAGE_JSON)}`,
    corpusVersion: String(corpus.corpusVersion),
    corpusHash: accuracyCorpusHash(),
    os: hostOs(),
    cpu: hostCpu(),
    runtime: `${options.engine}-${outcome.version}`,
    command: `node scripts/assessment-browser-run.mjs ${process.argv.slice(2).join(" ")}`.trim(),
  };

  const result = await buildAndEmitAccuracyResult({
    surface: "browser-wasm",
    profileId: PROFILE_ID,
    metrics,
    mismatches,
    provenance,
    jsonOut,
    markdownOut: options.markdownOut,
    mismatchesOut: options.mismatchesOut,
  });

  const { accuracy } = result;
  console.error(
    `${options.engine} accuracy: ${accuracy.truePositives} true positive(s), ` +
      `${accuracy.falsePositives} false positive(s), ${accuracy.falseNegatives} false negative(s), ` +
      `${accuracy.policyMismatches} policy mismatch(es) across ${fixturesEvaluated} fixture(s)`,
  );

  if (options.strict && (accuracy.falsePositives > 0 || accuracy.falseNegatives > 0 || accuracy.policyMismatches > 0)) {
    fail("--strict: at least one mismatch was found");
  }
}

await main();
