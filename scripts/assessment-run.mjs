/**
 * Evaluates the real, installed `@redact-secret/core` package on Node
 * against `assessment/fixtures/accuracy-corpus.json` — the reviewed
 * synthetic accuracy corpus (`decision-define-cross-language-evaluation-
 * protocol`) — and emits a conforming `AssessmentResult` for the `"node"`
 * surface, plus a Markdown report.
 *
 * This drives the published package's public API exactly as
 * `scripts/qualify-node-addon.mjs`'s `integrateWithPackage` pass does,
 * except this measures accuracy against reviewed expectations rather than
 * conformance against the canonical corpus; the two corpora are kept
 * distinct on purpose (`assessment/README.md`). It expects the package
 * already built (`npm run js:build`) and the platform's native addon already
 * resolvable — this script does no building or linking of its own, so a
 * missing or unusable artifact fails loudly rather than being silently
 * worked around.
 *
 * Every fixture is scored by `assessment/adapters/scoring.ts`'s
 * `runAccuracyFixtures`, the same corpus-iteration path the browser runner
 * uses, so "what counts as a match" cannot drift between the two surfaces.
 * A `scan()` throw or a package that fails to initialize aborts the run
 * before any `AssessmentResult` is emitted — a failed evaluation never
 * reports as a zero-finding success.
 *
 * Usage:
 *
 *     node scripts/assessment-run.mjs
 *     node scripts/assessment-run.mjs --json-out out/node.json --markdown-out out/node.md
 *     node scripts/assessment-run.mjs --strict
 *
 * Every fixture in the corpus is synthetic or explicitly revoked, and
 * nothing this script prints or writes carries a fixture's `input` or a
 * matched value — mismatches are reported by fixture id and safe metadata
 * only.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { buildAndEmitAccuracyResult, loadAssessmentSchema, loadAssessmentScoring } from "./lib/assessment-emit.mjs";
import {
  accuracyCorpusHash,
  gitCommit,
  hostCpu,
  hostOs,
  loadAccuracyCorpus,
  REPO_ROOT,
  readPackageVersion,
} from "./lib/assessment-provenance.mjs";

const JS_PACKAGE_DIR = join(REPO_ROOT, "packages", "javascript");
const PROFILE_ID = "accuracy-corpus";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = {
    jsonOut: undefined,
    markdownOut: undefined,
    mismatchesOut: undefined,
    strict: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--json-out") {
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

async function loadInstalledPackage() {
  const entry = join(JS_PACKAGE_DIR, "dist", "index.js");
  if (!existsSync(entry)) {
    fail(`${entry}: missing; build the package with \`npm run js:build\` first`);
  }
  const api = await import(pathToFileURL(entry).href);
  try {
    await api.initialize();
  } catch (error) {
    fail(
      "the installed package failed to initialize; build and link the native " +
        `addon first (\`npm run addon:qualify\`): ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return api;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const jsonOut = options.jsonOut ?? "-";

  const api = await loadInstalledPackage();
  const schema = await loadAssessmentSchema();
  const scoring = await loadAssessmentScoring();

  const corpus = loadAccuracyCorpus();
  if (corpus.offsetUnit !== "utf8-byte") {
    fail(`accuracy-corpus.json: unexpected offsetUnit ${corpus.offsetUnit}`);
  }
  const fixtures = schema.validateAssessmentFixtures(corpus.fixtures);
  if (fixtures.length !== corpus.fixtureCount || fixtures.length === 0) {
    fail(`accuracy-corpus.json: expected ${corpus.fixtureCount} fixture(s), found ${fixtures.length}`);
  }

  let run;
  try {
    run = await scoring.runAccuracyFixtures(fixtures, (input) =>
      api.scan(input).map((finding) => ({
        detector: finding.detector,
        type: finding.type,
        start: finding.start,
        end: finding.end,
        action: finding.action,
      })),
    );
  } catch (error) {
    fail(`accuracy evaluation FAILED before completing — ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  if (run.fixturesEvaluated !== fixtures.length) {
    fail(`evaluated ${run.fixturesEvaluated} of ${fixtures.length} fixtures`);
  }

  const packageJsonPath = join(JS_PACKAGE_DIR, "package.json");
  const provenance = {
    commit: gitCommit(),
    artifactIdentity: `@redact-secret/core@${readPackageVersion(packageJsonPath)}`,
    corpusVersion: String(corpus.corpusVersion),
    corpusHash: accuracyCorpusHash(),
    os: hostOs(),
    cpu: hostCpu(),
    runtime: `node-${process.version.slice(1)}`,
    command: `node scripts/assessment-run.mjs ${process.argv.slice(2).join(" ")}`.trim(),
  };

  const result = await buildAndEmitAccuracyResult({
    surface: "node",
    profileId: PROFILE_ID,
    metrics: run.metrics,
    mismatches: run.mismatches,
    provenance,
    jsonOut,
    markdownOut: options.markdownOut,
    mismatchesOut: options.mismatchesOut,
  });

  const { accuracy } = result;
  console.error(
    `node accuracy: ${accuracy.truePositives} true positive(s), ` +
      `${accuracy.falsePositives} false positive(s), ${accuracy.falseNegatives} false negative(s), ` +
      `${accuracy.policyMismatches} policy mismatch(es) across ${run.fixturesEvaluated} fixture(s)`,
  );

  if (options.strict && (accuracy.falsePositives > 0 || accuracy.falseNegatives > 0 || accuracy.policyMismatches > 0)) {
    fail("--strict: at least one mismatch was found");
  }
}

await main();
