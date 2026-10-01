/** Accuracy runner for an installed Python candidate package. */

import { buildAndEmitAccuracyResult, loadAssessmentSchema, loadAssessmentScoring } from "./lib/assessment-emit.mjs";
import { accuracyCorpusHash, gitCommit, hostCpu, hostOs, loadAccuracyCorpus } from "./lib/assessment-provenance.mjs";
import { runPythonWorker } from "./lib/assessment-python.mjs";

const PROFILE_ID = "accuracy-corpus";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { python: "python3", jsonOut: "-", markdownOut: undefined, mismatchesOut: undefined, strict: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--python") {
      options.python = value;
      index += 1;
    } else if (argument === "--json-out") {
      options.jsonOut = value;
      index += 1;
    } else if (argument === "--markdown-out") {
      options.markdownOut = value;
      index += 1;
    } else if (argument === "--mismatches-out") {
      options.mismatchesOut = value;
      index += 1;
    } else if (argument === "--strict") options.strict = true;
    else fail(`unknown argument: ${argument}`);
  }
  if (typeof options.python !== "string" || options.python.length === 0) fail("--python requires a value");
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const schema = await loadAssessmentSchema();
  const scoring = await loadAssessmentScoring();
  const corpus = loadAccuracyCorpus();
  if (corpus.offsetUnit !== "utf8-byte") fail("accuracy-corpus.json: unexpected offset unit");
  const fixtures = schema.validateAssessmentFixtures(corpus.fixtures);
  if (fixtures.length !== corpus.fixtureCount || fixtures.length === 0)
    fail("accuracy-corpus.json: fixture count mismatch");

  let worker;
  let metadata;
  try {
    metadata = runPythonWorker(options.python, "metadata");
    worker = runPythonWorker(options.python, "accuracy", {
      fixtures: fixtures.map((fixture) => ({ id: fixture.id, input: fixture.input })),
    });
  } catch {
    fail("Python accuracy evaluation FAILED before completing");
  }
  if (
    worker.fixturesEvaluated !== fixtures.length ||
    worker.fixtures.length !== fixtures.length ||
    worker.fixtures.some((fixture, index) => fixture.id !== fixtures[index]?.id)
  ) {
    fail(
      `Python accuracy evaluation incomplete: evaluated ${worker.fixturesEvaluated ?? 0} of ${fixtures.length} fixtures`,
    );
  }
  let fixtureIndex = 0;
  const run = await scoring.runAccuracyFixtures(fixtures, () => {
    const findings = worker.fixtures[fixtureIndex]?.findings;
    fixtureIndex += 1;
    return findings ?? [];
  });
  if (run.fixturesEvaluated !== fixtures.length) fail("Python accuracy evaluation incomplete");

  const provenance = {
    commit: gitCommit(),
    artifactIdentity: `redact-secret==${metadata.version}`,
    corpusVersion: String(corpus.corpusVersion),
    corpusHash: accuracyCorpusHash(),
    os: hostOs(),
    cpu: hostCpu(),
    runtime: metadata.runtime,
    command: `node scripts/assessment-python-run.mjs ${process.argv.slice(2).join(" ")}`.trim(),
  };
  const result = await buildAndEmitAccuracyResult({
    surface: "python",
    profileId: PROFILE_ID,
    metrics: run.metrics,
    mismatches: run.mismatches,
    provenance,
    jsonOut: options.jsonOut,
    markdownOut: options.markdownOut,
    mismatchesOut: options.mismatchesOut,
  });
  const { accuracy } = result;
  console.error(
    `python accuracy: ${accuracy.truePositives} true positive(s), ${accuracy.falsePositives} false positive(s), ${accuracy.falseNegatives} false negative(s), ${accuracy.policyMismatches} policy mismatch(es) across ${run.fixturesEvaluated} fixture(s)`,
  );
  if (options.strict && (accuracy.falsePositives || accuracy.falseNegatives || accuracy.policyMismatches)) {
    fail("--strict: at least one mismatch was found");
  }
}

await main();
