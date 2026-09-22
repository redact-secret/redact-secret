/** Evaluate a complete assessment against criteria fixed before the candidate run. */
import { readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";

import { loadTsModule } from "./lib/load-ts-module.mjs";
import { REPO_ROOT } from "./lib/assessment-provenance.mjs";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { criteria: undefined, summary: undefined, jsonOut: undefined, markdownOut: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (!["--criteria", "--summary", "--json-out", "--markdown-out"].includes(argument) || value === undefined || value.length === 0) fail("acceptance: invalid arguments");
    if (argument === "--criteria") options.criteria = value;
    else if (argument === "--summary") options.summary = value;
    else if (argument === "--json-out") options.jsonOut = value;
    else options.markdownOut = value;
    index += 1;
  }
  // Core no longer ships a bundled acceptance-criteria document (issue #603;
  // DS11): redact-secret-benchmarks owns criteria and judgement, and passes
  // its own criteria path explicitly.
  if (options.criteria === undefined) fail("--criteria requires a value");
  if (options.summary === undefined) fail("--summary requires a value");
  return options;
}

const options = parseArguments(process.argv.slice(2));
const acceptance = await loadTsModule("assessment/acceptance.ts");
const criteria = JSON.parse(readFileSync(resolve(REPO_ROOT, options.criteria), "utf8"));
const summary = JSON.parse(readFileSync(resolve(REPO_ROOT, options.summary), "utf8"));
const evaluation = acceptance.evaluateAcceptance(summary, criteria);
evaluation.summaryPath = relative(resolve(REPO_ROOT, options.markdownOut === undefined ? "." : `${options.markdownOut}/..`), resolve(REPO_ROOT, options.summary));
const json = `${JSON.stringify(evaluation, null, 2)}\n`;
const markdown = acceptance.renderAcceptanceMarkdown(evaluation);
if (options.jsonOut === undefined) process.stdout.write(json);
else writeFileSync(resolve(REPO_ROOT, options.jsonOut), json);
if (options.markdownOut !== undefined) writeFileSync(resolve(REPO_ROOT, options.markdownOut), markdown);
console.error(`RC acceptance: ${evaluation.status}`);
if (evaluation.status !== "accepted") process.exitCode = 1;
