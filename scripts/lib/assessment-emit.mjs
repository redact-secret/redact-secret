/**
 * Assembles, validates, and writes one surface's `AssessmentResult` — shared
 * by every surface's CLI runner (`scripts/assessment-run.mjs`,
 * `scripts/assessment-browser-run.mjs`) so building the common result
 * contract, checking it against `assessment/schema.ts`'s own validator, and
 * rendering it as JSON and Markdown happens in exactly one place.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeJsonResult, writeMarkdownReport, writeMismatches } from "./assessment-output.mjs";
import { loadTsModule } from "./load-ts-module.mjs";

const SCRIPTS_LIB_DIR = dirname(fileURLToPath(import.meta.url));
const ASSESSMENT_DIR = join(SCRIPTS_LIB_DIR, "..", "..", "assessment");

export async function loadAssessmentSchema() {
  return loadTsModule(join(ASSESSMENT_DIR, "schema.ts"));
}

export async function loadAssessmentScoring() {
  return loadTsModule(join(ASSESSMENT_DIR, "adapters", "scoring.ts"));
}

async function loadAssessmentReport() {
  return loadTsModule(join(ASSESSMENT_DIR, "adapters", "report.ts"));
}

/**
 * Builds the `AssessmentResult` for one surface's accuracy run, validates it
 * against the schema's own validator (never trust a hand-assembled object
 * over the contract it must satisfy), and writes the JSON result plus the
 * optional Markdown report and mismatch detail.
 */
export async function buildAndEmitAccuracyResult({
  surface,
  profileId,
  metrics,
  mismatches,
  provenance,
  jsonOut,
  markdownOut,
  mismatchesOut,
}) {
  const schema = await loadAssessmentSchema();
  const result = {
    schemaVersion: schema.RESULT_SCHEMA_VERSION,
    surface,
    profileId,
    accuracy: metrics,
    provenance,
  };
  schema.validateAssessmentResults([result]);

  writeJsonResult(result, jsonOut);
  if (markdownOut !== undefined) {
    const report = await loadAssessmentReport();
    writeMarkdownReport(report.renderMarkdownReport(result, mismatches), markdownOut);
  }
  writeMismatches(mismatches, mismatchesOut);

  return result;
}

export async function buildAndEmitPerformanceResult({
  surface,
  profileId,
  performance,
  provenance,
  jsonOut,
  markdownOut,
}) {
  const schema = await loadAssessmentSchema();
  const result = {
    schemaVersion: schema.RESULT_SCHEMA_VERSION,
    surface,
    profileId,
    performance,
    provenance,
  };
  schema.validateAssessmentResults([result]);
  writeJsonResult(result, jsonOut);
  if (markdownOut !== undefined) {
    const report = await loadAssessmentReport();
    writeMarkdownReport(report.renderMarkdownPerformanceReport(result), markdownOut);
  }
  return result;
}
