import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { validateAssessmentFixtures, validateAssessmentResults } from "../schema.js";

const root = process.cwd();

function readJson<T>(...parts: string[]): T {
  return JSON.parse(readFileSync(join(root, ...parts), "utf8")) as T;
}

const evidence = readJson<{
  testbed: {
    status: string;
    source_revision: string;
    surfaces: string[];
    run_count: number;
    performance_repetitions: number;
    validation_failures: number;
  };
  accuracy_corpus: {
    version: string;
    sha256: string;
    fixtures: number;
    categories: Record<string, number>;
    expected_findings: number;
    expected_empty_fixtures: number;
  };
  workload_profiles: { version: string; sha256: string; evaluated_profiles: string[] };
  per_surface_detection_result: Record<string, number>;
  range_interpretation: {
    paired_fixture_id: string;
    safe_mismatch_records_per_surface: number;
    missing_records_per_surface: number;
    extra_records_per_surface: number;
    policy_mismatch_records_per_surface: number;
    ordinary_negative_false_positive_observed: boolean;
  };
  redaction_evidence: {
    redacting_surface_whole_input_profile_results_complete: number;
    redacting_surface_incremental_profile_results_complete: number;
    cli_performance_profile_results_complete: number;
    cli_accuracy_exact_output_oracle: string;
    python_accuracy_whole_incremental_equivalence_fixtures: number;
    cross_surface_assessment_redaction_rate_published: boolean;
    canonical_correctness_evidence: {
      source_revision: string;
      synchronous_corpus_sha256: string;
      synchronous_fixtures: number;
      supported_fixtures: number;
      all_current_product_surfaces: string;
      redaction_specific_rate_published: boolean;
    };
  };
  disposition: {
    confirmed_detector_defects: number;
    documented_limitation_fixture_ids: string[];
    contract_disagreement_fixture_ids: string[];
  };
  universal_accuracy_claimed: boolean;
  release_authorized: boolean;
  artifacts_published: boolean;
}>("docs", "audits", "evidence", "200", "verification-summary.json");

const complete = readJson<{
  status: string;
  sourceCommit: string;
  accuracyCorpus: { version: string; hash: string };
  workloadProfiles: { version: string; hash: string };
  repetitions: number;
  validationFailures: string[];
  runs: Array<{
    surface: string;
    kind: "accuracy" | "performance";
    profileId: string;
    path: "whole-input" | "incremental" | "standard-input";
    status: string;
    resultPath: string;
    result?: unknown;
  }>;
}>("assessment", "results", "complete", "summary.json");

describe("published detection reliability evidence", () => {
  it("re-derives the public corpus scope and denominators", () => {
    const corpusPath = join(root, "assessment", "fixtures", "accuracy-corpus.json");
    const corpusBytes = readFileSync(corpusPath);
    const corpus = JSON.parse(corpusBytes.toString("utf8")) as {
      corpusVersion: string;
      fixtures: Array<{ category: string; expected: unknown[] }>;
    };
    const fixtures = validateAssessmentFixtures(corpus.fixtures as never);
    const categories = Object.fromEntries(
      ["logs", "code", "chat", "negative-text"].map((category) => [
        category,
        fixtures.filter((fixture) => fixture.category === category).length,
      ]),
    );

    expect(evidence.accuracy_corpus).toMatchObject({
      version: corpus.corpusVersion,
      sha256: createHash("sha256").update(corpusBytes).digest("hex"),
      fixtures: fixtures.length,
      categories,
      expected_findings: fixtures.reduce(
        (total, fixture) => total + fixture.expected.length,
        0,
      ),
      expected_empty_fixtures: fixtures.filter((fixture) => fixture.expected.length === 0).length,
    });
  });

  it("binds every published surface result to the complete Testbed", () => {
    expect(evidence.testbed).toMatchObject({
      status: complete.status,
      source_revision: complete.sourceCommit,
      run_count: complete.runs.length,
      performance_repetitions: complete.repetitions,
      validation_failures: complete.validationFailures.length,
    });
    expect(evidence.accuracy_corpus).toMatchObject({
      version: complete.accuracyCorpus.version,
      sha256: complete.accuracyCorpus.hash,
    });
    expect(evidence.workload_profiles).toMatchObject({
      version: complete.workloadProfiles.version,
      sha256: complete.workloadProfiles.hash,
    });

    const accuracyRuns = complete.runs.filter((run) => run.kind === "accuracy");
    expect(accuracyRuns.map((run) => run.surface)).toEqual(evidence.testbed.surfaces);
    expect(accuracyRuns.every((run) => run.status === "complete")).toBe(true);

    for (const run of accuracyRuns) {
      const [result] = validateAssessmentResults([run.result as never]);
      expect(result.provenance.commit).toBe(evidence.testbed.source_revision);
      expect(result.provenance.corpusVersion).toBe(evidence.accuracy_corpus.version);
      expect(result.provenance.corpusHash).toBe(evidence.accuracy_corpus.sha256);
      expect(result.accuracy).toEqual({
        truePositives: evidence.per_surface_detection_result.true_positives,
        falsePositives: evidence.per_surface_detection_result.false_positives,
        falseNegatives: evidence.per_surface_detection_result.false_negatives,
        policyMismatches: 0,
      });
      expect(
        (result.accuracy?.truePositives ?? 0) + (result.accuracy?.falseNegatives ?? 0),
      ).toBe(evidence.per_surface_detection_result.false_negative_denominator_expected);
      expect(
        (result.accuracy?.truePositives ?? 0) + (result.accuracy?.falsePositives ?? 0),
      ).toBe(evidence.per_surface_detection_result.false_positive_denominator_actual);

      const mismatches = readJson<Array<{
        fixtureId: string;
        kind: string;
        detector: string;
        type: string;
      }>>(
        "assessment",
        "results",
        "complete",
        run.resultPath.replace(".json", "-mismatches.json"),
      );
      expect(mismatches).toHaveLength(
        evidence.range_interpretation.safe_mismatch_records_per_surface,
      );
      expect(mismatches.filter(({ kind }) => kind === "missing")).toHaveLength(
        evidence.range_interpretation.missing_records_per_surface,
      );
      expect(mismatches.filter(({ kind }) => kind === "extra")).toHaveLength(
        evidence.range_interpretation.extra_records_per_surface,
      );
      expect(mismatches.filter(({ kind }) => kind === "policy-mismatch")).toHaveLength(
        evidence.range_interpretation.policy_mismatch_records_per_surface,
      );
      expect(mismatches.filter(({ fixtureId }) =>
        fixtureId === evidence.range_interpretation.paired_fixture_id
      )).toHaveLength(2);
      expect(JSON.stringify(mismatches)).not.toMatch(/input|matchedValue|plaintext/i);
    }
  });

  it("pins path-completion and redaction claims without inventing a rate", () => {
    const performanceRuns = complete.runs.filter((run) => run.kind === "performance");
    expect(performanceRuns.every((run) => run.status === "complete")).toBe(true);
    const redactingSurfaces = new Set(["rust-core", "python", "node", "browser-wasm"]);
    expect(performanceRuns.filter((run) =>
      redactingSurfaces.has(run.surface) && run.path === "whole-input"
    )).toHaveLength(
      evidence.redaction_evidence.redacting_surface_whole_input_profile_results_complete,
    );
    expect(performanceRuns.filter((run) =>
      redactingSurfaces.has(run.surface) && run.path === "incremental"
    )).toHaveLength(
      evidence.redaction_evidence.redacting_surface_incremental_profile_results_complete,
    );
    expect(performanceRuns.filter((run) => run.surface === "cli")).toHaveLength(
      evidence.redaction_evidence.cli_performance_profile_results_complete,
    );
    expect([...new Set(performanceRuns.map((run) => run.profileId))]).toEqual(
      evidence.workload_profiles.evaluated_profiles,
    );

    const cliRunner = readFileSync(join(root, "scripts", "assessment-cli-run.mjs"), "utf8");
    expect(cliRunner.indexOf("verifyRedactMode(invoke, fixtures, rawFindingsByFixture)")).toBeLessThan(
      cliRunner.lastIndexOf("buildAndEmitAccuracyResult"),
    );
    expect(evidence.redaction_evidence.cli_accuracy_exact_output_oracle).toBe(
      "passed-before-result-emission",
    );

    const pythonWorker = readFileSync(
      join(root, "scripts", "assessment-python-worker.py"),
      "utf8",
    );
    expect(pythonWorker).toContain("whole.text != incremental_text");
    expect(evidence.redaction_evidence.python_accuracy_whole_incremental_equivalence_fixtures)
      .toBe(evidence.accuracy_corpus.fixtures);
    expect(evidence.redaction_evidence.cross_surface_assessment_redaction_rate_published)
      .toBe(false);

    const contractEvidence = readJson<{
      source_revision: string;
      corpus: { "synchronous-corpus.json": { sha256: string; fixtures: number; supported: number } };
      current_host_artifacts: Record<string, { result: string }>;
    }>("docs", "audits", "evidence", "199", "verification-summary.json");
    const canonical = evidence.redaction_evidence.canonical_correctness_evidence;
    expect(canonical).toMatchObject({
      source_revision: contractEvidence.source_revision,
      synchronous_corpus_sha256: contractEvidence.corpus["synchronous-corpus.json"].sha256,
      synchronous_fixtures: contractEvidence.corpus["synchronous-corpus.json"].fixtures,
      supported_fixtures: contractEvidence.corpus["synchronous-corpus.json"].supported,
      all_current_product_surfaces: "passed-applicable-redaction-checks",
      redaction_specific_rate_published: false,
    });
    expect(Object.keys(contractEvidence.current_host_artifacts)).toHaveLength(4);
  });

  it("preserves mismatch dispositions and public claim boundaries", () => {
    const beta2 = readJson<{
      confirmedDetectorDefects: number;
      dispositions: Array<{ fixtureIds: string[]; status: string }>;
    }>("assessment", "results", "beta.2", "summary.json");
    expect(evidence.disposition.confirmed_detector_defects).toBe(
      beta2.confirmedDetectorDefects,
    );
    expect(beta2.dispositions.filter(({ status }) => status === "documented-limitation")
      .flatMap(({ fixtureIds }) => fixtureIds)).toEqual(
      evidence.disposition.documented_limitation_fixture_ids,
    );
    expect(beta2.dispositions.filter(({ status }) => status === "contract-disagreement")
      .flatMap(({ fixtureIds }) => fixtureIds)).toEqual(
      evidence.disposition.contract_disagreement_fixture_ids,
    );
    expect(evidence.range_interpretation.ordinary_negative_false_positive_observed).toBe(false);
    expect(evidence.universal_accuracy_claimed).toBe(false);
    expect(evidence.release_authorized).toBe(false);
    expect(evidence.artifacts_published).toBe(false);

    const publicContract = readFileSync(
      join(root, "docs", "reference", "detection-reliability.md"),
      "utf8",
    );
    expect(publicContract).toContain("evidence/200/verification-summary.json");
    expect(publicContract).toMatch(/not\s+precision, recall, or accuracy estimates/);
    expect(publicContract).toMatch(/does not claim that those artifacts\s+were published/);
  });
});
