import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { evaluateAcceptance, validateAcceptanceCriteria, type AcceptanceCriteria } from "./acceptance.js";
import type { CompleteAssessment } from "./complete.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const criteria = validateAcceptanceCriteria(JSON.parse(readFileSync(join(HERE, "acceptance-criteria.json"), "utf8")) as AcceptanceCriteria);
const baseline = JSON.parse(readFileSync(join(HERE, "results", "complete-v4", "summary.json"), "utf8")) as CompleteAssessment;

function candidate(): CompleteAssessment {
  return {
    ...baseline,
    repetitions: criteria.minimumRepetitions,
    runs: baseline.runs.map((run) => ({
      ...run,
      result: run.result === undefined ? undefined : {
        ...run.result,
        provenance: {
          ...run.result.provenance,
          buildProfile: "release",
          os: "darwin-25.5.0",
          cpu: run.surface === "rust-core" ? "aarch64" : "arm64",
          runtime: run.surface === "rust-core" ? "rustc-1.98.1" : run.surface === "python" ? "cpython-3.14.7" : run.surface === "node" ? "node-22.16.0" : run.surface === "browser-wasm" ? "chromium-153" : "rustc 1.98.1",
        },
        performance: run.result.performance === undefined ? undefined : {
          ...run.result.performance,
          initialization: { ...run.result.performance.initialization, samples: Array(criteria.minimumRepetitions).fill(run.result.performance.initialization.median) },
          processing: { ...run.result.performance.processing, samples: Array(criteria.minimumRepetitions).fill(run.result.performance.processing.median) },
          throughput: { ...run.result.performance.throughput, samples: Array(criteria.minimumRepetitions).fill(run.result.performance.throughput.median) },
          memory: Object.fromEntries(Object.entries(run.result.performance.memory).map(([name, metric]) => [name, {
            ...metric,
            samples: metric.samples.length === 0 ? [] : Array(criteria.minimumRepetitions).fill(metric.samples[0]),
          }])) as typeof run.result.performance.memory,
        },
      },
    })),
  };
}

// Dated waiver (2026-09-18, issue #415): the pinned macOS baseline
// (results/complete-v4/) fails these exact 46-check evaluation's checks --
// every non-Rust surface's processing-p95-ms and
// throughput-minimum-bytes-per-second, plus two initialization-p95-ms misses
// -- for reasons documented in results/complete-v4/README.md and
// assessment/README.md#fixed-rc-performance-and-resource-acceptance:
// reproduced on real hardware outside any sandbox, uniformly across five
// independently implemented runtimes, and unrelated to the accuracy-corpus
// re-pin that baseline otherwise supports. Listing the exact keys (rather
// than accepting any failure whose key merely contains ":performance:") is
// what makes "accept the representative baseline-shaped candidate" below
// able to fail again: a further regression -- a new check going red, or the
// checked count drifting from 46 -- changes this list and the test catches
// it. Narrowing this list requires either the separate, deliberate
// threshold review assessment/README.md calls for (options (a)/(b) on issue
// #415) or, for a check that stops failing, updating this waiver to match.
const MACOS_PERFORMANCE_WAIVER_2026_09_18: readonly string[] = [
  "browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms",
  "browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second",
  "browser-wasm:performance:scale-logs-small-whole:processing-p95-ms",
  "browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second",
  "cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms",
  "cli:performance:scale-logs-medium-fixed4096:processing-p95-ms",
  "cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second",
  "cli:performance:scale-logs-small-whole:initialization-p95-ms",
  "cli:performance:scale-logs-small-whole:processing-p95-ms",
  "cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second",
  "node:performance:scale-logs-medium-fixed4096:initialization-p95-ms",
  "node:performance:scale-logs-medium-fixed4096:processing-p95-ms",
  "node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second",
  "node:performance:scale-logs-small-whole:processing-p95-ms",
  "node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second",
  "python:performance:scale-logs-medium-fixed4096:initialization-p95-ms",
  "python:performance:scale-logs-medium-fixed4096:processing-p95-ms",
  "python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second",
  "python:performance:scale-logs-small-whole:processing-p95-ms",
  "python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second",
];

describe("fixed RC acceptance criteria", () => {
  test("criteria are bound to the reviewed baseline", () => {
    expect(criteria.baseline.sourceCommit).toBe(baseline.sourceCommit);
    expect(criteria.baseline.accuracyCorpusVersion).toBe(baseline.accuracyCorpus?.version);
    expect(criteria.baseline.accuracyCorpusHash).toBe(baseline.accuracyCorpus?.hash);
    expect(criteria.baseline.workloadProfilesVersion).toBe(baseline.workloadProfiles?.version);
    expect(criteria.baseline.workloadProfilesHash).toBe(baseline.workloadProfiles?.hash);
  });

  test("accept the representative baseline-shaped candidate's accuracy and identity against the dated macOS performance waiver", () => {
    // This asserts the pinned baseline is a correct accuracy-and-identity
    // reference -- the thing a corpus re-pin actually changes -- while still
    // holding every performance check to account, via
    // MACOS_PERFORMANCE_WAIVER_2026_09_18 above, rather than waving through
    // any failure merely because its key contains ":performance:".
    const evaluation = evaluateAcceptance(candidate(), criteria);
    const nonPerformanceFailures = evaluation.failures.filter((failure) => !failure.includes(":performance:"));
    expect(nonPerformanceFailures).toEqual([]);
    expect(evaluation.checks).toHaveLength(46);
    const failingCheckKeys = evaluation.checks.filter((item) => !item.passed).map((item) => item.key).sort();
    expect(failingCheckKeys).toEqual(MACOS_PERFORMANCE_WAIVER_2026_09_18);
  });

  test("a rust-core performance run built without --release cannot bypass release-build evidence", () => {
    // Deliberately constructed, not read from whichever baseline directory
    // happens to be pinned: this must hold regardless of whether that
    // directory's own historical rust-core provenance happens to predate
    // this check.
    const input = candidate();
    const index = input.runs.findIndex((run) => run.surface === "rust-core" && run.kind === "performance" && run.profileId === "scale-logs-small-whole");
    const runs = [...input.runs];
    const result = runs[index].result!;
    runs[index] = { ...runs[index], result: { ...result, provenance: { ...result.provenance, buildProfile: undefined } } };
    const evaluation = evaluateAcceptance({ ...input, runs }, criteria);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures).toContain("rust-core:performance:scale-logs-small-whole:release-build-required");
    expect(evaluation.checks.some(c => c.key.startsWith("rust-core:performance:scale-logs-small-whole"))).toBe(false);
  });

  test("rejects performance, resource, environment, and accuracy regressions", () => {
    const input = candidate();
    const runs = [...input.runs];
    const index = runs.findIndex((run) => run.surface === "node" && run.profileId === "scale-logs-small-whole");
    const result = runs[index].result!;
    runs[index] = {
      ...runs[index],
      result: {
        ...result,
        provenance: { ...result.provenance, cpu: "x64" },
        performance: {
          ...result.performance!,
          processing: { ...result.performance!.processing, p95: 999 },
          memory: {
            ...result.performance!.memory,
            nodeRss: { ...result.performance!.memory.nodeRss, samples: [] },
          },
        },
      },
    };
    const accuracyIndex = runs.findIndex((run) => run.surface === "python" && run.kind === "accuracy");
    runs[accuracyIndex] = {
      ...runs[accuracyIndex],
      result: { ...runs[accuracyIndex].result!, accuracy: { ...runs[accuracyIndex].result!.accuracy!, policyMismatches: 1 } },
    };
    const evaluation = evaluateAcceptance({ ...input, runs }, criteria);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:environment-cpu-mismatch");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:memory-nodeRss:insufficient-samples");
    expect(evaluation.failures).toContain("python:accuracy:accuracy-corpus:policyMismatches-mismatch");
  });

  test("rejects incomplete, under-repeated, or identity-drifted evidence", () => {
    const input = candidate();
    const evaluation = evaluateAcceptance({
      ...input,
      status: "incomplete",
      repetitions: 2,
      workloadProfiles: { version: "1", hash: "f".repeat(64) },
    }, criteria);
    expect(evaluation.failures).toContain("suite:assessment-incomplete");
    expect(evaluation.failures).toContain("suite:insufficient-repetitions");
    expect(evaluation.failures).toContain("suite:workload-profile-identity-mismatch");
  });
});

const linuxCriteria = validateAcceptanceCriteria(JSON.parse(readFileSync(join(HERE, "acceptance-criteria-linux-x64.json"), "utf8")) as AcceptanceCriteria);
const linuxBaseline = JSON.parse(readFileSync(join(HERE, "results", "complete-linux-x64-v4", "summary.json"), "utf8")) as CompleteAssessment;

describe("fixed RC acceptance criteria — Linux x86_64", () => {
  test("is a separately identified, separately loaded profile that leaves the macOS criteria untouched", () => {
    expect(linuxCriteria.criteriaId).not.toBe(criteria.criteriaId);
    expect(linuxCriteria.environment.id).not.toBe(criteria.environment.id);
    expect(criteria.environment.id).toBe("macos-arm64-node22-chromium");
    expect(linuxCriteria.environment.id).toBe("linux-x64-node22-chromium");
    expect(linuxCriteria.environment.osPrefixes).toEqual(["linux-"]);
    expect(linuxCriteria.environment.cpus).toEqual(["x86_64", "x64"]);
  });

  test("criteria are bound to the committed Linux x86_64 baseline run", () => {
    expect(linuxCriteria.baseline.sourceCommit).toBe(linuxBaseline.sourceCommit);
    expect(linuxCriteria.baseline.accuracyCorpusVersion).toBe(linuxBaseline.accuracyCorpus?.version);
    expect(linuxCriteria.baseline.accuracyCorpusHash).toBe(linuxBaseline.accuracyCorpus?.hash);
    expect(linuxCriteria.baseline.workloadProfilesVersion).toBe(linuxBaseline.workloadProfiles?.version);
    expect(linuxCriteria.baseline.workloadProfilesHash).toBe(linuxBaseline.workloadProfiles?.hash);
    expect(linuxBaseline.status).toBe("complete");
    expect(linuxBaseline.repetitions).toBe(linuxCriteria.minimumRepetitions);
    expect(linuxBaseline.runs).toHaveLength(15);

    const evidenceRoot = join(HERE, "results", "complete-linux-x64-v4");
    const evaluation = JSON.parse(readFileSync(join(evidenceRoot, "acceptance.json"), "utf8")) as { status: string; environmentId: string; checks: readonly { passed: boolean }[]; failures: readonly string[] };
    expect(evaluation.status).toBe("accepted");
    expect(evaluation.environmentId).toBe("linux-x64-node22-chromium");
    expect(evaluation.checks).toHaveLength(46);
    expect(evaluation.checks.every((item) => item.passed)).toBe(true);
    expect(evaluation.failures).toEqual([]);
    for (const run of linuxBaseline.runs) {
      expect(join(evidenceRoot, run.resultPath)).toSatisfy(existsSync);
      expect(join(evidenceRoot, run.markdownPath)).toSatisfy(existsSync);
      if (run.mismatchesPath !== undefined) expect(join(evidenceRoot, run.mismatchesPath)).toSatisfy(existsSync);
    }
  });

  test("the macOS-shaped candidate cannot silently satisfy the Linux profile", () => {
    const evaluation = evaluateAcceptance(candidate(), linuxCriteria);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures.some((failure) => failure.endsWith(":environment-os-mismatch"))).toBe(true);
  });

  test("the Linux-shaped baseline cannot silently satisfy the macOS profile", () => {
    const evaluation = evaluateAcceptance({ ...linuxBaseline, repetitions: criteria.minimumRepetitions }, criteria);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures.some((failure) => failure.endsWith(":environment-os-mismatch"))).toBe(true);
  });

  test("the Complete assessment workflow names the criteria file matching its runs-on host", () => {
    const workflow = readFileSync(join(HERE, "..", ".github", "workflows", "complete-assessment.yml"), "utf8");
    expect(workflow).toMatch(/^\s*runs-on:\s*ubuntu-latest\s*$/m);
    expect(workflow).toContain("--criteria assessment/acceptance-criteria-linux-x64.json");
    expect(linuxCriteria.environment.osPrefixes).toContain("linux-");
  });
});

describe("accuracy corpus identity pin does not drift from the live corpus", () => {
  test("both criteria files pin the current accuracy-corpus.json hash", () => {
    const liveCorpusHash = createHash("sha256")
      .update(readFileSync(join(HERE, "fixtures", "accuracy-corpus.json")))
      .digest("hex");
    expect(criteria.baseline.accuracyCorpusHash).toBe(liveCorpusHash);
    expect(linuxCriteria.baseline.accuracyCorpusHash).toBe(liveCorpusHash);
  });
});
