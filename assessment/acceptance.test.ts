import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { evaluateAcceptance, renderAcceptanceMarkdown, validateAcceptanceCriteria, type AcceptanceCriteria } from "./acceptance.js";
import type { CompleteAssessment } from "./complete.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const criteria = validateAcceptanceCriteria(JSON.parse(readFileSync(join(HERE, "acceptance-criteria.json"), "utf8")) as AcceptanceCriteria);
const baseline = JSON.parse(readFileSync(join(HERE, "results", "complete", "summary.json"), "utf8")) as CompleteAssessment;

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

describe("fixed RC acceptance criteria", () => {
  test("criteria are bound to the reviewed baseline and durable candidate evidence", () => {
    expect(criteria.baseline.sourceCommit).toBe(baseline.sourceCommit);
    expect(criteria.baseline.accuracyCorpusVersion).toBe(baseline.accuracyCorpus?.version);
    expect(criteria.baseline.accuracyCorpusHash).toBe(baseline.accuracyCorpus?.hash);
    expect(criteria.baseline.workloadProfilesVersion).toBe(baseline.workloadProfiles?.version);
    expect(criteria.baseline.workloadProfilesHash).toBe(baseline.workloadProfiles?.hash);

    const evidenceRoot = join(HERE, "results", "acceptance");
    const summary = JSON.parse(readFileSync(join(evidenceRoot, "summary.json"), "utf8")) as CompleteAssessment;
    const evaluation = JSON.parse(readFileSync(join(evidenceRoot, "acceptance.json"), "utf8")) as { status: string; checks: readonly { passed: boolean }[]; failures: readonly string[] };
    expect(summary.status).toBe("complete");
    expect(summary.repetitions).toBe(criteria.minimumRepetitions);
    expect(summary.runs).toHaveLength(15);
    expect(evaluation.status).toBe("accepted");
    expect(evaluation.checks).toHaveLength(46);
    expect(evaluation.checks.every((item) => item.passed)).toBe(true);
    expect(evaluation.failures).toEqual([]);
    for (const run of summary.runs) {
      expect(join(evidenceRoot, run.resultPath)).toSatisfy(existsSync);
      expect(join(evidenceRoot, run.markdownPath)).toSatisfy(existsSync);
      if (run.mismatchesPath !== undefined) expect(join(evidenceRoot, run.mismatchesPath)).toSatisfy(existsSync);
    }
  });

  test("accept the representative baseline-shaped candidate with five repetitions", () => {
    const evaluation = evaluateAcceptance(candidate(), criteria);
    expect(evaluation.status).toBe("accepted");
    expect(evaluation.failures).toEqual([]);
    expect(evaluation.checks).toHaveLength(46);
    expect(renderAcceptanceMarkdown(evaluation)).toContain("Status: **ACCEPTED**");
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
