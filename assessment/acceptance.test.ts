import { describe, expect, test } from "vitest";

import { evaluateAcceptance, validateAcceptanceCriteria, type AcceptanceCriteria } from "./acceptance.js";
import { REQUIRED_ASSESSMENT_SURFACES, type CompleteAssessment, type CompleteAssessmentRun } from "./complete.js";
import type { AssessmentMemoryMetrics, AssessmentResult, AssessmentSurface } from "./schema.js";

// This file no longer reads a committed `assessment/results/` baseline or a
// committed `assessment/acceptance-criteria*.json` document: ownership of
// performance results, RC acceptance criteria, and judgement moved to
// `redact-secret-benchmarks` (issue #603; DS11). `evaluateAcceptance` and
// `validateAcceptanceCriteria` stay in core as reusable tooling, so this
// suite exercises their code paths against synthetic criteria and a
// synthetic candidate instead of a pinned historical evidence directory.

const PROFILES = [
  { id: "scale-logs-small-whole" },
  { id: "scale-logs-medium-fixed4096" },
] as const;

const ACCURACY_CORPUS = { version: "1", hash: "a".repeat(64) };
const WORKLOAD_PROFILES = { version: "1", hash: "b".repeat(64) };
const ACCURACY = { truePositives: 1, falsePositives: 0, falseNegatives: 0, policyMismatches: 0 };

function memory(overrides: Partial<Record<keyof AssessmentMemoryMetrics, readonly { baselineBytes: number; maximumObservedBytes: number }[]>> = {}): AssessmentMemoryMetrics {
  const unavailable = { unit: "bytes" as const, samples: [], unavailableReason: "not available", samplingLimit: "no samples" };
  const categories: (keyof AssessmentMemoryMetrics)[] = [
    "nodeHeap", "nodeRss", "nodeExternal", "browserJsHeap",
    "wasmLinearMemory", "pythonHeap", "processRss", "streamingBuffer",
  ];
  return Object.fromEntries(categories.map((category) => {
    const samples = overrides[category];
    return [category, samples === undefined ? unavailable : {
      unit: "bytes" as const, samples, samplingLimit: "sampled at process boundaries",
    }];
  })) as unknown as AssessmentMemoryMetrics;
}

function environment(id: string, os: string, cpu: string, runtime: string) {
  return {
    id, osPrefixes: [os], cpus: [cpu],
    runtimePrefixes: Object.fromEntries(REQUIRED_ASSESSMENT_SURFACES.map((surface) => [surface, [runtime]])) as Record<AssessmentSurface, readonly string[]>,
  };
}

function accuracyResult(surface: AssessmentSurface, os: string, cpu: string, runtime: string): AssessmentResult {
  return {
    schemaVersion: "3", surface, profileId: "accuracy-corpus",
    accuracy: { ...ACCURACY },
    provenance: {
      commit: "2".repeat(40), artifactIdentity: `${surface}@synthetic`,
      corpusVersion: ACCURACY_CORPUS.version, corpusHash: ACCURACY_CORPUS.hash,
      os, cpu, runtime, command: `synthetic-${surface}-accuracy`, buildProfile: "release",
    },
  };
}

function performanceResult(surface: AssessmentSurface, profileId: string, os: string, cpu: string, runtime: string, repetitions: number): AssessmentResult {
  const fill = (value: number) => Array(repetitions).fill(value) as number[];
  return {
    schemaVersion: "3", surface, profileId,
    performance: {
      initialization: { unit: "milliseconds", samples: fill(1), minimum: 1, median: 1, p95: 2, maximum: 2, mean: 1, standardDeviation: 0.5 },
      processing: { unit: "milliseconds", samples: fill(3), minimum: 3, median: 3, p95: 4, maximum: 4, mean: 3, standardDeviation: 0.5 },
      throughput: { unit: "bytes-per-second", samples: fill(6), minimum: 6, median: 6, p95: 7, maximum: 7, mean: 6, standardDeviation: 0.5 },
      memory: memory({ processRss: fill(0).map(() => ({ baselineBytes: 500, maximumObservedBytes: 1000 })) }),
    },
    provenance: {
      commit: "2".repeat(40), artifactIdentity: `${surface}@synthetic`,
      corpusVersion: WORKLOAD_PROFILES.version, corpusHash: WORKLOAD_PROFILES.hash,
      os, cpu, runtime, command: `synthetic-${surface}-${profileId}`,
      buildProfile: "release",
    },
  };
}

function candidate(os: string, cpu: string, runtime: string, repetitions = 2): CompleteAssessment {
  const runs: CompleteAssessmentRun[] = REQUIRED_ASSESSMENT_SURFACES.flatMap((surface) => [
    {
      surface, kind: "accuracy" as const, profileId: "accuracy-corpus", path: "whole-input" as const, status: "complete" as const,
      resultPath: `${surface}/accuracy.json`, markdownPath: `${surface}/accuracy.md`,
      result: accuracyResult(surface, os, cpu, runtime),
    },
    ...PROFILES.map((profile) => ({
      surface, kind: "performance" as const, profileId: profile.id, path: "whole-input" as const, status: "complete" as const,
      resultPath: `${surface}/${profile.id}.json`, markdownPath: `${surface}/${profile.id}.md`,
      result: performanceResult(surface, profile.id, os, cpu, runtime, repetitions),
    })),
  ]);
  return {
    schemaVersion: "1", status: "complete", sourceCommit: "2".repeat(40),
    accuracyCorpus: ACCURACY_CORPUS, workloadProfiles: WORKLOAD_PROFILES,
    repetitions, performanceProfiles: PROFILES.map((profile) => ({ id: profile.id, chunkProfile: "whole" })),
    requiredSurfaces: REQUIRED_ASSESSMENT_SURFACES, runs, validationFailures: [],
  };
}

function criteria(id: string, os: string, cpu: string, runtime: string): AcceptanceCriteria {
  return validateAcceptanceCriteria({
    schemaVersion: "1", criteriaId: id, fixedAt: "2026-09-22",
    baseline: {
      summaryPath: "assessment-output/summary.json", sourceCommit: "2".repeat(40),
      accuracyCorpusVersion: ACCURACY_CORPUS.version, accuracyCorpusHash: ACCURACY_CORPUS.hash,
      workloadProfilesVersion: WORKLOAD_PROFILES.version, workloadProfilesHash: WORKLOAD_PROFILES.hash,
    },
    minimumRepetitions: 2,
    environment: environment(id, os, cpu, runtime),
    accuracy: { ...ACCURACY },
    performance: REQUIRED_ASSESSMENT_SURFACES.flatMap((surface) => PROFILES.map((profile) => ({
      surface, profileId: profile.id,
      maxInitializationP95Ms: 10, maxProcessingP95Ms: 10, minThroughputBytesPerSecond: 1,
      memoryCapsBytes: { processRss: 10_000 },
    }))),
  });
}

const PROFILE_A = criteria("env-a", "test-os-a", "test-cpu-a", "test-runtime-a");
const PROFILE_B = criteria("env-b", "test-os-b", "test-cpu-b", "test-runtime-b");
const CANDIDATE_A = candidate("test-os-a", "test-cpu-a", "test-runtime-a");
const CANDIDATE_B = candidate("test-os-b", "test-cpu-b", "test-runtime-b");

describe("acceptance criteria", () => {
  test("is a separately identified, separately loaded profile that does not touch a second one", () => {
    expect(PROFILE_A.criteriaId).not.toBe(PROFILE_B.criteriaId);
    expect(PROFILE_A.environment.id).not.toBe(PROFILE_B.environment.id);
  });

  test("an in-spec candidate is accepted", () => {
    const evaluation = evaluateAcceptance(CANDIDATE_A, PROFILE_A);
    expect(evaluation.status).toBe("accepted");
    expect(evaluation.failures).toEqual([]);
    expect(evaluation.checks).toHaveLength(REQUIRED_ASSESSMENT_SURFACES.length * PROFILES.length * 4);
    expect(evaluation.checks.every((item) => item.passed)).toBe(true);
  });

  test("a rust-core performance run built without --release cannot bypass release-build evidence", () => {
    const input = candidate("test-os-a", "test-cpu-a", "test-runtime-a");
    const runs = [...input.runs];
    const index = runs.findIndex((run) => run.surface === "rust-core" && run.kind === "performance" && run.profileId === "scale-logs-small-whole");
    const result = runs[index].result!;
    runs[index] = { ...runs[index], result: { ...result, provenance: { ...result.provenance, buildProfile: undefined } } };
    const evaluation = evaluateAcceptance({ ...input, runs }, PROFILE_A);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures).toContain("rust-core:performance:scale-logs-small-whole:release-build-required");
    expect(evaluation.checks.some((item) => item.key.startsWith("rust-core:performance:scale-logs-small-whole"))).toBe(false);
  });

  test("rejects performance, resource, environment, and accuracy regressions", () => {
    const input = candidate("test-os-a", "test-cpu-a", "test-runtime-a");
    const runs = [...input.runs];
    const index = runs.findIndex((run) => run.surface === "node" && run.profileId === "scale-logs-small-whole");
    const result = runs[index].result!;
    runs[index] = {
      ...runs[index],
      result: {
        ...result,
        provenance: { ...result.provenance, cpu: "unexpected-cpu" },
        performance: {
          ...result.performance!,
          processing: { ...result.performance!.processing, p95: 999 },
          memory: { ...result.performance!.memory, processRss: { ...result.performance!.memory.processRss, samples: [] } },
        },
      },
    };
    const accuracyIndex = runs.findIndex((run) => run.surface === "python" && run.kind === "accuracy");
    runs[accuracyIndex] = {
      ...runs[accuracyIndex],
      result: { ...runs[accuracyIndex].result!, accuracy: { ...runs[accuracyIndex].result!.accuracy!, policyMismatches: 1 } },
    };
    const evaluation = evaluateAcceptance({ ...input, runs }, PROFILE_A);
    expect(evaluation.status).toBe("rejected");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:environment-cpu-mismatch");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met");
    expect(evaluation.failures).toContain("node:performance:scale-logs-small-whole:memory-processRss:insufficient-samples");
    expect(evaluation.failures).toContain("python:accuracy:accuracy-corpus:policyMismatches-mismatch");
  });

  test("rejects incomplete, under-repeated, or identity-drifted evidence", () => {
    const input = candidate("test-os-a", "test-cpu-a", "test-runtime-a");
    const evaluation = evaluateAcceptance({
      ...input,
      status: "incomplete",
      repetitions: 1,
      workloadProfiles: { version: "1", hash: "f".repeat(64) },
    }, PROFILE_A);
    expect(evaluation.failures).toContain("suite:assessment-incomplete");
    expect(evaluation.failures).toContain("suite:insufficient-repetitions");
    expect(evaluation.failures).toContain("suite:workload-profile-identity-mismatch");
  });

  test("a candidate shaped for one environment profile cannot silently satisfy another", () => {
    const crossedToB = evaluateAcceptance(CANDIDATE_A, PROFILE_B);
    expect(crossedToB.status).toBe("rejected");
    expect(crossedToB.failures.some((failure) => failure.endsWith(":environment-os-mismatch"))).toBe(true);

    const crossedToA = evaluateAcceptance(CANDIDATE_B, PROFILE_A);
    expect(crossedToA.status).toBe("rejected");
    expect(crossedToA.failures.some((failure) => failure.endsWith(":environment-os-mismatch"))).toBe(true);
  });
});
