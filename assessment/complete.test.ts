import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import {
  buildCompleteAssessment,
  renderCompleteAssessmentMarkdown,
  REQUIRED_ASSESSMENT_SURFACES,
  type AssessmentAttempt,
} from "./complete.js";
import {
  validateAssessmentResults,
  type AssessmentResult,
  type AssessmentSurface,
} from "./schema.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const PROFILES = [
  { id: "scale-logs-small-whole", chunkProfile: "whole" },
  { id: "scale-logs-medium-fixed4096", chunkProfile: "fixed-4096" },
] as const;

function memory() {
  const unavailable = { unit: "bytes" as const, samples: [], unavailableReason: "not available", samplingLimit: "no samples" };
  return {
    nodeHeap: unavailable, nodeRss: unavailable, nodeExternal: unavailable,
    browserJsHeap: unavailable, wasmLinearMemory: unavailable, pythonHeap: unavailable,
    processRss: unavailable, streamingBuffer: unavailable,
  };
}

function result(surface: AssessmentSurface, profileId: string, kind: "accuracy" | "performance", hash = "a".repeat(64)): AssessmentResult {
  const provenance = {
    commit: "1".repeat(40), artifactIdentity: `${surface}@synthetic`, corpusVersion: "1",
    corpusHash: hash, os: "test-os", cpu: "test-cpu", runtime: "test-runtime",
    command: `synthetic-${surface}-${profileId}`,
  };
  return kind === "accuracy" ? {
    schemaVersion: "3", surface, profileId,
    accuracy: { truePositives: 1, falsePositives: 0, falseNegatives: 0, policyMismatches: 0 },
    provenance,
  } : {
    schemaVersion: "3", surface, profileId,
    performance: {
      initialization: { unit: "milliseconds", samples: [1, 2], minimum: 1, median: 1.5, p95: 2, maximum: 2, mean: 1.5, standardDeviation: 0.5 },
      processing: { unit: "milliseconds", samples: [3, 4], minimum: 3, median: 3.5, p95: 4, maximum: 4, mean: 3.5, standardDeviation: 0.5 },
      throughput: { unit: "bytes-per-second", samples: [5, 6], minimum: 5, median: 5.5, p95: 6, maximum: 6, mean: 5.5, standardDeviation: 0.5 },
      memory: memory(),
    },
    provenance,
  };
}

function completeAttempts(): AssessmentAttempt[] {
  return REQUIRED_ASSESSMENT_SURFACES.flatMap((surface) => [
    {
      surface, kind: "accuracy" as const, profileId: "accuracy-corpus",
      resultPath: `${surface}/accuracy.json`, markdownPath: `${surface}/accuracy.md`,
      result: result(surface, "accuracy-corpus", "accuracy", "a".repeat(64)),
    },
    ...PROFILES.map((profile) => ({
      surface, kind: "performance" as const, profileId: profile.id,
      resultPath: `${surface}/${profile.id}.json`, markdownPath: `${surface}/${profile.id}.md`,
      result: result(surface, profile.id, "performance", "b".repeat(64)),
    })),
  ]);
}

describe("complete assessment aggregation", () => {
  test("requires every surface and preserves whole and incremental evidence", () => {
    const aggregate = buildCompleteAssessment({ attempts: completeAttempts(), performanceProfiles: PROFILES, repetitions: 2 });
    expect(aggregate.status).toBe("complete");
    expect(aggregate.runs).toHaveLength(15);
    expect(aggregate.runs.find((run) => run.surface === "node" && run.profileId === PROFILES[1].id)?.path).toBe("incremental");
    expect(aggregate.runs.find((run) => run.surface === "cli" && run.profileId === PROFILES[1].id)?.path).toBe("standard-input");
    expect(renderCompleteAssessmentMarkdown(aggregate)).toContain("Status: **COMPLETE**");
  });

  test("the committed baseline is complete, schema-valid, and fully linked", () => {
    const baselinePath = join(HERE, "results", "complete", "summary.json");
    const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as {
      status: string;
      validationFailures: readonly string[];
      runs: readonly AssessmentAttempt[];
    };
    expect(baseline.status).toBe("complete");
    expect(baseline.validationFailures).toEqual([]);
    expect(baseline.runs).toHaveLength(15);
    for (const run of baseline.runs) {
      expect(run.result).toBeDefined();
      expect(() => validateAssessmentResults([run.result!])).not.toThrow();
      expect(existsSync(join(HERE, "results", "complete", run.resultPath))).toBe(true);
      expect(existsSync(join(HERE, "results", "complete", run.markdownPath))).toBe(true);
      if (run.mismatchesPath !== undefined) {
        expect(existsSync(join(HERE, "results", "complete", run.mismatchesPath))).toBe(true);
      }
    }
  });

  test("a missing or failed product surface makes the aggregate incomplete", () => {
    const withoutBrowser = completeAttempts().filter((attempt) => attempt.surface !== "browser-wasm");
    const missing = buildCompleteAssessment({ attempts: withoutBrowser, performanceProfiles: PROFILES, repetitions: 2 });
    expect(missing.status).toBe("incomplete");
    expect(missing.validationFailures).toContain("browser-wasm:accuracy:accuracy-corpus:missing-run");

    const failed = completeAttempts();
    failed[0] = { ...failed[0], result: undefined, failureCode: "runner-failed" };
    expect(buildCompleteAssessment({ attempts: failed, performanceProfiles: PROFILES, repetitions: 2 }).status).toBe("incomplete");
  });

  test("identity drift and incomplete repetition samples cannot report completion", () => {
    const attempts = completeAttempts();
    const pythonAccuracy = attempts.findIndex((attempt) => attempt.surface === "python" && attempt.kind === "accuracy");
    attempts[pythonAccuracy] = {
      ...attempts[pythonAccuracy],
      result: result("python", "accuracy-corpus", "accuracy", "c".repeat(64)),
    };
    const nodePerformance = attempts.findIndex((attempt) => attempt.surface === "node" && attempt.kind === "performance");
    const original = attempts[nodePerformance].result!;
    attempts[nodePerformance] = {
      ...attempts[nodePerformance],
      result: {
        ...original,
        performance: {
          ...original.performance!,
          initialization: {
            ...original.performance!.initialization,
            samples: [1], minimum: 1, median: 1, p95: 1, maximum: 1, mean: 1,
            standardDeviation: 0,
          },
          processing: {
            ...original.performance!.processing,
            samples: [3], minimum: 3, median: 3, p95: 3, maximum: 3, mean: 3,
            standardDeviation: 0,
          },
          throughput: {
            ...original.performance!.throughput,
            samples: [5], minimum: 5, median: 5, p95: 5, maximum: 5, mean: 5,
            standardDeviation: 0,
          },
        },
      },
    };
    const aggregate = buildCompleteAssessment({ attempts, performanceProfiles: PROFILES, repetitions: 2 });
    expect(aggregate.status).toBe("incomplete");
    expect(aggregate.validationFailures).toContain("suite:accuracy-corpus-identity-mismatch");
    expect(aggregate.validationFailures.some((failure) => failure.endsWith("repetition-count-mismatch"))).toBe(true);
  });
});
