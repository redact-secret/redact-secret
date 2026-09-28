import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import {
  ACCURACY_MAX_INPUT_BYTES,
  utf8ByteLength,
  validateAssessmentFixtures,
  validateAssessmentResults,
  validateAssessmentWorkloadProfiles,
  type AssessmentFixture,
  type AssessmentResult,
  type AssessmentWorkloadProfile,
} from "./schema.js";
import { GENERATOR_ALGORITHM, generateWorkloadInput } from "./generate.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

function readJson<T>(...segments: readonly string[]): T {
  return JSON.parse(readFileSync(path.join(ROOT, ...segments), "utf-8")) as T;
}

const accuracyCorpus = readJson<{
  fixtureCount: number;
  fixtures: readonly AssessmentFixture[];
}>("assessment", "fixtures", "accuracy-corpus.json");
const workloadProfiles = readJson<{
  profileCount: number;
  profiles: readonly AssessmentWorkloadProfile[];
}>("assessment", "fixtures", "workload-profiles.json");
const resultExamples = readJson<{
  resultCount: number;
  results: readonly AssessmentResult[];
}>("assessment", "fixtures", "result-contract-examples.json");

describe("assessment fixture files validate against the assessment schema", () => {
  test("accuracy-corpus.json", () => {
    expect(() => validateAssessmentFixtures(accuracyCorpus.fixtures)).not.toThrow();
    expect(accuracyCorpus.fixtures.length).toBe(accuracyCorpus.fixtureCount);
  });

  test("workload-profiles.json", () => {
    expect(() => validateAssessmentWorkloadProfiles(workloadProfiles.profiles)).not.toThrow();
    expect(workloadProfiles.profiles.length).toBe(workloadProfiles.profileCount);
  });

  test("result-contract-examples.json", () => {
    expect(() => validateAssessmentResults(resultExamples.results)).not.toThrow();
    expect(resultExamples.results.length).toBe(resultExamples.resultCount);
  });

  test("every accuracy fixture category is represented", () => {
    const categories = new Set(accuracyCorpus.fixtures.map((f) => f.category));
    expect(categories).toEqual(new Set(["logs", "code", "chat", "negative-text"]));
  });

  test("every chunk profile is exercised by some workload profile", () => {
    const chunkProfiles = new Set(workloadProfiles.profiles.map((p) => p.chunkProfile));
    expect(chunkProfiles).toEqual(
      new Set(["whole", "fixed-1024", "fixed-4096", "fixed-65536", "utf16-boundary"]),
    );
  });

  test("schema.json parses and declares the assessment $id", () => {
    const raw = readFileSync(path.join(ROOT, "assessment", "schema.json"), "utf-8");
    const parsed = JSON.parse(raw) as { $id: string };
    expect(parsed.$id).toBe(
      "https://github.com/redact-secret/redact-secret/assessment/schema.json",
    );
  });
});

/** A minimal, otherwise-valid assessment fixture a rejection test can mutate
 * one field of at a time. Offsets are computed from the literal parts rather
 * than hardcoded so an edit to either string cannot silently desync them. */
function baseFixture(): AssessmentFixture {
  const prefix = "token=";
  const body = "ghp_ASSESSMENTSYNTHETIC0000000000000000";
  return {
    id: "schema-test-base",
    category: "logs",
    unicode: false,
    input: `${prefix}${body}`,
    expected: [
      {
        detector: "github-token",
        type: "github_token",
        confidence: "high",
        specificity: "provider",
        start: prefix.length,
        end: prefix.length + body.length,
        policyOutcome: "redact",
      },
    ],
    note: "schema validator test fixture",
  };
}

describe("validateAssessmentFixtures (issue #192)", () => {
  test("accepts a well-formed fixture", () => {
    expect(() => validateAssessmentFixtures([baseFixture()])).not.toThrow();
  });

  test("rejects an expectation carrying a forbidden extra key", () => {
    const fixture = baseFixture();
    const tampered = {
      ...fixture,
      expected: [{ ...fixture.expected[0], matchedValue: "SYNTHETIC" }],
    } as unknown as AssessmentFixture;
    expect(() => validateAssessmentFixtures([tampered])).toThrow(
      /plaintext-bearing-expectation/,
    );
  });

  test("rejects an invalid policy outcome", () => {
    const fixture = baseFixture();
    const tampered = {
      ...fixture,
      expected: [{ ...fixture.expected[0], policyOutcome: "quarantine" }],
    } as unknown as AssessmentFixture;
    expect(() => validateAssessmentFixtures([tampered])).toThrow(/invalid-expectation/);
  });

  test("rejects a negative-text fixture that carries a finding", () => {
    const fixture = baseFixture();
    const tampered: AssessmentFixture = { ...fixture, category: "negative-text" };
    expect(() => validateAssessmentFixtures([tampered])).toThrow(
      /negative-text-with-finding/,
    );
  });

  test("rejects overlapping expectations", () => {
    const fixture = baseFixture();
    const only = fixture.expected[0];
    const tampered: AssessmentFixture = {
      ...fixture,
      expected: [only, { ...only, start: only.start + 1 }],
    };
    expect(() => validateAssessmentFixtures([tampered])).toThrow(/invalid-expectation/);
  });

  test("rejects a duplicate fixture id", () => {
    const fixture = baseFixture();
    expect(() => validateAssessmentFixtures([fixture, fixture])).toThrow(/invalid-id/);
  });
});

/** A minimal, otherwise-valid workload profile a rejection test can mutate
 * one field of at a time. */
function baseProfile(): AssessmentWorkloadProfile {
  return {
    id: "schema-test-scale",
    purpose: "scale",
    category: "logs",
    targetInputBytes: ACCURACY_MAX_INPUT_BYTES + 1,
    targetDensityPerKiB: 1,
    chunkProfile: "fixed-4096",
    unicodeMix: false,
    generatorAlgorithm: GENERATOR_ALGORITHM,
    note: "schema validator test profile",
  };
}

describe("validateAssessmentWorkloadProfiles (issue #192)", () => {
  test("accepts a well-formed scale profile", () => {
    expect(() => validateAssessmentWorkloadProfiles([baseProfile()])).not.toThrow();
  });

  test("accepts a well-formed accuracy profile", () => {
    const profile: AssessmentWorkloadProfile = {
      ...baseProfile(),
      id: "schema-test-accuracy",
      purpose: "accuracy",
      targetInputBytes: ACCURACY_MAX_INPUT_BYTES,
      chunkProfile: "whole",
    };
    expect(() => validateAssessmentWorkloadProfiles([profile])).not.toThrow();
  });

  test("rejects an accuracy profile larger than the minimal-size cap", () => {
    const profile: AssessmentWorkloadProfile = {
      ...baseProfile(),
      purpose: "accuracy",
      chunkProfile: "whole",
    };
    expect(() => validateAssessmentWorkloadProfiles([profile])).toThrow(
      /accuracy-profile-exceeds-minimal-size/,
    );
  });

  test("rejects an accuracy profile that is not whole-chunked", () => {
    const profile: AssessmentWorkloadProfile = {
      ...baseProfile(),
      purpose: "accuracy",
      targetInputBytes: ACCURACY_MAX_INPUT_BYTES,
    };
    expect(() => validateAssessmentWorkloadProfiles([profile])).toThrow(
      /accuracy-profile-must-be-whole-chunked/,
    );
  });

  test("rejects a scale profile at or under the accuracy cap", () => {
    const profile: AssessmentWorkloadProfile = {
      ...baseProfile(),
      targetInputBytes: ACCURACY_MAX_INPUT_BYTES,
    };
    expect(() => validateAssessmentWorkloadProfiles([profile])).toThrow(
      /scale-profile-not-larger-than-accuracy-cap/,
    );
  });

  test("rejects a duplicate profile id", () => {
    const profile = baseProfile();
    expect(() => validateAssessmentWorkloadProfiles([profile, profile])).toThrow(
      /invalid-id/,
    );
  });
});

/** A minimal, otherwise-valid result-contract record a rejection test can
 * mutate one field of at a time. */
function baseResult(): AssessmentResult {
  return {
    schemaVersion: "3",
    surface: "rust-core",
    profileId: "schema-test-scale",
    performance: {
      initialization: {
        unit: "milliseconds", samples: [1], minimum: 1, median: 1, p95: 1,
        maximum: 1, mean: 1, standardDeviation: 0,
      },
      processing: {
        unit: "milliseconds", samples: [2], minimum: 2, median: 2, p95: 2,
        maximum: 2, mean: 2, standardDeviation: 0,
      },
      throughput: {
        unit: "bytes-per-second", samples: [1000], minimum: 1000, median: 1000,
        p95: 1000, maximum: 1000, mean: 1000, standardDeviation: 0,
      },
      memory: {
        nodeHeap: {
          unit: "bytes", samples: [{ baselineBytes: 1024, maximumObservedBytes: 2048 }],
          samplingLimit: "sampled at operation boundaries",
        },
        nodeRss: {
          unit: "bytes", samples: [], unavailableReason: "not this surface",
          samplingLimit: "no samples",
        },
        nodeExternal: {
          unit: "bytes", samples: [], unavailableReason: "not this surface",
          samplingLimit: "no samples",
        },
        browserJsHeap: {
          unit: "bytes", samples: [], unavailableReason: "not this surface",
          samplingLimit: "no samples",
        },
        wasmLinearMemory: {
          unit: "bytes", samples: [], unavailableReason: "not exposed",
          samplingLimit: "no samples",
        },
        pythonHeap: {
          unit: "bytes", samples: [], unavailableReason: "not this surface",
          samplingLimit: "no samples",
        },
        processRss: {
          unit: "bytes", samples: [], unavailableReason: "not this surface",
          samplingLimit: "no samples",
        },
        streamingBuffer: {
          unit: "bytes", samples: [], unavailableReason: "not exposed",
          samplingLimit: "no samples",
        },
      },
    },
    provenance: {
      commit: "0123456789abcdef0123456789abcdef01234567",
      artifactIdentity: "redact-secret@0.1.0-beta.1",
      corpusVersion: "1",
      corpusHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      os: "linux-6.8",
      cpu: "x86_64",
      runtime: "rustc-1.88.0",
      command: "cargo test --release -p secret-scan-core --test assessment_scale",
    },
  };
}

describe("validateAssessmentResults (issue #192)", () => {
  test("accepts a well-formed result", () => {
    expect(() => validateAssessmentResults([baseResult()])).not.toThrow();
  });

  test("rejects a result carrying neither accuracy nor performance", () => {
    const { performance: _performance, ...rest } = baseResult();
    expect(() => validateAssessmentResults([rest as AssessmentResult])).toThrow(
      /invalid-metadata/,
    );
  });

  test("accepts a recorded resolved artifact and rejects an unknown one (benchmarks #405/#415)", () => {
    const result = baseResult();
    for (const resolvedArtifact of ["node-addon", "wasm"] as const) {
      expect(() => validateAssessmentResults([{ ...result, provenance: { ...result.provenance, resolvedArtifact } }])).not.toThrow();
    }
    const tampered = { ...result, provenance: { ...result.provenance, resolvedArtifact: "addon" } } as unknown as AssessmentResult;
    expect(() => validateAssessmentResults([tampered])).toThrow(/invalid-provenance/);
  });

  test("rejects a malformed commit", () => {
    const result = baseResult();
    const tampered: AssessmentResult = {
      ...result,
      provenance: { ...result.provenance, commit: "not-a-sha" },
    };
    expect(() => validateAssessmentResults([tampered])).toThrow(/invalid-provenance/);
  });

  test("rejects a negative metric", () => {
    const result = baseResult();
    const tampered: AssessmentResult = {
      ...result,
      performance: {
        ...result.performance!,
        processing: { ...result.performance!.processing, samples: [-1] },
      },
    };
    expect(() => validateAssessmentResults([tampered])).toThrow(
      /invalid-performance-metrics/,
    );
  });

  test("rejects inconsistent units and repetition counts", () => {
    const result = baseResult();
    expect(() => validateAssessmentResults([{
      ...result,
      performance: {
        ...result.performance!,
        throughput: {
          ...result.performance!.throughput,
          unit: "milliseconds",
          samples: [1000, 1001],
        },
      },
    }])).toThrow(/invalid-performance-metrics/);
  });

  test("rejects unavailable memory without a reason and sampled maxima below baseline", () => {
    const result = baseResult();
    const noReason = {
      ...result,
      performance: {
        ...result.performance!,
        memory: {
          ...result.performance!.memory,
          nodeRss: { unit: "bytes" as const, samples: [], samplingLimit: "none" },
        },
      },
    };
    expect(() => validateAssessmentResults([noReason])).toThrow(/invalid-performance-metrics/);

    const descending = {
      ...result,
      performance: {
        ...result.performance!,
        memory: {
          ...result.performance!.memory,
          nodeHeap: {
            unit: "bytes" as const,
            samples: [{ baselineBytes: 20, maximumObservedBytes: 19 }],
            samplingLimit: "boundary",
          },
        },
      },
    };
    expect(() => validateAssessmentResults([descending])).toThrow(/invalid-performance-metrics/);
  });
});

describe("generateWorkloadInput determinism and safety (issue #192)", () => {
  test("known answer: zero density emits only filler, no synthetic secret", () => {
    const profile: AssessmentWorkloadProfile = {
      id: "known-answer-filler-only",
      purpose: "accuracy",
      category: "negative-text",
      targetInputBytes: 1,
      targetDensityPerKiB: 0,
      chunkProfile: "whole",
      unicodeMix: false,
      generatorAlgorithm: GENERATOR_ALGORITHM,
      note: "known-answer case",
    };
    expect(generateWorkloadInput(profile)).toBe(
      "The quick brown fox jumps over the lazy dog near the old fixture barn.\n",
    );
  });

  test("known answer: overwhelming density emits only the synthetic secret line", () => {
    const profile: AssessmentWorkloadProfile = {
      id: "known-answer-secret-only",
      purpose: "scale",
      category: "logs",
      targetInputBytes: 1,
      targetDensityPerKiB: 1_000_000,
      chunkProfile: "whole",
      unicodeMix: false,
      generatorAlgorithm: GENERATOR_ALGORITHM,
      note: "known-answer case",
    };
    expect(generateWorkloadInput(profile)).toBe(
      "token=ghp_ASSESSMENTSYNTHETIC0000000000000000\n",
    );
  });

  for (const profile of workloadProfiles.profiles) {
    test(`${profile.id}: regenerating is byte-identical and meets its target size`, () => {
      const first = generateWorkloadInput(profile);
      const second = generateWorkloadInput(profile);
      expect(first).toBe(second);
      expect(utf8ByteLength(first)).toBeGreaterThanOrEqual(profile.targetInputBytes);
    });
  }
});
