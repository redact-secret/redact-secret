import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import {
  utf8ByteLength,
  validateCanonicalCoverageDeclarations,
  validateCanonicalErrorCodes,
  validateCanonicalFixtures,
  validateCanonicalIncrementalFixtures,
  validateCanonicalLifecycleFixtures,
  type CanonicalCoverageContext,
  type CanonicalCoverageDeclaration,
  type CanonicalErrorCode,
  type CanonicalFixture,
  type CanonicalIncrementalFixture,
  type CanonicalLifecycleFixture,
} from "./schema.js";
import {
  GITHUB_CLASSIC_SEED_ID,
  generateGithubClassicMutations,
} from "./fixtures/github-classic-mutations.js";
import {
  DOCKER_TOKEN_EXACT_LENGTH_SEED_ID,
  generateDockerTokenMutations,
} from "./fixtures/docker-token-mutations.js";
import {
  DIGITALOCEAN_V1_SEED_ID,
  generateDigitaloceanV1Mutations,
} from "./fixtures/digitalocean-v1-mutations.js";
import {
  HUGGINGFACE_TOKEN_EXACT_LENGTH_SEED_ID,
  generateHuggingFaceTokenMutations,
} from "./fixtures/huggingface-token-mutations.js";
import {
  CLOUDFLARE_TOKEN_CHECKSUM_SUFFIX_SEED_ID,
  generateCloudflareTokenMutations,
} from "./fixtures/cloudflare-token-mutations.js";
import {
  LINEAR_TOKEN_API_EXACT_LENGTH_SEED_ID,
  generateLinearTokenMutations,
} from "./fixtures/linear-token-mutations.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

function readJson<T>(...segments: readonly string[]): T {
  return JSON.parse(readFileSync(path.join(ROOT, ...segments), "utf-8")) as T;
}

const manifest = readJson<{
  types: readonly { detector: string; type: string }[];
  consumers: readonly { path: string }[];
}>("docs", "coverage", "detector-inventory.json");
const corpus = readJson<{ fixtures: readonly CanonicalFixture[] }>(
  "conformance",
  "fixtures",
  "synchronous-corpus.json",
);
const incrementalCorpus = readJson<{ fixtures: readonly CanonicalIncrementalFixture[] }>(
  "conformance",
  "fixtures",
  "incremental-corpus.json",
);
const lifecycleCorpus = readJson<{ fixtures: readonly CanonicalLifecycleFixture[] }>(
  "conformance",
  "fixtures",
  "incremental-lifecycle-corpus.json",
);
const unicodeCorpus = readJson<{ fixtures: readonly CanonicalFixture[] }>(
  "conformance",
  "fixtures",
  "unicode-conversion-corpus.json",
);
const errorCodesDoc = readJson<{ codes: readonly CanonicalErrorCode[] }>(
  "conformance",
  "fixtures",
  "error-codes.json",
);
const coverageDeclarations = readJson<{ declarations: readonly CanonicalCoverageDeclaration[] }>(
  "docs",
  "coverage",
  "coverage-declarations.json",
);

function realContext(): CanonicalCoverageContext {
  return {
    knownDetectors: new Set(manifest.types.map((entry) => entry.detector)),
    knownDetectorTypes: new Set(
      manifest.types.map((entry) => `${entry.detector}:${entry.type}`),
    ),
    knownConsumerPaths: new Set(manifest.consumers.map((consumer) => consumer.path)),
    // Every fixture id is a legitimate citation regardless of `support`
    // state -- an `intentionally-unsupported` boundary fixture is itself
    // evidence, not a gap (evidence-requirements.md §2). This set only
    // guards against citing an id that does not exist.
    knownEvidenceIds: new Set([
      ...corpus.fixtures.map((f) => f.id),
      ...unicodeCorpus.fixtures.map((f) => f.id),
      ...incrementalCorpus.fixtures.map((f) => f.id),
      ...lifecycleCorpus.fixtures.map((f) => f.id),
      ...errorCodesDoc.codes.map((c) => c.code),
    ]),
  };
}

/** A minimal, otherwise-valid provider row a rejection test can mutate one
 * field of at a time. */
function baseRow(): CanonicalCoverageDeclaration {
  return {
    type: "github_token",
    detector: "github-token",
    behaviorClass: "provider",
    dimensions: [
      { dimension: "positive", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      { dimension: "near-miss-negative", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      { dimension: "boundary", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      { dimension: "malformed", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      { dimension: "overlap", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      {
        dimension: "host-context",
        state: "supported",
        evidenceFixtureIds: ["github-positive-classic"],
        classLevel: true,
      },
      {
        dimension: "range",
        state: "supported",
        evidenceFixtureIds: ["unicode-conversion-astral-before"],
        classLevel: true,
      },
      { dimension: "adversarial", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
    ],
    note: "test row",
  };
}

describe("canonical fixture files validate against the canonical schema", () => {
  test("synchronous-corpus.json", () => {
    expect(() => validateCanonicalFixtures(corpus.fixtures)).not.toThrow();
  });

  test("unicode-conversion-corpus.json", () => {
    expect(() => validateCanonicalFixtures(unicodeCorpus.fixtures)).not.toThrow();
  });

  test("incremental-corpus.json", () => {
    expect(() => validateCanonicalIncrementalFixtures(incrementalCorpus.fixtures)).not.toThrow();
  });

  test("incremental-lifecycle-corpus.json", () => {
    expect(() => validateCanonicalLifecycleFixtures(lifecycleCorpus.fixtures)).not.toThrow();
  });

  test("error-codes.json", () => {
    expect(() => validateCanonicalErrorCodes(errorCodesDoc.codes)).not.toThrow();
  });
});

/** A minimal, otherwise-valid canonical fixture a rejection test can mutate
 * one field of at a time. Offsets are computed from the literal parts rather
 * than hardcoded so an edit to either string cannot silently desync them. */
function baseFixture(): CanonicalFixture {
  const prefix = "TOKEN_VALUE=";
  const body = "abcdefghijklmnopqrstuvwxyz012345";
  return {
    id: "schema-test-base",
    detector: "generic-token",
    kind: "positive",
    support: "supported",
    tier: "canonical",
    contexts: ["plain-text"],
    input: `${prefix}${body}`,
    expected: [
      {
        detector: "generic-token",
        type: "generic_token",
        confidence: "high",
        specificity: "structural",
        start: prefix.length,
        end: prefix.length + body.length,
      },
    ],
    note: "schema validator test fixture",
  };
}

describe("validateCanonicalFixtures (issue #116)", () => {
  test("accepts a well-formed fixture", () => {
    expect(() => validateCanonicalFixtures([baseFixture()])).not.toThrow();
  });

  test("rejects an expectation carrying a forbidden extra key", () => {
    const fixture = baseFixture();
    const tampered = {
      ...fixture,
      expected: [{ ...fixture.expected![0], matchedValue: "SYNTHETIC" }],
    } as unknown as CanonicalFixture;
    expect(() => validateCanonicalFixtures([tampered])).toThrow(
      /plaintext-bearing-expectation/,
    );
  });

  test("rejects invalid mutation provenance", () => {
    const fixture = baseFixture();
    const tampered: CanonicalFixture = {
      ...fixture,
      mutation: {
        grammar: "github-classic",
        seedId: GITHUB_CLASSIC_SEED_ID,
        operation: "identity",
        ordinal: -1,
      },
    };
    expect(() => validateCanonicalFixtures([tampered])).toThrow(
      /invalid-mutation-provenance/,
    );
  });

  test("rejects a resource expectation smaller than the actual input", () => {
    const fixture = baseFixture();
    const adversarial: CanonicalFixture = {
      ...fixture,
      id: "schema-test-adversarial",
      kind: "adversarial",
      tier: "adversarial",
      resource: {
        maxInputBytes: utf8ByteLength(fixture.input) - 1,
        maxFindings: 1,
        maxRuntimeMs: 10,
      },
    };
    expect(() => validateCanonicalFixtures([adversarial])).toThrow(
      /invalid-resource-expectation/,
    );
  });

  test("rejects an adversarial-kind fixture with no resource expectation", () => {
    const fixture = baseFixture();
    const adversarial: CanonicalFixture = {
      ...fixture,
      id: "schema-test-adversarial",
      kind: "adversarial",
      tier: "adversarial",
    };
    expect(() => validateCanonicalFixtures([adversarial])).toThrow(
      /adversarial-without-resource-expectation/,
    );
  });

  test("rejects a positive fixture with no expected finding", () => {
    const fixture = baseFixture();
    const tampered: CanonicalFixture = { ...fixture, expected: [] };
    expect(() => validateCanonicalFixtures([tampered])).toThrow(
      /positive-without-finding/,
    );
  });

  test("rejects a negative fixture that carries a finding", () => {
    const fixture = baseFixture();
    const tampered: CanonicalFixture = {
      ...fixture,
      kind: "negative",
      tier: "negative",
    };
    expect(() => validateCanonicalFixtures([tampered])).toThrow(
      /excluded-with-finding/,
    );
  });

  test("rejects overlapping expectations", () => {
    const fixture = baseFixture();
    const only = fixture.expected![0];
    const tampered: CanonicalFixture = {
      ...fixture,
      expected: [only, { ...only, start: only.start + 1 }],
    };
    expect(() => validateCanonicalFixtures([tampered])).toThrow(
      /invalid-expectation/,
    );
  });

  test("rejects a duplicate fixture id", () => {
    const fixture = baseFixture();
    expect(() => validateCanonicalFixtures([fixture, fixture])).toThrow(
      /invalid-id/,
    );
  });
});

describe("validateCanonicalIncrementalFixtures rejects unsafe shapes (issue #116)", () => {
  test("rejects an expected entry carrying a forbidden extra key", () => {
    const fixture = baseFixture();
    const incremental = {
      id: "schema-test-incremental",
      input: fixture.input,
      text: fixture.input,
      expected: [{ ...fixture.expected![0], matchedValue: "SYNTHETIC" }],
      note: "test",
    } as unknown as CanonicalIncrementalFixture;
    expect(() => validateCanonicalIncrementalFixtures([incremental])).toThrow(
      /invalid-expectation/,
    );
  });
});

describe("validateCanonicalErrorCodes rejects unsafe shapes (issue #116)", () => {
  test("rejects a duplicate error code", () => {
    const entry: CanonicalErrorCode = {
      code: "SCHEMA_TEST_ERROR",
      message: "A fixed, input-free test message.",
      surface: "incremental",
    };
    expect(() => validateCanonicalErrorCodes([entry, entry])).toThrow(
      /invalid-code/,
    );
  });
});

/** One generator's mutation case shape: every `generate*Mutations()` function
 * returns this, `readonly` fields and all. */
interface GrammarMutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

interface GrammarMutationFamily {
  readonly grammar: string;
  readonly issue: string;
  readonly seedId: string;
  readonly generate: () => readonly GrammarMutationCase[];
  /**
   * A full positive/negative partition: every declared fixture's operation
   * must be a single supported positive when this returns `true`, and an
   * intentionally-unsupported non-match otherwise. Omitted for a grammar
   * whose fixtures do not reduce to that binary split (`github-classic`'s
   * own multi-shape boundary cases; `digitalocean-v1`'s context-embedding
   * operations, which are supported positives for a reason orthogonal to
   * its documented-prefix identity shapes — see `identityOperations`
   * below).
   */
  readonly isFullPartitionPositive?: (operation: string) => boolean;
  /**
   * Operations that must each be the grammar's single supported positive
   * match for one documented prefix — checked as a subset of `declared`,
   * not a full partition. The direct analogue of a full-partition
   * grammar's `identity` case, generalized to a grammar with more than one
   * documented-prefix identity shape (`digitalocean-v1`'s three prefixes).
   */
  readonly identityOperations?: readonly string[];
}

const GRAMMAR_MUTATION_FAMILIES: readonly GrammarMutationFamily[] = [
  {
    grammar: "github-classic",
    issue: "#116",
    seedId: GITHUB_CLASSIC_SEED_ID,
    generate: generateGithubClassicMutations,
  },
  {
    grammar: "docker-token-exact-length",
    issue: "#370",
    seedId: DOCKER_TOKEN_EXACT_LENGTH_SEED_ID,
    generate: generateDockerTokenMutations,
    isFullPartitionPositive: (operation) => operation.endsWith("-identity"),
  },
  {
    grammar: "digitalocean-v1",
    issue: "#369",
    seedId: DIGITALOCEAN_V1_SEED_ID,
    generate: generateDigitaloceanV1Mutations,
    identityOperations: ["identity", "oauth-access-prefix", "oauth-refresh-prefix"],
  },
  {
    grammar: "huggingface-token-exact-length",
    issue: "#372",
    seedId: HUGGINGFACE_TOKEN_EXACT_LENGTH_SEED_ID,
    generate: generateHuggingFaceTokenMutations,
    isFullPartitionPositive: (operation) => operation === "identity" || operation === "digit-bearing",
  },
  {
    grammar: "cloudflare-token-checksum-suffix",
    issue: "#373",
    seedId: CLOUDFLARE_TOKEN_CHECKSUM_SUFFIX_SEED_ID,
    generate: generateCloudflareTokenMutations,
    // Issue #481 added `account-token-prefix`, a second documented-prefix
    // identity shape (`cfat_`, alongside `cfut_`'s `identity`), so this no
    // longer reduces to a single-positive binary partition; the direct
    // analogue is `digitalocean-v1`'s `identityOperations` above.
    identityOperations: ["identity", "account-token-prefix"],
  },
  {
    grammar: "linear-token-api-exact-length",
    issue: "#374",
    seedId: LINEAR_TOKEN_API_EXACT_LENGTH_SEED_ID,
    generate: generateLinearTokenMutations,
    isFullPartitionPositive: (operation) => operation === "identity",
  },
];

describe.each(GRAMMAR_MUTATION_FAMILIES)(
  "$grammar mutation reproducibility (issue $issue)",
  ({ grammar, seedId, generate, isFullPartitionPositive, identityOperations }) => {
    function declaredFixtures(): readonly CanonicalFixture[] {
      return corpus.fixtures.filter((fixture) => fixture.mutation?.grammar === grammar);
    }

    test("every corpus fixture declaring this grammar reproduces byte-for-byte", () => {
      const generated = new Map(generate().map((mutation) => [mutation.ordinal, mutation]));
      const declared = declaredFixtures();

      expect(declared.length).toBe(generated.size);
      for (const fixture of declared) {
        const mutation = fixture.mutation!;
        const reproduced = generated.get(mutation.ordinal);
        expect(reproduced, `${fixture.id}: no generated case for ordinal ${mutation.ordinal}`)
          .toBeDefined();
        expect(mutation.seedId).toBe(seedId);
        expect(mutation.operation).toBe(reproduced!.operation);
        expect(fixture.input).toBe(reproduced!.input);
      }
    });

    test.runIf(isFullPartitionPositive !== undefined)(
      "each supported positive is exactly the operations this grammar's documented shape allows",
      () => {
        for (const fixture of declaredFixtures()) {
          const isPositive = isFullPartitionPositive!(fixture.mutation!.operation);
          expect(fixture.expected.length, fixture.id).toBe(isPositive ? 1 : 0);
          expect(fixture.support, fixture.id).toBe(
            isPositive ? "supported" : "intentionally-unsupported",
          );
        }
      },
    );

    test.runIf(identityOperations !== undefined)(
      "each documented-prefix identity case is a single supported positive",
      () => {
        const declared = declaredFixtures();
        for (const operation of identityOperations!) {
          const fixture = declared.find((candidate) => candidate.mutation!.operation === operation);
          expect(fixture, `${grammar}: no fixture for operation ${operation}`).toBeDefined();
          expect(fixture!.expected.length, `${grammar}:${operation}`).toBe(1);
          expect(fixture!.support, `${grammar}:${operation}`).toBe("supported");
        }
      },
    );
  },
);

describe("docs/coverage/coverage-declarations.json migrates deterministically", () => {
  test("validates against the real detector-inventory.json and corpus context", () => {
    expect(() =>
      validateCanonicalCoverageDeclarations(coverageDeclarations.declarations, realContext()),
    ).not.toThrow();
  });

  test("declares exactly the baseline's types, the incremental surface, and every consumer", () => {
    const declaredTypes = new Set(coverageDeclarations.declarations.map((row) => row.type));
    for (const entry of manifest.types) expect(declaredTypes.has(entry.type)).toBe(true);
    for (const consumer of manifest.consumers) expect(declaredTypes.has(consumer.path)).toBe(true);
    expect(declaredTypes.has("incremental")).toBe(true);
  });

  test("re-running the generator produces byte-identical output (migration determinism)", () => {
    const run = () =>
      execFileSync("python3", ["-B", "scripts/generate-coverage-declarations.py"], {
        cwd: ROOT,
        encoding: "utf-8",
      });
    const first = run();
    const second = run();
    expect(first).toEqual(second);
    expect(JSON.parse(first)).toEqual(coverageDeclarations);
  });
});

describe("validateCanonicalCoverageDeclarations", () => {
  test("accepts a well-formed row", () => {
    expect(() => validateCanonicalCoverageDeclarations([baseRow()], realContext())).not.toThrow();
  });

  test("rejects an unknown detector", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [{ ...row, detector: "not-a-real-detector" }],
        realContext(),
      ),
    ).toThrow(/unknown-detector-or-type/);
  });

  test("rejects an unknown type for a known detector", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations([{ ...row, type: "not_a_real_type" }], realContext()),
    ).toThrow(/unknown-detector-or-type/);
  });

  test("rejects a row missing a required dimension", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [{ ...row, dimensions: row.dimensions.filter((d) => d.dimension !== "adversarial") }],
        realContext(),
      ),
    ).toThrow(/missing-required-dimension/);
  });

  test("rejects a stale evidence fixture id", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [
          {
            ...row,
            dimensions: row.dimensions.map((d) =>
              d.dimension === "positive"
                ? { ...d, evidenceFixtureIds: ["this-fixture-id-does-not-exist"] }
                : d,
            ),
          },
        ],
        realContext(),
      ),
    ).toThrow(/stale-evidence-id/);
  });

  test("rejects a supported dimension with no evidence and no exception", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [
          {
            ...row,
            dimensions: row.dimensions.map((d) =>
              d.dimension === "positive" ? { ...d, evidenceFixtureIds: [] } : d,
            ),
          },
        ],
        realContext(),
      ),
    ).toThrow(/unsupported-claim/);
  });

  test("rejects a supported dimension that also carries an exception", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [
          {
            ...row,
            dimensions: row.dimensions.map((d) =>
              d.dimension === "positive"
                ? { ...d, exception: { code: "no-concept" as const } }
                : d,
            ),
          },
        ],
        realContext(),
      ),
    ).toThrow(/contradictory-state/);
  });

  test("rejects a pending dimension whose backlogId is free-form prose", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [
          {
            ...row,
            dimensions: row.dimensions.map((d) =>
              d.dimension === "positive"
                ? {
                    dimension: d.dimension,
                    state: "pending" as const,
                    evidenceFixtureIds: [],
                    exception: {
                      code: "pending" as const,
                      backlogId: "we'll get to this eventually",
                    },
                  }
                : d,
            ),
          },
        ],
        realContext(),
      ),
    ).toThrow(/unjustified-exception/);
  });

  test("rejects owned-elsewhere pointing at a row that does not exist", () => {
    const row = baseRow();
    expect(() =>
      validateCanonicalCoverageDeclarations(
        [
          {
            ...row,
            dimensions: row.dimensions.map((d) =>
              d.dimension === "positive"
                ? {
                    dimension: d.dimension,
                    state: "supported" as const,
                    evidenceFixtureIds: [],
                    exception: {
                      code: "owned-elsewhere" as const,
                      ownedBy: "nonexistent_type:positive",
                    },
                  }
                : d,
            ),
          },
        ],
        realContext(),
      ),
    ).toThrow(/unjustified-exception/);
  });

  test("rejects owned-elsewhere pointing at a dimension that is not itself supported", () => {
    const owner = baseRow();
    const pendingOwner: CanonicalCoverageDeclaration = {
      ...owner,
      type: "aws_access_key_id",
      detector: "aws-access-key",
      dimensions: owner.dimensions.map((d) =>
        d.dimension === "overlap"
          ? {
              dimension: "overlap" as const,
              state: "pending" as const,
              evidenceFixtureIds: [],
              exception: { code: "pending" as const, backlogId: "aws-overlap-gap" },
            }
          : d,
      ),
    };
    const base = baseRow();
    const claimant: CanonicalCoverageDeclaration = {
      ...base,
      dimensions: base.dimensions.map((d) =>
        d.dimension === "overlap"
          ? {
              dimension: "overlap" as const,
              state: "supported" as const,
              evidenceFixtureIds: [],
              exception: { code: "owned-elsewhere" as const, ownedBy: "aws_access_key_id:overlap" },
            }
          : d,
      ),
    };
    expect(() =>
      validateCanonicalCoverageDeclarations([pendingOwner, claimant], realContext()),
    ).toThrow(/unjustified-exception/);
  });

  test("rejects single-detector-family citing a type on a different detector", () => {
    const sibling: CanonicalCoverageDeclaration = {
      ...baseRow(),
      type: "gitlab_token",
      detector: "gitlab-token",
    };
    const base = baseRow();
    const claimant: CanonicalCoverageDeclaration = {
      ...base,
      dimensions: base.dimensions.map((d) =>
        d.dimension === "overlap"
          ? {
              dimension: "overlap" as const,
              state: "supported" as const,
              evidenceFixtureIds: [],
              exception: { code: "single-detector-family" as const, sharedWith: "gitlab_token" },
            }
          : d,
      ),
    };
    expect(() =>
      validateCanonicalCoverageDeclarations([sibling, claimant], realContext()),
    ).toThrow(/unjustified-exception/);
  });

  test("rejects a declared dimension the matrix marks not-applicable for the row's class", () => {
    const incrementalRow: CanonicalCoverageDeclaration = {
      type: "incremental",
      detector: "unassigned",
      behaviorClass: "incremental",
      dimensions: [
        { dimension: "malformed", state: "supported", evidenceFixtureIds: ["INVALID_UTF8"] },
        {
          dimension: "range",
          state: "supported",
          evidenceFixtureIds: ["unicode-conversion-astral-before"],
        },
        {
          dimension: "incremental",
          state: "supported",
          evidenceFixtureIds: ["fixed-width-unicode"],
        },
        {
          dimension: "adversarial",
          state: "supported",
          evidenceFixtureIds: ["github-positive-classic"],
        },
        // "positive" is not-applicable for the incremental class.
        { dimension: "positive", state: "supported", evidenceFixtureIds: ["github-positive-classic"] },
      ],
      note: "test row",
    };
    expect(() =>
      validateCanonicalCoverageDeclarations([incrementalRow], realContext()),
    ).toThrow(/dimension-not-applicable-for-class/);
  });

  test("rejects an unknown consumer path", () => {
    const row: CanonicalCoverageDeclaration = {
      type: "not/a/declared/consumer.rs",
      detector: "unassigned",
      behaviorClass: "binding-edge",
      dimensions: [
        { dimension: "malformed", state: "supported", evidenceFixtureIds: ["INVALID_UTF8"] },
        {
          dimension: "range",
          state: "supported",
          evidenceFixtureIds: ["unicode-conversion-astral-before"],
        },
        {
          dimension: "incremental",
          state: "not-applicable",
          evidenceFixtureIds: [],
          exception: { code: "no-concept" },
        },
        {
          dimension: "adversarial",
          state: "supported",
          evidenceFixtureIds: [],
          exception: {
            code: "owned-elsewhere",
            ownedBy: "crates/secret-scan-core/tests/adversarial_bounds.rs:adversarial",
          },
        },
      ],
      note: "test row",
    };
    expect(() => validateCanonicalCoverageDeclarations([row], realContext())).toThrow(
      /unknown-consumer/,
    );
  });
});
