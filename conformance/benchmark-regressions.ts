/** Cross-repository provenance for benchmark-originated product regressions. */

export type RegressionGateStatus = "pending" | "passed";

export interface BenchmarkRegressionRecord {
  readonly id: string;
  readonly benchmarkRecordId: string;
  readonly benchmarkIssue: string;
  readonly productIssue: string;
  readonly benchmarkFixtureIds: readonly string[];
  readonly corpusHashes: readonly string[];
  readonly fixingCommit?: string;
  readonly canonicalFixtures: {
    readonly synchronous: readonly string[];
    readonly incremental: readonly string[];
  };
  readonly gates: {
    readonly productConformance: {
      readonly status: RegressionGateStatus;
      readonly evidence: readonly string[];
    };
    readonly benchmarkRevalidation: {
      readonly status: RegressionGateStatus;
      readonly evidence: readonly string[];
    };
  };
  readonly note: string;
}

export interface BenchmarkRegressionManifest {
  readonly schemaVersion: 1;
  readonly lifecycleAuthority: string;
  readonly records: readonly BenchmarkRegressionRecord[];
}

export interface BenchmarkRegressionFixtureIndex {
  readonly synchronous: ReadonlySet<string>;
  readonly incremental: ReadonlySet<string>;
}

const ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const BENCHMARK_FIXTURE_ID = /^[a-z][a-z0-9-]*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const BENCHMARK_ISSUE = /^https:\/\/github\.com\/redact-secret\/redact-secret-benchmarks\/issues\/10$/;
const PRODUCT_ISSUE = /^https:\/\/github\.com\/redact-secret\/redact-secret\/issues\/[1-9][0-9]*$/;
const HTTPS = /^https:\/\//;

function invalid(id: string, code: string): never {
  throw new TypeError(`Invalid benchmark regression ${id}: ${code}.`);
}

function hasOnly(value: object, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function validStringList(value: unknown, pattern: RegExp, allowEmpty = false): value is string[] {
  return Array.isArray(value) &&
    (allowEmpty || value.length > 0) &&
    value.every((item) => typeof item === "string" && pattern.test(item)) &&
    new Set(value).size === value.length;
}

function validateGate(
  id: string,
  gate: { readonly status: RegressionGateStatus; readonly evidence: readonly string[] },
  code: string,
): void {
  if (
    typeof gate !== "object" || gate === null ||
    !hasOnly(gate, ["status", "evidence"]) ||
    !["pending", "passed"].includes(gate.status) ||
    !validStringList(gate.evidence, HTTPS, true) ||
    (gate.status === "passed" && gate.evidence.length === 0)
  ) invalid(id, code);
}

/**
 * Validate provenance and both acceptance gates without reading fixture input.
 * Diagnostics contain only the public record id and a stable error code.
 */
export function validateBenchmarkRegressionManifest(
  value: BenchmarkRegressionManifest,
  fixtures: BenchmarkRegressionFixtureIndex,
): BenchmarkRegressionManifest {
  if (
    typeof value !== "object" || value === null ||
    !hasOnly(value, ["schemaVersion", "lifecycleAuthority", "records"]) ||
    value.schemaVersion !== 1 ||
    typeof value.lifecycleAuthority !== "string" ||
    !HTTPS.test(value.lifecycleAuthority) ||
    !Array.isArray(value.records)
  ) invalid("manifest", "invalid-metadata");

  const recordIds = new Set<string>();
  const benchmarkRecordIds = new Set<string>();
  const canonicalIds = new Set<string>();
  for (const record of value.records) {
    const id = typeof record?.id === "string" && ID.test(record.id) ? record.id : "unknown";
    if (recordIds.has(id)) invalid(id, "duplicate-id");
    recordIds.add(id);
    if (
      id === "unknown" ||
      !hasOnly(record, [
        "id", "benchmarkRecordId", "benchmarkIssue", "productIssue",
        "benchmarkFixtureIds", "corpusHashes", "fixingCommit",
        "canonicalFixtures", "gates", "note",
      ]) ||
      typeof record.benchmarkRecordId !== "string" || !ID.test(record.benchmarkRecordId) ||
      benchmarkRecordIds.has(record.benchmarkRecordId) ||
      !BENCHMARK_ISSUE.test(record.benchmarkIssue) ||
      !PRODUCT_ISSUE.test(record.productIssue) ||
      !validStringList(record.benchmarkFixtureIds, BENCHMARK_FIXTURE_ID) ||
      !validStringList(record.corpusHashes, SHA256) ||
      (record.fixingCommit !== undefined && !COMMIT.test(record.fixingCommit)) ||
      typeof record.note !== "string" || record.note.length === 0 ||
      typeof record.canonicalFixtures !== "object" || record.canonicalFixtures === null ||
      !hasOnly(record.canonicalFixtures, ["synchronous", "incremental"]) ||
      !validStringList(record.canonicalFixtures.synchronous, ID, true) ||
      !validStringList(record.canonicalFixtures.incremental, ID, true) ||
      typeof record.gates !== "object" || record.gates === null ||
      !hasOnly(record.gates, ["productConformance", "benchmarkRevalidation"])
    ) invalid(id, "invalid-metadata");
    benchmarkRecordIds.add(record.benchmarkRecordId);

    validateGate(id, record.gates.productConformance, "invalid-product-gate");
    validateGate(id, record.gates.benchmarkRevalidation, "invalid-benchmark-gate");
    if (
      record.gates.productConformance.status === "passed" &&
      record.canonicalFixtures.synchronous.length + record.canonicalFixtures.incremental.length === 0
    ) invalid(id, "passed-without-canonical-fixture");

    for (const fixtureId of record.canonicalFixtures.synchronous) {
      if (!fixtures.synchronous.has(fixtureId)) invalid(id, "unknown-synchronous-fixture");
      if (canonicalIds.has(fixtureId)) invalid(id, "duplicate-canonical-fixture");
      canonicalIds.add(fixtureId);
    }
    for (const fixtureId of record.canonicalFixtures.incremental) {
      if (!fixtures.incremental.has(fixtureId)) invalid(id, "unknown-incremental-fixture");
      if (canonicalIds.has(fixtureId)) invalid(id, "duplicate-canonical-fixture");
      canonicalIds.add(fixtureId);
    }
  }
  return value;
}
