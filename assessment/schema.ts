/**
 * Canonical, language-neutral evaluation-protocol schema: the synthetic
 * assessment corpus, its workload profiles, and the common result contract
 * described by `decision-define-cross-language-evaluation-protocol`.
 *
 * This corpus is deliberately distinct from `conformance/`: `conformance/` is
 * the executable behavioral contract every binding must pass to release.
 * This corpus measures accuracy and performance against a common result
 * contract and is never itself a release gate. Types are redeclared rather
 * than imported from `conformance/schema.ts` so the two stay independently
 * reviewable and one cannot silently widen the other's contract.
 *
 * Canonical `expected[].start`/`end` are UTF-8 byte offsets into `input`,
 * encoded as UTF-8 — the same range model `conformance/README.md` documents.
 * A runner comparing its own native offsets against this corpus first
 * normalizes both sides to UTF-8 byte ranges, then verifies the converted
 * span selects the same original substring in its native units.
 */

export type AssessmentConfidence = "high" | "medium" | "low";

export type AssessmentSpecificity =
  | "private-key"
  | "provider"
  | "structural"
  | "contextual"
  | "entropy";

/** The text domain a fixture or workload profile draws from. */
export type AssessmentCategory = "logs" | "code" | "chat" | "negative-text";

/** The disposition the shipped default policy applies to a finding. */
export type AssessmentPolicyOutcome = "block" | "redact" | "warn" | "allow";

/**
 * A safe public expectation. Deliberately closed to exactly these fields, on
 * the same terms as `conformance/schema.ts`'s `CanonicalExpectation`:
 * nothing here may carry the matched plaintext.
 */
export interface AssessmentExpectation {
  readonly detector: string;
  readonly type: string;
  readonly confidence: AssessmentConfidence;
  readonly specificity: AssessmentSpecificity;
  /** UTF-8 byte offset, inclusive. */
  readonly start: number;
  /** UTF-8 byte offset, exclusive. */
  readonly end: number;
  /** The default policy's disposition for this finding. */
  readonly policyOutcome: AssessmentPolicyOutcome;
}

/** One reviewed accuracy fixture: a synthetic input and its expected result. */
export interface AssessmentFixture {
  readonly id: string;
  readonly category: AssessmentCategory;
  /** True when this fixture specifically exercises non-ASCII or astral text. */
  readonly unicode: boolean;
  readonly input: string;
  readonly expected: readonly AssessmentExpectation[];
  readonly note: string;
}

/** Which purpose a workload profile serves; see `ACCURACY_MAX_INPUT_BYTES`. */
export type AssessmentProfilePurpose = "accuracy" | "scale";

/**
 * How a runner partitions a generated workload input across calls to a
 * streaming or incremental API. Generation produces the whole input; a
 * runner applies the chunking, the same way `conformance/README.md`'s
 * partition-invariance model keeps partitioning out of stored fixture data.
 */
export type AssessmentChunkProfile =
  | "whole"
  | "fixed-1024"
  | "fixed-4096"
  | "fixed-65536"
  | "utf16-boundary";

/**
 * A named workload profile. `generateWorkloadInput` (`assessment/generate.ts`)
 * is the pure, deterministic function of exactly these fields; nothing about
 * a profile's generated input is stored as data, so this record is its own
 * complete provenance.
 */
export interface AssessmentWorkloadProfile {
  readonly id: string;
  readonly purpose: AssessmentProfilePurpose;
  readonly category: AssessmentCategory;
  /** Target generated input size, in UTF-8 bytes. */
  readonly targetInputBytes: number;
  /** Target findings per KiB (1024 bytes) of generated input. */
  readonly targetDensityPerKiB: number;
  readonly chunkProfile: AssessmentChunkProfile;
  /** Swaps in the category's non-ASCII filler variant instead of the ASCII one. */
  readonly unicodeMix: boolean;
  /** Identifies the exact generator function version this profile targets. */
  readonly generatorAlgorithm: string;
  readonly note: string;
}

/**
 * Accuracy profiles measure detector and policy behavior, not scale or
 * timing, and must stay small enough that measuring them never contends
 * with timing measurements. A profile at or above this size is a scale
 * profile instead.
 */
export const ACCURACY_MAX_INPUT_BYTES = 4096;

/**
 * The version of this result contract itself (the shape `AssessmentResult`
 * declares), not the corpus a result was measured against — see
 * `AssessmentProvenance.corpusVersion`. A runner stamps every result it
 * emits with this constant rather than a free-form literal.
 */
export const RESULT_SCHEMA_VERSION = "3";

/** The five product surfaces this protocol defines a common contract for. */
export type AssessmentSurface =
  | "rust-core"
  | "python"
  | "node"
  | "browser-wasm"
  | "cli";

export interface AssessmentAccuracyMetrics {
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falseNegatives: number;
  readonly policyMismatches: number;
}

export interface AssessmentPerformanceMetrics {
  readonly initialization: AssessmentDistribution;
  readonly processing: AssessmentDistribution;
  readonly throughput: AssessmentDistribution;
  readonly memory: AssessmentMemoryMetrics;
}
/** Detailed raw-sample shapes are declared after the validators below. */


/**
 * Everything needed to reproduce and place one result: the exact revision,
 * artifact, corpus, host, and command that produced it.
 */
export interface AssessmentProvenance {
  /** Full 40-character source commit SHA. */
  readonly commit: string;
  /** The exact built artifact this result ran against, e.g. a package@version. */
  readonly artifactIdentity: string;
  readonly corpusVersion: string;
  /** SHA-256 hex digest of the exercised corpus/profile file(s). */
  readonly corpusHash: string;
  readonly os: string;
  readonly cpu: string;
  /** The language runtime and its version, e.g. "node-22.11.0". */
  readonly runtime: string;
  readonly command: string;
  /** Standard Cargo profile; absent in historical results and non-Rust adapters. */
  readonly buildProfile?: "debug" | "release";
}

/**
 * One surface's result for one workload profile. An accuracy-purpose profile
 * result carries `accuracy`; a scale-purpose profile result carries
 * `performance`. At least one must be present.
 */
export interface AssessmentResult {
  readonly schemaVersion: string;
  readonly surface: AssessmentSurface;
  readonly profileId: string;
  readonly accuracy?: AssessmentAccuracyMetrics;
  readonly performance?: AssessmentPerformanceMetrics;
  readonly provenance: AssessmentProvenance;
}

const CASE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const CATEGORIES: readonly AssessmentCategory[] = [
  "logs",
  "code",
  "chat",
  "negative-text",
];
const CONFIDENCE: readonly AssessmentConfidence[] = ["high", "medium", "low"];
const SPECIFICITY: readonly AssessmentSpecificity[] = [
  "private-key",
  "provider",
  "structural",
  "contextual",
  "entropy",
];
const POLICY_OUTCOMES: readonly AssessmentPolicyOutcome[] = [
  "block",
  "redact",
  "warn",
  "allow",
];
const EXPECTATION_KEYS = new Set([
  "detector",
  "type",
  "confidence",
  "specificity",
  "start",
  "end",
  "policyOutcome",
]);
const PURPOSES: readonly AssessmentProfilePurpose[] = ["accuracy", "scale"];
const CHUNK_PROFILES: readonly AssessmentChunkProfile[] = [
  "whole",
  "fixed-1024",
  "fixed-4096",
  "fixed-65536",
  "utf16-boundary",
];
const SURFACES: readonly AssessmentSurface[] = [
  "rust-core",
  "python",
  "node",
  "browser-wasm",
  "cli",
];

const encoder = new TextEncoder();

/** UTF-8 byte length of a JavaScript string, without retaining the string. */
export function utf8ByteLength(input: string): number {
  return encoder.encode(input).length;
}

/**
 * The set of UTF-8 byte offsets into `input` that fall on a code point
 * boundary (including 0 and the full byte length), on the same terms as
 * `conformance/schema.ts`'s `utf8BoundaryOffsets`.
 */
function utf8BoundaryOffsets(input: string): ReadonlySet<number> {
  const boundaries = new Set<number>([0]);
  let byteIndex = 0;
  for (const codePoint of input) {
    byteIndex += encoder.encode(codePoint).length;
    boundaries.add(byteIndex);
  }
  return boundaries;
}

/**
 * Diagnostics carry only a record identity and a stable failure code — never
 * fixture `input`, a matched substring, or any other content-derived value.
 */
function invalid(id: string, code: string): never {
  throw new TypeError(`Invalid assessment record ${id}: ${code}.`);
}

/**
 * Validates the assessment corpus shape and its UTF-8 byte-offset
 * invariants. Rejects invalid, overlapping, out-of-bounds, or
 * plaintext-bearing public expectations. Never reads fixture `input` content
 * into a diagnostic.
 */
export function validateAssessmentFixtures(
  value: readonly AssessmentFixture[],
): readonly AssessmentFixture[] {
  if (!Array.isArray(value)) invalid("corpus", "not-an-array");

  const ids = new Set<string>();
  for (const fixture of value) {
    const rawId =
      typeof fixture === "object" && fixture !== null &&
      typeof fixture.id === "string"
        ? fixture.id
        : undefined;
    const id =
      rawId !== undefined && rawId.length <= 64 && CASE_ID_PATTERN.test(rawId)
        ? rawId
        : "unknown";
    if (id === "unknown" || ids.has(id)) invalid(id, "invalid-id");
    ids.add(id);

    if (
      !CATEGORIES.includes(fixture.category) ||
      typeof fixture.unicode !== "boolean" ||
      typeof fixture.input !== "string" ||
      typeof fixture.note !== "string" ||
      fixture.note.length === 0
    ) {
      invalid(id, "invalid-metadata");
    }
    if (!Array.isArray(fixture.expected)) invalid(id, "missing-expectation");
    if (fixture.category === "negative-text" && fixture.expected.length !== 0) {
      invalid(id, "negative-text-with-finding");
    }

    const inputByteLength = utf8ByteLength(fixture.input);
    const boundaries = fixture.expected.length > 0
      ? utf8BoundaryOffsets(fixture.input)
      : undefined;
    let previousEnd = 0;
    for (const expected of fixture.expected) {
      if (
        typeof expected !== "object" ||
        expected === null ||
        Object.keys(expected).some((key) => !EXPECTATION_KEYS.has(key))
      ) {
        invalid(id, "plaintext-bearing-expectation");
      }
      if (
        !IDENTIFIER_PATTERN.test(expected.detector) ||
        !IDENTIFIER_PATTERN.test(expected.type) ||
        !CONFIDENCE.includes(expected.confidence) ||
        !SPECIFICITY.includes(expected.specificity) ||
        !POLICY_OUTCOMES.includes(expected.policyOutcome) ||
        !Number.isInteger(expected.start) ||
        !Number.isInteger(expected.end) ||
        expected.start < previousEnd ||
        expected.end <= expected.start ||
        expected.end > inputByteLength ||
        !boundaries?.has(expected.start) ||
        !boundaries.has(expected.end)
      ) {
        invalid(id, "invalid-expectation");
      }
      previousEnd = expected.end;
    }
  }

  return value;
}

/**
 * Validates workload profile shape, and that every profile's purpose matches
 * its own size and chunking constraints: an accuracy profile stays at or
 * under `ACCURACY_MAX_INPUT_BYTES` and is never chunked, so measuring it
 * never contends with timing; a scale profile is always larger.
 */
export function validateAssessmentWorkloadProfiles(
  value: readonly AssessmentWorkloadProfile[],
): readonly AssessmentWorkloadProfile[] {
  if (!Array.isArray(value)) invalid("profiles", "not-an-array");

  const ids = new Set<string>();
  for (const profile of value) {
    const rawId =
      typeof profile === "object" && profile !== null &&
      typeof profile.id === "string"
        ? profile.id
        : undefined;
    const id =
      rawId !== undefined && rawId.length <= 64 && CASE_ID_PATTERN.test(rawId)
        ? rawId
        : "unknown";
    if (id === "unknown" || ids.has(id)) invalid(id, "invalid-id");
    ids.add(id);

    if (
      !PURPOSES.includes(profile.purpose) ||
      !CATEGORIES.includes(profile.category) ||
      !Number.isSafeInteger(profile.targetInputBytes) ||
      profile.targetInputBytes <= 0 ||
      typeof profile.targetDensityPerKiB !== "number" ||
      !Number.isFinite(profile.targetDensityPerKiB) ||
      profile.targetDensityPerKiB < 0 ||
      !CHUNK_PROFILES.includes(profile.chunkProfile) ||
      typeof profile.unicodeMix !== "boolean" ||
      !IDENTIFIER_PATTERN.test(profile.generatorAlgorithm) ||
      typeof profile.note !== "string" ||
      profile.note.length === 0
    ) {
      invalid(id, "invalid-metadata");
    }

    if (profile.purpose === "accuracy") {
      if (profile.targetInputBytes > ACCURACY_MAX_INPUT_BYTES) {
        invalid(id, "accuracy-profile-exceeds-minimal-size");
      }
      if (profile.chunkProfile !== "whole") {
        invalid(id, "accuracy-profile-must-be-whole-chunked");
      }
    } else if (profile.targetInputBytes <= ACCURACY_MAX_INPUT_BYTES) {
      invalid(id, "scale-profile-not-larger-than-accuracy-cap");
    }
  }

  return value;
}

/**
 * Validates result-contract records: metrics ranges and the presence of at
 * least one metrics kind, plus full reproducibility provenance. Never
 * inspects fixture or workload content — a result carries only counts,
 * durations, and identity fields.
 */
export function validateAssessmentResults(
  value: readonly AssessmentResult[],
): readonly AssessmentResult[] {
  if (!Array.isArray(value)) invalid("results", "not-an-array");

  for (const result of value) {
    const rawId =
      typeof result === "object" && result !== null &&
      typeof result.profileId === "string"
        ? result.profileId
        : undefined;
    const id = rawId ?? "unknown";

    if (
      result.schemaVersion !==
        RESULT_SCHEMA_VERSION ||
      !SURFACES.includes(result.surface) ||
      rawId === undefined ||
      !CASE_ID_PATTERN.test(rawId) ||
      (result.accuracy === undefined && result.performance === undefined)
    ) {
      invalid(id, "invalid-metadata");
    }

    if (result.accuracy !== undefined && (
      !Number.isSafeInteger(result.accuracy.truePositives) ||
      result.accuracy.truePositives < 0 ||
      !Number.isSafeInteger(result.accuracy.falsePositives) ||
      result.accuracy.falsePositives < 0 ||
      !Number.isSafeInteger(result.accuracy.falseNegatives) ||
      result.accuracy.falseNegatives < 0 ||
      !Number.isSafeInteger(result.accuracy.policyMismatches) ||
      result.accuracy.policyMismatches < 0
    )) invalid(id, "invalid-accuracy-metrics");

    if (result.performance !== undefined) {
      const distributions = [
        result.performance.initialization,
        result.performance.processing,
        result.performance.throughput,
      ];
      if (distributions.some((distribution) =>
        typeof distribution !== "object" || distribution === null ||
        !["milliseconds", "bytes-per-second"].includes(distribution.unit) ||
        !Array.isArray(distribution.samples) || distribution.samples.length === 0 ||
        distribution.samples.some((sample) => !Number.isFinite(sample) || sample < 0) ||
        [distribution.minimum, distribution.median, distribution.p95,
          distribution.maximum, distribution.mean, distribution.standardDeviation]
          .some((summary) => !Number.isFinite(summary) || summary < 0)
      )) invalid(id, "invalid-performance-metrics");
      if (
        result.performance.initialization.unit !== "milliseconds" ||
        result.performance.processing.unit !== "milliseconds" ||
        result.performance.throughput.unit !== "bytes-per-second" ||
        result.performance.initialization.samples.length !==
          result.performance.processing.samples.length ||
        result.performance.processing.samples.length !==
          result.performance.throughput.samples.length
      ) invalid(id, "invalid-performance-metrics");

      const memory = result.performance.memory;
      const metrics = memory === undefined ? [] : [
        memory.nodeHeap,
        memory.nodeRss,
        memory.nodeExternal,
        memory.browserJsHeap,
        memory.wasmLinearMemory,
        memory.pythonHeap,
        memory.processRss,
        memory.streamingBuffer,
      ];
      if (metrics.length !== 8 || metrics.some((metric) =>
        typeof metric !== "object" || metric === null || metric.unit !== "bytes" ||
        !Array.isArray(metric.samples) ||
        metric.samples.some((sample) =>
          !Number.isSafeInteger(sample.baselineBytes) || sample.baselineBytes < 0 ||
          !Number.isSafeInteger(sample.maximumObservedBytes) ||
          sample.maximumObservedBytes < sample.baselineBytes
        ) ||
        (metric.samples.length === 0
          ? typeof metric.unavailableReason !== "string" || metric.unavailableReason.length === 0
          : metric.unavailableReason !== undefined ||
            metric.samples.length !== result.performance.processing.samples.length) ||
        typeof metric.samplingLimit !== "string" || metric.samplingLimit.length === 0
      )) invalid(id, "invalid-performance-metrics");
    }

    const provenance = result.provenance;
    if (
      typeof provenance !== "object" ||
      provenance === null ||
      !COMMIT_PATTERN.test(provenance.commit) ||
      typeof provenance.artifactIdentity !== "string" ||
      provenance.artifactIdentity.length === 0 ||
      typeof provenance.corpusVersion !== "string" ||
      provenance.corpusVersion.length === 0 ||
      !SHA256_PATTERN.test(provenance.corpusHash) ||
      typeof provenance.os !== "string" ||
      provenance.os.length === 0 ||
      typeof provenance.cpu !== "string" ||
      provenance.cpu.length === 0 ||
      typeof provenance.runtime !== "string" ||
      provenance.runtime.length === 0 ||
      typeof provenance.command !== "string" ||
      provenance.command.length === 0 ||
      (provenance.buildProfile !== undefined && !["debug", "release"].includes(provenance.buildProfile))
    ) {
      invalid(id, "invalid-provenance");
    }
  }

  return value;
}

export interface AssessmentDistribution {
  readonly unit: "milliseconds" | "bytes-per-second";
  readonly samples: readonly number[];
  readonly minimum: number;
  readonly median: number;
  readonly p95: number;
  readonly maximum: number;
  readonly mean: number;
  readonly standardDeviation: number;
}

export interface AssessmentMemorySample {
  readonly baselineBytes: number;
  readonly maximumObservedBytes: number;
}

export interface AssessmentMemoryMetric {
  readonly unit: "bytes";
  readonly samples: readonly AssessmentMemorySample[];
  readonly unavailableReason?: string;
  /** Explains where sampling can miss a short-lived true peak. */
  readonly samplingLimit: string;
}

export interface AssessmentMemoryMetrics {
  readonly nodeHeap: AssessmentMemoryMetric;
  readonly nodeRss: AssessmentMemoryMetric;
  readonly nodeExternal: AssessmentMemoryMetric;
  readonly browserJsHeap: AssessmentMemoryMetric;
  readonly wasmLinearMemory: AssessmentMemoryMetric;
  /** Python allocations observed by an external assessment runner. */
  readonly pythonHeap: AssessmentMemoryMetric;
  /** Whole-process resident memory for non-Node native host processes. */
  readonly processRss: AssessmentMemoryMetric;
  readonly streamingBuffer: AssessmentMemoryMetric;
}
