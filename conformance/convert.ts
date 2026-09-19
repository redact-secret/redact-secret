/**
 * UTF-16 code unit <-> UTF-8 byte offset conversion. It originally
 * translated the retired TypeScript oracle's corpus shape (UTF-16 code unit
 * offsets) into the canonical schema (`conformance/schema.ts`, UTF-8 byte
 * offsets); the conversion functions remain as infrastructure a UTF-16 host
 * runner can still reach for (`decision-govern-cross-language-conformance`).
 * Nothing here should be treated as itself authoritative — the canonical
 * JSON under `fixtures/` is.
 */

import type {
  CanonicalExpectation,
  CanonicalFixture,
  CanonicalIncrementalFixture,
  CanonicalResourceExpectation,
} from "./schema.js";

/** A structural subset of the TypeScript oracle's `ConformanceExpectation`. */
export interface Utf16Expectation {
  readonly detector: string;
  readonly type: string;
  readonly confidence: CanonicalExpectation["confidence"];
  readonly specificity: CanonicalExpectation["specificity"];
  readonly obfuscation?: CanonicalExpectation["obfuscation"];
  readonly start: number;
  readonly end: number;
}

/** A structural subset of the TypeScript oracle's `ConformanceCase`, kept
 * local so this module does not depend on `test/` types. */
export interface Utf16Fixture {
  readonly id: string;
  readonly detector: string;
  readonly kind: CanonicalFixture["kind"];
  readonly support: CanonicalFixture["support"];
  readonly tier: CanonicalFixture["tier"];
  readonly contexts: CanonicalFixture["contexts"];
  readonly mutation?: CanonicalFixture["mutation"];
  readonly resource?: {
    readonly maxInputCodeUnits: number;
    readonly maxFindings: number;
    readonly maxRuntimeMs: number;
  };
  readonly input: string;
  readonly expected: readonly Utf16Expectation[] | null;
  readonly note: string;
}

const encoder = new TextEncoder();

/**
 * Converts a UTF-16 code unit offset into `input` to the UTF-8 byte offset
 * of the same logical position. `utf16Offset` must be a code point boundary
 * (it may not fall between the two code units of a surrogate pair) and must
 * be within `[0, input.length]`.
 */
export function utf16OffsetToUtf8ByteOffset(
  input: string,
  utf16Offset: number,
): number {
  if (
    !Number.isInteger(utf16Offset) ||
    utf16Offset < 0 ||
    utf16Offset > input.length
  ) {
    throw new RangeError("UTF-16 offset is out of bounds.");
  }
  if (utf16Offset > 0) {
    const precedingUnit = input.charCodeAt(utf16Offset - 1);
    if (precedingUnit >= 0xd800 && precedingUnit <= 0xdbff) {
      throw new RangeError("UTF-16 offset splits a surrogate pair.");
    }
  }
  return encoder.encode(input.slice(0, utf16Offset)).length;
}

/**
 * Converts a UTF-8 byte offset back to the UTF-16 code unit offset of the
 * same logical position. `byteOffset` must land on a code point boundary
 * and must be within `[0, utf8ByteLength(input)]`; any other value throws
 * rather than silently rounding to a neighboring position.
 */
export function utf8ByteOffsetToUtf16Offset(
  input: string,
  byteOffset: number,
): number {
  if (!Number.isInteger(byteOffset) || byteOffset < 0) {
    throw new RangeError("UTF-8 byte offset is out of bounds.");
  }
  let utf16Index = 0;
  let byteIndex = 0;
  for (const codePoint of input) {
    if (byteIndex === byteOffset) return utf16Index;
    if (byteIndex > byteOffset) break;
    byteIndex += encoder.encode(codePoint).length;
    utf16Index += codePoint.length;
  }
  if (byteIndex === byteOffset) return utf16Index;
  throw new RangeError(
    "UTF-8 byte offset is out of bounds or splits a code point.",
  );
}

/**
 * Conservative UTF-16-code-unit-count to UTF-8-byte-count cap conversion,
 * used only for resource caps (a bound, not a position in `input`). Every
 * UTF-16 code unit encodes as at most 3 UTF-8 bytes if it stands alone, and
 * a surrogate pair (2 code units) encodes as exactly 4 UTF-8 bytes — so
 * `codeUnits * 3` never under-counts the worst case.
 */
function conservativeMaxBytes(maxInputCodeUnits: number): number {
  return maxInputCodeUnits * 3;
}

function convertExpectation(
  input: string,
  expected: Utf16Expectation,
): CanonicalExpectation {
  return {
    detector: expected.detector,
    type: expected.type,
    confidence: expected.confidence,
    specificity: expected.specificity,
    ...(expected.obfuscation !== undefined
      ? { obfuscation: expected.obfuscation }
      : {}),
    start: utf16OffsetToUtf8ByteOffset(input, expected.start),
    end: utf16OffsetToUtf8ByteOffset(input, expected.end),
  };
}

function convertResource(
  input: string,
  resource: NonNullable<Utf16Fixture["resource"]>,
): CanonicalResourceExpectation {
  return {
    maxInputBytes: Math.max(
      conservativeMaxBytes(resource.maxInputCodeUnits),
      encoder.encode(input).length,
    ),
    maxFindings: resource.maxFindings,
    maxRuntimeMs: resource.maxRuntimeMs,
  };
}

/** Converts one UTF-16-offset fixture into its canonical UTF-8-byte-offset form. */
export function convertFixtureToCanonical(
  fixture: Utf16Fixture,
): CanonicalFixture {
  return {
    id: fixture.id,
    detector: fixture.detector,
    kind: fixture.kind,
    support: fixture.support,
    tier: fixture.tier,
    contexts: fixture.contexts,
    ...(fixture.mutation !== undefined
      ? { mutation: fixture.mutation }
      : {}),
    ...(fixture.resource !== undefined
      ? { resource: convertResource(fixture.input, fixture.resource) }
      : {}),
    input: fixture.input,
    expected: fixture.expected === null
      ? null
      : fixture.expected.map((expected) =>
        convertExpectation(fixture.input, expected)
      ),
    note: fixture.note,
  };
}

/** Converts a whole UTF-16-offset corpus into its canonical form. */
export function convertCorpusToCanonical(
  fixtures: readonly Utf16Fixture[],
): readonly CanonicalFixture[] {
  return fixtures.map(convertFixtureToCanonical);
}

/**
 * A structural subset of the incremental oracle's whole-input finding shape.
 * `specificity` is not part of the oracle's public `SecretFinding` (it is
 * resolved and dropped before a finding becomes public); migration tooling
 * supplies it by cross-referencing the synchronous corpus for the same
 * `type`, so this module stays a mechanical converter rather than a source
 * of classification defaults.
 */
export interface Utf16IncrementalExpectation {
  readonly detector: string;
  readonly type: string;
  readonly confidence: CanonicalExpectation["confidence"];
  readonly specificity: CanonicalExpectation["specificity"];
  readonly start: number;
  readonly end: number;
}

/** A structural subset of the retired TypeScript oracle's
 * `IncrementalPartitionCase` shape, kept local so this module stays
 * independent of any TypeScript detector implementation's types. */
export interface Utf16IncrementalFixture {
  readonly id: string;
  readonly input: string;
  readonly expected: {
    readonly text: string;
    readonly findings: readonly Utf16IncrementalExpectation[];
  };
  readonly note: string;
}

/** Converts one whole-input incremental reference into its canonical form. */
export function convertIncrementalFixtureToCanonical(
  fixture: Utf16IncrementalFixture,
): CanonicalIncrementalFixture {
  return {
    id: fixture.id,
    input: fixture.input,
    text: fixture.expected.text,
    expected: fixture.expected.findings.map((finding) => ({
      detector: finding.detector,
      type: finding.type,
      confidence: finding.confidence,
      specificity: finding.specificity,
      start: utf16OffsetToUtf8ByteOffset(fixture.input, finding.start),
      end: utf16OffsetToUtf8ByteOffset(fixture.input, finding.end),
    })),
    note: fixture.note,
  };
}

/** Converts a whole incremental-reference corpus into its canonical form. */
export function convertIncrementalCorpusToCanonical(
  fixtures: readonly Utf16IncrementalFixture[],
): readonly CanonicalIncrementalFixture[] {
  return fixtures.map(convertIncrementalFixtureToCanonical);
}
