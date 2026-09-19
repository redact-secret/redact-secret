/**
 * The compile-time half of the package contract. `tsc --project
 * packages/javascript/test/tsconfig.json` is the assertion: nothing here runs.
 *
 * It proves what a runtime test cannot — that findings are immutable in the
 * declarations, that offsets are documented UTF-16 numbers, that the internal
 * modules and any custom detector surface are absent, and that a consumer can
 * write the documented calls without reaching for `any`.
 */

import * as publicApi from "../src/index.js";
import {
  createNodeStreamSanitizer,
  NodeStreamSanitizer,
} from "../src/adapters/node-stream.js";
import { createNodeStreamSanitizer as createCommonNodeStreamSanitizer } from "../src/adapters/node-stream-common.js";
import {
  createWebStreamSanitizer,
  WebStreamSanitizer,
} from "../src/adapters/web-stream.js";
import { createWebStreamSanitizer as createCommonWebStreamSanitizer } from "../src/adapters/web-stream-common.js";
import {
  artifact,
  createIncrementalSanitizer,
  defaultPlaceholderFormatter,
  initialize,
  PROFILE,
  RANGE_UNIT,
  redact,
  scan,
  scanAndRedact,
  SecretScanError,
  typedPlaceholderFormatter,
  VERSION,
} from "../src/index.js";
import type {
  ArtifactKind,
  DetectedSecretFinding,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSanitizerResult,
  PlaceholderContext,
  PlaceholderFormatter,
  PolicyContext,
  RangeUnit,
  ScanAndRedactOptions,
  ScanOptions,
  ScanResult,
  SecretAction,
  SecretConfidence,
  SecretFinding,
  SecretPolicy,
  SecretScanErrorCode,
  WholeInputLimits,
} from "../src/index.js";

type Expect<T extends true> = T;
type IsAbsent<Key extends string> = Key extends keyof typeof publicApi
  ? false
  : true;
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;

/** Findings are immutable, and carry no plaintext value. */
type FindingIsImmutable = Expect<Equal<SecretFinding, Readonly<SecretFinding>>>;
type ScanResultIsImmutable = Expect<Equal<ScanResult, Readonly<ScanResult>>>;
type FindingHasNoValue = Expect<
  "value" extends keyof SecretFinding ? false : true
>;
type FindingsAreImmutable = Expect<
  Equal<ScanResult["findings"], readonly SecretFinding[]>
>;

/** Offsets are UTF-16 code units, and the unit is stated in the type. */
type OffsetsAreNumbers = Expect<
  Equal<SecretFinding["start"], number> extends true
    ? Equal<SecretFinding["end"], number>
    : false
>;
type RangeUnitIsUtf16 = Expect<Equal<RangeUnit, "utf16-code-units">>;

/** The full-profile entry states its profile as a literal, not a wide string. */
type ProfileIsFullLiteral = Expect<Equal<typeof PROFILE, "full">>;

/** Custom detector callbacks and internal surfaces are not published. */
type NoDetectorRegistry = Expect<IsAbsent<"DetectorRegistry">>;
type NoDetectorFactory = Expect<IsAbsent<"createDetectorRegistry">>;
type NoBuiltInDetectors = Expect<IsAbsent<"builtInDetectors">>;
type NoEntropyHelper = Expect<IsAbsent<"calculateShannonEntropy">>;
type NoNativeHandle = Expect<IsAbsent<"NATIVE_HANDLE">>;
type NoRuntimeFactory = Expect<IsAbsent<"createRedactSecretRuntime">>;
type NoImplementationLookaround = Expect<
  IsAbsent<"INCREMENTAL_LOOKAROUND_CODE_UNITS">
>;

/** Synchronous operations stay synchronous; only initialize is awaited. */
type InitializeIsAsync = Expect<Equal<ReturnType<typeof initialize>, Promise<void>>>;
type ScanIsSync = Expect<
  Equal<ReturnType<typeof scan>, readonly SecretFinding[]>
>;
type RedactIsSync = Expect<Equal<ReturnType<typeof redact>, string>>;
type ScanAndRedactIsSync = Expect<
  Equal<ReturnType<typeof scanAndRedact>, ScanResult>
>;

const policy: SecretPolicy = {
  evaluate(finding: DetectedSecretFinding, context: PolicyContext): SecretAction {
    const confidence: SecretConfidence = finding.confidence;
    return context.findingIndex + 1 === context.findingCount &&
      confidence === "high"
      ? "block"
      : "warn";
  },
};

const formatter: PlaceholderFormatter = (
  finding: SecretFinding,
  context: PlaceholderContext,
) => `<${finding.type}_${context.placeholderIndex}>`;

const wholeInputLimits: WholeInputLimits = {
  maxInputBytes: 64 * 1024 * 1024,
  maxFindings: 50_000,
};
const scanOptions: ScanOptions = { policy, limits: wholeInputLimits };
const scanAndRedactOptions: ScanAndRedactOptions = {
  policy,
  placeholderFormatter: formatter,
  limits: wholeInputLimits,
};

const incrementalOptions: IncrementalSanitizerOptions = {
  limits: {
    maxInputCodeUnits: 4_096,
    maxBufferedCodeUnits: 2_176,
    maxTokenCodeUnits: 1_024,
    maxMultilineCodeUnits: 2_048,
  },
  policy: {
    evaluate: (_finding, context) =>
      context.findingIndex === 0 ? "redact" : "warn",
  },
  placeholderFormatter: typedPlaceholderFormatter,
};

async function documentedUsage(input: string): Promise<void> {
  await initialize();

  const loaded: ArtifactKind = artifact();
  const findings: readonly SecretFinding[] = scan(input, scanOptions);
  const text: string = redact(input, findings, {
    placeholderFormatter: defaultPlaceholderFormatter,
  });
  const result: ScanResult = scanAndRedact(input, scanAndRedactOptions);

  const session: IncrementalSanitizer = createIncrementalSanitizer(
    incrementalOptions,
  );
  const appended: IncrementalSanitizerResult = session.append(input);
  const finalized: IncrementalSanitizerResult = session.finalize();

  const error = new SecretScanError("NOT_INITIALIZED");
  const code: SecretScanErrorCode = error.code;
  const unit: RangeUnit = RANGE_UNIT;
  const version: string = VERSION;

  void [
    loaded,
    text,
    result,
    appended,
    finalized,
    code,
    unit,
    version,
    session.state,
  ];
}

void documentedUsage;

/**
 * The stream adapters. Neither is reachable from the root export: they are
 * published as their own subpaths, `./node-stream` being the only module that
 * resolves `node:stream` and `./web-stream` resolving nothing Node-only.
 */

type NodeSanitizerFindings = Expect<
  Equal<NodeStreamSanitizer["findings"], readonly SecretFinding[]>
>;
type WebSanitizerFindings = Expect<
  Equal<WebStreamSanitizer["findings"], readonly SecretFinding[]>
>;
type WebSanitizerReadsStrings = Expect<
  Equal<ReturnType<typeof createWebStreamSanitizer>["readable"], ReadableStream<string>>
>;

/** Each adapter owns exactly one session, and takes it as its constructor. */
function documentedStreamUsage(session: IncrementalSanitizer): void {
  const fromSession: NodeStreamSanitizer = new NodeStreamSanitizer(session);
  const fromOptions: NodeStreamSanitizer = createNodeStreamSanitizer(
    incrementalOptions,
  );
  const web: WebStreamSanitizer = createWebStreamSanitizer(incrementalOptions);
  const wrapped: WebStreamSanitizer = new WebStreamSanitizer(session);

  const nodeFindings: readonly SecretFinding[] = fromOptions.findings;
  const webFindings: readonly SecretFinding[] = web.findings;
  web.abort();

  void [fromSession, wrapped, nodeFindings, webFindings];
}

void documentedStreamUsage;

/**
 * The `common`-profile stream subpaths report the exact same
 * `NodeStreamSanitizer`/`WebStreamSanitizer` types as their `full` siblings:
 * only which runtime the factory opens a session against differs.
 */
function documentedCommonStreamUsage(): void {
  const commonNode: NodeStreamSanitizer = createCommonNodeStreamSanitizer(
    incrementalOptions,
  );
  const commonWeb: WebStreamSanitizer = createCommonWebStreamSanitizer(
    incrementalOptions,
  );

  void [commonNode, commonWeb];
}

void documentedCommonStreamUsage;
