/**
 * The compile-time half of the package contract. `tsc --project
 * packages/javascript/test/tsconfig.json` is the assertion: nothing here runs.
 *
 * It proves what a runtime test cannot — that findings are immutable in the
 * declarations, that offsets are documented UTF-16 numbers, that the internal
 * modules and any custom detector surface are absent, and that a consumer can
 * write the documented calls without reaching for `any`.
 */

import { createNodeStreamSanitizer, NodeStreamSanitizer } from "../src/adapters/node-stream.js";
import { createNodeStreamSanitizer as createCommonNodeStreamSanitizer } from "../src/adapters/node-stream-common.js";
import { createWebStreamSanitizer, WebStreamSanitizer } from "../src/adapters/web-stream.js";
import { createWebStreamSanitizer as createCommonWebStreamSanitizer } from "../src/adapters/web-stream-common.js";
import type * as publicApi from "../src/index.js";
import type {
  ActionComparison,
  ActionCounts,
  ActionDecision,
  ActionPolicyDocument,
  ActionPolicyInput,
  ActionPolicyMatch,
  ActionPolicyRuleAction,
  ArtifactKind,
  CompareActionPoliciesOptions,
  ComparedFinding,
  ComparedPolicy,
  ComparedPolicyKind,
  ComparedPolicySummary,
  ConfigDiagnostic,
  ConfigResolution,
  ConfigSnapshot,
  CoreStatus,
  DecisionBasis,
  DefaultSecretPolicy,
  DetectedSecretFinding,
  DetectionSelection,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSanitizerResult,
  IncrementalSecretPolicy,
  PlaceholderContext,
  PlaceholderFormatter,
  PolicyContext,
  RangeUnit,
  ResolveConfigOptions,
  RuntimeConfig,
  ScanAndRedactOptions,
  ScanOptions,
  ScanResult,
  SecretAction,
  SecretConfidence,
  SecretFinding,
  SecretObfuscation,
  SecretPolicy,
  SecretScanErrorCode,
  WholeInputLimits,
} from "../src/index.js";
import {
  artifact,
  compareActionPolicies,
  createIncrementalSanitizer,
  defaultPlaceholderFormatter,
  defaultPolicy,
  type describeConfig,
  initialize,
  type PROFILE,
  RANGE_UNIT,
  redact,
  type resolveConfig,
  SecretScanError,
  scan,
  scanAndRedact,
  type status,
  typedPlaceholderFormatter,
  VERSION,
} from "../src/index.js";

type Expect<T extends true> = T;
type IsAbsent<Key extends string> = Key extends keyof typeof publicApi ? false : true;
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

/** Findings are immutable, and carry no plaintext value. */
type FindingIsImmutable = Expect<Equal<SecretFinding, Readonly<SecretFinding>>>;
type ScanResultIsImmutable = Expect<Equal<ScanResult, Readonly<ScanResult>>>;
type FindingHasNoValue = Expect<"value" extends keyof SecretFinding ? false : true>;
type FindingsAreImmutable = Expect<Equal<ScanResult["findings"], readonly SecretFinding[]>>;

/** Offsets are UTF-16 code units, and the unit is stated in the type. */
type OffsetsAreNumbers = Expect<
  Equal<SecretFinding["start"], number> extends true ? Equal<SecretFinding["end"], number> : false
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
type NoImplementationLookaround = Expect<IsAbsent<"INCREMENTAL_LOOKAROUND_CODE_UNITS">>;

/** Synchronous operations stay synchronous; only initialize is awaited. */
type InitializeIsAsync = Expect<Equal<ReturnType<typeof initialize>, Promise<void>>>;
type ScanIsSync = Expect<Equal<ReturnType<typeof scan>, readonly SecretFinding[]>>;
type RedactIsSync = Expect<Equal<ReturnType<typeof redact>, string>>;
type ScanAndRedactIsSync = Expect<Equal<ReturnType<typeof scanAndRedact>, ScanResult>>;
/** status() is synchronous, input-free, and carries only fixed fields. */
type StatusIsSync = Expect<Equal<ReturnType<typeof status>, CoreStatus>>;
type StatusTakesNoInput = Expect<Equal<Parameters<typeof status>, []>>;
type StatusIsImmutable = Expect<Equal<CoreStatus, Readonly<CoreStatus>>>;
type StatusFieldsAreFixed = Expect<Equal<keyof CoreStatus, "initialized" | "profile" | "activation" | "configuration">>;
/** The configuration digest is a string once initialized and null before. */
type StatusConfigurationIsADigestOrNull = Expect<Equal<CoreStatus["configuration"], string | null>>;

/**
 * Configuration resolution is synchronous data. `resolveConfig` takes data and
 * an options bag, `describeConfig` takes nothing at all (it is input-free), and
 * both return frozen, readonly snapshots that carry no value.
 */
type ResolveConfigIsSync = Expect<Equal<ReturnType<typeof resolveConfig>, ConfigResolution>>;
type ResolveConfigTakesDataAndOptions = Expect<
  Parameters<typeof resolveConfig> extends [
    config?: RuntimeConfig | undefined,
    options?: ResolveConfigOptions | undefined,
  ]
    ? true
    : false
>;
type DescribeConfigIsSync = Expect<Equal<ReturnType<typeof describeConfig>, ConfigSnapshot>>;
type DescribeConfigTakesNoInput = Expect<Equal<Parameters<typeof describeConfig>, []>>;
type SnapshotIsImmutable = Expect<Equal<ConfigSnapshot, Readonly<ConfigSnapshot>>>;
type ResolutionIsImmutable = Expect<Equal<ConfigResolution, Readonly<ConfigResolution>>>;
type DiagnosticIsImmutable = Expect<Equal<ConfigDiagnostic, Readonly<ConfigDiagnostic>>>;
type SnapshotCarriesNoScalarSensitivity = Expect<
  "sensitivity" | "score" | "probability" | "percentage" extends never
    ? true
    : Extract<keyof ConfigSnapshot, "sensitivity" | "score" | "probability" | "percentage"> extends never
      ? true
      : false
>;
type SnapshotHoldsNoInputOrRulesetBody = Expect<
  Extract<keyof ConfigSnapshot, "input" | "text" | "value" | "body" | "pattern"> extends never ? true : false
>;
/** Detection is an `initialize` setting and a configuration key, never a call option. */
type NoPerCallDetection = Expect<
  "detection" extends keyof ScanOptions | keyof ScanAndRedactOptions | keyof IncrementalSanitizerOptions ? false : true
>;
type DetectionIsOneOfTwoLists = Expect<Equal<keyof DetectionSelection, "include" | "exclude">>;
/** A callback is not configuration data. */
type RuntimeConfigHasNoCallback = Expect<"policy" extends keyof RuntimeConfig ? false : true>;

const policy: SecretPolicy = {
  evaluate(finding: DetectedSecretFinding, context: PolicyContext): SecretAction {
    const confidence: SecretConfidence = finding.confidence;
    const obfuscation: SecretObfuscation = finding.obfuscation;
    void obfuscation;
    return context.findingIndex + 1 === context.findingCount && confidence === "high" ? "block" : "warn";
  },
};

const formatter: PlaceholderFormatter = (finding: SecretFinding, context: PlaceholderContext) =>
  `<${finding.type}_${context.placeholderIndex}>`;

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
    evaluate: (_finding, context) => (context.findingIndex === 0 ? "redact" : "warn"),
  },
  placeholderFormatter: typedPlaceholderFormatter,
};

// The byte-named aliases (#1184) and a per-limit mix type-check as well.
const incrementalBytesOptions: IncrementalSanitizerOptions = {
  limits: {
    maxInputBytes: 4_096,
    maxBufferedBytes: 2_176,
    maxTokenCodeUnits: 1_024,
    maxMultilineBytes: 2_048,
  },
};

async function documentedUsage(input: string): Promise<void> {
  await initialize();

  const loaded: ArtifactKind = artifact();
  const findings: readonly SecretFinding[] = scan(input, scanOptions);
  const text: string = redact(input, findings, {
    placeholderFormatter: defaultPlaceholderFormatter,
  });
  const result: ScanResult = scanAndRedact(input, scanAndRedactOptions);

  const session: IncrementalSanitizer = createIncrementalSanitizer(incrementalOptions);
  createIncrementalSanitizer(incrementalBytesOptions);
  const appended: IncrementalSanitizerResult = session.append(input);
  const finalized: IncrementalSanitizerResult = session.finalize();

  const error = new SecretScanError("NOT_INITIALIZED");
  const code: SecretScanErrorCode = error.code;
  const unit: RangeUnit = RANGE_UNIT;
  const version: string = VERSION;

  void [loaded, text, result, appended, finalized, code, unit, version, session.state];
}

void documentedUsage;

/**
 * The declarative action policy (#1219): a typed object, text or bytes, never
 * together with a callback `policy`, and `defaultPolicy` as a policy object
 * for both whole-input calls and incremental sessions.
 */
const actionPolicyDocument: ActionPolicyDocument = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [
    { id: "redact-acme-tokens", match: { type: ["acme-alnum-token"] }, action: "redact" },
    { id: "keep-default-jwt", match: { type: ["jwt"], confidence: ["medium"] }, action: "default" },
  ],
};
const actionPolicyInputs: readonly ActionPolicyInput[] = [
  actionPolicyDocument,
  '{"actionPolicyRevision":1,"base":"default","rules":[]}',
  new Uint8Array(0),
];
const withActionPolicy: ScanOptions = { actionPolicy: actionPolicyDocument };
const textActionPolicy: ActionPolicyInput = '{"actionPolicyRevision":1,"base":"default","rules":[]}';
const sessionWithActionPolicy: IncrementalSanitizerOptions = {
  limits: incrementalBytesOptions.limits,
  actionPolicy: textActionPolicy,
};
const mineElseDefault: SecretPolicy = {
  evaluate: (finding, context) =>
    finding.type === "acme-alnum-token" ? "redact" : defaultPolicy.evaluate(finding, context),
};
const defaultIsBoth: SecretPolicy & IncrementalSecretPolicy = defaultPolicy;
const defaultAsNamedType: DefaultSecretPolicy = defaultPolicy;
const directAction: SecretAction = defaultPolicy.evaluate({} as DetectedSecretFinding);
type DefaultPolicyReturnsAnAction = Expect<Equal<ReturnType<typeof defaultPolicy.evaluate>, SecretAction>>;
type RuleActionAddsDefault = Expect<Equal<ActionPolicyRuleAction, SecretAction | "default">>;
type ActionPolicyHasNoThreshold = Expect<"threshold" extends keyof ActionPolicyMatch ? false : true>;
type InvalidActionPolicyIsACode = Expect<"INVALID_ACTION_POLICY" extends SecretScanErrorCode ? true : false>;
void [withActionPolicy, sessionWithActionPolicy, mineElseDefault, defaultIsBoth, defaultAsNamedType, directAction];

/**
 * The comparison primitive (#1220): whole-input only, one to four sides of a
 * closed set of kinds, and a result of plain readonly data.
 */
function documentedComparisonUsage(): void {
  const options: CompareActionPoliciesOptions = {
    policies: [
      { kind: "default" },
      { kind: "action-policy", actionPolicy: { actionPolicyRevision: 1, base: "default", rules: [] } },
      { kind: "action-policy", actionPolicy: '{"actionPolicyRevision":1,"base":"default","rules":[]}' },
      { kind: "callback", policy: defaultPolicy },
    ],
    limits: { maxInputBytes: 1_024, maxFindings: 10 },
    ruleset: "ruleset-revision: 1\n",
  };
  const comparison: ActionComparison = compareActionPolicies("input", options);
  const mode: "preview" = comparison.mode;
  const enforced: false = comparison.enforced;
  const profile: "full" | "common" | null = comparison.detection.profile;
  const summary: ComparedPolicySummary = comparison.policies[0] as ComparedPolicySummary;
  const kind: ComparedPolicyKind = summary.kind;
  const digest: string | null = summary.documentSha256;
  const counts: ActionCounts = summary.counts;
  const finding: ComparedFinding = comparison.findings[0] as ComparedFinding;
  const detected: DetectedSecretFinding = finding;
  const decision: ActionDecision = finding.decisions[0] as ActionDecision;
  const action: SecretAction = decision.action;
  const basis: DecisionBasis = decision.basis;
  const ruleId: string | null = decision.ruleId;
  const ruleIndex: number | null = decision.ruleIndex;

  // @ts-expect-error a comparison is frozen data: no field is assignable.
  comparison.findings = [];
  // @ts-expect-error a decision is frozen data.
  decision.action = "allow";
  // @ts-expect-error `enforced` is the literal false: a comparison never enforces.
  const enforcedTrue: true = comparison.enforced;

  void [mode, enforced, profile, kind, digest, counts, detected, action, basis, ruleId, ruleIndex, enforcedTrue];
}

void documentedComparisonUsage;

/** No incremental, stream or placeholder option belongs to a comparison, and a side's kind is closed. */
function rejectedComparisonUsage(): void {
  // @ts-expect-error a comparison takes no incremental or stream option.
  const incremental: CompareActionPoliciesOptions = { policies: [{ kind: "default" }], incremental: true };
  const sessionLimits: CompareActionPoliciesOptions = {
    policies: [{ kind: "default" }],
    // @ts-expect-error incremental limits are not whole-input limits.
    limits: { maxInputBytes: 1, maxFindings: 1, maxBufferedBytes: 1 },
  };
  // @ts-expect-error `session` is not a side kind.
  const sessionSide: ComparedPolicy = { kind: "session" };
  // @ts-expect-error a default side carries no policy.
  const defaultWithPolicy: ComparedPolicy = { kind: "default", policy: defaultPolicy };
  // @ts-expect-error an action policy side carries an action policy, not a callback.
  const documentWithCallback: ComparedPolicy = { kind: "action-policy", policy: defaultPolicy };
  // @ts-expect-error a comparison takes a string, never a chunk or a stream.
  compareActionPolicies(["a", "b"], { policies: [{ kind: "default" }] });
  // @ts-expect-error the options are required: there is nothing to compare without sides.
  compareActionPolicies("input");

  void [incremental, sessionLimits, sessionSide, defaultWithPolicy, documentWithCallback];
}

void rejectedComparisonUsage;

type ComparedKindsAreClosed = Expect<Equal<ComparedPolicy["kind"], ComparedPolicyKind>>;
type BasisNamesAreTheCores = Expect<
  Equal<DecisionBasis, "rule" | "rule-default" | "no-rule-matched" | "default-policy" | "callback">
>;
/** No incremental or stream surface mentions a comparison. */
type SessionHasNoComparison = Expect<"compareActionPolicies" extends keyof IncrementalSanitizer ? false : true>;
type StreamHasNoComparison = Expect<"compareActionPolicies" extends keyof NodeStreamSanitizer ? false : true>;
type WebStreamHasNoComparison = Expect<"compareActionPolicies" extends keyof WebStreamSanitizer ? false : true>;

/**
 * The stream adapters. Neither is reachable from the root export: they are
 * published as their own subpaths, `./node-stream` being the only module that
 * resolves `node:stream` and `./web-stream` resolving nothing Node-only.
 */

type NodeSanitizerFindings = Expect<Equal<NodeStreamSanitizer["findings"], readonly SecretFinding[]>>;
type WebSanitizerFindings = Expect<Equal<WebStreamSanitizer["findings"], readonly SecretFinding[]>>;
type WebSanitizerReadsStrings = Expect<
  Equal<ReturnType<typeof createWebStreamSanitizer>["readable"], ReadableStream<string>>
>;

/** Each adapter owns exactly one session, and takes it as its constructor. */
function documentedStreamUsage(session: IncrementalSanitizer): void {
  const fromSession: NodeStreamSanitizer = new NodeStreamSanitizer(session);
  const fromOptions: NodeStreamSanitizer = createNodeStreamSanitizer(incrementalOptions);
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
  const commonNode: NodeStreamSanitizer = createCommonNodeStreamSanitizer(incrementalOptions);
  const commonWeb: WebStreamSanitizer = createCommonWebStreamSanitizer(incrementalOptions);

  void [commonNode, commonWeb];
}

void documentedCommonStreamUsage;
