/**
 * The runtime-neutral half of `compareConfigurations`
 * (`configuration-comparison/v1`, issue #1254): relating the findings of
 * independent per-side passes, and freezing the one public result.
 *
 * Both runtimes return the same single-side shape for one pass, and this
 * module is the only place that relates sides, so a comparison is the same
 * object on the native addon and on WebAssembly by construction. The Rust core
 * has the same correspondence in `configuration_compare.rs` (for Rust callers);
 * the shared conformance fixtures under `conformance/configuration-comparison`
 * pin the two to the same answers. It is kept here, outside the WebAssembly
 * artifact, because the artifact's size budget is a constraint of the epic
 * (`decision-define-the-artifact-manifest-and-configuration-data-contracts`,
 * Size). Nothing here reads anything but the bindings' own safe metadata.
 */

import { RANGE_UNIT } from "./entry-core.js";
import type { NativeActionComparison } from "./native.js";
import type {
  ActionCounts,
  ComparedConfigurationSummary,
  ComparedSideStatus,
  ConfigurationChange,
  ConfigurationComparison,
  ConfigurationDifference,
  ConfigurationDifferences,
  ConfigurationFinding,
  ConfigurationSideResult,
  DecisionBasis,
  SecretAction,
  SecretConfidence,
  SecretObfuscation,
} from "./types.js";
import { VERSION } from "./version.js";

const LIMITED: readonly string[] = ["INPUT_LIMIT_EXCEEDED", "FINDING_LIMIT_EXCEEDED"];
const UNSUPPORTED: readonly string[] = [
  "DETECTION_SELECTION_UNSUPPORTED",
  "PII_SELECTOR_UNSUPPORTED",
  "PII_SELECTOR_UNAVAILABLE",
];

/**
 * The status a failure code means: a limit is `limited`, something the
 * artifact cannot do is `unsupported`, anything else is `error`.
 */
export function statusOfFailure(code: string | null): ComparedSideStatus {
  if (code === null) return "scanned";
  if (LIMITED.includes(code)) return "limited";
  return UNSUPPORTED.includes(code) ? "unsupported" : "error";
}

/** The attributes a `changed` entry names, in bit order. */
const CHANGES: readonly ConfigurationChange[] = ["range", "type", "detector", "confidence", "action", "reason"];

/** What the runtime knows about one side once it has resolved and scanned it. */
export interface SideOutcome {
  readonly summary: ComparedConfigurationSummary;
  /** The failure code of a side that was not scanned; otherwise `null`. */
  readonly failure: string | null;
  /** The single-side pass of a scanned side. */
  readonly native: NativeActionComparison | null;
}

function toFinding(native: NativeActionComparison["findings"][number]): ConfigurationFinding {
  const decision = native.decisions[0];
  if (decision === undefined) throw new Error("unreachable: a one-side pass has one decision");
  return Object.freeze({
    type: native.type,
    detector: native.detector,
    confidence: native.confidence as SecretConfidence,
    obfuscation: native.obfuscation as SecretObfuscation,
    start: native.start,
    end: native.end,
    action: decision.action as SecretAction,
    reason: Object.freeze({
      basis: decision.basis as DecisionBasis,
      ruleId: decision.ruleId ?? null,
      ruleIndex: decision.ruleIndex ?? null,
    }),
  });
}

function toResult(outcome: SideOutcome): ConfigurationSideResult {
  const side = outcome.native?.sides[0];
  const counts: ActionCounts = Object.freeze({
    redact: side?.redact ?? 0,
    block: side?.block ?? 0,
    warn: side?.warn ?? 0,
    allow: side?.allow ?? 0,
  });
  return Object.freeze({
    status: statusOfFailure(outcome.failure),
    failure: outcome.failure,
    counts,
    findings: Object.freeze((outcome.native?.findings ?? []).map(toFinding)),
  });
}

/** The attributes in which two paired findings differ, as a bit set over {@link CHANGES}. */
function changedBits(base: ConfigurationFinding, other: ConfigurationFinding): number {
  const differs = [
    base.start !== other.start || base.end !== other.end,
    base.type !== other.type,
    base.detector !== other.detector,
    base.confidence !== other.confidence,
    base.action !== other.action,
    base.reason.basis !== other.reason.basis ||
      base.reason.ruleId !== other.reason.ruleId ||
      base.reason.ruleIndex !== other.reason.ruleIndex,
  ];
  return differs.reduce((bits, flag, bit) => bits | (flag ? 1 << bit : 0), 0);
}

/**
 * Groups both sides' findings into overlap clusters over their declared-unit
 * ranges and relates each cluster. See the module documentation of the Rust
 * core's `configuration_compare` for the table; this is the same algorithm.
 */
export function relateFindings(
  base: readonly ConfigurationFinding[],
  other: readonly ConfigurationFinding[],
): ConfigurationDifferences {
  // [start, end, isOther, position]
  const spans: [number, number, number, number][] = [];
  for (const [isOther, side] of [
    [0, base],
    [1, other],
  ] as const) {
    side.forEach((finding, position) => {
      spans.push([finding.start, finding.end, isOther, position]);
    });
  }
  spans.sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2] || a[3] - b[3]);

  const entries: ConfigurationDifference[] = [];
  let unchanged = 0;
  for (let first = 0; first < spans.length; ) {
    let end = spans[first]?.[1] ?? 0;
    let stop = first + 1;
    while (stop < spans.length && (spans[stop]?.[0] ?? 0) < end) {
      end = Math.max(end, spans[stop]?.[1] ?? 0);
      stop += 1;
    }
    const left: number[] = [];
    const right: number[] = [];
    for (const [, , isOther, position] of spans.slice(first, stop)) (isOther === 1 ? right : left).push(position);
    first = stop;

    const entry = (
      kind: ConfigurationDifference["kind"],
      baseSide: readonly number[],
      otherSide: readonly number[],
      bits = 0,
    ): ConfigurationDifference => {
      const correspondence =
        kind === "added" || kind === "removed"
          ? null
          : kind === "changed"
            ? (bits & 1) === 0
              ? "exact"
              : "overlap"
            : "ambiguous";
      return Object.freeze({
        kind,
        correspondence,
        base: Object.freeze([...baseSide]),
        other: Object.freeze([...otherSide]),
        changes: Object.freeze(CHANGES.filter((_, bit) => (bits >> bit) & 1)),
      });
    };

    if (left.length === 0) {
      for (const position of right) entries.push(entry("added", [], [position]));
    } else if (right.length === 0) {
      for (const position of left) entries.push(entry("removed", [position], []));
    } else if (left.length === 1 && right.length === 1) {
      const bits = changedBits(
        base[left[0] as number] as ConfigurationFinding,
        other[right[0] as number] as ConfigurationFinding,
      );
      if (bits === 0) unchanged += 1;
      else entries.push(entry("changed", left, right, bits));
    } else {
      entries.push(entry(left.length === 1 ? "split" : right.length === 1 ? "merged" : "regrouped", left, right));
    }
  }
  return Object.freeze({ entries: Object.freeze(entries), unchanged });
}

/** Freezes the sides' outcomes as the one public {@link ConfigurationComparison}. */
export function toConfigurationComparison(outcomes: readonly SideOutcome[]): ConfigurationComparison {
  const results = outcomes.map(toResult);
  const baseline = results[0];
  const differences = results.map((result, index) =>
    index > 0 && baseline?.status === "scanned" && result.status === "scanned"
      ? relateFindings(baseline.findings, result.findings)
      : null,
  );
  const callbackSides = outcomes.flatMap((outcome, index) =>
    outcome.summary.policy.kind === "callback" ? [index] : [],
  );
  return Object.freeze({
    schema: "configuration-comparison/v1",
    version: VERSION,
    rangeUnit: RANGE_UNIT,
    scope: "input",
    mode: "preview",
    enforced: false,
    callbackSides: Object.freeze(callbackSides),
    configs: Object.freeze(outcomes.map((outcome) => outcome.summary)),
    results: Object.freeze(results),
    differences: Object.freeze(differences),
  });
}
