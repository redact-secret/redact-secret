/**
 * The runtime-neutral half of `compareActionPolicies`
 * (`decision-explain-and-compare-action-policies-over-one-detection-pass`):
 * turning what a binding returned into the one public, frozen result.
 *
 * Both bindings return the same field names, and this module is the only place
 * that shapes them, so a comparison is the same object on the native addon and
 * on WebAssembly by construction. Nothing here inspects the host or reads
 * anything but the binding's own safe metadata.
 */

import { RANGE_UNIT } from "./entry-core.js";
import type { NativeActionComparison } from "./native.js";
import type {
  ActionComparison,
  ActionDecision,
  ComparedFinding,
  ComparedPolicyKind,
  ComparedPolicySummary,
  DecisionBasis,
  SecretAction,
  SecretConfidence,
  SecretObfuscation,
} from "./types.js";
import { VERSION } from "./version.js";

/** `"baseline"` for the first side, then `"candidate-N"`, as the CLI report labels them. */
function sideLabel(index: number): string {
  return index === 0 ? "baseline" : `candidate-${index}`;
}

function toDecision(decision: NativeActionComparison["findings"][number]["decisions"][number]): ActionDecision {
  return Object.freeze({
    action: decision.action as SecretAction,
    basis: decision.basis as DecisionBasis,
    ruleId: decision.ruleId ?? null,
    ruleIndex: decision.ruleIndex ?? null,
  });
}

function toComparedFinding(finding: NativeActionComparison["findings"][number]): ComparedFinding {
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence as SecretConfidence,
    obfuscation: finding.obfuscation as SecretObfuscation,
    start: finding.start,
    end: finding.end,
    differs: finding.differs,
    decisions: Object.freeze(finding.decisions.map(toDecision)),
  });
}

function toSummary(side: NativeActionComparison["sides"][number], index: number): ComparedPolicySummary {
  return Object.freeze({
    label: sideLabel(index),
    kind: side.kind as ComparedPolicyKind,
    documentSha256: side.documentSha256 ?? null,
    counts: Object.freeze({
      redact: side.redact,
      block: side.block,
      warn: side.warn,
      allow: side.allow,
    }),
  });
}

/** Freezes what a binding returned as the public {@link ActionComparison}. */
export function toActionComparison(native: NativeActionComparison): ActionComparison {
  return Object.freeze({
    version: VERSION,
    rangeUnit: RANGE_UNIT,
    mode: "preview",
    enforced: false,
    detection: Object.freeze({
      activationIdentity: native.detection.activationIdentity,
      profile: (native.detection.profile ?? null) as "full" | "common" | null,
      detectorCount: native.detection.detectorCount,
    }),
    policies: Object.freeze(native.sides.map(toSummary)),
    findingCount: native.findings.length,
    changedCount: native.changedCount,
    findings: Object.freeze(native.findings.map(toComparedFinding)),
  });
}
