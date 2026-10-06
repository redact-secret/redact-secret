---
decision_id: decision-explain-and-compare-action-policies-over-one-detection-pass
status: accepted
scope: workspace
title: Explain and compare action policies over one detection pass
decided_at: 2026-10-06
spec: engine
---

# Explain and compare action policies over one detection pass

## Context

Issue [#1220](https://github.com/redact-secret/redact-secret/issues/1220), a
child of epic [#1216](https://github.com/redact-secret/redact-secret/issues/1216).
[`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md)
(ADR-1217) gave users a declarative overlay and left two promises open: the
matched rule id appears "only in #1220's explain output" and never on the public
`Finding`, and a user who mistypes a `type` in a tightening rule keeps the
default without being told. [#1218](https://github.com/redact-secret/redact-secret/issues/1218)
fixed that a policy applies to finalized findings only
([`decision-resolve-overlap-precedence-by-resolved-action-severity`](2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md)),
and `scan` already separates detection from policy application internally.
That separation is evidence that detect-once, evaluate-N is possible. It is not
a public re-evaluation API, and no code ran a comparison before this record.

A user needs to answer two questions before adopting a change: why did this
finding get this action, and what would change if I swapped policy A for policy
B. The answers must not be produced by editing rendered placeholders, must not
contradict enforcement, and must expose nothing a `Finding` does not already
expose.

## Decision

### 1. A public primitive exists: detect once, evaluate N

The core exposes one whole-input function, `compare_action_policies`, with an
explicit-limits variant and the same pair as `BuiltInRegistry` methods. It takes
the input once and a registry (the detection configuration), runs the existing
detection pipeline **once**, then evaluates 1 to 4 policies on the same
finalized findings.

```rust
pub fn compare_action_policies(
    input: &str, registry: &DetectorRegistry, policies: &[ComparedPolicy<'_>],
) -> Result<ActionComparison, SecretScanError>;
pub fn compare_action_policies_with_limits(
    input: &str, registry: &DetectorRegistry, policies: &[ComparedPolicy<'_>],
    limits: &WholeInputLimits,
) -> Result<ActionComparison, SecretScanError>;
```

Why this shape and not another:

- **Rerun `scan` per policy.** Rejected. It detects N times, so the cost is N
  times and a custom detector with state could disagree with itself; it calls
  every callback side's detection-time work again; and it makes "same findings"
  an assumption instead of a fact.
- **A finding-level primitive** (`evaluate(findings, policy)` or `explain(finding)`
  taking caller-built `DetectedFinding` values). Rejected. A caller could then
  explain a finding no detector produced and call it a comparison, and a
  binding would have to expose finding construction. Detection stays inside
  the call, so every compared finding is finalized by construction. A single
  policy is explained by passing one side.
- **A rule id on `Finding`.** Rejected, as ADR-1217 already decided: the public
  finding type does not grow, and the rule id exists only in comparison output.
- **Edit rendered placeholders** (redact twice, diff the text). Rejected by the
  issue and here: placeholder numbering and spans depend on the actions, a
  `warn`/`allow` leaves text unchanged so the diff cannot tell them apart, and
  the output would carry plaintext.

`ComparedPolicy` is `Default` (the running artifact's default evaluation),
`ActionPolicy(&ActionPolicy)` or `Callback(&dyn Policy)`. The result is an
`ActionComparison`:

| Type | Fields (all accessors) |
| --- | --- |
| `ActionComparison` | `detection() -> &DetectionIdentity`, `sides() -> &[ComparedSide]`, `findings() -> &[ComparedFinding]`, `changed_count() -> usize` |
| `DetectionIdentity` | `activation_identity() -> &str`, `profile() -> Option<Profile>`, `detector_count() -> usize` |
| `ComparedSide` | `binding() -> &PolicyBinding`, `counts() -> ActionCounts` |
| `PolicyBinding` | `Default`, `ActionPolicy { document_sha256: [u8; 32] }`, `Callback`; `kind() -> "default" \| "action-policy" \| "callback"`, `document_sha256()`, `document_sha256_hex()` |
| `ActionCounts` | `redact()`, `block()`, `warn()`, `allow()`, `get(Action)` |
| `ComparedFinding` | `finding() -> &DetectedFinding`, `decisions() -> &[ActionDecision]` (one per side, side order), `differs() -> bool` |
| `ActionDecision` | `action() -> Action`, `basis() -> &DecisionBasis` |
| `DecisionBasis` | `Rule { rule_id, rule_index }`, `RuleDefault { rule_id, rule_index }`, `NoRuleMatched`, `DefaultPolicy`, `Callback`; `as_str()`, `rule_id()`, `rule_index()` |

Every enum is `#[non_exhaustive]`. The wire names of `DecisionBasis` are
`rule`, `rule-default`, `no-rule-matched`, `default-policy` and `callback`.

**Explanation.** A basis answers "matched rule versus base default" without
inspecting anything beyond what the policy already reads: `rule` is a
fixed-action rule (id and zero-based index); `rule-default` is a rule whose
action is `default`, so the action is the base and evaluation stopped at that
rule; `no-rule-matched` is the fallback to the base; `default-policy` is the
default side; `callback` is a callback side. The core's `ActionPolicy::explain`
is the one evaluation behind `Policy::evaluate`, `IncrementalPolicy::evaluate`
and the comparison, so the explained action cannot differ from the enforced
one.

**Revision binding.** A declarative policy is bound to the SHA-256 of the exact
bytes the loader received (ADR-1217 section 6 already named that digest as the
caller's key). The core now computes it at load, once, with a small
dependency-free implementation checked against the FIPS 180-4 vectors, and
exposes it as `ActionPolicy::document_sha256()` and `document_sha256_hex()`.
Computing it in the core, not in each binding, is what makes the binding
deterministic across surfaces: the same bytes give the same 64 lowercase hex
characters everywhere, and a changed byte, including insignificant whitespace,
changes it. The digest identifies a document, not its meaning. The default side
has no document and evolves with the artifact, so evidence keyed to it records
`VERSION` as well. A callback has no identity (ADR-1217 section 9: the library
keeps no revision of a callback). This refines, and does not reverse, ADR-1217
section 6, which said the core keeps no hash of a particular policy: the core
now keeps the digest of the one document it parsed and nothing else about it.

### 2. Scope: finalized findings, one pass, identified apart

The comparison covers the findings `scan` returns for the same input and
registry, in the same order with the same ids, ranges and metadata, and nothing
else. It is **not** a rerun of detection per policy, **not** a statement about
overlap losers, candidates that never survived, or PII alternatives the
resolver suppressed (ADR-1217 section 3), and **not** a coverage claim: it says
what each policy does with what was found, never that nothing else exists. A
policy cannot add, remove or reorder a finding, so one pass is exact for every
side.

The detection configuration is a separate fact in the result,
`DetectionIdentity`: the registry's canonical activation identity (credentials
profile and PII selection), its `Profile` when it has one, and its detector
count. It does not cover a custom detector set. A caller who loaded a ruleset
keys that to its own identity (a digest of the ruleset bytes) next to the
comparison; the core has no hash of a ruleset and this record adds none. The two
configurations are never merged into one identifier: swapping a policy leaves
`detection()` unchanged and swapping the registry leaves every `binding()`
unchanged (tested).

### 3. Preview is not enforcement

The primitive is an observation. It never edits the input, produces no
placeholder and no rendered text, and takes no part in `scan`, `redact`,
`scan_and_redact` or an incremental session. The enforcement path is not
modified: the detection half of `scan` was extracted into a shared function with
the same two limit checks in the same order, and the existing suites pass
unchanged. A caller who needs the effect of a policy calls `scan` or `redact`
with it; the comparison states only what that call would choose, and the CLI
report says `"mode": "preview"` and `"enforced": false`.

**Incremental and stream comparison is unsupported in v1, explicitly.** No
`IncrementalSanitizer` or stream-adapter surface gains a comparison, and the CLI
refuses standard input (a usage failure, never a silent fallback to a different
path). Reasons: a session evaluates its policy at finalization with an
`IncrementalPolicyContext` that has no finding count, so comparing N policies
inside a session would either change the enforcement path's callback count,
order or finalization (which the issue forbids) or run N sessions and detect N
times (which section 1 rejects). A whole-input comparison over the complete text
describes what a session over the same text finalizes for built-in detection,
because the incremental contract is partition-independent and equal to the
whole-input reference; it does not observe a session's context. Reopening needs
a session mode that evaluates extra sides after, and independently of,
enforcement, with a proof that the enforcement callback sequence is unchanged.

### 4. Callback policies

A legacy callback participates as a side (`ComparedPolicy::Callback`), because
migrating from a callback to a declarative policy is the main comparison a user
makes.

- It is invoked **exactly once per finalized finding, in finding order**, with
  the same `PolicyContext(finding_index, finding_count)` that `scan` gives it.
- Sides are evaluated **one at a time in the order supplied**, each over all
  findings, so each callback sees precisely the call sequence it would see in
  `scan`, whatever the other sides are. Two callbacks therefore run
  `A0 A1 A2 B0 B1 B2`, never interleaved.
- A callback failure fails the **whole** comparison with the existing
  `POLICY_FAILURE`. There is **no partial result**: nothing from any side is
  returned, the failing callback is not called for a later finding, and no later
  side is evaluated. This is the same short-circuit `scan` has.
- A binding that adapts a host callback keeps its existing adapter and its
  existing codes, so a bad return value is `INVALID_POLICY_ACTION` exactly as in
  `scan`. Rust's typed return cannot be invalid.
- A callback's basis is `callback` and it has no rule id and no binding
  identity. What it does between calls is invisible, and a callback with state
  or side effects advances them during a comparison like any other call:
  comparing it is not free of effects, and the guide says so.
- A callback side written for incremental sessions takes an
  `IncrementalPolicyContext`; it is not accepted here (section 3).

A comparison does not alter the callback count of the enforcement path: a
test counts callback invocations of `scan` and of a one-side comparison over the
same input and requires them equal, and runs enforcement before and after a
comparison with identical output and identical call logs.

### 5. Bounds and errors

- **Findings and input.** The whole-input limits apply as `scan` applies them: the
  byte bound before detection (`INPUT_LIMIT_EXCEEDED`) and the finding bound
  after it (`FINDING_LIMIT_EXCEEDED`), against the default limits or the
  caller's. The finding bound fails the call before any policy, callback
  included, runs.
- **Sides.** At least 1 and at most `MAX_COMPARED_POLICIES` (4: a baseline and
  three candidates). Anything else is the existing `INVALID_OPTIONS`, checked
  before detection and before any callback.
- **Result size.** At most `max_findings` findings with at most 4 decisions
  each, so 200,000 decisions at the default limits. A decision holds an action
  and, for a rule, the rule id (an identifier of at most 64 bytes) and an
  index. This is a bound by construction, not a measured cost, and this record
  makes no performance claim.
- **Errors.** No new code. `INVALID_OPTIONS`, `INPUT_LIMIT_EXCEEDED`,
  `FINDING_LIMIT_EXCEEDED`, `POLICY_FAILURE` and (in a binding) the existing
  callback and document codes cover every failure; `SecretScanErrorCode::ALL`
  stays at 23. A rejected policy document is rejected at load with
  `INVALID_ACTION_POLICY`, before it can be compared.
- **Content.** The result holds no input byte, matched value, snippet, hash of
  either, retained input or score. Confidence stays categorical. The only digest
  is a policy document's.

### 6. CLI surface

`--compare-action-policy <path>` is added, because the CLI is where a policy
author tests a file, and it needs no new core surface.

- Repeatable, 1 to 3 times. Requires exactly one explicit file path as the input.
  `--action-policy <path>` names the baseline; without it the baseline is the
  default policy. Candidates follow in the order given, labelled `baseline`,
  `candidate-1`, `candidate-2`, `candidate-3`.
- `--json` writes one object; the default writes one line per finding with each
  side as `label=action(basis)`, plus a summary on standard error. `--ruleset`
  and `--pii` select the detection configuration and apply to every side.
- Usage failures, each a fixed message and exit 2: standard input given,
  `--redact` combined, more than one path, a missing path value, a fourth
  candidate.
- **Exit codes are explicit.** `0`: the comparison completed and every policy
  chooses the same action for every finding (including zero findings). `1`: it
  completed and at least one finding's action differs between the policies. `2`:
  any failure, with nothing written to standard output. A finding is never a
  failure here, so a CI gate "this candidate changes nothing" is `exit 0`.
  Redact mode is unaffected.
- A policy file rejected by the core fails the run with `INVALID_ACTION_POLICY`,
  its class and rule index, before any input is read.

### 7. Binding obligations

Binding tracks mirror the Rust names without reimplementing evaluation. The
public shape is the CLI JSON with camel-cased native names; the names themselves
are fixed by each binding's `core-public-api` review. A binding exposes the
whole-input primitive only, runs `action-policy-compare-v1.json`, exposes the
policy digest on its policy handle, and applies its existing callback adapter.
No binding exposes a stream or session comparison.

### Truth table

The fixture
[`conformance/fixtures/action-policy-compare-v1.json`](../../conformance/fixtures/action-policy-compare-v1.json)
holds the machine-readable form (8 cases, 7 error cases, 4 digests, 8 host
obligations). `base` stands for the running surface's own default evaluation of
the same finding and is never a literal.

| Case | Sides | Result |
| --- | --- | --- |
| all four actions, one pass | default, `four-actions`, `block-high`, `default-carve-out` over three findings (a medium ruleset token, a high GitHub token, a private key) | default: warn, redact, block. `four-actions`: redact (`rule#0`), allow (`rule#1`), warn (`rule#2`). `block-high`: no rule (base warn), block, block (`rule#0`). `default-carve-out`: no rule (base), `rule-default` (base redact), allow (`rule#1`). All three findings `differs`; per-side counts follow the decisions |
| same action, different reasons | default, empty rules, explicit `redact` rule | redact by `default-policy`, `no-rule-matched` and `rule`; `differs` false; exit 0 |
| overlap loser | default, `allow-bearer` | one finding (`bearer_token`); the lower `twilio_auth_token` candidate is never reported |
| obfuscated finding | default, a rule on `obfuscation` | the finding carries `invisible-characters`; the rule decides `block` |
| no findings | any | zero findings, zero changes |
| one side | one policy | allowed; explains without comparing |
| callback as a side | callback, declarative | `callback` basis, no rule; call sequence `A0 A1 A2` |
| two callbacks | callback A, callback B | call sequence `A0 A1 A2 B0 B1 B2` |
| callback fails at finding 1 | declarative, callback | `POLICY_FAILURE`, calls `A0 A1`, no partial result |
| callback fails in the first side | callback A (fails at 0), callback B | `POLICY_FAILURE`, calls `A0`, B never runs |
| zero or five sides | any | `INVALID_OPTIONS`, no detection, no callback call |
| input over the byte bound | callback | `INPUT_LIMIT_EXCEEDED`, no callback call |
| findings over the count bound | callback | `FINDING_LIMIT_EXCEEDED`, no callback call |
| digest | four documents | lowercase SHA-256 of the exact text; whitespace changes it |

Ordering is the finding order of `scan` for findings and the supplied order for
sides, in every row. A runner also asserts enforcement parity (each declarative
side's action equals what `scan` with that document yields for that finding) and
that the serialized result contains no byte of the input.

## Examples

Before, a user cannot tell which of two rules fired, or what a swap changes:

```text
$ redact-secret --action-policy current.json app.env      # check mode: action only
app.env:8-48 github_token detector=github-token confidence=high action=allow
```

After, one pass reports both policies and the reason:

```text
$ redact-secret --action-policy current.json --compare-action-policy next.json app.env
app.env:8-48 github_token detector=github-token confidence=high obfuscation=none id=finding-1 baseline=allow(rule:allow-github#0) candidate-1=redact(no-rule-matched) differs
redact-secret: baseline: action-policy sha256=... redact=0 block=0 warn=0 allow=1
redact-secret: candidate-1: action-policy sha256=... redact=1 block=0 warn=0 allow=0
redact-secret: preview only, nothing was enforced; 1 finding(s), 1 differ; ...
$ echo $?
1
```

## Trade-offs

- **False negatives.** A comparison can say a candidate is safe because it
  agrees with the baseline on the findings that exist; it cannot see what
  detection missed or an overlap loser it hid, and it never claims to. The
  guide states it. A rule that fires on no finding of the sample input is not
  proven dead: `no-rule-matched` on a sample only shows that sample.
- **False positives.** `differs` is the action only, so a changed reason with
  the same action is not flagged; a user may over-read an exit 1 as a regression
  when a candidate is deliberately stricter.
- **Cost.** One public function pair and nine types on the core surface, a
  dependency-free SHA-256 computed at every policy load (at most 64 KiB), one
  evaluation per side, and a result bounded by 4 times
  the finding count. The stateful-callback caveat is real and documented.

## Alternatives considered

- **Rerun detection per side, a finding-level re-evaluation primitive, a rule id
  on `Finding`, and placeholder editing.** Rejected in section 1.
- **Interleave sides per finding.** Rejected: with two callbacks it would give
  each a call order it never gets in `scan`, so a stateful callback could behave
  differently under comparison than in enforcement.
- **Return partial results with a per-side error.** Rejected: a half comparison
  invites a half conclusion, and `scan` has no partial result either.
- **A new error code for a failed comparison.** Rejected: every failure already
  has a fixed code a caller handles.
- **Compare sessions and streams in v1.** Rejected in section 3.
- **Hash the policy in each binding.** Rejected: the bindings would agree only
  as long as each serialization and hash implementation did.
- **Exit 0 whenever the comparison completes.** Rejected for the CLI: a gate
  would have to parse the report to learn whether anything changed.

## Consequences

The Rust core and the CLI ship the primitive with this change (#1220). The
Node, WebAssembly and JavaScript bindings ship it in the same change and the
Python binding in its own track, each against the fixture; a surface that has not
shipped it exposes no comparison and no digest. The 0.1.x additive contract
covers every new name. ADR-1217 gains one sentence pointing at
this record. No detector, default action, finding field, error code or version
changes.

**JavaScript surface (#1220).** `compareActionPolicies(input, { policies, limits?,
ruleset? })` is one function in `@redact-secret/core` and
`@redact-secret/core/common`, and the result is the CLI's `--json` object with
camel-case names. A side is `{ kind: "default" }`, `{ kind: "action-policy",
actionPolicy }` (the forms of the `actionPolicy` option, serialized once) or
`{ kind: "callback", policy }`; the `kind` strings are the ones the result
reports (`default`, `action-policy`, `callback`). Section 3 is enforced in the
shape: the function takes one string, a non-string is `INVALID_INPUT`, and an
option or side key that could suggest an incremental or stream comparison (or
belongs to another kind) is `INVALID_OPTIONS` instead of being ignored. The
JavaScript package keeps no policy handle, so the digest section 7 puts on the
policy handle is read from the result's `policies[].documentSha256`; for an object
policy it is the digest of the compact `JSON.stringify` bytes the package
serialized, the case the fixture's last host obligation names. Callback sides use
the existing adapters: `POLICY_FAILURE` for a throw or a non-string return and
`INVALID_POLICY_ACTION` for a string outside the four names, identically on the
Node addon and on WebAssembly. The addon and the WebAssembly artifact return the
same fields, the package builds the one public object from them, and the
qualification requires the same result digest from both runtimes on the same
profile.

**WebAssembly cost, measured.** The five-surface increase was left to the
binding track. Release `wasm-bindgen` builds, brotli quality 11, against the
branch head that already held the core's comparison and SHA-256 but linked
neither into a binding export (so the `full` baseline is 1,477 bytes above
#1219's 170,442: the core change since then, which includes the SHA-256 computed
at every policy load, is already in it): `full` 171,919 to 176,282 (+4,363, 2.54%), `common`
123,785 to 128,114 (+4,329), `full` with `pii` 270,450 to 274,706 (+4,256) and
`common` with `pii` 220,910 to 225,522 (+4,612). Against `db0e5c8d`, the parser,
the digest and the comparison together add 11,493 bytes to `full` (7.0%). About
2,600 of the 4,363 are the core comparison and its call, about 900 the argument
glue and about 900 the flat result; a nested object result cost 881 bytes more
than the flat array the package now rebuilds. The cost is
accepted and recorded in
[the evidence](../audits/evidence/1220/README.md); later growth of the
comparison re-measures against it.

### Reopening bar

A measured need to compare inside a session, a ruleset digest the core can
compute without a new dependency, or a result bound that real inputs reach
reopens the matching item.
