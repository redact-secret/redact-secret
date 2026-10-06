---
decision_id: decision-define-the-versioned-declarative-action-policy-and-default-overlay
status: accepted
scope: workspace
title: Define the versioned declarative action policy and its default overlay
decided_at: 2026-10-06
spec: engine
---

# Define the versioned declarative action policy and its default overlay

## Context

Issue [#1217](https://github.com/redact-secret/redact-secret/issues/1217), the
design child of epic [#1216](https://github.com/redact-secret/redact-secret/issues/1216).
A policy callback decides every finalized finding and replaces the default, so a
user who wants one small change must reproduce the default table, which is a
moving list (`ALWAYS_REDACT_TYPES` grew from 135 to 140 entries between the
2026-10-05 research baseline and `db0e5c8d`). Four accepted records bound the
design:

- [`decision-resolve-overlap-precedence-by-resolved-action-severity`](2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md):
  overlap ranking uses the fixed default classification and policy runs only on
  finalized findings.
- [`decision-keep-credential-role-facts-out-of-detection-attribution-and-default-action`](2026-10-06-keep-credential-role-facts-out-of-detection-attribution-and-default-action.md):
  the default is frozen and a user override, "the declarative overlay when #1216
  to #1222 land", is the only way to change it. No role matcher.
- [`decision-define-declarative-ruleset-revisioning`](2026-10-02-define-declarative-ruleset-revisioning.md):
  the revision, unknown-input and support-period model this record reuses.
- [`decision-define-declarative-detector-ruleset-contract`](2026-09-19-define-declarative-detector-ruleset-contract.md):
  the core parses the format itself, with no serde and no host-side validation.

This record specifies the contract only. It changes no code, type list, default
action, public item or version. Implementation is
[#1219](https://github.com/redact-secret/redact-secret/issues/1219).

## Decision

### 1. What an action policy is, and is not

An **action policy** is a data document that maps the safe metadata of a
finalized finding to one of `redact`, `block`, `warn` or `allow`. It is a third
configuration, separate from the **detection configuration** (profile, PII
selection, ruleset) and from **host budgets** (whole-input limits, incremental
limits, traversal limits). A ruleset adds detections and never an action. A
policy never adds, removes or reranks a detection. Confidence stays the
categorical `high`/`medium`/`low`; no number, threshold or ordered comparison
(`>= medium`) exists anywhere in the document.

### 2. Document

UTF-8 JSON, parsed by one strict parser in the Rust core (no new dependency, no
serde; `allowed-dependencies` is unchanged). Every surface hands the core the
document bytes; none validates or interprets it. A host may also accept a plain
native object (a JavaScript object, a Python dict) by serializing it once with
its standard compact encoder and passing those bytes; a serializer failure is
`INVALID_ACTION_POLICY`, class `MALFORMED_DOCUMENT`.

```json
{
  "actionPolicyRevision": 1,
  "base": "default",
  "rules": [
    { "id": "redact-acme-tokens", "match": { "type": ["acme-alnum-token"] }, "action": "redact" },
    { "id": "block-obfuscated-github",
      "match": { "type": ["github_token"], "obfuscation": ["invisible-characters"] },
      "action": "block" }
  ]
}
```

| Object | Member | Required | Value |
| --- | --- | --- | --- |
| document | `actionPolicyRevision` | yes, first member | integer `1` |
| document | `base` | yes | `"default"` |
| document | `rules` | yes | array of rules, 0 to 128, evaluated in order |
| rule | `id` | yes | caller rule id, an identifier (`is_identifier`: lowercase, at most 64 bytes), unique in the document |
| rule | `match` | yes | object with one to four of the keys below |
| rule | `action` | yes | `redact`, `block`, `warn`, `allow` or `default` |
| `match` | `type`, `detector` | no | non-empty array of identifiers |
| `match` | `confidence` | no | non-empty array of `high`, `medium`, `low` |
| `match` | `obfuscation` | no | non-empty array of `none`, `invisible-characters` |

There is no other member, no comment, no free-text field, no scalar shorthand
for a set, no wildcard, prefix, glob, regex or negation. Strings are printable
ASCII without a backslash, so no escape sequence is accepted. The only number
is the canonical decimal integer revision (`1.0`, `01`, `+1` and `1e0` are
rejected). Insignificant whitespace is space, tab, LF and CR. A byte-order mark,
trailing content and invalid UTF-8 are rejected. The document is at most 65,536
bytes, checked before parsing; a set holds at most 256 members.

### 3. Evaluation

For one finalized finding, rules are tried in document order. A rule matches
when every key it has holds (AND) and each key holds when the finding's value
is a member of that key's set (OR within a key). The **first matching rule
wins** and later rules are not consulted. Its `action` is the result, except
that `default` means the base action. When no rule matches, the result is the
base action. A key a rule omits does not constrain the match.

- **Base.** `base: "default"` is the running artifact's own default evaluation,
  `default_action_for(type, confidence)`, called at evaluation time. A document
  never carries, pins or snapshots the table, so a type added to the always-redact
  set protects an existing document on upgrade. A different base (a fixed
  action, a strict mode) would be revision 2. No fail-open base exists.
- **`default` as a rule action.** It matches and stops evaluation with the base
  result, which is how a user carves an exception out of a later broader rule
  without knowing what the default is.
- **Inputs.** Only `type`, `detector`, `confidence` and `obfuscation`. Not the
  finding id, range, finding index, finding count, specificity, a role or the
  input. A policy is therefore valid for a whole-input call and for an
  incremental session, whose context has no finding count.
- **Purity.** Evaluation is total, deterministic, infallible and free of I/O and
  callbacks, so a declarative policy never raises `POLICY_FAILURE` or
  `INVALID_POLICY_ACTION`. Worst-case cost per finding is linear in the
  document's member count, which the byte bound caps near 2,400 members; an
  index built at load is permitted when it is observationally identical.
- **Scope.** The policy sees finalized findings only. An overlap loser, a PII
  alternative and a candidate that never survived are never inputs, so a rule
  cannot resurrect them: allowing a winner leaves the loser unreported and its
  text unchanged. Ranking keeps using the fixed default, never the policy.

### 4. Unknown names: allowed for `type` and `detector`, rejected elsewhere

| Where | Unknown value | Result |
| --- | --- | --- |
| `type`, `detector` set member | an identifier no built-in emits | **accepted**; it matches only when a finding carries it |
| `type`, `detector` set member | not an identifier (uppercase, `*`, `a_`, over 64 bytes) | `INVALID_IDENTIFIER` |
| `confidence`, `obfuscation` set member, `action`, `base`, revision | outside the revision 1 vocabulary | `UNKNOWN_VOCABULARY_ENTRY`, `INVALID_ACTION`, `UNKNOWN_BASE`, `UNKNOWN_REVISION` |
| any object | unknown field | `UNKNOWN_FIELD`, at the key, before its value is read |

Unknown `type` and `detector` strings are valid for four reasons. (1) Both are
open sets by the 0.1.x stable contract: built-in types are added in patch
releases, so a document naming a type added in 0.1.5 must still load on 0.1.4,
or every added type would be a breaking change for the documents that mention
it. (2) A custom ruleset emits its own ids, which the policy cannot know,
and requiring the registry at load would couple the policy to detection
configuration that this record separates. (3) PII types exist only under an
activation. (4) The cost of a miss is bounded: an unmatched rule falls to the
security-first base. The closed vocabularies are different, because
`Action`, `Confidence` and `Specificity` are closed by contract, and an
unknown entry there can only be a mistake or a document written for a newer
revision, which must fail closed rather than be weakened.

A typo in a name is therefore silent. A typo in a loosening rule leaves the
default, which is safe. A typo in a tightening rule leaves the default instead
of the intended stricter action. The mitigation is feedback, not rejection:
[#1220](https://github.com/redact-secret/redact-secret/issues/1220) reports
which rule matched each finalized finding, and the guide tells authors to test
every rule against a representative input.

**Empty and contradictory matchers.** An empty `match`, an empty set and a
repeated key or member are rejected, because each is either a dead rule or a
silent catch-all. A contradiction cannot be written: keys are ANDed memberships
over sets, so the only ways to make one look contradictory are the rejected ones.
A `type` and `detector` pair no detector emits loads and never matches, and a
rule fully covered by an earlier rule loads and never fires, because open sets
make both undecidable at load; #1220 shows them. A full confidence set is a
deliberate catch-all and is accepted. An empty `rules` array is accepted: it is
the identity (the base only) and a legitimate "no overrides yet" state, unlike an
empty ruleset, which signals a loading mistake.

### 5. Errors

One new fixed code, **`INVALID_ACTION_POLICY`**, message "The supplied action
policy is invalid.", added to `SecretScanErrorCode` (an open set, so additive).
Loading either returns the whole policy or rejects the whole document; there is
no partial load and no fallback to the default. The class is reported on Rust,
Python, the CLI and the raw Node and WebAssembly errors; public JavaScript
carries only the code in 0.1.x, as the stable contract decides for rulesets.
Rust, Python and the CLI also report `rule_index`, the zero-based index of the
rule being read, or none for a document-level violation. Both are fixed
identifiers and integers; no error echoes a document string or an input byte.

The violation reported is the first in document order, with two fixed
precedences: the byte bound before any parsing, and the revision, which must be
the first member and is checked immediately, so a future revision is never read
under this grammar. A missing member is reported when its object closes.

| Class | Meaning |
| --- | --- |
| `ACTION_POLICY_TOO_LARGE` | over 65,536 bytes |
| `MALFORMED_DOCUMENT` | invalid UTF-8, BOM, syntax, unsupported token, escape, non-ASCII, non-canonical integer, trailing content |
| `UNKNOWN_REVISION` | revision is an integer other than 1 |
| `UNKNOWN_FIELD` | a member the object does not define (a role, range or specificity matcher included) |
| `DUPLICATE_FIELD` | a repeated member; the last never wins |
| `MISSING_FIELD` | a required member is absent, or the revision is not first |
| `WRONG_TYPE` | a supported value kind in the wrong slot (including a scalar where a set belongs) |
| `UNKNOWN_BASE` | `base` is not `default` |
| `INVALID_ACTION` | `action` is not one of the five |
| `INVALID_IDENTIFIER` | a rule id, `type` or `detector` member that is not an identifier |
| `DUPLICATE_RULE_ID` | two rules share an id |
| `EMPTY_MATCH` | a `match` with no key |
| `EMPTY_SET` | a set with no member |
| `DUPLICATE_SET_MEMBER` | a repeated member in one set |
| `UNKNOWN_VOCABULARY_ENTRY` | a `confidence` or `obfuscation` member outside the vocabulary |
| `TOO_MANY_RULES` | more than 128 rules |
| `SET_TOO_LARGE` | more than 256 members in one set |

A host-level misuse keeps its existing code: supplying a callback and an action
policy together is `INVALID_OPTIONS`.

### 6. Revision semantics

`actionPolicyRevision: 1` is frozen byte for byte, by the same rules as
[`decision-define-declarative-ruleset-revisioning`](2026-10-02-define-declarative-ruleset-revisioning.md):
a new key, vocabulary entry, action, base, matcher, bound or document kind is
revision 2, and an unknown revision, field or entry always fails closed. A new
`Obfuscation` value the core later emits does not change revision 1: such a
finding matches only rules without an `obfuscation` key, and a document that
names it needs revision 2. Revisions coexist, share one internal evaluator, and
revision 1 is supported through the major series in which revision 2 ships and
the next one. New `ActionPolicyErrorClass` variants that relabel a rejection
already made are additive. A changed result for the same document and finding is
a behavioral change only through the base (the default evolves under its own
changelog rules), never through the grammar. Revision 2 candidates, listed so
none enters revision 1: a different base, role or range matchers (barred until a
role grammar reopens [that decision](2026-10-06-keep-credential-role-facts-out-of-detection-attribution-and-default-action.md)),
negation, wildcards, a note field, and a rule that adds an action.

The core keeps no identity, hash or version of a particular policy. A caller who
keys evidence to a policy uses the SHA-256 of the exact document bytes.

### 7. Evaluator ownership: Rust-owned, exposed through each binding

The core owns parsing, validation, evaluation and the base delegation. Rust
exposes an immutable, `Clone`, `Send + Sync` value (proposed `ActionPolicy`,
built by parsing bytes) that implements both `Policy` and `IncrementalPolicy`.
Node, WebAssembly, Python and the CLI are thin handles over the same code.
Rejected: an equivalent evaluator per host. It would implement the accept and
reject rules once per binding, so surfaces could diverge on which documents
load, the exact failure the ruleset record rejected for a typed builder. It
would also need the default table or a foreign call per finding to reach the
core's default, and every evaluation would cross the callback boundary that a
Rust evaluator avoids. Conformance is still required: the shared fixture
`conformance/fixtures/action-policy-v1.json` is run by the Rust core for
semantics and by every binding and the CLI for plumbing, so the same bytes
yield the same code, class, rule index and action on every surface. The cost is
parser bytes in the engine floor that `common` and `full` WebAssembly both
carry. The 3% of `full` bound this record first proposed was an estimate, not an
enforced budget, and #1219 measured the cost instead of treating it as a gate.
Against the `db0e5c8d` build, with `scripts/build-browser-artifact.mjs` under the
release profile and brotli quality 11 (the call `scripts/measure-wasm-profiles.mjs`
uses), the increment is:

| Artifact | `db0e5c8d` brotli | With the parser | Increase |
| --- | --- | --- | --- |
| `full` | 164,789 | 170,442 | +5,653 (3.43% of `full`) |
| `common` | 116,647 | 122,535 | +5,888 |
| `full` + `pii` | 262,175 | 268,265 | +6,090 |
| `common` + `pii` | 214,169 | 219,420 | +5,251 |

That is the accepted cost. It includes about 800 bytes for the exported
JavaScript default evaluator (section 8). Dropping the evaluator export and
the rule index from the raw WebAssembly error text would still leave `full` at
+5,064 (3.07%) in a diagnostic build, so the parser, not the binding glue, is the cost. Leaving
WebAssembly without the option was rejected because every runtime must load and
evaluate the same documents. Future growth of the
parser re-measures against these figures, and the evidence is
[`docs/audits/evidence/1219`](../audits/evidence/1219/README.md).

A binding must not hold a compiled policy in a process-global, thread-local or
one-slot cache another caller can evict or overwrite (the single ruleset slot
#1221 documents for WebAssembly). The compiled value is owned by the object the
caller holds.

### 8. Surfaces, the callback, and the public default evaluator

The policy applies to whole-input calls, to incremental sessions and stream
adapters, and to the CLI (`--action-policy <path>`, the host reads the file).
Check mode keeps its rule that any finding exits 1, and redact mode replaces
`redact` and `block` spans. The option is new and additive on every surface
(proposed JavaScript `actionPolicy`, Python `action_policy`); #1219 fixes the
names through the `core-public-api` review. Public findings gain no field: the
matched rule id appears only in #1220's explain output.

The legacy callback is unchanged. It replaces the default entirely, runs once
per finalized finding, a throw is `POLICY_FAILURE`, a bad return is
`INVALID_POLICY_ACTION`, and nothing merges it with an overlay. It stays the
escape hatch for what four matchers cannot say (position, count, external
state). A call or session takes a callback or an action policy, never both.

A public default evaluator is needed on exactly one surface. Rust
`DefaultPolicy` and Python `default_policy` exist; JavaScript has none, so a
JavaScript callback that wants "mine, else the default" can only copy the table.
#1219 adds a JavaScript `defaultPolicy` (`evaluate` delegating to the core) for
parity. No surface exports the type list, and an empty-rules document is the
declarative equivalent.

### 9. What requires reconstruction

A policy is immutable. There is no edit, merge, reload or hot-swap API.

| Change | Requires |
| --- | --- |
| any byte of the document | parse a new policy; existing sessions keep the old one |
| callback to document, or back | new options or session |
| ruleset, PII selection or profile | nothing for the policy; the detection side rebuilds under its own contract |
| whole-input, incremental or traversal limits | nothing for the policy |
| artifact upgrade | nothing; documents are portable, the compiled form is never persisted, only the base may evolve |
| captured state of a callback closure | undetectable: the library calls the supplied object at each finding and keeps no revision of it |

An incremental session binds its policy at construction and evaluates it once
per finding after the finding is final. A native object passed in is serialized
at that moment, so a later mutation of it changes nothing. A callback that
mutates its own state mid-stream makes the output depend on timing; a caller who
needs a consistent configuration builds a new callback and a new session. A
configuration-bound scanner ([#1222](https://github.com/redact-secret/redact-secret/issues/1222))
holds one policy as part of its immutable snapshot and is rebuilt to change it.

## Examples

Before, to redact a ruleset detection (default `warn`) a JavaScript caller
writes a callback that must also reproduce every other default:

```js
const policy = { evaluate(f) { return f.type === "acme-alnum-token" ? "redact" : COPIED_DEFAULT_TABLE(f); } };
```

After, the same intent is data, and the default is never copied:

```js
actionPolicy: { actionPolicyRevision: 1, base: "default",
  rules: [{ id: "redact-acme", match: { type: ["acme-alnum-token"] }, action: "redact" }] }
```

An exception to a broader rule uses `default` (finding `jwt` at medium keeps the
base action, any other medium finding is allowed):

```json
{ "actionPolicyRevision": 1, "base": "default", "rules": [
  { "id": "keep-default-jwt", "match": { "type": ["jwt"] }, "action": "default" },
  { "id": "allow-medium", "match": { "confidence": ["medium"] }, "action": "allow" } ] }
```

## Conformance fixture and evidence

[`conformance/fixtures/action-policy-v1.json`](../../conformance/fixtures/action-policy-v1.json)
is the truth table: 37 evaluations (matched rule, unmatched fallback, unknown
type, all four actions, the `default` action, AND, set membership, and an
ordering conflict in both orders), 17 first rejections (one per class), 41
additional rejections, accepted edge documents at every bound, five end-to-end
cases, and the host obligations above. `base` is a sentinel resolved by each
surface's own default evaluation, never a literal, so the fixture copies no
part of the default table. Seven anchors check that resolution against facts
accepted decisions freeze.

The truth table was cross-checked with a throwaway reference implementation
written from this page; no product code or installed artifact ran it. The
end-to-end findings and byte offsets were observed with the CLI built from
`db0e5c8d` (0.1.0-beta.13). No host parity, performance or size claim is made.

## Trade-offs

- **False negatives.** An overlay can lower an action, so a user can leave a
  credential in output; the default is unchanged and the user owns the change,
  as the role decision already says. A lowering rule on `contextual_secret`
  lowers every finding of that type, because findings carry no role: selection is
  as coarse as the type. A broad early rule can shadow a later `block`; revision 1
  does not analyse shadowing. A tightening typo leaves the default. Overlap losers
  stay out of reach, so `allow` on a winner never reveals the loser.
- **False positives.** A user may raise `warn` to `redact` or `block` for a whole
  type, over-redacting its benign values. Explicit sets keep this deliberate: a
  wildcard such as `aws_*` was rejected because an `allow` rule would silently
  cover every future type, and a new type always falls to the base until named.
- **Cost.** A parser in the engine floor; per-finding linear work bounded by the
  byte cap; a second configuration object callers must test.

## Alternatives considered

- **Per-host evaluators.** Rejected in section 7.
- **A line grammar like the ruleset's.** Rejected: a policy is most often built
  from a native object or a JSON file, and a text grammar would make every host
  render a second format. The strict subset keeps the parser small.
- **Pinning the base to a table snapshot.** Rejected: an upgrade would stop
  protecting a document against new always-redact types.
- **Rejecting unknown types, or a registry-aware load.** Rejected in section 4.
- **Layering a callback over an overlay.** Rejected: two orders, two failure
  modes and a second place to copy the default; the callback stays a replacement.
- **Ordered comparison or numeric thresholds on confidence.** Rejected: the
  value is categorical and a threshold reads as a probability.
- **Optional or generated rule ids.** Rejected: #1220 needs ids that survive a
  reorder.

## Consequences

#1219 implements the core parser and evaluator, the `INVALID_ACTION_POLICY` code
(`SecretScanErrorCode::ALL` grows to 23), the five surfaces and the JavaScript
default evaluator, and runs the fixture on every surface. #1220 builds on the
evaluator returning the action and the matched rule index, kept crate-internal
until it decides what is public. [#1218](https://github.com/redact-secret/redact-secret/issues/1218)
documents finalized-finding scope under the existing record; this one adds no
policy-aware overlap. The role decision's open question, selecting "search-only
keys", is answered: revision 1 selects by type, detector, confidence and
obfuscation only. This record adds one row to `docs/specs/engine.md` and changes
no detector, default, type or version.

### Reopening bar

A reviewed role or specificity grammar, a measured need for a second base, or a
documented case a four-key match cannot express reopens the matching item, as a
revision 2 proposal with a benign corpus and an overlap analysis.
