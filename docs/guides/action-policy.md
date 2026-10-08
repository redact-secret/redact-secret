# Declarative action policy

[Documentation home](../README.md) · [Detection and limits](../reference/detection.md)

A policy decides what happens to each finalized finding: `redact`, `block`,
`warn` or `allow`. The default policy covers every finding, so a user who wants
one small change should not have to reproduce it. An action policy is data that
changes only what a few rules name and leaves every other finding at the default
action the running artifact computes. The contract is
[`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](../decisions/2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md).
A policy is an argument of each call and owns no detection configuration; see
[configuration ownership](configuration-ownership.md) for what each surface owns
and how to keep several policies, or several PII selections, in one deployment.

Every surface below was introduced in `0.1.0-beta.14`; `0.1.0-beta.13` has none of
them. Support today (`current`): the Rust core (`load_action_policy`), the command
line (`--action-policy <path>`), Python (`action_policy=`) and the JavaScript package
`@redact-secret/core` (`actionPolicy`) on both runtimes, the Node addon and the
WebAssembly artifact.

## Write a policy

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
| document | `actionPolicyRevision` | yes, the first member | the integer `1` |
| document | `base` | yes | `"default"` |
| document | `rules` | yes | an array of 0 to 128 rules, evaluated in order |
| rule | `id` | yes | a lowercase identifier of at most 64 bytes, unique in the document |
| rule | `match` | yes | an object with one to four of the keys below |
| rule | `action` | yes | `redact`, `block`, `warn`, `allow` or `default` |
| `match` | `type`, `detector` | no | a non-empty array of identifiers |
| `match` | `confidence` | no | a non-empty array of `high`, `medium`, `low` |
| `match` | `obfuscation` | no | a non-empty array of `none`, `invisible-characters` |

The document is UTF-8 JSON of at most 65,536 bytes. It has no other member, no
comment, no wildcard, no regular expression, no negation and no numeric
threshold. Strings are printable ASCII without a backslash, so no escape
sequence is accepted, and the only number is the integer revision. A set holds
at most 256 members. A host that has a native object serializes it once and
passes the bytes.

## How a finding is decided

For one finalized finding the rules are tried in order. A rule matches when
every key it has holds, and a key holds when the finding's value is a member of
that key's set. The first matching rule wins and later rules are not consulted.
Its `action` is the result, except that `default` means the base action. When no
rule matches, the result is the base action.

The base is the running artifact's own default evaluation of the same finding,
computed when the finding is decided. The document never carries the table, so a
type added to the always-redact set protects an existing document after an
upgrade. The rule action `default` is how a rule carves an exception out of a
later, broader rule without knowing what the default is:

```json
{ "actionPolicyRevision": 1, "base": "default", "rules": [
  { "id": "keep-default-jwt", "match": { "type": ["jwt"] }, "action": "default" },
  { "id": "allow-medium", "match": { "confidence": ["medium"] }, "action": "allow" } ] }
```

A policy sees finalized findings only. A candidate that lost an overlap is never
an input, so a rule cannot bring it back: allowing a winner leaves the loser
unreported and its text unchanged. A policy never adds, removes or reranks a
detection, and it changes no default.

## Limits you should know

- `type` and `detector` names are open sets. A name no built-in emits loads and
  matches only when a finding carries it, so a typo in a name is silent. A typo
  in a loosening rule leaves the default; a typo in a tightening rule leaves the
  default instead of the stricter action you meant. The loader still accepts
  them; [`resolveConfig`](#diagnose-a-policy-before-use) reports them as
  warnings. Test every rule against a representative input and check the
  reported action; the [comparison](#explain-and-compare) names the rule that
  decided each finding.
- A rule on `contextual_secret` lowers or raises every finding of that type,
  because findings carry no credential role.
- A broad early rule shadows a later one, and a rule an earlier rule fully covers
  loads and never fires. The loader does not analyse this;
  [`resolveConfig`](#diagnose-a-policy-before-use) reports the cases it can prove.
- An `allow` rule can leave a credential in the output. The default is unchanged
  and the policy owner owns that change.

## Diagnose a policy before use

`resolveConfig` (JavaScript) and `resolve_config` (Rust) check a policy that
loaded against the artifact's catalog and the resolved configuration, and report
findings as `config-diagnostics/v1` items. They never change loading: the same
document is accepted or rejected as before, a typo leaves `ok` true, and the
only place it shows is the diagnostics. Each item carries a code, a severity, a
fixed-syntax `path` such as `actionPolicy.rules[2].match.type[0]`, and an `id`
that is only a catalog detector id or a rule id. A name you typed is never
echoed, only its position. At most 256 items are returned, errors first; the
`truncated` flag says when more existed.

| Code | Severity | Meaning |
| --- | --- | --- |
| `ACTION_POLICY_UNKNOWN_TYPE` | warning | No detector this artifact includes declares that `type`. It may be a typo, or a ruleset, custom or future type |
| `ACTION_POLICY_UNKNOWN_DETECTOR` | warning | Neither the catalog nor the supplied ruleset has that `detector` id |
| `ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR` | warning | The detector (or the only detector declaring that type) is compiled in but disabled by the selection |
| `ACTION_POLICY_RULE_ON_NOT_INCLUDED_DETECTOR` | warning | A `full` built-in this artifact does not include, for example a provider detector in `common` |
| `ACTION_POLICY_SHADOWED_RULE` | warning | One earlier rule matches everything this rule matches, so this rule never decides a finding. `related` names the earlier rule |
| `ACTION_POLICY_ANALYSIS_UNCERTAIN` | info | Nothing can be proven: a callback policy, or a name a ruleset or PII selection could emit |

A shadow is reported only when it is provable from the two documents. A rule
matches when every key it has holds, a key holds when the finding's value is in
its set, the first matching rule wins, and a `default` action stops evaluation
too. So an earlier rule shadows a later one when, for each key, it has no such
key or the later rule has it with a subset of the members. Partial overlap,
disjoint rules, a narrow rule before a broad one, a later rule that needs a key
the earlier lacks, and a combination of several earlier rules are not reported,
so some real shadowing goes unreported but no rule that can fire is called dead.
The test compares your own strings, so it holds for custom names too.

The diagnostics say nothing about whether a finding of a type can occur or about
detection coverage. Which rules decided a set of sample findings is a separate
question: a Rust caller folds the `DecisionBasis` of a comparison into
`SampleRuleHits`. A rule with no sample hit is not unreachable and is never
reported for that reason.

Only a vocabulary you declare closed makes an unknown name an error. In Rust,
`ConfigRequest::closed_types` and `closed_detectors` turn
`ACTION_POLICY_UNKNOWN_TYPE` and `ACTION_POLICY_UNKNOWN_DETECTOR` into errors
(`ok` is then false) for names outside the catalog, the supplied ruleset and
your list. JavaScript supports the same declarations in an explicitly tagged
`runtime-config/v2` preview:

```ts
const preview = resolveConfig({
  schema: "runtime-config/v2",
  actionPolicy: myPolicy,
  closedTypes: [],
  closedDetectors: [],
});
if (!preview.ok) throw new Error("Invalid action policy configuration");
```

An absent list preserves open-vocabulary diagnostics; `[]` declares no additional
names, while a string array declares your additional types or detector ids. Known
artifact names and supplied ruleset detector ids remain recognized. These lists
are validation declarations, not detector registrations. `runtime-config/v1`
and an omitted schema reject either new field, so use the explicit v2 tag.
Malformed lists are `WRONG_TYPE`; no invalid name is echoed. A successful preview
changes no owner or future scan: pass the reviewed `actionPolicy` separately to
the operation that will use it. `SampleRuleHits` remains Rust-only.

## Explain and compare

Before adopting a change, run it against a representative input and read why
each finding got its action. The Rust core, the command line, Python and
JavaScript compare 1 to 4 policies (a baseline and up to three candidates) over
**one** detection pass: detection runs once, then every policy decides the same
finalized findings. Support today (`current`): Rust (`compare_action_policies`),
the command line (`--compare-action-policy`), Python
(`redact_secret.compare_action_policies`, see the [Python guide](python.md#explain-and-compare-action-policies))
and JavaScript (`compareActionPolicies` on the Node addon and WebAssembly alike,
see [Compare in JavaScript](#compare-in-javascript)). Every surface now ships it.

```bash
redact-secret --action-policy current.json --compare-action-policy next.json app.env
redact-secret --json --compare-action-policy next.json app.env   # baseline is the default
```

For every finding the report gives each policy's action and its reason:

| Basis | Meaning |
| --- | --- |
| `rule` | a rule matched; its `ruleId` and zero-based `ruleIndex` are reported |
| `rule-default` | a rule with action `default` matched, so the action is the base (the running artifact's default) and evaluation stopped there |
| `no-rule-matched` | no rule matched, so the action is the base |
| `default-policy` | the side is the default policy, with no document |
| `callback` | the side is a legacy callback; only its action is known |

Each document-based policy is bound to the SHA-256 of its exact bytes
(`documentSha256`, `document_sha256` in Python), so the same file gives the same binding on every surface and
any changed byte, including whitespace, changes it. The detection configuration
(activation identity, profile, detector count) is reported separately; a custom
ruleset's identity is yours to record, for example a digest of its bytes.

What a comparison is, and is not:

- It is a **preview**. It edits no input, renders no placeholder and changes
  nothing `scan`, `redact` or a session does. The report says `"mode": "preview"`
  and `"enforced": false`. To get the effect, run the real call with the policy.
- It covers **finalized findings only**. An overlap loser, a suppressed PII
  alternative and anything detection missed are not listed, and a clean report is
  not a coverage claim. A rule that fires on no finding of your sample has not
  been shown dead; try more inputs.
- It carries no input byte, matched value, snippet, hash of either, or score.
- A comparison runs **whole inputs only**. Standard input, incremental sessions
  and stream adapters are not compared in this version, and the CLI refuses
  standard input rather than substituting another path.
- A legacy **callback** can be one side. It is called once per finding in finding
  order, with the same context `scan` gives it, one side at a time in the order
  supplied. If it fails, the whole comparison fails with `POLICY_FAILURE` and no
  partial result. A callback with state or side effects advances them during a
  comparison like any other call.
- The result is bounded: the whole-input byte and finding limits apply, and at
  most 4 policies are accepted (`INVALID_OPTIONS` otherwise).

`--compare-action-policy` exits `0` when every policy chooses the same action for
every finding (or there are no findings), `1` when at least one finding's action
differs, and `2` on any failure, with nothing on standard output. Finding
something is never a failure in this mode. See the
[command line guide](cli.md#compare-action-policies) and the
[Rust guide](rust.md#compare-action-policies); the decision is
[explain and compare action policies](../decisions/2026-10-06-explain-and-compare-action-policies-over-one-detection-pass.md).

## Rust

`load_action_policy` returns an immutable, `Clone`, `Send` and `Sync`
`ActionPolicy` that is both a `Policy` and an `IncrementalPolicy`; see the
[Rust guide](rust.md#action-policy). A session binds the policy it was built with.
The legacy callback is unchanged and replaces the default entirely: a call takes
a callback or an action policy, never both.

## Python

`scan` and `scan_and_redact` take a keyword-only `action_policy`, and
`IncrementalSanitizer` takes the same keyword. It is a `dict` or the document
itself as `bytes`, `bytearray` or `str`:

```python
import redact_secret

policy = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "warn-jwt", "match": {"type": ["jwt"]}, "action": "warn"}],
}
result = redact_secret.scan_and_redact(text, action_policy=policy)
```

A `dict` is serialized once, when the call or session is built, with
`json.dumps(value, separators=(",", ":"))`, so a later change to it affects
nothing. A value the encoder cannot serialize is `MALFORMED_DOCUMENT`. Because
the document is compact JSON in insertion order, the revision must be the first
key. Any other type raises `InvalidOptionsError`, and so does passing both a
`policy` callback and an `action_policy`; nothing is scanned in either case.

A whole-input call parses its document on every call. A session validates its
document once at construction and keeps the compiled policy for its whole life,
so an `IncrementalSanitizer` is the reusable form for a stream. No compiled
policy is kept anywhere but in the call or session that was given the document.
A rejected document raises `InvalidActionPolicyError` with `code`
`INVALID_ACTION_POLICY`, `error_class` (one of the classes below) and
`rule_index`. The message stays the fixed text and repeats no byte of the
document. See the [Python guide](python.md#declarative-action-policy).

## JavaScript

`actionPolicy` is an option of `scan`, `scanAndRedact`,
`createIncrementalSanitizer` and the stream factories, in the root package and
in `@redact-secret/core/common`, on the Node addon and on the WebAssembly
artifact. It takes the document as a plain object, as UTF-8 JSON text, or as
bytes. An object is serialized once with `JSON.stringify`, at the call or when
the session is created, so changing it afterwards changes nothing; the member
order is the object's own, and `actionPolicyRevision` must be written first. A
value that cannot be serialized (a cycle, a `BigInt`) is `INVALID_ACTION_POLICY`,
and a value that is not an object, text or bytes is `INVALID_OPTIONS`.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const { text } = scanAndRedact("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", {
  actionPolicy: {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "keep-github", match: { type: ["github_token"] }, action: "warn" }],
  },
});
```

The Rust core parses and validates the document on both runtimes and the
package never reads it, so the same bytes load or fail identically on the addon
and in WebAssembly. The compiled policy belongs to the call or the session that
built it: nothing is cached in the module, so two live policies of different
content never affect each other, in either order, and a session keeps the policy
it was created with. Supplying a callback `policy` together with `actionPolicy`
is `INVALID_OPTIONS`, reported before the document is read, and a callback still
replaces the default entirely.

`defaultPolicy` is the core's default evaluation as a policy object. Its
`evaluate(finding)` asks the loaded binding, so a callback that wants "mine,
else the default" does not copy the default table, and an empty `rules` array
is the same behavior as data:

```ts
import { defaultPolicy } from "@redact-secret/core";
import type { SecretPolicy } from "@redact-secret/core";

const policy: SecretPolicy = {
  evaluate: (finding, context) =>
    finding.type === "acme-alnum-token" ? "redact" : defaultPolicy.evaluate(finding, context),
};
```

A rejected document throws the package's `SecretScanError` with the code
`INVALID_ACTION_POLICY` and the one fixed message; the public package carries
the code only in 0.1.x. The raw addon and WebAssembly errors (not part of the
public API) append the fixed class and the rule index to the message, for
example `The supplied action policy is invalid. (INVALID_ACTION, rule 0)`.

The WebAssembly artifacts carry the parser. Against the `db0e5c8d` build the
brotli size grows by 5,653 bytes for `full` (164,789 to 170,442, 3.43%), 5,888
for `common`, 6,090 for `full` with `pii` and 5,251 for `common` with `pii`; see
the [evidence](https://github.com/redact-secret/redact-secret/blob/0c62fd38bca75c5b28b042dc79789b708ebf1d17/docs/audits/evidence/1219/README.md).

### Compare in JavaScript

`compareActionPolicies(input, { policies, limits?, ruleset? })` is the
whole-input comparison, in the root package and in `@redact-secret/core/common`,
with identical results on the Node addon and on WebAssembly (the qualification
runs one fixture on both and requires the same result digest). `policies` holds
one to four sides, each with a `kind`:

- `{ kind: "default" }`, the default evaluation the loaded artifact computes;
- `{ kind: "action-policy", actionPolicy }`, the same object, text or bytes forms
  as the `actionPolicy` option, serialized once at the call;
- `{ kind: "callback", policy }`, a legacy `SecretPolicy`.

```ts
import { compareActionPolicies, initialize } from "@redact-secret/core";

await initialize();
const result = compareActionPolicies("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", {
  policies: [
    { kind: "default" },
    {
      kind: "action-policy",
      actionPolicy: {
        actionPolicyRevision: 1,
        base: "default",
        rules: [{ id: "allow-github", match: { type: ["github_token"] }, action: "allow" }],
      },
    },
  ],
});
// result.findings[0].decisions[1] is { action: "allow", basis: "rule", ruleId: "allow-github", ruleIndex: 0 }
// result.policies[1].documentSha256 is 64 lowercase hex characters
```

The result is frozen plain data in the CLI's `--json` shape with camel-case
names: `version`, `rangeUnit`, `mode: "preview"`, `enforced: false`, `detection`
(`activationIdentity`, `profile`, `detectorCount`), `policies` (`label` of
`baseline`, `candidate-1`, `candidate-2` and `candidate-3`, `kind`,
`documentSha256` or `null`, and per-action `counts`), `findingCount`,
`changedCount` and `findings` (the six finding fields, UTF-16 `start` and `end`,
`differs` and one `decisions` entry per side). An absent value is `null`, never
missing. `documentSha256` is the SHA-256 of the exact bytes the core parsed: the
text or bytes you gave, or, for an object, its compact `JSON.stringify` bytes.
The package keeps no policy handle, so the digest is read from the result.

Misuse is refused rather than ignored, each as `INVALID_OPTIONS` before detection
and before any callback: no side or more than four, an unknown `kind`, a field
that belongs to another kind, and any other option key, including keys that
could suggest an incremental or stream comparison (`incremental`, `stream`,
`chunks`, incremental limits). A non-string input is `INVALID_INPUT`. There is no
incremental or stream comparison in this version: the function takes one string,
and no session or stream adapter gains a method for it. A rejected document is
`INVALID_ACTION_POLICY` before any callback runs; `limits` and `ruleset` fail as
for `scan`.

A callback side is called once per finding in finding order with the same
`{ findingIndex, findingCount }` context `scan` gives it, sides one at a time in
the order supplied. If a callback throws the whole comparison fails with
`POLICY_FAILURE`, and if it returns something other than the four actions with
`INVALID_POLICY_ACTION`, on both runtimes, with no partial result and no later
call. Comparing a callback with state or side effects advances them like any
other call.

The WebAssembly artifacts also carry the comparison and the SHA-256. Against the
branch head that already held the core's comparison, the brotli size grows by
4,363 bytes for `full` (171,919 to 176,282, 2.54%), 4,329 for `common`, 4,256 for
`full` with `pii` and 4,612 for `common` with `pii`; against the `db0e5c8d` build
the parser, the digest and the comparison together add 11,493 bytes to `full`
(7.0%). See the [evidence](https://github.com/redact-secret/redact-secret/blob/0c62fd38bca75c5b28b042dc79789b708ebf1d17/docs/audits/evidence/1220/README.md).

### Compare configurations, not only policies

`compareActionPolicies` is for a change that only moves the action: it detects once,
because no policy can add, remove or move a finding. When the change may alter what is
detected (the detector selection, the PII selection, a ruleset or the limits), the
two passes are different passes, and `compareConfigurations` (issue #1254) runs one
independent pass per side and relates the findings:

```ts
import { compareConfigurations, initialize } from "@redact-secret/core";

await initialize();
const result = compareConfigurations("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", {
  configs: [{}, { detection: { exclude: ["github-token"] } }],
});
// result.differences[1].entries[0] is
// { kind: "changed", correspondence: "exact", base: [0], other: [0],
//   changes: ["type", "detector", "confidence", "action"] }
```

With the provider detector off, a contextual detector holds the same span, so the
difference is a type and detector change, not a removed finding. Each side takes the
`RuntimeConfig` members (`detection`, `pii`, `ruleset`, `actionPolicy`, `limits`); an
`actionPolicy` or callback `policy` at the top level applies to every side that has no
policy of its own. Findings carry no per-scan id; they correspond by their ranges in the
declared unit, and a split, merge or regrouping is listed as `ambiguous` rather than
paired. A side that cannot be built or hits a limit is reported with a fixed code and
gets no difference. The result is a preview scoped to that input
(`scope: "input"`, `enforced: false`): it has no text, and a side without findings does
not say a detector is ineffective. Policies with the same bytes on two sides do not make
two rulesets equal: compare `detectionDigest`. A callback may have side effects and has
no identity; it runs once per finding of each scanned side, side by side, and is listed
in `callbackSides`. It does not change an owner's selection: the temporary registries
exist only for the call. See the [API contract](../reference/api-contract.md#configuration-comparison).

## Command line

```bash
redact-secret --action-policy policy.json config.txt
redact-secret --redact --action-policy policy.json input.txt > sanitized.txt
git diff --cached | redact-secret --action-policy policy.json
```

The file is read once with a bounded read before any source is touched. Check
mode still exits 1 when any finding exists, whatever its action, and redact mode
replaces only `redact` and `block` spans. To preview a change instead of
enforcing it, use `--compare-action-policy` (see
[Explain and compare](#explain-and-compare)). See the [command line guide](cli.md).

## Errors

A rejected document fails whole, with the fixed code `INVALID_ACTION_POLICY`
and the message "The supplied action policy is invalid." There is no partial
load and no fallback to the default. Rust and the CLI also report the fixed
class and `rule_index`, the zero-based index of the rule being read (none for a
document-level violation); Python exposes them as `error_class` and `rule_index`, the raw Node addon
and WebAssembly errors append both to the message, and the public JavaScript package reports the code
only. No error repeats a byte of the document. The first
violation in document order is reported, after two fixed precedences: the size
bound before any parsing, and the revision, which must be the first member.

| Class | Meaning |
| --- | --- |
| `ACTION_POLICY_TOO_LARGE` | over 65,536 bytes |
| `MALFORMED_DOCUMENT` | invalid UTF-8, a byte-order mark, a syntax error, an unsupported token, an escape, a non-ASCII byte, a non-canonical integer or trailing content |
| `UNKNOWN_REVISION` | the revision is an integer other than 1 |
| `UNKNOWN_FIELD` | a member the object does not define |
| `DUPLICATE_FIELD` | a repeated member |
| `MISSING_FIELD` | a required member is absent, or the revision is not first |
| `WRONG_TYPE` | a supported value kind in the wrong slot |
| `UNKNOWN_BASE` | `base` is not `default` |
| `INVALID_ACTION` | `action` is not one of the five |
| `INVALID_IDENTIFIER` | a rule id, `type` or `detector` that is not an identifier |
| `DUPLICATE_RULE_ID` | two rules share an id |
| `EMPTY_MATCH` | a `match` with no key |
| `EMPTY_SET` | a set with no member |
| `DUPLICATE_SET_MEMBER` | a repeated member in one set |
| `UNKNOWN_VOCABULARY_ENTRY` | a `confidence` or `obfuscation` member outside the vocabulary |
| `TOO_MANY_RULES` | more than 128 rules |
| `SET_TOO_LARGE` | more than 256 members in one set |

## Revisions

`actionPolicyRevision: 1` is frozen byte for byte. A new key, vocabulary entry,
action, base, matcher or bound is revision 2, and an unknown revision, field or
entry always fails closed. A caller who keys evidence to a policy uses the
SHA-256 of the exact document bytes; the core keeps no identity of a policy.
