# Declarative action policy

[Documentation home](../README.md) · [Detection and limits](../reference/detection.md)

A policy decides what happens to each finalized finding: `redact`, `block`,
`warn` or `allow`. The default policy covers every finding, so a user who wants
one small change should not have to reproduce it. An action policy is data that
changes only what a few rules name and leaves every other finding at the default
action the running artifact computes. The contract is
[`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](../decisions/2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md).

Support today (`current`): the Rust core (`load_action_policy`), the command
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
  default instead of the stricter action you meant. Test every rule against a
  representative input and check the reported action.
- A rule on `contextual_secret` lowers or raises every finding of that type,
  because findings carry no credential role.
- A broad early rule shadows a later one. Revision 1 does not analyse shadowing,
  and a rule an earlier rule fully covers loads and never fires.
- An `allow` rule can leave a credential in the output. The default is unchanged
  and the policy owner owns that change.

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
the [evidence](../audits/evidence/1219/README.md).

## Command line

```bash
redact-secret --action-policy policy.json config.txt
redact-secret --redact --action-policy policy.json input.txt > sanitized.txt
git diff --cached | redact-secret --action-policy policy.json
```

The file is read once with a bounded read before any source is touched. Check
mode still exits 1 when any finding exists, whatever its action, and redact mode
replaces only `redact` and `block` spans. See the [command line guide](cli.md).

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
