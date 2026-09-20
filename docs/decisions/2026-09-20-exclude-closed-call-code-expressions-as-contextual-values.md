---
decision_id: decision-exclude-closed-call-code-expressions-as-contextual-values
status: accepted
scope: workspace
title: Exclude closed-call source-code expressions from generic-token's contextual values
decided_at: 2026-09-20
---

# Exclude closed-call source-code expressions from generic-token's contextual values

## Decision

Extend `generic-token`'s source-code-expression exclusion
(`crates/secret-scan-core/src/detectors/generic_token.rs`,
`is_source_code_expression`) with two further checks, both built on one
scanner, `scan_identifier_chain`, that walks a value as
`Segment ( '.' Segment )*` where a `Segment` is an identifier optionally
followed by balanced `(...)` / `[...]` groups:

- **A complete call expression.** `is_call_expression` excludes a value the
  scanner consumes end to end where at least one segment carried a balanced
  `(...)` argument group: `getSecretOrThrow(SECRET_NAME_CONSTANT)`,
  `SecretManagerServiceClient.access_secret_version(req)`,
  `django.core.signing.get_cookie_signer(salt=SALT)`,
  `rsa.generate_private_key(public_exponent=65537)`.
- **A call expression cut short inside its arguments.**
  `is_truncated_call_expression` excludes a value whose chain runs into a `(`
  or `[` — opened directly on an identifier segment — that never closes
  before the value ends: `crypto.createPrivateKey({` from
  `crypto.createPrivateKey({ key: pem })`, `helper(FIRST_ARGUMENT` from
  `helper(FIRST_ARGUMENT, SECOND_ARGUMENT)`. This check applies only to
  **unquoted** values, which the detector now distinguishes through a
  `ValueForm` argument threaded from `assignment_value` down to
  `is_non_secret_reference`.

`ends_with_open_call_or_subscript` (issue #278) is kept unchanged rather than
folded into the new truncation check, so quoted values keep exactly the
behavior #278 gave them.

## Rationale

#278 closed the *open*-bracket half of the problem: it excluded a value
ending in an unmatched `(` or `[`, which is what the unquoted-value scan
leaves behind when a call's argument is a quoted string. It left the closed
half open. An expression whose call parentheses are balanced —
`Klass.method(arg)`, `helper(ARG)` — matched none of #278's four checks: it
starts with no listed reference root, a `PascalCase` segment or an attached
call group stops it being an all-`lower_snake_case` dotted chain, it carries
no `Identifier<…>` / `Identifier[…]` syntax, and it does not *end* on an open
bracket. Assigned to a credential-named variable, which is exactly how SDK
and configuration code reads, it was reported at high confidence and the
default policy **redacted** it, rewriting ordinary source code (issue #467).

Anchoring both new checks to `scan_identifier_chain` rather than to the
presence of a parenthesis is what keeps this from being the blanket "value
contains `(`" rule #467 itself rejected as too broad:

- **The chain must span the whole value.** A passphrase that merely embeds a
  balanced group, `SYNTHETIC(REVOKED)_CONTEXT_VALUE`, has characters after
  the group that are neither `.` nor end-of-value, so it is not a call
  expression and stays detected.
- **Every bracket group must open on an identifier.** `$(`, `#{`, and `{{`
  open on punctuation, so the interpolation and template *fragments* that
  issues #266 and #279 deliberately keep detected
  (`$(SYNTHETIC_REVOKED_CONTEXT_VALUE`, `SYNTHETIC_REVOKED_{{`,
  `SYNTHETIC_REVOKED_#{x`) scan as "not a chain" rather than as truncated
  code.
- **Truncation is an unquoted-only concept.** An unquoted value ends wherever
  `is_unquoted_value_boundary` says it does, so it can be cut in the middle
  of a bracket group; a quoted value carries its own delimiters and never is.
  Restricting `is_truncated_call_expression` to unquoted values is what keeps
  a parenthesized *literal* passphrase, `password: "SYNTHETIC(REVOKED_CONTEXT_VALUE"`,
  detected at high confidence — the paired positive #467 asked for.

The truncation check also fixes #467's worst case, where the defect was not
merely over-redaction but corruption. Because the value boundary stopped at
the space inside `createPrivateKey({ key: pem })`, redaction replaced only
`crypto.createPrivateKey({` and left ` key: pem })` stranded, turning valid
source into syntactically broken output. Excluding a value that opens a
bracket group it never closes is precisely the condition under which that
stranding can happen for a code expression.

Downgrading these values to `warn` rather than excluding them was rejected
for the same reason #278 rejected it: `Klass.method(arg)` under a
credential-named variable is ordinary code, common enough that a `warn`
action is a hit a reviewer dismisses repeatedly, and neither signal above
plausibly matches real secret content.

## Consequences

- `generic_token.rs` gains `is_identifier_byte`, `closing_bracket_for`,
  `balanced_group_end`, `ChainScan`, `scan_identifier_chain`,
  `is_call_expression`, `is_truncated_call_expression`, and a `ValueForm`
  argument on `assignment_value`, `assignment_confidence`,
  `is_non_secret_reference`, and `is_source_code_expression`.
  `authorization_candidates` passes `ValueForm::Unquoted`; the distinction
  cannot matter there, because `is_authorization_value_byte` already excludes
  every bracket from an authorization value's character class.
- All five of #467's reproducers produce no finding, across all five public
  surfaces, since they share this Rust core detector. Negative fixtures in
  `conformance/fixtures/synchronous-corpus.json` cover the
  PascalCase-member-call, bare-call, dotted-chain-plus-call,
  keyword-argument-call, `{`-truncated, and comma-truncated shapes; paired
  positive fixtures cover the embedded balanced group, the quoted unbalanced
  one, and the plain underscored control. A fixture in
  `conformance/fixtures/incremental-corpus.json` carries all of them together
  so every partition boundary must reproduce the whole-input reference.
- #278's five reproducers and the Go `cfg.RedisPassword` shape are unaffected:
  their fixtures and unit tests are unchanged and still pass, and the
  regenerated `common-profile-expectations.json` shows no existing fixture's
  result changing.
- **Accepted false-negative risk.** An unquoted value that is exactly an
  identifier chain plus a balanced argument group — a passphrase of the
  literal form `word(word)` — is now excluded, as is an unquoted value that
  opens a bracket on an identifier character and never closes it, such as
  `Tr0ub4(dor&3`. Both are judged rare next to the breadth of call syntax
  they let through clean, and the quoted form of either stays detected, which
  is how real credentials are overwhelmingly written in the syntaxes this
  detector targets. This is the same order of risk #278 accepted for its
  `lower_snake_case`-chain check.
- **Known residual, out of scope.** A value that embeds an interpolation or
  template delimiter opened on punctuation is still detected and still cut at
  the value boundary, so redacting `password=SYNTHETIC_REVOKED_#{x}_CONTEXT_VALUE`
  still strands `}_CONTEXT_VALUE`. That behavior is pinned by #266's and
  #279's tests and belongs to those issues, not to the code-expression
  boundary this record governs.
