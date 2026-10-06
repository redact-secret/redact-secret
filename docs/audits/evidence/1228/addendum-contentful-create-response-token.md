# Addendum to #1228: the Contentful create-token response `token` member

**Result:** partly implemented, partly recorded as **policy-limited**, by the
rule that a bare `token` stays unmatched ([#1241](../1241/README.md) and the
decision `redact-provider-named-credential-assignments`). The independent round-1
measurement of Group C (benchmarks, candidate `e1284537`) found the `token`
member of the Contentful create-token response silent in 15 scored cases of
`contentful:cma-personal-access-token` (`G-token-member`, Contentful half). The
product now reads a `token` member beside the response's own documented
siblings, `sys` or `scopes`; it does **not** read a `token` member that stands
alone or beside only a `name`, which is what the measured cases hold, so the
group is expected to stay open on a re-run. The reason, the choices the
maintainers have and their cost are below. Evidence is project-authored and
maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `contentful-cma-personal-access-token-bearer-header-and-create-response-member`
  (`must-flag`, basis `project-policy`, redact-secret#1228 Group C): the value of
  the `token` member of the create-token response is treated as a credential
  "whatever its shape"; the page states no prefix, alphabet or length; the
  `sys.redactedValue` member is not asserted. Contentful documents
  `POST /users/me/access_tokens` with `content_management_read` or
  `content_management_manage` scopes, the token "only returned once", and an
  example response with a `token` member and a `sys.redactedValue` member
  (contract `contentful:cma-personal-access-token@2`, claims
  `creation-api-bearer-carrier-shown-once` and `reference-example-token-shape-differs`).
* The evidence fixture of the Case is `{"name": "<n>", "token": "<v>"}`; the
  round-1 spans show the generated layouts: `{"token":"<v>"}` (compact, spaced,
  CRLF and tabs, big preceding text, a neighbouring `password`) and the pretty
  `name` plus `token` object. No layout carries a `sys` or a `scopes` member.
* Case `contentful-cma-personal-access-token-documented-placeholders-and-masks`
  (`must-not-flag`): `CFPAT-123...789`, `CFPAT-xxx` (silent through the
  [#1234 addendum](../1234/addendum-brace-angle-mask-placeholders.md)).

## Root cause

`token` is the bare member name. Under the accepted rule it is not a credential
name by itself (`csrf_token`, pagination cursors, CAPTCHA and API tokens of every
kind share it), so a lone `{"token": "<v>"}` is never read, whatever the value.

## What is implemented

`scoped_context.rs` reads a quoted `token` JSON member, judged as `access_token`,
when a quoted `sys` or `scopes` member sits on its line or within the sibling
window of the [Elastic addendum](../1229/addendum-elastic-encoded-member.md) (the
documented members of a create-token response and of the request that makes it).
A real response, `{"sys": {...}, "name": "...", "scopes": [...], "token": "<v>"}`
in any member order and any layout of the window, now redacts the token, exactly
the value; the incremental retention hint of that addendum holds the lines.
`{"token": "<v>"}`, a `name` beside it, `token=<v>`, `token: <v>`, a `scopes` more
than five lines away and look-alike names (`tokens`, `token_type`, `tokenId`) stay
silent.

## Why the measured cases stay open: policy-limited

The 15 measured cases carry the member alone or beside `name`. Reading them is not
a scoping of the bare `token` rule, it is the bare rule itself, or a `name`
sibling that is as common as `token`:

| Choice | Reads the 15 cases | Cost |
| --- | --- | --- |
| A. **Kept (this record):** `token` only beside `sys` or `scopes` | no | the evidence fixture's own layout and a lone `{"token": ...}` are not read: a stated false negative that leaves a created token in a response log whose members are only `name` and `token` |
| B. `token` beside `name` | the pretty `name` plus `token` cases only (not the compact lone `token` ones) | every `{"name": ..., "token": ...}` object (a login response, a webhook, a CSRF form) becomes a candidate: a high-confidence `redact` of whatever the 8+ byte random value is |
| C. a bare `token` JSON member | all 15 | reverses the accepted bare-name rule of #1241 for JSON members; every `{"token": "<random>"}` (a pagination cursor, an anti-forgery token, a JWT already read by its own detector) is a `redact`; the bare name was ruled out as an accepted rule |

Choice A is the one consistent with the standing rule; it is a **deliberate policy
deviation from the Case** for the measured layouts, with the basis above. The
security-first default would read the member (choice C); it is not taken here
because the bare-name rule is an accepted decision, not an oversight, and
because the cost of C is a redaction of ordinary documents, which the maintainers
weighed in #1241 and the contextual-detection decision.

## Per-party consequences

* Product: a documented create-token response is protected; a lone `token` member
  is not.
* Benchmarks: the 15 `token-member-*` and `fixture-replay-cma-pat-create-response-token-member`
  cases are expected to remain misses on a re-run; they should be scored as
  policy-limited (recorded false negatives), not as a defect, until the
  maintainers rule on B or C. A re-run will show whether any layout carries a
  `scopes` or `sys` member that was not visible from the gap list.
* credential-evidence: if the maintainers keep choice A, the Case's fixture
  should carry a documented sibling (`sys` or `scopes`) or be restated as a
  `policy: not-read` layout; the Case's text ("the token member of the create-token
  response") is not contradicted.

## False-positive measurement

Scanned with the CLI before and after this change: redact-secret 1,536 tracked
files, credential-evidence 4,398, the other sibling repositories 3,232. New
findings from this reader: **0**; removed: 0.

## Tradeoffs

* False positive added: a `token` member of a JSON document that also has a `sys`
  or `scopes` member within five lines and a random 8+ byte value (a token
  response with scopes, which is a credential).
* False negative kept, stated: the lone `token` and the `name` plus `token`
  layouts, `token` in any non-member layout, and a `token` more than five lines
  from its sibling.

## Tests

`crates/secret-scan-core/tests/contentful_create_response_token_1228.rs` (4 tests):
the member beside `sys` and `scopes` in every order and layout (pretty, compact,
CRLF and tabs, a raw HTTP response); context, multibyte and large preceding text
and a neighbouring secret; the lone, `name`-only, distant-sibling, non-member and
look-alike layouts silent; placeholders, masks, references and the four-character
`redactedValue` silent. Every input runs whole, in 7-byte chunks and in 1-byte
chunks with equal text and findings.
