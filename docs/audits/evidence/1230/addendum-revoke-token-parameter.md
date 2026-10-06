# Addendum to #1230: the `token` parameter of a revocation or introspection request

**Result:** partly implemented, partly recorded as **policy-limited**, under the
accepted rule that a bare `token` stays unmatched ([#1241](../1241/README.md)).
The independent round-1 measurement of Group E (benchmarks, candidate `e1284537`)
found the `token` field of the Reddit revoke request body silent in 24 scored
cases of `reddit:oauth-access-token` (`G-reddit-token`: 23 with no finding, 1 with
a finding on a neighbouring secret only). The product now reads `token=` in a
form body or curl argument **when the request names a revoke or introspect
endpoint or carries `token_type_hint=`**, which is what RFC 7009 and RFC 7662
define, and does not read a `token=` with neither, so the cases whose input holds
neither are expected to stay open. Evidence is project-authored and
maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `reddit-oauth-revoke-token-request-body-token-field` (`must-flag`, basis
  `project-policy`, credential-evidence#238, Group E): the value of the `token`
  parameter of a `revoke_token` request body is treated as a credential whatever
  its shape, without deciding whether it is an access or a refresh token; both
  families are subjects (a shared slot); the carriers are Reddit's archived wiki,
  historical and unresolved, and "the uncertainty about currency is not a reason
  to stay silent". The evidence fixtures are a raw form request
  (`POST /api/v1/revoke_token`, `Content-Type: application/x-www-form-urlencoded`,
  body `token=<v>`) and a curl `-d token=<v> -d token_type_hint=refresh_token`.
* The same carrier exists outside Reddit: the OAuth 2.0 Token Revocation
  (RFC 7009) request is a form body with `token` and an optional
  `token_type_hint`, and Token Introspection (RFC 7662) the same `token`; the
  evidence fixtures of Adobe's web-app revocation (`POST /revoke`) use it too.

## Root cause

`token` is the bare name, which is not a credential name by itself under the
accepted rule (`csrf` and pagination `token=` parameters, a bare `token=` in any
unrelated form). Nothing in a bare `token=<v>` line says it is a revocation
request, so the generic reader never evaluated it.

## What is implemented

`scoped_context.rs` reads `token=<value>` (an assignment whose name is `token` and
whose operator is `=`: a form body, a curl `-d`, `--data`, `--data-urlencode`
argument, a query parameter), judged as `access_token`, only when the request
context is present:

* the line holds `token_type_hint=` (the optional parameter of RFC 7009 and
  RFC 7662, in either order with `token=`); or
* the line, or one of the nine lines above it (at most 2,048 bytes from that line
  through the `token=` line), carries a revoke or introspect endpoint as a whole
  path segment, any letter case: `/revoke`, `/revoke_token`, `/introspect`
  (`/revoked`, `/revoke-all` and a `revoke` in a query string are not).

The nine lines cover a raw HTTP request with its headers and blank line, and a
continued curl command (`curl ... /revoke_token \` on one line, `-d token=<v> \` on
the next). The incremental retention hint of the
[Elastic addendum](../1229/addendum-elastic-encoded-member.md) holds a unit open
for nine lines after a line that names an endpoint or the hint, so the request
line and the body are scanned together at any chunking (with the hint disabled
the raw request and the continued curl layouts fail the chunked runs). Everything
else is unchanged: the 8-byte floor, the entropy tiers and the placeholder,
reference and mask exclusions apply, and the `token_type_hint` parameter itself
and every other name in the request keep their own reading (`client_secret=` in a
revoke body is read as before).

## Measured behaviour (synthetic values built at run time; whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| `POST /api/v1/revoke_token` (or `/oauth2/revoke`, `/revoke`, `/oauth/introspect`) with a form body, `token=<v>` first, middle, last, LF, CRLF, end of input, percent-escaped neighbours | silent | high, `redact`, exactly `<v>` |
| `curl -X POST <url>/revoke_token -d` (also `--data`, `--data-raw`, `--data-urlencode`) `token=<v>`, in double or single quotes or none, the flag before the URL, a continued command | silent | same |
| `token=<v>&token_type_hint=refresh_token` (either order) with no endpoint anywhere; `curl -d "token=<v>&token_type_hint=access_token" <other url>` | silent | same |
| shapes: 32 hex, 64 alphanumeric, 40 URL-safe, 16 lower-case, hyphenated, dotted and underscored, 150 bytes, 16 bytes | silent | same |
| two requests in a row, multibyte text around, a 64 KB preceding body, a neighbouring `password=` | the password only | each value exact |
| `token=<v>` alone, `?token=<v>`, a body under another endpoint, `TOKEN=<v>`, `{"token":"<v>"}` in a revoke request, the endpoint more than nine lines above, `/revoked`, `/revoke-all` | silent | silent |
| `token=${REDDIT_TOKEN}`, `$TOKEN`, `<token>`, `{token}`, `{{ token }}`, `********`, `TOKEN`, empty, prose naming the parameter | silent | silent |

## Policy-limited layouts

The Case's `token` slot is bare, and the round-1 corpus generates it in layouts
with no endpoint and no hint on the line or in the window (the gap list shows
expected spans starting at bytes 6, 22, 31 and 33 for `form-repeat`,
`form-curl-data-single`, `form-curl-data-urlencode` and `form-utf8-before-after`,
too early to hold an endpoint). Those are **not read**: reading a bare `token=`
anywhere is the bare-name rule, which #1241 and the contextual-detection decision
keep out: a `curl --data 'token=<v>'` with no endpoint and no hint cannot be told
apart from any other form field named `token`. The expected consequence for the
benchmarks is that the cases whose inputs carry the revoke request line, the URL
or the hint (the raw requests, the long curl lines, the fixture replays) move and
the short ones stay misses; the replay decides the split, and the stay-open ones
are recorded false negatives, a deliberate policy deviation from the Case with the
basis above and the consequence in the next section.

## Per-party consequences

* Product: a token in a revocation or introspection request is protected where
  the request names itself; a lone `token=<v>` is not.
* Benchmarks: score the context-free `token=` layouts as policy-limited
  (recorded false negatives), not as a defect, until the maintainers rule on a
  bare `token=` form parameter.
* credential-evidence: if the maintainers keep this, the Case's bare-slot layouts
  should be restated with the endpoint or the hint, or recorded as `policy:
  not-read` without them.

## False-positive measurement

The CLI built before and after this change over the tracked text files of the
maintainers' repositories: redact-secret 1,538 files, credential-evidence 4,398,
the other sibling repositories 3,232 (9,168 files). New findings from this
reader: **1**, the curl `token=<v> -d token_type_hint=refresh_token` fixture of
credential-evidence's `reddit-authored.json` (a true positive); no other `token=`
became a finding; removed findings: 0. (The raw-request fixtures sit inside JSON
strings with escaped `\n`, where a `token=` after `\n` has no boundary and is not
an assignment; that is the escaped-representation limit of
`keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`.)

## Tradeoffs

* False positive added: a `token=` value of 8 or more bytes in a request that
  names a revoke or introspect endpoint or carries `token_type_hint`, which is a
  credential by definition of those requests; a CSRF `token=` in a form that also
  posts to a `/revoke` path is the only conceivable non-credential.
* False negative kept, stated: the context-free layouts above; a JSON `token`
  member of a revoke request; an escaped or encoded body.
* No Reddit or Adobe attribution and no access or refresh claim: the shared slot
  is generic, as the Case says. The client-secret `curl --user id:secret` of the
  same requests remains issue #1247.

## Tests

`crates/secret-scan-core/tests/revoke_token_parameter_1230.rs` (7 tests): the form
body of four endpoints in every layout and shape; curl on one line and continued;
the `token_type_hint` alone; context, large preceding body, two requests and a
neighbouring secret; the bare `token` silent without a context (alone, query,
another endpoint, uppercase, JSON member, distant endpoint, `/revoked`,
`/revoke-all`); another name in a revoke request keeps its own reading;
placeholders silent. Every input runs whole, in 7-byte chunks and in 1-byte chunks
with equal text and findings.
