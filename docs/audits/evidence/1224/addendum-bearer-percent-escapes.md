# Addendum to #1224: percent escapes in the Authorization Bearer header value

**Result:** the #1224 record and the 2026-10-05 decision kept percent-containing
representations outside the raw-input contract and recorded that a Bearer value
containing `%XX` is redacted only up to the first `%`. Applying that decision's own
reopening bar, the one carrier with documentary evidence, the explicit
`Authorization:` / `Proxy-Authorization:` Bearer header, now reads the whole run.
The decision is
[`decision-admit-percent-escapes-in-the-authorization-bearer-header-value`](../../../decisions/2026-10-06-admit-percent-escapes-in-the-authorization-bearer-header-value.md).
Nothing else widens: the bare `Bearer` form, `secret-token:`, the `generic-token`
authorization alphabet and every other grammar keep theirs.

## Root cause

`crates/secret-scan-core/src/detectors/bearer_token.rs`, `bearer_scheme_candidates`
and `joined_value_end`: the token run was `[A-Za-z0-9._~+/-]` (`is_token_char`, the
RFC 6750 `b64token` alphabet), so the run ended at the first `%`. The same bytes
under `access_token=` are read by the contextual authorization-value alphabet and
redacted whole, hence the inconsistency.

## Measured before and after

CLI `0.1.0-beta.14` before (`1ddb4b42` and earlier) and with this change, check mode,
synthetic values (24, 10, 12 and 8 generated alphanumerics joined by `%2B`, `%2F`,
`%3D`):

| Input | Before | After |
| --- | --- | --- |
| `Authorization: Bearer <value>` (also `Proxy-Authorization`, CRLF, curl `-H`) | `bearer_token`, high, redact, only the 24 bytes before the first `%`; tail in the output | one `bearer_token`, high, redact, the whole value; nothing of it in the output |
| `Authorization: Bearer <7 alnum>%2B<12 alnum>` | no finding (7 bytes under the 12-byte header floor) | whole value |
| `Bearer <value>` (no header name) | prefix before `%` | unchanged: prefix only, tail in the output (stated limit) |
| `access_token=<value>` | one `contextual_secret` over the whole value | unchanged |
| `Authorization: Bearer abc%20def`, `ab%2Bcd%3D` | no finding | unchanged (under the floor) |
| `Authorization: Bearer <16 alnum>%zz`, `%`, `%2` | the 16 bytes | unchanged (`%` without two hex digits ends the run) |
| `Authorization%3A%20Bearer%20<run>` | no finding | unchanged (not the scheme) |
| `Authorization: Bearer <16 alnum>%0A%22%7D` | the 16 bytes | the whole run, escapes included |

## Reopening bar, applied

1. One representation, one carrier: a `%XX` triplet inside the value of an explicit
   `Authorization` / `Proxy-Authorization` Bearer header.
2. Provider documentation making it the wire form: the X developer documentation,
   application-only authentication page (`docs.x.com`), observed 2026-10-06 through a
   page-fetch tool: the `Authorization: Bearer` example carries `%2F` and `%3D`
   inside the token, and the page gives the token as returned by the token endpoint,
   not as a client encoding. Limit: this is a project observation, not a
   credential-evidence reviewed layout; the literal example should be re-read by a
   maintainer before the row is described as documented, and
   `x:app-only-bearer-token` is not claimed covered.
3. Benign corpus: the table above and `tests/bearer_percent_escapes_1224.rs`
   (short escaped text, a stray `%`, a glued scheme, whitespace, escaped prose after a
   real token).
4. Span model: the whole run, escapes included, not decoded.
5. Overlap with provider detectors: the Bearer span equals the value a provider
   detector would select; overlap resolution is unchanged.
6. Incremental retention: the value is read on one line under a header name the
   session already holds open; no bound changes (7-byte and 1-byte chunks equal the
   whole input in the tests).

## Tradeoffs

* FN removed: the tail of a percent-escaped Bearer token under an explicit header.
* FP added: escape bytes and token bytes that follow a real header value in the same
  whitespace-free run are redacted with it (`<token>%0A%22%7D`); a header value that
  reaches the 12-byte floor only through escapes is now read. The over-redaction is
  confined to a credential header.
* Not claimed: the bare Bearer form and every other carrier still leave the tail of a
  percent-containing value in the output (the 2026-10-05 stated limit), and no
  coverage is claimed for any X token. A redacted prefix is never full coverage.

## Tests

`crates/secret-scan-core/tests/bearer_percent_escapes_1224.rs` (7 tests), whole input,
7-byte and 1-byte chunks equal to whole.
