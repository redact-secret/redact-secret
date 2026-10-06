# Addendum to #1226: the Atlas URI password with a malformed escape or raw punctuation

**Result:** the #1226 record and the 2026-10-05 decision kept "a password whose
punctuation the carrier grammar ends on" as a stated, unrepaired blind spot. The
Batch 2 closeout measured it as a leak: a `mongodb` or `mongodb+srv` URI whose
password has a malformed percent escape or a raw `@`, `/`, `?` or `#` produced no
finding at all, so a real password ending in `%` stayed in the output in full. It is
now read for those two schemes at medium confidence, which `redact`s. The decision
is [`decision-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed`](../../../decisions/2026-10-06-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed.md).

## Root cause

`crates/secret-scan-core/src/detectors/connection_string.rs`, the URI loop of
`ConnectionStringDetector::detect`: the authority ends at the first `/`, `?` or `#`
(`authority_end`), `single_at` rejects more than one `@`, and
`has_valid_userinfo_encoding` rejects any `%` not followed by two hex digits and any
byte outside the RFC 3986 userinfo set. Each of these sends the URI to `continue`.
The spec's benign case `connection-negative-malformed-percent` is a postgres URI
and was the only case for the behaviour.

## Measured before and after

CLI `0.1.0-beta.14` at `1ddb4b42` (before) and with this change (after), check mode,
one URI per line, synthetic values, UTF-8 byte ranges:

| Input (value shape) | Before | After |
| --- | --- | --- |
| `mongodb+srv://app:<14>%@cluster0.example.test/admin` (password ends in `%`) | no finding | `connection_string_password`, medium, redact, exactly the 15-byte password |
| `app:ab%zz<10>`, `app:100%<10>`, `app:100%%` | no finding | same, exactly the password |
| `app:<6>@<7>@<host>` (raw `@`) | no finding | same, span to the last `@` |
| `app:<6>/<7>@<host>`, `?`, `#` | no finding | same, exactly the password with the raw delimiter inside |
| `mongodb+srv://app:<14>@cluster0.example.test/admin` (well formed) | high, redact | unchanged |
| `mongodb://localhost:27017/db?appname=a@b.example` | no finding | unchanged |
| `postgres://app:<14>%@localhost:5432/db` | no finding | unchanged (strict grammar) |

## Decisions and tradeoffs

* **Confidence.** `connection_string_password` is in the always-redact list
  (`policy.rs`, `ALWAYS_REDACT_TYPES`), so medium redacts: the documented per-family
  rule (the #1226 record: "URI: redact at any confidence") already gives the
  security-first result. Medium records that the span is a reconstruction, not the
  strict form's high.
* **Span for a raw `@`.** The userinfo ends at the last `@` before the first `/`, `?`
  or `#`, the Go driver's reading. The Node driver stops at the first `@` and `pymongo`
  rejects the URI; the MongoDB specification requires the character escaped. A
  first-`@` reading would leave the password's tail readable, which is the failure
  this change removes. For a raw `/`, `?` or `#` that ended the authority first, the
  first `@` followed by a valid host list ends the userinfo, because the last `@` of a
  whitespace-free run may sit in a later query value.
* **Guards.** A host list is required after the `@`; a run whose text before the
  first `/`, `?` or `#` is already a valid host list with no `@` is host-only; the user
  is non-empty and made of userinfo bytes and `%`; placeholders, references and filler
  stay excluded; the run is whitespace-free and bounded by 8,192 bytes, the password
  by 4,096.
* **The benign cases, re-decided.** `connection-negative-malformed-percent` stays
  benign for postgres and the strict grammar (so do the other schemes' `*-malformed-percent`
  cases). Two corpus cases were benign for MongoDB for the same reason:
  `connection-negative-mongodb-malformed-percent` and
  `connection-negative-mongodb-srv-malformed-percent` (`SYNTHETIC%GGREVOKED`). They are
  now the positives `connection-regression-mongodb-malformed-percent-password` (18-37) and
  `connection-regression-mongodb-srv-malformed-percent-password` (22-41), medium,
  `redact`, in `conformance/fixtures/synchronous-corpus.json` and
  `common-profile-expectations.json`; `docs/coverage/` is regenerated. The cross-language
  corpus is shared, so every binding's conformance run follows; this is the only
  conformance change and it is a contract change recorded by the decision.
* **FN removed:** the five forms above. **FP added:** a malformed MongoDB-looking run
  whose text before a valid host is not a password, redacted at medium; bounded by the
  guards.
* **Residuals, unchanged and recorded:** a digit-only password directly before a raw
  `/` (`app:123/x@host` reads as `host:port` plus a path); a password with both a raw
  `@` and a raw `/`, `?` or `#` is split at the first delimiter; a password containing
  whitespace; other schemes (postgres, mysql, redis, http and the rest) keep the strict
  grammar until a measured case exists.

## Tests

`crates/secret-scan-core/tests/mongodb_relaxed_userinfo_1226.rs` (8 tests), whole
input, 7-byte and 1-byte chunks equal to whole: the malformed-escape forms across
four URI layouts (including an uppercase scheme, a seed list, CRLF and a quoted
value), the raw `@` (one and two), the raw `/`, `?` and `#`, well-formed positives
keeping their span and high confidence, host-only and other benign neighbours,
placeholders in the relaxed forms, the digit residual, and the other schemes with
the postgres benign case.
