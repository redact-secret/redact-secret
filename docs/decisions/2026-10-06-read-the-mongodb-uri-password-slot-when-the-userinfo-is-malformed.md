---
decision_id: decision-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed
status: accepted
scope: workspace
title: Read the MongoDB URI password slot when the userinfo is malformed
decided_at: 2026-10-06
spec: detector-families
---

# Read the MongoDB URI password slot when the userinfo is malformed

## Context

`generic:connection-string-password` reads a URI password only inside a strict
RFC 3986 authority: exactly one `@`, valid percent escapes, an authority that ends
at the first `/`, `?` or `#`. A `mongodb` or `mongodb+srv` URI whose password
carries a malformed escape (`user:ab%zz<v>@host`, a password ending in `%`,
`100%%`), a raw `@`, or a raw `/`, `?` or `#` therefore gave no finding at all,
and a real password ending in `%` was written to the output in full.

[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md)
(section 4) recorded "a password whose punctuation the carrier grammar ends on" as
a stated blind spot, not repaired. The independent Batch 2 closeout measured it
as a leak (#1226) and the spec's benign case `connection-negative-malformed-percent`
was written for a postgres URI, so no case speaks for MongoDB. The MongoDB URI
specification requires `: / ? # [ ] @` in a username or password to be
percent-encoded, and a connection string that does not do it is a broken string
that still names a real password.

Product observation at `efe71496` (CLI `0.1.0-beta.14`, synthetic inputs): the
cases above gave no finding; the same password in a well-formed URI is a high
`connection_string_password`, `redact`.

## Decision

1. **For the `mongodb` and `mongodb+srv` schemes only, the password slot of a
   userinfo the strict grammar declines is read.** The finding is
   `connection_string_password` over exactly the password substring, undecoded,
   at **medium** confidence. `connection_string_password` redacts at every
   confidence (the policy's always-redact list), so medium costs no protection;
   it records that the span is read from a malformed or ambiguous userinfo and is
   never claimed with the strict form's high confidence.
2. **Span rule.** The user is the non-empty run before the first `:` of the
   userinfo; the password is everything after it. With a raw `@` the userinfo ends
   at the last `@` before the first `/`, `?` or `#`, the Go driver's reading (the
   Node driver stops at the first `@` and `pymongo` rejects the URI; neither
   accepts the raw form, and the product follows the reading that keeps the most of
   the secret inside the span). With a raw `/`, `?` or `#` that ended the authority
   before any `@`, the first `@` followed by a valid host list for the scheme ends
   the userinfo. The text after that `@`, up to the next `/`, `?` or `#`, must be a
   valid host list for the scheme.
3. **A host-only URI is not a userinfo.** When the text before the first `/`, `?`
   or `#` is already a valid host list with no `@` (`mongodb://host:27017/db?x=a:b@c.example`)
   nothing is read. A digit-only password directly before a raw `/`
   (`user:123/x@host`) is `host:port` plus a path to every reader and stays unread:
   a recorded residual.
4. **Everything else keeps the strict grammar.** Every well-formed URI keeps its
   high or medium span, a URI the strict grammar reads is never re-read, other
   schemes (postgres, mysql, redis, http and the rest) keep the postgres
   `connection-negative-malformed-percent` benign case, placeholders and references
   stay excluded in the relaxed form, and the 4,096-byte password and 8,192-byte
   authority bounds apply.
5. **The benign cases are re-decided explicitly.** `connection-negative-malformed-percent`
   and the other schemes' `*-malformed-percent` cases stay benign for the strict
   grammar. The two MongoDB cases that were benign for that reason
   (`connection-negative-mongodb-malformed-percent`, `connection-negative-mongodb-srv-malformed-percent`)
   become the positives `connection-regression-mongodb-malformed-percent-password` and
   `connection-regression-mongodb-srv-malformed-percent-password`: for MongoDB a
   malformed escape is a finding.

### Alternatives considered

- **Keep the blind spot (the 2026-10-05 stance).** Rejected. The cost is a
  plaintext password in the output for any user whose password ends in `%` or holds
  an `@`, and the repair needs no decoding and no new grammar.
- **Extend every scheme.** Rejected for now. The evidence and the leak are
  MongoDB's (a caller-chosen password the provider requires to be escaped); other
  schemes have no measured case, and each needs its own benign corpus.
- **Report at high confidence.** Rejected: the span is a reconstruction.
- **Read the first `@` for a raw `@`.** Rejected: it leaves the password's tail,
  and a credential after the first `@` readable in the output.

## Consequences

Tradeoff. False negatives removed: a MongoDB URI password with a malformed escape,
a raw `@`, `/`, `?` or `#`. False positives added: a malformed or ambiguous URI
whose "password" is not one (for example a userinfo-shaped run in text that happens
to end in `@` and a valid host), bounded by the guards above and by the
whitespace-free run; the cost is a redacted non-secret in a malformed MongoDB URI.
Residuals: digit-only password before a raw `/`; a raw `@` password with a later
`@` inside a path or query is read to the last `@` before the first `/`, `?` or
`#`, so a password containing both a raw `@` and a raw delimiter is split at the
delimiter; a password containing whitespace.

`docs/specs/detector-families.md` gains the amended row text. The #1226 evidence
addendum [`docs/audits/evidence/1226/addendum-atlas-uri-userinfo.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1226/addendum-atlas-uri-userinfo.md) holds the
measurements. No public interface, finding type, detector id or version changes.
Item 4 of the 2026-10-05 record is amended for the MongoDB URI only.
