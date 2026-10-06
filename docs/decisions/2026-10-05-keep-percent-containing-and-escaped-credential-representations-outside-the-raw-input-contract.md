---
decision_id: decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract
status: accepted
scope: workspace
title: Keep percent-containing and escaped credential representations outside the raw-input contract
decided_at: 2026-10-05
spec: engine
---

# Keep percent-containing and escaped credential representations outside the raw-input contract

## Context

The Batch 2 core packages
[#1223](https://github.com/redact-secret/redact-secret/issues/1223) to
[#1226](https://github.com/redact-secret/redact-secret/issues/1226) turn 58
credential-evidence rows into product contracts. The benchmarks readiness
inventory (benchmarks#739) names exactly two rows that wait on a product
representation decision and not on a provider source:

- `x:app-only-bearer-token`: X documents the Bearer Token as a byte array of
  unspecified format. The only percent-containing shape is a scanner-corroborated
  lead, and the raw, serialized-escaped and percent forms have no
  source-established carrier.
- `mongodb-atlas:database-user-password`: a write-only, caller-chosen string
  with no generated grammar, which may be short, low entropy or contain
  punctuation, and may be percent-encoded when placed in a connection string.

The existing records already defer decoding
(`decision-defer-encoded-input-decoding`, #491, percent-encoding named
individually), put a fragmented credential outside the raw-input contract
(`decision-define-fragmented-credentials-as-outside-the-raw-input-contract`) and
leave a token behind a percent-encoded delimiter unread
(`decision-settle-the-snapshot-2026-10-04-4-added-case-roots`). None of them says
what the product does with a value whose own bytes contain `%XX`, or whether a
carrier grammar may be widened so that an example passes.

Product observation at `3b1a5aa9` (CLI `0.1.0-beta.13` built from that commit,
synthetic inputs, UTF-8 byte ranges, check mode; not a benchmark result): in
`Authorization: Bearer <24 alphanumeric>%2B<12 alphanumeric>` the one finding is
`bearer_token`, `redact`, covering the 24 bytes before the `%`; the `%2B...`
tail stays in the redacted output. With a 7-byte run before the `%` the value
is under the explicit-header floor of 12 bytes and there is no finding. The
same tail in a form or assignment value (`access_token=<run>%2B<run>%3D&...`) is
one `contextual_secret` over the whole value up to the `&`.

## Decision

1. **The contract reads contiguous raw bytes under the carrier's existing value
   grammar.** A credential whose wire form contains percent escapes (`%XX`) or
   serialized escapes (`+`, `\/`) is not decoded and is not a claimed
   representation. No carrier grammar is widened to admit `%` or a backslash
   escape: the RFC 6750 `b64token` alphabet of `bearer-token`, the authorization
   value alphabet of `generic-token` and every other frozen grammar stay as
   they are, and a generated or scanner-derived example is never a reason to
   change one.
2. **Such a variant is unsupported and unassertable, not a miss and not a pass.**
   A row or case whose expectation needs percent or escape handling is
   recorded as outside the contract until a separate decision adopts that
   representation. It is not a false negative, a true negative or passing
   coverage.
3. **A redacted prefix is never full coverage.** When a carrier grammar ends a
   value before the credential ends, the product redacts the span it read and
   the residual bytes remain in the output. Evidence and benchmarks must not
   score that prefix as covering the credential, and the product states the
   residual as a known limit, not as an unprotected-by-accident case. A host
   that must protect a percent-escaped or escaped carrier decodes or unescapes
   in its own layer and scans the result, or keeps the carrier out of logs.
4. **Atlas user-chosen passwords keep the current policy.** In contract: the
   `mongodb` and `mongodb+srv` URI userinfo password (`connection_string_password`,
   high or medium, `redact`, the undecoded password substring; valid percent
   escapes are kept as written) and a documented password field under the
   existing contextual vocabulary (`contextual_secret`, `redact` at high
   confidence, `warn` at medium). Blind spots, stated and not repaired: a
   password under the 8-byte contextual floor, a low-entropy password that
   lands at `warn`, a password in a carrier the core does not read, and a
   password whose punctuation the carrier grammar ends on. No provider grammar
   is invented and the product does not claim all passwords are protected.

### Alternatives considered

- **Widen the Bearer alphabet to include `%`.** Rejected for now. It would close
  the residual shown above for percent-bearing tokens, which is a real benefit,
  and it costs over-redaction wherever `%` follows a Bearer run (URL-encoded
  text, log lines) for every provider that uses the shared grammar. The only
  evidence is a scanner lead for one row whose provider states no format. A
  shared frozen grammar does not change on one lead.
- **Decode, redact and re-encode.** Rejected by #491 (option C).
- **Report a percent-containing run as detect-only.** Rejected for the #491
  reason: a finding that leaves the secret in the output is detection theater.

### Reopening bar

A proposal names one representation and one carrier, brings the provider
documentation that makes that representation the wire form for that carrier, a
benign corpus for the widened grammar (percent in ordinary text after the
carrier), the span model (the whole run, as redaction requires), the effect on
overlap with provider detectors, and incremental-retention bounds. It meets the
#491 criteria for percent-encoding individually. The readiness evidence for
`x:app-only-bearer-token` becomes eligible only when the evidence repository
names the layout and the provider or a reviewed reproduction states the form.

## Consequences

`docs/specs/engine.md` gains one row citing this record. No detector, fixture or
public interface changes; no version change and no release. The Batch 2 evidence
records [`docs/audits/evidence/1223`](https://github.com/redact-secret/redact-secret/tree/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1223) to `1226` apply it to their rows, and
[the #1223 record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1223/README.md) holds the shared
Bearer-grammar observation.

## Amendments

- 2026-10-06: item 4 of the Decision (the Atlas URI password) is amended for the `mongodb` and `mongodb+srv` URI only by [`decision-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed`](2026-10-06-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed.md): a password with a malformed escape or raw punctuation is read at medium confidence.
- 2026-10-06: item 1 and the rejected alternative "Widen the Bearer alphabet to include `%`" are amended for the `Authorization:`/`Proxy-Authorization:` Bearer header value only by [`decision-admit-percent-escapes-in-the-authorization-bearer-header-value`](2026-10-06-admit-percent-escapes-in-the-authorization-bearer-header-value.md): a `%XX` triplet is part of the token run there. Every other carrier, including the bare `Bearer` form, keeps its alphabet.
