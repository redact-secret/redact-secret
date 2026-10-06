---
decision_id: decision-admit-percent-escapes-in-the-authorization-bearer-header-value
status: accepted
scope: workspace
title: Admit percent escapes in the Authorization Bearer header value
decided_at: 2026-10-06
spec: engine
---

# Admit percent escapes in the Authorization Bearer header value

## Context

[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md)
(2026-10-05) kept every carrier grammar as it was, including the RFC 6750
`b64token` alphabet of `bearer-token`, and set a reopening bar. It rejected
widening the Bearer alphabet "for now" because the only evidence was a
scanner-corroborated lead and the widening costs over-redaction wherever `%`
follows a Bearer run.

Two facts changed the weighing. The measured product gap (#1224): in
`Authorization: Bearer <24 alphanumeric>%2B<12 alphanumeric>%3D` the finding covers
only the 24 bytes before the first `%`; the `%2B...` tail stays in the redacted
output, while the same value under `access_token=` is redacted whole. And the X
developer documentation for application-only authentication, observed 2026-10-06
(`docs.x.com`, application-only page, fetched for this record), shows the
`Authorization: Bearer` header carrying a token with `%2F` and `%3D` escapes
inside it (the page states the token as returned by the token endpoint; it gives no
statement that the client encodes it). The same page's documented example is the
shape the product leaves partly readable.

Evidence class and limit: a provider documentation page observed through a fetch
tool, project-authored and not reviewed; credential-evidence has not yet named the
layout for `x:app-only-bearer-token`. This record does not make that row covered and
does not assert a width, alphabet or prefix for any X token.

## Decision

1. **Reopening bar, item by item.** One representation and one carrier: a `%XX`
   triplet (a `%` and two hex digits) inside the value of an explicit
   `Authorization:` or `Proxy-Authorization:` header with the `Bearer` scheme,
   nothing else. Provider documentation: the X page above, the wire form for that
   carrier (observed, not independently reviewed). Benign corpus: percent after the
   carrier in ordinary text, listed below and pinned by tests. Span model: the whole
   run, as redaction requires. Overlap with provider detectors: the span is the
   same Bearer value a provider detector would already select; overlap resolution
   is unchanged. Incremental retention: the value is read on one line and the
   session already holds an open header line, so no retention bound changes.
2. **Admit `%XX` triplets in the Bearer value alphabet for the header carrier
   only.** Under an explicit `Authorization:` or `Proxy-Authorization:` header
   name, a `%` followed by two hex digits is part of the token run, in the first
   run and in each `:` or `|` joined run, and counts as three bytes toward the
   12-byte header floor. A `%` that does not start a valid triplet ends the run, as
   before. The bare `Bearer <token>` form (no header name), the `generic-token`
   authorization alphabet, `secret-token:` and every other grammar are unchanged:
   no bare grammar admits `%`.
3. **Still not decoded.** The span is the raw bytes as written, escapes included.
   The 2026-10-05 sections 1 (no decoding), 2 (unsupported variants are not a miss
   or a pass) and 4 (Atlas passwords) stand for every other carrier. A redacted
   prefix is never full coverage: a Bearer value whose escape is malformed or in a
   bare carrier still leaves its residual in the output, and that stays a stated
   limit.
4. **Benign corpus.** An escape right after a header Bearer value
   (`Authorization: Bearer <run>%20the rest`, `%0A`, `%22%7D`) is read as part of
   the run: the over-redaction cost is the escape and following token bytes of the
   same whitespace-free run, which sit in a credential header already.
   `Authorization: Bearer abc%20def` is under the 12-byte floor and silent. A
   `Bearer` scheme glued to an escape instead of whitespace
   (`Authorization%3A%20Bearer%20<run>`) does not match, as before. A literal `%`
   not followed by two hex digits ends the run.

### Alternatives considered

- **Keep the 2026-10-05 stance.** Rejected: the documented example is partly
  readable after redaction, a security-first failure with a one-carrier repair.
- **Admit `%` in the bare Bearer grammar.** Rejected: no carrier evidence, and bare
  `Bearer` in prose and logs is where over-redaction matters.
- **Decode and re-encode.** Rejected by #491 and the 2026-10-05 record.

## Consequences

Tradeoff. False negative removed: the tail of a percent-escaped Bearer token under
an explicit header. False positives added: the escape bytes and token bytes after
them in the same header value when the header value is itself followed by escaped
text; a header whose token is longer than 12 bytes only because of escapes now
matches. The 2026-10-05 record is amended for the `Authorization`/`Proxy-Authorization`
Bearer carrier only; it is not superseded. `docs/specs/engine.md` carries the amended text; the evidence is
[`docs/audits/evidence/1224/addendum-bearer-percent-escapes.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1224/addendum-bearer-percent-escapes.md). No version,
public interface or finding type changes.
