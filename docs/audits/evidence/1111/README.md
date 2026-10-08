---
owner: #1111
reviewed_source: f6f481b168b000ac27e8d60598cd2cb5c0265d59
status: in-progress
retire_on: after-issue:#1111
---

# #1111 evidence: `baseten:api-key` structure

Product judgement. Desk research only, retrieved 2026-10-07: no key was issued
and no issued or leaked credential is evidence. `credential-evidence` holds no
Baseten record (searched 2026-10-07), so the provider's own documentation is
the source. Structure only; no value appears here.

**Verdict: sufficient (T1, `provider-documented`).** The provider publishes the
scanner regex, so no issuance observation is needed.

## Statements

| # | Source (provider-authored) | Retrieved | Statement |
|---|---|---|---|
| 1 | [Baseten docs, API keys](https://docs.baseten.co/organization/api-keys.md) | 2026-10-07 | "Baseten API keys use the stable `b10_` prefix so secret-scanning tools can identify exposed credentials. Configure your scanner to match the complete key format:" with the regex `b10_[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}` |
| 2 | same page | 2026-10-07 | "Keys created before 3:00 PM GMT on October 1, 2026, don't contain the `b10_` prefix, so this regular expression detects only keys created on or after that time." |
| 3 | same page | 2026-10-07 | earlier keys remain accepted for authentication (both formats work) |
| 4 | same page, CLI and API examples | 2026-10-07 | placeholders show `b10_` + 8 characters + `.` + 32 letters, matching the regex |
| 5 | [Baseten changelog, upcoming API key format change](https://www.baseten.co/resources/changelog/upcoming-change-to-baseten-api-key-format/) | 2026-10-07 | newly created keys add a `b10_` prefix from Thursday, October 1 at 15:00 UTC; "Existing keys will continue to work unchanged"; no rotation required; tooling that "validates, parses, redacts, or scans API keys based on their current format or length" should be updated |

Statements 1 and 5 agree. The same regex and cutoff were recorded on 2026-09-29
in the [#1012 record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1012/baseten.md),
which also found no `b10_` literal in the provider CLI or SDKs.

## Frozen shapes

- New shape: `b10_` + 8 `[A-Za-z0-9]` (id) + `.` + 32 `[A-Za-z0-9]` (secret);
  45 bytes; created on or after 2026-10-01 15:00 GMT.
- Old shape: created before that time, no prefix. No source states its length
  or alphabet, so it is not read. Both formats authenticate; only the new one is
  in the contract.
- No checksum is documented.

## Limits

- The docs page is mutable and no archived copy was captured (the Wayback
  service rate-limited the request on 2026-10-07). The statements above are
  quoted so a later reader can compare.
- The 8-character id is the visible key prefix used for revocation; whether the
  id alone is secret is not stated, and the contract does not claim it.
- No peer scanner rule exists for the format.
