---
decision_id: decision-adopt-cloudflare-account-token-prefix
status: accepted
scope: workspace
title: Adopt the Cloudflare account-token prefix under the frozen cfut_ contract
decided_at: 2026-09-20
spec: detector-families
---

# Adopt the Cloudflare account-token prefix under the frozen cfut_ contract

## Decision

Add Cloudflare's `cfat_` (account token) prefix to the `cloudflare-token`
detector (`crates/secret-scan-core/src/detectors/cloudflare.rs`, id
`cloudflare-token`, type `cloudflare_api_token`) for issue #481, as a second
`PrefixShape` over the identical body and checksum grammar the `cfut_`
contract already froze in issue #367/#373
(`docs/audits/evidence/367/precision-contracts.json`,
`families.cloudflare-token`):

```
cfat_<40 characters from [A-Za-z0-9]><8-character lowercase-hex checksum>
```

`cfat_` shares the detector id, finding type, confidence (`High`),
specificity (`Provider`), and default policy of `cfut_`; there is no new
detector, and `cfut_`'s own contract is unchanged. Cloudflare's third
documented scannable prefix, `cfk_` (scannable global key), is explicitly
**not** adopted here: neither consulted tool corroborates its checksum width
or alphabet (trufflehog's `cf[ua]t_` alternation excludes `k`, and gitleaks'
`cloudflare-global-api-key` rule targets only the legacy unprefixed hex key),
so freezing a grammar for it would be a guess rather than a reviewed
contract. `cfk_` is split into issue #486 and stays in
`precision-contracts.json`'s `pending` list.

## Rationale

`docs/audits/evidence/367/precision-contracts.json` recorded `cfat_` as a
known false negative when #373 froze the `cfut_` contract, deferring it as a
coverage change rather than a precision fix, but tiered it T1 — the same
tier as the supported `cfut_` variant — because the evidence was already
sufficient: Cloudflare's token-formats page documents `cfat_` with the
identical `[40 characters][checksum]` format cell as `cfut_`, and trufflehog
3.97.4's `cloudflareapitoken` v2 rule
(`\b(cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`) matches both prefixes under one
alternation with the same body and checksum shape. Issue #481 reproduced the
false negative against `0.1.0-beta.4` (built from `ebce029`): three `cfat_`
positive shapes (bare, quoted, after a Unicode/CRLF comment) all returned no
finding, while the equivalent `cfut_` inputs matched at the documented
ranges. Adopting `cfat_` over the same `PrefixShape` the `cfut_` contract
already uses is not new matching logic — `USER_PREFIX` and `ACCOUNT_PREFIX`
differ only in their literal and the corroborating source, and both reuse
`BODY_LEN`, `is_alnum`, and the `checksum_tail_is_lower_hex` post-check.

## Consequences

- **Coverage change, not a precision fix.** A `cfat_` value that previously
  produced no finding is now detected identically to `cfut_`. `cfut_`'s
  matching, confidence, specificity, and policy are unaffected — verified by
  running every existing `cfut_` test unchanged alongside a parameterized
  `cfat_` counterpart in `crates/secret-scan-core/src/detectors/cloudflare.rs`'s
  `mod tests`.
- **New precision-test file.** `crates/secret-scan-core/tests/cloudflare_account_token_precision.rs`
  pins the issue's self-contained synthetic reproduction — a paired
  positive, its non-hex-checksum negative twin, and the positive again after
  a Unicode/CRLF comment — on the whole-input surface, the provider detector
  in isolation, and every UTF-8 byte partition of the incremental surface.
  `conformance/fixtures/cloudflare-token-mutations.ts` and
  `conformance/fixtures/synchronous-corpus.json` gained the matching
  fixtures, wired through `conformance/schema.test.ts` the same way
  `docker-token-mutations.ts` is.
- **Evidence record updated.** `docs/audits/evidence/367/precision-contracts.json`
  moved `cfat_` from `pending` to `variants` (`support: "supported"`, tier
  `T1`) and extended the checksum-alphabet `conflicts` resolution and the
  non-hex-checksum `mutations` entry to name `cfat_` explicitly; `cfk_`
  remains the sole `pending` entry for this family, re-worded to record that
  it was reverified against the live token-formats page on 2026-09-20 and
  split into #486 rather than left undecided.
- A real Cloudflare account token whose body or checksum segment does not
  match the documented length or alphabet, should one exist, goes undetected
  until the contract is re-reviewed — the same accepted cost `cfut_`'s own
  contract already carries, now extended to `cfat_` on the same evidence.
