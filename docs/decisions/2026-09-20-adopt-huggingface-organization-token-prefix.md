---
decision_id: decision-adopt-huggingface-organization-token-prefix
status: accepted
scope: workspace
title: Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2
decided_at: 2026-09-20
spec: detector-families
---

# Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2

## Decision

Add Hugging Face's `api_org_` (organization API token) prefix to the
`huggingface-token` detector
(`crates/secret-scan-core/src/detectors/additional_providers.rs`,
`HUGGING_FACE`, id `huggingface-token`, type `huggingface_token`) for issue
#485, as a second `PrefixShape` over the identical 34-byte
`[A-Za-z0-9]` body grammar the `hf_` contract already froze in issue
#367/#372 (`docs/audits/evidence/367/precision-contracts.json`,
`families.huggingface-token`):

```
api_org_<34 characters from [A-Za-z0-9]>
```

`api_org_` shares the detector id, finding type, confidence (`High`),
specificity (`Provider`), and default policy of `hf_`; there is no new
detector, and `hf_`'s own contract is unchanged.

## Rationale

`docs/audits/evidence/367/precision-contracts.json` recorded `api_org_` as a
known false negative when #372 froze the `hf_` contract, tiered T0 and
deferred as a scope boundary ("adding a variant is a coverage change, not a
precision fix"), not because its evidence was weaker than `hf_`'s own. Issue
#485 measured that directly: against the same T2 bar `hf_` is already held
to ("no provider documentation for the property; pinned tool sources
corroborate it"), `api_org_` has the identical basis. gitleaks 8.30.1
registers `api_org_` as its own `huggingface-organization-api-token` rule
with a 34-byte letters-only body, and trufflehog 3.97.4 matches both `hf_`
and `api_org_` under one `(?:hf_|api_org_)[a-zA-Z0-9]{34}` rule — the same
dual-tool 34-byte-length agreement, and the same gitleaks
(letters-only)-versus-trufflehog (letters-and-digits) alphabet conflict,
that `hf_`'s own T2 tier already rests on. No Hugging Face documentation page
states either prefix's body length or alphabet; it states only `hf_`'s bare
prefix, as a placeholder. Because the absence of provider text for
`api_org_`'s prefix does not distinguish it from `hf_` at the property the
tier scores, `api_org_` is re-tiered from T0 to T2 and adopted as a second
shape over `hf_`'s identical body grammar — not new matching logic. Issue
#485 reproduced the false negative against `0.1.0-beta.4` (built from
`ebce029`): three `api_org_` positive shapes (bare, quoted, after a
Unicode/CRLF comment) all returned no finding, while the equivalent `hf_`
inputs matched at the documented ranges.

## Consequences

- **Coverage change, not a precision fix.** An `api_org_` value that
  previously produced no finding is now detected identically to `hf_`.
  `hf_`'s matching, confidence, specificity, and policy are unaffected;
  `mod tests` in `additional_providers.rs` adds parameterized coverage
  proving both prefixes are detected independently in the same input
  without either shape swallowing the other, that a 33- or 35-byte body is
  rejected for `api_org_` exactly as it already is for `hf_`, that an
  embedded prefix or an underscore/dash in the body is rejected, and that a
  digit-bearing body is accepted under the same alphabet-union
  support-policy choice `hf_` already made.
- **Alphabet-union policy extended.** The `hf_` body-alphabet conflict
  (gitleaks letters-only vs. trufflehog letters-and-digits) is resolved
  identically for `api_org_`: the union `[A-Za-z0-9]` is accepted as a
  support-policy choice that favors not missing a real token, and
  digit-bearing samples stay pending (T0) and unscored, per the existing
  `digit-bearing-body` entry, now noted as applying to both prefixes.
- **Evidence record updated.** `docs/audits/evidence/367/precision-contracts.json`
  moved `organization-token` from `pending` (T0) to `variants` (`support:
  "supported"`, tier `T2`), added a `conflicts` entry recording the
  T0-to-T2 re-tiering reasoning above, and extended the
  `underscore-or-dash-in-body` exclusion and the 33-vs-34-byte-length
  `mutations` entry to name `api_org_` explicitly.
  `conformance/fixtures/huggingface-token-mutations.ts`,
  `conformance/fixtures/incremental-corpus.json`, and
  `conformance/fixtures/synchronous-corpus.json` gained the matching
  fixtures, wired through `conformance/schema.test.ts` the same way other
  mutation-fixture files are.
- A real Hugging Face organization token whose body does not match the
  documented 34-byte `[A-Za-z0-9]` length and alphabet, should one exist,
  goes undetected until the contract is re-reviewed — the same accepted
  cost `hf_`'s own T2 contract already carries, now extended to `api_org_`
  on the same evidence.
