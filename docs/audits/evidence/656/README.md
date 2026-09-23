# Issue #656 — T1 provider evidence for `new-relic:license-key`

[Audit archive](../../README.md) ·
[Issue #656](https://github.com/redact-secret/redact-secret/issues/656) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5784943534) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5785640607) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5786035362) ·
[False-negative note](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5786154351) ·
[Detector fix #672 / PR #682](https://github.com/redact-secret/redact-secret/pull/682)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for the suffix and total length only

A provider-domain page states the ingest license key's identifying element
(the trailing literal `NRAL`) and its total length (40). The body alphabet,
the `FFFF` segment and the `eu01xx` region prefix are not provider-stated.
New Relic's canonical API-keys page still describes the key as
"40-character hexadecimal", which contradicts the `NRAL` source.

| property | provable at T1 | basis |
| --- | --- | --- |
| suffix `NRAL` (trailing marker) | yes | prose comment in a docs.newrelic.com config example |
| total length 40 | yes | same comment; canonical API-keys page also says 40 |
| body alphabet (lowercase hex) | no | canonical page says "hexadecimal", but for the legacy all-hex key, not the `NRAL` key; hex body is provider-code and tool only |
| `FFFF` segment before `NRAL` | no | shown in elided docs examples (eBPF pages) and the docs style-guide placeholder, never stated as a rule |
| region prefix `eu01xx` | no | provider code (newrelic-cli) and provider-staff forum posts only; no docs page |
| checksum | no | none documented anywhere |

## The source

`https://docs.newrelic.com/docs/opentelemetry/integrations/ibm-mq/host/`
(provider source: `newrelic/docs-website`
`src/content/docs/opentelemetry/integrations/ibm-mq/host.mdx`). Re-fetched
2026-09-23, HTTP 200. The sentence appears twice, as a comment above
`NEW_RELIC_LICENSE_KEY=<YOUR-LICENSE-KEY>` in the env-file examples:

> New Relic ingest license key (40 chars, suffix NRAL)

`observedAt`: 2026-09-23 (first observed 2026-09-22). It is a config-example
comment, not a reference-page sentence.

Supporting examples on the provider domain, not a grammar, re-fetched
2026-09-23 (HTTP 200 each): `https://docs.newrelic.com/docs/ebpf/k8s-installation/`
and `https://docs.newrelic.com/docs/ebpf/linux-installation/` each show one
elided `licenseKey` example ending `FFFFNRAL`. The docs style guide
(`newrelic/docs-website` `archives/style-guide/structure/code-examples.mdx`,
line 306, re-fetched 2026-09-23) uses 32 masked characters then `FFFFNRAL` as
the house placeholder.

Precedent fit: an identifying element stated on the provider domain, with the
body left tool-corroborated, is the same shape as the accepted T1 contracts
listed in the issue. The T1 bar in `benchmarks/lib/assessment.ts` is unchanged.

## Proposed `covers` sentence

> New Relic's own documentation (docs.newrelic.com, IBM MQ host-integration
> page) states the ingest license key as 40 characters with the literal suffix
> `NRAL`, establishing the suffix and total length; its eBPF install pages
> show elided examples ending `FFFFNRAL`. The body alphabet, the `FFFF`
> segment and the EU `eu01xx` prefix are not provider-stated: they rest on
> New Relic-authored code (newrelic-cli `IsValidLicenseKeyFormat`,
> docs-website `check-for-keys.sh`) and trufflehog 3.97.4.

## Contradictions with the current contract

Current detector (`crates/secret-scan-core/src/detectors/new_relic.rs`, after
PR #682 merged 2026-09-23 as `0c32289`): same-line keyword gate, then 40
lowercase hex (legacy), or 32 lowercase hex + `FFFFNRAL`, or `eu01xx` + 26
lowercase hex + `FFFFNRAL`. No `new-relic` entry exists in
`docs/contracts/precision/precision-contracts.json`. `benchmarks/support-matrix.json`
lists the family as `provisional`, tier T2, `providerSource: null`, 9 twin pairs.

- **Canonical page vs `NRAL`.** `https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/`
  (re-fetched 2026-09-23, 0 occurrences of `NRAL`) still says "The license key
  is a 40-character hexadecimal string". `NRAL` is not hex. The sources in the
  issue comments read this as a description of the legacy key; New Relic does
  not say so.
- **`FFFF` is stricter than the provider source.** The provider source proves
  only `…NRAL` at 40 total. The detector requires `FFFFNRAL`, so the first
  `NRAL` generation (36 hex + `NRAL`, which New Relic's docs scanner labels
  `_OLD`) and region prefixes other than `eu01xx` go undetected. The module
  and CHANGELOG record these as known gaps.
- **Stale rationale in the module header.** The grammar paragraph still says
  the license format "carries no marker of its own" and points to a
  "Rejected: an unofficial license-key suffix" section that PR #682 removed.
- **Stale spec wording.** `docs/specs/detector-families.md` (lines 59 and 97)
  still describes the license key as "a keyword-gated bare hex shape".
- **Docs error on the provider domain.** `https://docs.newrelic.com/docs/opentelemetry/integrations/docker-monitoring/troubleshooting/`
  (re-fetched 2026-09-23) says the license key "Should be 40-character
  NRAK-prefixed key". `NRAK-` is the User key prefix; this conflicts with every
  other source and reads as a doc error.

None of these is decided here. Whether the T1 contract should keep `FFFF`
(detector and trufflehog) or only `NRAL` (provider source) belongs to the T1
re-tier batch.

## Sources checked

Every class required by the issue's "Done when" was checked on 2026-09-22;
the load-bearing pages were re-fetched 2026-09-23. Full URL-level tables are
in the [research pass 2](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5784943534),
[broad-discovery](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5785640607)
and [web-search](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5786035362)
comments.

| source class | result |
| --- | --- |
| product docs and API reference | IBM MQ page: `NRAL` + 40 found; eBPF pages: `FFFFNRAL` examples; API-keys page: "40-character hexadecimal", `Ingest - License` key type naming; NerdGraph key-management page: no format; no public OpenAPI/JSON schema (NerdGraph introspection needs auth, 401) |
| changelog / release notes | 2024-08 EOL notice, 2025 REST-key EOL what's-new, and a code search of `docs-website` `src/content/whats-new` for `NRAL`: no format |
| engineering / security blog | "Managing New Relic keys with NerdGraph": "40-character key", no suffix. `newrelic.com/blog/how-to-relic/rotate-license-keys` redirects to the blog index (re-tried 2026-09-23), so it was not read |
| secret-scanning partner pages | GitHub partner list: `new_relic_license_key` listed, no pattern, not provider domain; no New Relic token-format announcement found |
| SDK / CLI docs on provider domain | Node agent config (`'40HexadecimalCharacters'`), PHP compatibility ("40-character hexadecimal"), Java/Python/infrastructure agent and CLI install pages: no `NRAL`. Provider-authored code (newrelic-cli, docs-website scanner, rusty-hog, Diagnostics CLI, agents) is corroboration only |
| broad discovery (non-provider) | GitGuardian, trufflehog, Nosey Parker, gitleaks (no rule), Stack Overflow, Hacker News, New Relic support forum, dev.to, grep.app: corroboration only |

Not read: Reddit (blocked in every pass), recorded as unchecked. It cannot
meet the T1 bar, so it does not change the verdict.

## Open items

- Empirical check of one or two freshly issued `Ingest - License` keys (length,
  exact tail `FFFFNRAL` vs other, lowercase-hex body, US region prefix, EU
  `eu01xx` vs `eu01x`), as specified in the
  [web-search comment](https://github.com/redact-secret/redact-secret/issues/656#issuecomment-5786035362).
  Record counts and fixed markers only; delete each key.
- `minimumTwinPairs` was 3 in the issue's measurement; the current support
  matrix shows 9. That gate is outside this issue.
- Stale module header and spec wording (above) are for the re-tier batch or a
  follow-up, not this document.

## What this document does not do

It changes no detector, contract, fixture, spec, or tier. The re-tier and any
`covers` edit happen in the T1 re-tier batch of #575. It contains no
credential and no full example token value; `NRAL`, `FFFF` and `eu01xx` are
quoted as fixed markers only.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
