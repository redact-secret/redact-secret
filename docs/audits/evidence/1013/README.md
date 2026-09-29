# Issue #1013: T1/T2 evidence for blocked provisional and pending credential families

[Audit archive](../../README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: detector families](../../../specs/detector-families.md) ·
[Spec: evidence and gates](../../../specs/evidence-and-gates.md)

Frozen record, written 2026-09-29, for the Beta.12 milestone. It covers the
credential families that the pinned support matrix
(`benchmarks/support-matrix.json` at `b9e90915`) holds `provisional` for a
corroboration gap or an unresolved contradiction, and the `pending` families
whose blocker is missing evidence. For each, it asks whether public sources
now supply T1 evidence (a provider-authored source, including dated provider
code under ruling R9 of #860) or clear the T2 corroborated route.

The corroborated route is the #177 amendment (2026-09-24) in
redact-secret-benchmarks, as encoded in its
[status criteria](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/support/status-criteria.json):
at least 3 verified, dated references from at least 3 distinct owners,
spanning at least 2 classes other than the summary class
`independent-research`. The counted classes are `peer-scanner-rule`,
`provider-owned-code`, `provider-example` and `independent-implementation`.
An unresolved contradiction blocks; only a provider-owned-code or
provider-example source can settle one, and otherwise the contract may
bound it by excluding the disputed shape.

Method: broad discovery first (web search, GitHub code search, provider SDK
and docs repositories, changelogs, forums, and the rules of trufflehog,
gitleaks, betterleaks, noseyparker, detect-secrets, secretlint, Kingfisher,
CredSweeper, osv-scalibr, semgrep and others), then each source's class,
owner and date. Every GitHub source is cited at a 40-hex commit. Each family
document lists where the searches went, including the empty ones. All
sources were read on 2026-09-29.

No key was issued for this research. No value here is, or is derived from,
an issued or leaked credential, and no complete key-shaped example appears:
shapes are given by prefix, length, alphabet and separators only.

It changes no detector, fixture, finding type, support status, package,
version or release record. Recording the new references, owners and
contradiction dispositions in
[`benchmarks/support/empirical-observations.json`](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/support/empirical-observations.json)
is a separate redact-secret-benchmarks change. Non-evidence gates that the
matrix also lists (fixture-profile counts, mutation, metamorphic and
differential findings, `mode`, `uncertainty`, `supportedContexts`) are out of
scope and noted per family.

## Verdict

| Family | Blocker at the pin | Verdict | Grammar the evidence supports | Record |
| --- | --- | --- | --- | --- |
| `github:fine-grained-personal-access-token` | corroboration 0 / 0 / 0 | **READY-T2** (T1 by ruling Q-GH) | `github_pat_` + 22 `[A-Za-z0-9]` + `_` + 59 `[A-Za-z0-9]` (93) | [github-fine-grained-personal-access-token.md](github-fine-grained-personal-access-token.md) |
| `openai:admin-api-key` | corroboration 0 / 0 / 0 | **READY-T2** | `sk-admin-` + 58 `[A-Za-z0-9_-]` + `T3BlbkFJ` + 58 (133); 74/74 unobserved, record outside the claim | [openai-admin-api-key.md](openai-admin-api-key.md) |
| `slack:app-level-token` | corroboration 0 / 0 / 0 | **READY-T2, conditional** on Q-SL; else issuance | `xapp-` + digits `-` alnum `-` digits `-` alnum, widths open | [slack-app-level-token.md](slack-app-level-token.md) |
| `together:api-key` | corroboration 2 / 2 / 1 | **READY-T2, conditional** on Q-TG; else issuance | `tgp_v1_` + 43 `[A-Za-z0-9_-]` (50) | [together-api-key.md](together-api-key.md) |
| `mistral:api-key` | classes 1 < 2 | **READY-T2** | context-gated 32 `[A-Za-z0-9]` | [mistral-api-key.md](mistral-api-key.md) |
| `okta:api-token` | 4 unresolved contradictions | **READY-T2** once the four are recorded bounded (Q-OK) | context-gated `00` + 40 `[A-Za-z0-9_-]` (42), no `=` | [okta-api-token.md](okta-api-token.md) |
| `ai21:api-key` | pending, T0 | **READY-T2** (context-constrained) | context-gated 32 `[A-Za-z0-9]` | [ai21-api-key.md](ai21-api-key.md) |
| `voyage-ai:api-key` | pending | **STILL-BLOCKED**; `al-` READY-T1 by Q-VO1 or Q-VO2, `pa-` by Q-VO2 | candidate `pa-`/`al-` + 43 `[A-Za-z0-9_-]`; `al-eu-` unknown | [voyage-ai-api-key.md](voyage-ai-api-key.md) |
| `mistral:realtime-client-token` | pending | **STILL-BLOCKED**; issuance only | prefix `rt_` only | [mistral-realtime-client-token.md](mistral-realtime-client-token.md) |
| `vercel:personal-access-token` | pending, T0 | **READY-T2** | `vcp_` + 56 `[A-Za-z0-9]` (60) | [vercel.md](vercel.md) |
| `vercel:app-access-token` | pending, T0 | **READY-T2** (thin: one provider value) | `vca_` + 56 `[A-Za-z0-9]` (60) | [vercel.md](vercel.md) |
| `vercel:app-refresh-token` | pending, T0 | **READY-T2** (thin: shared body) | `vcr_` + 56 `[A-Za-z0-9]` (60) | [vercel.md](vercel.md) |
| `vercel:integration-token` | pending, T0 | **STILL-BLOCKED**; Q-VC or issuance | `vci_` not provider-stated | [vercel.md](vercel.md) |
| `vercel:api-key` | pending, T0 | **STILL-BLOCKED** on length; Q-VC or issuance | marker `vck_` only | [vercel.md](vercel.md) |
| `vercel:access-token` | pending, T0 | **not a family** (compatibility aggregate) | — | [vercel.md](vercel.md) |

No family reaches READY-T1 on existing rulings. Two are one ruling away
from T1: GitHub (Q-GH) and the Voyage `al-` key (Q-VO1 or Q-VO2).

Corrections to the benchmarks record found on the way:

- trufflehog 3.97.4 does not exclude OpenAI admin keys; it moved them to a
  dedicated `openaiadmin` detector that requires marker + 58/58.
- Kingfisher's Together rule was a native rule from 2025-08-27, not only an
  alias of betterleaks.
- gitleaks' `xapp-` rule has open widths; 1/11/13/64 is only its test
  samples. osv-scalibr is the rule that fixes those widths.
- Okta: the `=` in gitleaks' rule comes from a generic helper, and both 2023
  "contradictions" come from one devforum thread.
- Vercel: `vci_` and `vck_` do not clear two classes on the length; the
  `vca_` provider example is checksum-valid.
- Voyage: "can't exceed 250 characters" is the key name's limit.

## Maintainer rulings requested

| Id | Question | Families affected |
| --- | --- | --- |
| Q-GH | Is a dated staff endorsement of the exact grammar (R3), or GitHub-owned code matching it exactly (R1/R9, a redactor), a T1 grammar statement? | GitHub fine-grained PAT: T2 → T1 |
| Q-SL | May Slack's four-section placeholders count as provider examples when other Slack placeholders show fewer sections (bounded)? | Slack `xapp-`: conditional → READY-T2 |
| Q-TG | Must the second corroboration class state the exact width, or is prefix + alphabet by provider code enough when three peer owners agree on the width? | Together: conditional → READY-T2 |
| Q-OK | Accept the four Okta contradiction dispositions (all bounded; #3 optionally settled by R3) | Okta → READY-T2 |
| Q-AI | Do provider-committed key literals of unknown validity count as provider examples? | AI21: decides settled vs bounded; READY-T2 either way |
| Q-VO1 | Is the Atlas Admin API example (R5) the `al-` grammar? | Voyage `al-` → T1 |
| Q-VO2 | Is a scanner rule authored by provider staff who say so (dated) an R3 staff statement? | Voyage `pa-` and `al-` → T1 |
| Q-VC | Do the five Vercel classes share one generator, so `vca_`/`vcp_` structure extends to `vci_`/`vck_`? | Vercel `vci_`, `vck_` → READY-T2 |

## Hands-on issuance by the maintainer

Required (no public source can close it):

| Family | Check (structure only; revoke afterwards) |
| --- | --- |
| `mistral:realtime-client-token` | mint 2+ tokens via `POST /v1/client/sessions`; total length and whether constant; body alphabet (hex, base62, base64url); `_`, `-` or `.` present; whether `Bearer rt_…` is accepted |
| `voyage-ai:api-key` (`al-eu-`) | one EU-scoped Atlas model API key: total length; whether 43 characters follow `al-eu-` or `al-`; alphabet |

Required unless the named ruling is granted:

| Family | Ruling | Check |
| --- | --- | --- |
| `voyage-ai:api-key` (`pa-`) | Q-VO2 | one dashboard key: total length (46 expected); `_` or `-` in the body |
| `vercel:api-key` (`vck_`) | Q-VC | one AI Gateway key: marker with `_`; total 60; body alphabet; last 6 = base62(CRC-32 of the previous 50) |
| `vercel:integration-token` (`vci_`) | Q-VC | one integration token via OAuth code exchange: same four checks |
| `together:api-key` | Q-TG | one project key: prefix `tgp_v1_`; total 50; `_` or `-` in the body |
| `slack:app-level-token` | Q-SL | one app-level token: section count 4; per-section alphabet and length; total length |

Optional, not required for the verdict: Okta (length 42, prefix `00`, `_`/`-`/`=`
present; closes contradiction 3 only if `_` appears) and AI21 (length 32,
alphanumeric only).
