# Issue #860: issuance-gate research and rulings R9–R10

[#860 handoff index](../README.md) ·
[Tier B re-rank](../tier-b-rerank.md) ·
[All-50 disposition](../disposition.md) ·
[Issue #860](https://github.com/redact-secret/redact-secret/issues/860)

Frozen record, written 2026-09-28. After step 4, eleven #860 families were
ISSUANCE-GATED or DATE-GATED. This record asks, family by family, whether a
public provider source can stand in for a maintainer-issued key. It then
records the maintainer's rulings R9 and R10 and the disposition of each
family.

No key was issued for this research. No value here is, or is derived from,
an issued or leaked credential, and no complete key-shaped example appears:
shapes are given by prefix, length, alphabet and separators only. Provider
test fixtures and placeholders are described, not reproduced. Staff are
named by public GitHub handle only.

It changes no detector, fixture, finding type, support status, package,
version or release record. Implementation is scheduled for Beta.12
(milestone `v0.1.0.beta.12`). No detector code for these families merges to
`main` until `0.1.0-beta.11` is released.

## Rulings R9 and R10

Posted by the maintainer on 2026-09-28:
[issuecomment-5880547337](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337).

- **R9 (dated code): yes.** R3's date rule now covers provider code too. A
  generator or validator in provider code counts as T1 as of its date. It
  holds until a newer provider source contradicts it. Applied to Daytona.
- **R10 (policy fill): yes, for Cerebras and RunPod only.** Where the
  provider states a length or a floor but not the whole grammar, project
  policy may fill the rest. The fill must be at least as wide as any
  provider-stated class, so it never causes a false negative that the
  provider's own rule would catch.

Rulings R1–R8 are indexed in the [handoff index](../README.md#research-inputs)
and the [Tier B re-rank](../tier-b-rerank.md#inputs).

## Verdict

| Family | Research verdict | Disposition after R9–R10 | Contract | Record |
| --- | --- | --- | --- | --- |
| `daytona:api-key` | still gated (code private since v0.190.0) | **READY** by R9 | `dtn_` + exactly 64 `[0-9a-f]`, T1 as of v0.190.0 (2026-06-23) | [daytona.md](daytona.md) |
| `clickhouse-cloud:api-key` | narrowed: 42 vs 39 resolves by R3 date order | **READY** under existing rulings | `4b1d` + exactly 38 `[A-Za-z0-9]` (42 in total), T1 as of 2025-04-16 | [clickhouse-cloud.md](clickhouse-cloud.md) |
| `nvidia:ngc-api-key` | closed as open-ended (R2) | **READY** under existing rulings | `nvapi-` + at least 60 `[A-Za-z0-9_-]`; cap is policy | [nvidia.md](nvidia.md) |
| `browserbase:api-key` (`bb_live_`) | closed as open-ended (R2) | **READY** under existing rulings | `bb_live_` + at least 20 `[A-Za-z0-9]`, boundaries on both sides; cap is policy | [browserbase.md](browserbase.md) |
| `cerebras:inference-api-key` | narrowed: length and prefixes T1, alphabet open | **READY** by R10 | `csk-` or `csk_` + exactly 48 `[A-Za-z0-9_-]`, leading boundary excludes `pcsk_` | [cerebras.md](cerebras.md) |
| `runpod:api-key` | still gated (provider floor 16 only) | **READY** by R10 | `rpa_` + at least 31 `[A-Za-z0-9]`; cap is policy | [runpod.md](runpod.md) |
| `weaviate:cloud-api-key` | still gated (slightly narrowed) | ISSUANCE-GATED | — | [weaviate.md](weaviate.md) |
| `planetscale:service-token` | still gated | ISSUANCE-GATED (the 2022 range was not accepted) | — | [planetscale.md](planetscale.md) |
| `convex:deployment-key` (cloud `eyJ2` body) | narrowed: body is Base64 of a `v2`-tagged JSON object | ISSUANCE-GATED (derived lead; length unknown) | — | [convex.md](convex.md) |
| `cartesia:api-key` | still gated | ISSUANCE-GATED (`<id>.<secret>` from a comment only) | — | [cartesia.md](cartesia.md) |
| `arcade:api-key` (`arc_proj_`) | still gated | ISSUANCE-GATED (placeholders only) | — | [arcade.md](arcade.md) |
| `browserbase:api-key` (`bb_test_`) | still gated | ISSUANCE-GATED | — | [browserbase.md](browserbase.md) |
| `baseten:api-key` | not researched (no key can exist yet) | DATE-GATED until real `b10_` keys exist (from 2026-10-01 15:00 GMT) | — | [baseten.md](../baseten.md) |

The six READY families have step-3 handoffs in the parent folder:
[daytona.md](../daytona.md), [clickhouse-cloud.md](../clickhouse-cloud.md),
[nvidia.md](../nvidia.md), [browserbase.md](../browserbase.md),
[cerebras.md](../cerebras.md) and [runpod.md](../runpod.md).

## Upper caps (policy)

NVIDIA, Browserbase and RunPod have open-ended provider grammars. Following
the Apify precedent ([apify.md](../apify.md)), each contract caps the body at
**128** bytes as project policy: a bounded run for streaming and
incremental scanning. A body over the cap is rejected whole (an intentional
false negative), never truncated into a match. Every observed or
tool-reported width (NVIDIA 64, Browserbase none, RunPod 46) is inside the
cap.

## Sanitization check

Before the record was frozen, this folder and every handoff file this
change touches were scanned twice:

- `gitleaks dir` 8.30.1 (default rules) over `docs/audits/evidence/860/`:
  no leaks found;
- the product CLI built from `main` at this record's base (`redact-secret`
  0.1.0-beta.10, release build) over each changed file: no provider or
  high-confidence finding. Two medium-confidence `warn` findings from
  `generic-token` land on quoted provider prose, not values: a code comment
  ("Access Tokens are base64 encoded strings", [convex.md](convex.md)) and
  a shell default expansion (`openssl rand -hex 32`,
  [daytona.md](daytona.md)).

Only documented non-secret prefixes, regexes and structural descriptions
appear.

## Authority

This record freezes research and rulings for review only. It does not
authorize implementation on `main` before `0.1.0-beta.11` is released,
support-status promotion, a version change, a tag, publication or release.
