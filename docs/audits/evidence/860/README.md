# Issue #860: Tier A deep handoffs for 11 provider credential families

[Audit archive](../../README.md) ·
[Issue #860](https://github.com/redact-secret/redact-secret/issues/860) ·
[Benchmarks counterpart #376](https://github.com/redact-secret/redact-secret-benchmarks/issues/376) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen record of step 3 of #860 ("deep handoff per selected family"), written
2026-09-28. It covers the 11 Tier A candidates chosen in step 2. It changes no
detector, fixture, finding type, support status, package, version or release
record, and it does not authorize implementation: step 5 of #860 opens
separately scoped product and benchmarks issues only after the maintainer
reviews these handoffs.

The desk research is not repeated here. Each family document cites the
per-candidate research table (an issue comment) for its full source list and
re-cites only the sources a grammar decision rests on. Sources were re-checked
on 2026-09-28 only where the handoff needs an exact length, alphabet or
separator, or where the source could have drifted; each family document says
what was re-checked.

No value in this folder is, or is derived from, an issued credential. No
complete key-shaped example appears: shapes are described by prefix, length,
alphabet and separators only. Test values are to be generated at test time
from those descriptions.

## Research inputs

- Broad-discovery roll-up, T1 facts and ruling questions:
  [issuecomment-5852386325](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386325).
- Per-candidate tables:
  [#01–#08](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450),
  [#09–#16](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571),
  [#17–#24](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386687),
  [#25–#32](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386808),
  [#33–#39](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967),
  [#40–#45](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387097).
- Maintainer rulings R1 (provider server-side generator/validator code, unit
  tests and CLI heuristics are T1: yes) and R3 (a dated provider-staff
  statement off the provider's domain is T1: yes, until a newer provider source
  contradicts it):
  [issuecomment-5852413851](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852413851).
- Maintainer rulings R2, R4–R8 (2026-09-28), applied here where they touch a
  Tier A family: R6 (a code comment is T2) lifts Composio's `uak_` gate; R8
  (no alphabet narrowing from a third-party library) fixes Helicone's alphabet
  at `[a-z0-9]`; R2 adds a second T1 basis for Composio's alphabet; R7 (JWT-only
  credentials get no distinct family) confirms that JWT siblings stay with
  `jwt`:
  [issuecomment-5871306275](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275).
- Step 2 selection and the beta.9 generic-coverage probe:
  [issuecomment-5852451907](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852451907).

## Verdict

| # | Family | Handoff | Readiness | Route | Finding types proposed |
| ---: | --- | --- | --- | --- | --- |
| 40 | `doppler:service-token` | [doppler.md](doppler.md) | **READY** | new detector | seven, one per documented `dp.<type>.` role |
| 20 | `trigger-dev:secret-api-key` | [trigger-dev.md](trigger-dev.md) | **READY** | new detector | secret API key (root and additional); personal access token |
| 05 | `e2b:api-key` | [e2b.md](e2b.md) | **READY** | new detector | one |
| 38 | `posthog:personal-api-key` | [posthog.md](posthog.md) | **READY** | new detector | personal API key; project secret API key. `phc_` stays unclaimed |
| 34 | `helicone:api-key` | [helicone.md](helicone.md) | **READY** | new detector | read-write key (`sk-`); write-only key (`pk-`), redacted |
| 04 | `firecrawl:api-key` | [firecrawl.md](firecrawl.md) | **READY** | new detector | one |
| 31 | `composio:api-key` | [composio.md](composio.md) | **READY** (`ak_`, `oak_`, `uak_`; step 2's `uak_` gate is lifted by R6, see the family document) | new detector | project key; org key; user key |
| 32 | `daytona:api-key` | [daytona.md](daytona.md) | **ISSUANCE-GATED** | new detector | one |
| 42 | `clickhouse-cloud:api-key` | [clickhouse-cloud.md](clickhouse-cloud.md) | **ISSUANCE-GATED** | new detector | one (the key secret; the key ID stays unclaimed) |
| 15 | `weaviate:cloud-api-key` | [weaviate.md](weaviate.md) | **ISSUANCE-GATED** | new detector | one |
| 10 | `baseten:api-key` | [baseten.md](baseten.md) | **DATE-GATED** (no `b10_` key exists before 2026-10-01 15:00 GMT) | new detector | one |

Every row is a **new registry detector with its own finding type(s)**. None is
an extension of an existing detector: no current detector claims any of these
prefixes (checked against the registry and detector sources at `main`
[`9ab0fa0`](https://github.com/redact-secret/redact-secret/commit/9ab0fa02f2aeeda16a2c99e04862ebb0f0e9b5e7)),
and none shares a prefix with an existing provider contract. The closest
neighbours, and why they are not extended, are recorded per family.

**Readiness definitions used here.**

- **READY:** every supported shape's prefix, length, alphabet and separators is
  T1 (a provider document, provider code under R1, or a dated staff statement
  under R3 that no newer provider source contradicts), and no open question
  changes the supported grammar. Issuance checks listed for these families
  would only confirm the grammar; they are not a precondition for a product
  detector.
- **ISSUANCE-GATED:** a supported-grammar fact is contradicted, unresolved, or
  known only from code that may no longer describe the live service. The
  contract cannot be frozen until a maintainer-issued key is checked for
  structure only, following the checklist in the family document.
- **DATE-GATED:** the grammar is T1 but no key of that shape can exist yet.
  No arrival or support claim is made before real keys exist.

## Current coverage on `main` (synthetic probe, 2026-09-28)

The step-2 probe ran against beta.9. It was repeated here against the CLI built
from `main` at
[`9ab0fa0`](https://github.com/redact-secret/redact-secret/commit/9ab0fa02f2aeeda16a2c99e04862ebb0f0e9b5e7)
(`redact-secret` 0.1.0-beta.10, release build), because `generic-token` has
changed since beta.9 (for example the SDK-call keyword-argument form,
[#866](https://github.com/redact-secret/redact-secret/issues/866)).

**Method.** One value per supported shape (and per sibling where the handoff
needs it) was generated at run time from a seeded random generator in the
documented shape, never written to disk, and scanned in nine contexts:

1. bare in prose;
2. `PROVIDER_ENV=value`;
3. `export PROVIDER_ENV="value"`;
4. `Authorization: Bearer value`;
5. `X-API-Key: value`;
6. JSON `{"token": "value"}`;
7. JSON `{"api_key": "value"}`;
8. `Client(api_key="value")`;
9. a chat sentence ("Here is my key … can you debug").

Only finding metadata was kept: type, confidence, action, and whether the span
covered the value. This measures today's generic coverage. It is not a recall,
precision or support-status measurement.

**Result.** The same for all 11 families and every sibling probed (41 shapes):

| Context | Finding today |
| --- | --- |
| env, `export`, `X-API-Key`, JSON `api_key`, SDK keyword argument | `contextual_secret`, high, redact, full span |
| `Authorization: Bearer` | `bearer_token`, high, redact, full span |
| bare prose, JSON `"token"`, chat sentence | **none** |

The `export` and keyword-argument misses reported at beta.9 are fixed on
`main`. The remaining gap for every family is the **bare, chat and JSON
`"token"`** occurrence: the LLM/agent-context cases #860 targets. A provider
detector's value is that coverage plus a provider-attributed finding type in
the contexts generic detection already redacts.

## Shared contract rules

These apply to every family document unless it says otherwise.

- **Output policy.** Each new finding type is `Specificity::Provider`,
  `Confidence::High`, and listed in `ALWAYS_REDACT_TYPES`, so the default
  action is `redact`. Overlap resolution then reports one finding per span:
  the provider candidate wins over `contextual_secret` (generic), and over
  `bearer_token` and `authorization_credential` in the header contexts,
  as with the #867 families. No type in this set is `block` or
  confidence-gated.
- **Boundary.** A match is rejected when the byte before the prefix or the byte
  after the body continues an identifier (`[A-Za-z0-9_-]`, widened per family
  where the body alphabet is wider). An embedded, over-long or glued value is
  an intentional false negative, never truncated into a match.
- **No generic-token deferral.** None of these providers is added to
  `generic-token`'s `DEDICATED_PROVIDER_SEGMENTS`. Several families have
  documented shapes these contracts exclude (Firecrawl dashed-UUID legacy keys,
  PostHog pre-prefix keys, Trigger.dev `tr_oat_`, Composio `ck_`, Helicone
  `sk-cp-`). Deferral would turn a provider-named assignment of one of those
  into a silent miss. The #868 section of the spec made the same call.
- **JWT siblings stay with `jwt`.** Where a provider also issues JWTs
  (Trigger.dev public access tokens and `tr_uat_`, Daytona `DAYTONA_JWT_TOKEN`),
  the existing `jwt` detector keeps them, as ruling R7 requires. No contract
  here claims a JWT.
- **Placeholders.** A placeholder shorter than the exact width, or with a byte
  outside the alphabet (`e2b_...`, `dtn_***`, `fc-YOUR-API-KEY`,
  `tr_dev_sk_xxxxxxxxxx`), is not claimed by construction. A placeholder padded
  to the exact width with alphabet bytes is claimed, following the #867
  precedent: no length-preserving placeholder exclusion is evidenced.
- **Tests.** Deterministic unit and registry integration tests per family:
  positives in every context above with exact spans, one-property twins,
  benign siblings, cross-family isolation, an adversarial repetition line, and
  whole-input vs two-chunk incremental parity. Test values are built at run
  time from a synthetic filler; no realistic literal is committed. The
  conformance-corpus entries the coverage gate requires use deliberately low
  entropy filler, as in #864.
- **Cost.** Every shape is a literal prefix (or, for Weaviate, a literal
  suffix) plus a bounded run with an O(1) or single-pass post check. Linear in
  the input with no per-line state, so incremental and WASM scanning pay the
  same cost as the other prefixed families. `scripts/measure-detector-cost.mjs`
  and the WASM profile checks run with the implementation.

## Issuance-check protocol (structure only)

Applies to the ISSUANCE-GATED and DATE-GATED families, and optionally to READY
families for confirmation. It follows the safe-observation rules already used
for the Beta.8 empirical route
([#726 evidence](../726/README.md#empirical-observation-plan)).

1. The maintainer issues the key in their own account and inspects it locally.
2. Record only: family, date, issuance route (console, CLI, API), key role,
   total length, per-segment lengths, alphabet classes present (lowercase,
   uppercase, digits, which punctuation), separator bytes and their positions,
   whether a documented fixed part (prefix, suffix) is present, and
   `rawValueRetained: false`.
3. Never paste, screenshot, hash, log, transmit, store or derive a fixture from
   the value. Revoke the key after inspection and record that it was revoked.
4. Post the structural record as an issue comment on #860 (or the family's
   implementation issue). A contradiction with the handoff grammar blocks the
   freeze and is recorded, not averaged into a wider grammar.

## Product and benchmark split

The product issues own detectors, finding types, unit/integration tests,
inventory rows, the detector-family spec rows and the conformance corpus
entries. The benchmarks issues own the independent contract, the synthetic
positive/twin/benign corpus, profile coverage, and the qualification run. The
spec gains its rows when a detector lands, not now, because the spec records
current behavior. Core conformance and benchmark arrival/profile evidence both
gate any promotion; nothing here is a support-status claim.

## Acceptance for this step

- [x] Each of the 11 Tier A families has a handoff with supported and excluded
  shapes, provenance, tier rationale, test axes, overlap and output policy,
  FP/FN boundary, issuance checklist and route.
- [x] Readiness is stated per family, including why Composio `uak_` moves
  from step 2's issuance gate to READY under R6.
- [x] Doppler scope, Helicone `pk-` policy and PostHog `phc_` are decided.
- [x] Current generic coverage is measured on `main`, not assumed.
- [x] No credential value or real-derived material appears in this record.

## Authority

This record freezes the proposed handoffs for review only. It does not
authorize implementation, support-status promotion, a version change, a tag,
publication or release.
