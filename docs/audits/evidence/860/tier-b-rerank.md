# Issue #860: Tier B re-rank after rulings R2 and R4–R8, and deep handoffs

[Audit archive](../../README.md) ·
[Issue #860](https://github.com/redact-secret/redact-secret/issues/860) ·
[Benchmarks counterpart #376](https://github.com/redact-secret/redact-secret-benchmarks/issues/376) ·
[Spec: detector families](../../../specs/detector-families.md) ·
[All-50 disposition](disposition.md) ·
[Issuance research and R9–R10](issuance-research/README.md)

Frozen record, written 2026-09-28. It re-ranks the 13 Tier B candidates from
step 2 of #860 after the maintainer's rulings R2 and R4–R8, and it writes
step-3 deep handoffs for the Tier B families that are now fully T1. It also
applies R4–R7 to the Tier C items those rulings touch, and records the #03
fal generic gap as a contextual-extension note.

It changes no detector, fixture, finding type, support status, package,
version or release record. It does not authorize implementation. Step 5 of
#860 opens scoped product and benchmarks issues only after maintainer review.

The Tier A handoffs (11 families) were written in parallel on branch
`beta11/860-tier-a-handoffs`. Their index is frozen at
[`270faf8`](https://github.com/redact-secret/redact-secret/blob/270faf84dc12f6a4a4cf61fe3ffab7aadc4f7262/docs/audits/evidence/860/README.md).
This record uses the same readiness definitions, shared contract rules,
issuance protocol and handoff format. It is placed in the same folder, in
separate files. Once both branches land, the permalinks here can become
relative links.

No value in this record is, or is derived from, an issued credential. No
complete key-shaped example appears. Test values are generated at run time.

## Inputs

- The per-candidate research tables, which are issue comments:
  - [#01–#08](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450)
  - [#09–#16](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571)
  - [#17–#24](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386687)
  - [#25–#32](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386808)
  - [#33–#39](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967)
  - [#40–#45](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387097)
  - [#46–#50](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387196)
- The T1 roll-up:
  [issuecomment-5852386325](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386325).
- Rulings R1 and R3 applied:
  [issuecomment-5852413851](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852413851).
- Step 2 selection, with Tier A/B/C:
  [issuecomment-5852451907](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852451907).
- Rulings R2 and R4–R8:
  [issuecomment-5871306275](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275).
- Tier A step 3:
  [issuecomment-5871361534](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871361534).
- Issuance-gate research, rulings R9 (dated provider code is T1 as of its
  date) and R10 (policy may fill a partly stated grammar, for Cerebras and
  RunPod only), and the per-family dispositions (added 2026-09-28, after this
  re-rank):
  [issuecomment-5880547337](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337);
  frozen in [issuance-research/](issuance-research/README.md).

Desk research was not repeated. A source was re-checked on 2026-09-28 only
where a ruling hinges on it: every R2 authorship, the R5 examples for
1Password, Resend, Inngest and W&B, and the Convex encoder. Each family
document says what was re-checked.

## Readiness definitions

These are the same as Tier A.

- **READY:** every supported shape's prefix, length, alphabet and separators
  is T1.
  - Where the provider's own grammar is open-ended (a floor, no exact width),
    that open-ended grammar is the T1 grammar. The contract adds only a
    bounded cap as project policy.
  - Where the provider states that the length varies (1Password's serialized
    token), the contract uses a floor chosen as project policy, below every
    T1 example.
- **ISSUANCE-GATED:** a supported-grammar fact is unresolved. The exact
  property is named below. A maintainer-issued key, checked for structure
  only, settles it.
- **NOT SELECTED:** no distinct family now. The reason is given, and the
  negative finding is retained.

## R2 authorship checks

R2 counts a scanner, redaction or lint regex as T1 only if the provider wrote
it; a vendored public scanner rule stays T2. Each rule below was traced to
its adding commit and author on 2026-09-28. None of them matches a public
scanner rule for the same provider.

| # | Rule (in the provider's own repo) | Added | Author and association | Public-rule comparison | Result |
| ---: | --- | --- | --- | --- | --- |
| 06 | `browserbase/stagehand` `packages/integrations/core/src/harness/redact.ts`: `bb_(?:live\|test)_[A-Za-z0-9]{4}` then `[A-Za-z0-9_-]+`, commented "Browserbase live and test keys"; duplicated in the Python eval runner | [`26c4aa8`](https://github.com/browserbase/stagehand/commit/26c4aa8b94ae), 2026-08-30 (#2746) | Miguel (`miguelg719`), `COLLABORATOR`, about 520 commits in the org | gitleaks, trufflehog, Kingfisher: no Browserbase rule | **provider-authored: T1** for prefix and alphabet. No length: the floor is 5 |
| 09 | `runpod/runpod-mcp` `src/alp/scrub.ts`: `\brpa_[A-Za-z0-9]{16,}\b` ("Runpod API keys") | [`57b3973`](https://github.com/runpod/runpod-mcp/commit/57b3973f3778), 2026-09-16 (#90) | Justin (`justinwlin`), about 300 commits across the `runpod` org; `COLLABORATOR` on `runpod/typescript-api-sdk`, `CONTRIBUTOR` on this repo | betterleaks is `rpa_[A-Z0-9]{40}[A-Za-z0-9]{6}`, which differs | **provider-authored: T1** for prefix, alphabet and a floor of 16. Affiliation is shown by activity, as with R3's ClickHouse case |
| 13 | `apify/awesome-skills` `scripts/lint_references.py`: `apify_api_[A-Za-z0-9]{20,}`, CI-enforced per `SECURITY.md` | [`4ba9177`](https://github.com/apify/awesome-skills/commit/4ba9177da814), 2026-08-12 | Pavel Chocholouš (`chocholous`), `COLLABORATOR`, about 150 commits in the org | trufflehog is `apify\_api\_[a-zA-Z-0-9]{36}`, which differs; gitleaks has none | **provider-authored: T1** for alphabet and a floor of 20 |
| 36 | `braintrustdata/braintrust-sdk` `.gitleaks.toml`: a custom `[[rules]]` block `\bsk-[a-zA-Z0-9]{40,}\b` on top of `useDefault = true` | [`3789d1c`](https://github.com/braintrustdata/braintrust-sdk/commit/3789d1cfb6cc), 2026-05-07 (#1968) | Stephen Belanger (`Qard`), `COLLABORATOR` | gitleaks's default set has no Braintrust rule, so this block is the provider's own | **provider-authored: T1** for `sk-` + at least 40 alphanumerics. Disposition unchanged: the shape equals legacy OpenAI `sk-` + 48 (Tier C) |

## Re-rank

Priority is the order below. The rule each fact rests on is in brackets.
"By example" means the #655 example-shape precedent, which R5 extends.

| Rank | # | Candidate | Prefix | Length | Alphabet / separators | Readiness | Handoff or gate |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 1 | 48 | `convex:deployment-key` | `(prod\|dev\|preview\|project):` + name/slugs + `\|` (docs + CLI/backend code) | hex body: 74–96, even, derived from the generator [R1]. Cloud `eyJ2` body: unknown [R4] | hex body: lowercase hex with a `01` version lead [R1]; cloud body: only `eyJ2` is T1 [R4] | **READY** for hex-body keys (self-hosted, dashboard admin, legacy typed). **ISSUANCE-GATED** for the cloud `eyJ2` body | [convex.md](convex.md). Gate property: cloud body alphabet (standard or URL-safe Base64, padding) and length, and whether scope changes it |
| 2 | 39 | `onepassword:service-account-token` | `ops_` (docs prose) | variable (serialized JSON); T1 example 634 [R5]; floor 250 by policy | Base64url (docs prose); `eyJ` lead (JSON, example) | **READY** | [onepassword.md](onepassword.md) |
| 3 | 50 | `inngest:signing-key` | `signkey-(prod\|test\|branch)-` (code constants) | exactly 64 [R5: docs `openssl rand -hex 32` + SDK fixtures] | lowercase hex (code + docs) | **READY** | [inngest.md](inngest.md). Also closes today's env-file medium/warn gap |
| 4 | 02 | `resend:api-key` | `re_` (CLI code + README) | 8 + `_` + 24 = 36 [R5: docs response example + SDK fixtures] | `[A-Za-z0-9]` superset by example; `_` at offset 11 | **READY** | [resend.md](resend.md). Mixed-case guard for the short prefix |
| 5 | 13 | `apify:api-token` | `apify_api_` [R4 docs placeholder; the `apify_ui_` branch is R6] | at least 20, open-ended [R2]; cap 128 by policy | `[A-Za-z0-9]` [R2] | **READY** (open-ended) | [apify.md](apify.md) |
| 6 | 37 | `wandb:api-key` (`wandb_v1_`) | `wandb_v1_` [R5 test constant] | total 86 [R5 SDK/Weave fixtures + docs "about 86"] | `[A-Za-z0-9_]` [R1 validator + error text] | **READY** (the legacy 40-hex key is NOT SELECTED) | [wandb.md](wandb.md). Issuance check recommended for the "about" |
| 7 | 01 | `nvidia:ngc-api-key` | `nvapi-` (docs + NGC CLI `SCOPED_KEY_PREFIX`) | not T1: 64 is tool-only; NemoClaw redaction floors of 10/12/16 are far too low for bare detection | not T1 (tool `[A-Za-z0-9_-]`) | **ISSUANCE-GATED** → **READY** after the issuance research (R2 floor 60, `[A-Za-z0-9_-]`) | [nvidia.md](nvidia.md). Was gated on body length and alphabet. Short floors would claim `nvapi-` SDK and crate names |
| 8 | 43 | `planetscale:service-token` | `pscale_tkn_` (docs + CLI/MCP code) | 32–64 per a staff statement of **2022-05** [R3]; not fixed | `[A-Za-z0-9=_.-]` per the same staff diff [R3] | **ISSUANCE-GATED** | whether a token issued today has a suffix inside 32–64 (trufflehog says 43), and which of `= . - _` occur. The only T1 source is 4+ years old and self-described as "very likely to change". A maintainer may instead accept the R3 range as-is; that would make it READY |
| 9 | 09 | `runpod:api-key` | `rpa_` (blog/docs + scrubber) [R2] | at least 16 [R2]; 46 empirical; a docs example of 48 without `_` [R5] contradicts it | `[A-Za-z0-9]` [R2] | **ISSUANCE-GATED** → **READY** by R10 (policy floor 31) | [runpod.md](runpod.md). Was gated on exact body length (46?) and the 40-upper/6-lower layout, needed to keep Redirect.pizza's `rpa_` + 30 from being reported as RunPod; the policy floor does that instead |
| 10 | 08 | `cerebras:inference-api-key` | `csk-` (docs: "starts with `csk-`") | not T1: 48 is tool-only | not T1: `[a-z0-9]` is tool-only | **ISSUANCE-GATED** → **READY** by R10 (validator length 48, `csk_` by staff statement, policy alphabet) | [cerebras.md](cerebras.md). Was gated on body length (48?) and alphabet. Pinecone's `pcsk-` contains `csk-`, and the leading boundary handles it |
| 11 | 17 | `cartesia:api-key` | `sk_car_`, `sk_car_admin_` (docs + runtime `startswith`) [R6] | fixtures 22 + `.` + 36 [R5], but conflicting: short `abc.def` fixtures, and a 2025-02 committed undotted `sk_car_` + 21 `[A-Za-z0-9_]` | the `<id>.<secret>` code comment is T2 [R6] | **ISSUANCE-GATED** | whether a key issued today contains `.`, its segment lengths, and whether `_` appears. The undotted 2025 shape suggests drift |
| 12 | 06 | `browserbase:api-key` | `bb_live_` / `bb_test_` (docs placeholders [R4] + redaction regex [R2]) | none: the regex floor is 5 | `[A-Za-z0-9_-]` with the first 4 alphanumeric [R2] | **ISSUANCE-GATED** → **READY** for `bb_live_` after the issuance research (R2 floor 20, alphanumeric); `bb_test_` stays gated | [browserbase.md](browserbase.md). Was gated on body length: a floor of 5 would claim `bb_test_data_…` identifiers. Whether `bb_test_` is issued to customers is still open |
| 13 | 33 | `arcade:api-key` | `arc_` [R6 runtime `startsWith`]; `arc_proj_` [R4 provider example-repo placeholders]; the code comment is T2 | none | none (empirical mixed-case alphanumeric) | **ISSUANCE-GATED** for `arc_proj_` only. Bare `arc_` is **NOT SELECTED** | whether a project key issued today starts `arc_proj_`, its body length and alphabet, and the read-only key's sub-prefix. Bare `arc_` is shared by at least 3 other issuers (Arcauthic, ArcAgent, Arcane), and personal keys are deprecated |

**What changed since step 2.**

- Six Tier B families reached a full T1 grammar (Convex only for its hex
  body). R5 unlocked 1Password, Inngest, Resend and W&B. R2 unlocked Apify.
  R1 had already covered Convex's hex body, and the handoff now uses it.
- RunPod, Browserbase and Arcade gained T1 facts (R2, R4, R6). Their
  remaining gap is a length, so each is gated on a single named property.
- NVIDIA, Cerebras and PlanetScale are unchanged. No R2–R8 ruling reaches
  their length.
- Cartesia's R5 fixtures conflict with an older undotted value, so it stays
  gated on drift.

**What changed after the issuance research and R9–R10 (2026-09-28).** See
[issuance-research/](issuance-research/README.md).

- NVIDIA and Browserbase (`bb_live_`) closed as open-ended grammars under R2
  from newly found provider-authored rules. Their caps are policy (128), as
  for Apify.
- Cerebras and RunPod became READY by R10: the provider states a length
  (Cerebras 48) or a floor (RunPod 16), and policy fills the rest (Cerebras
  alphabet `[A-Za-z0-9_-]`; RunPod floor 31).
- PlanetScale (the 2022 range was not accepted), Cartesia, Arcade,
  `bb_test_` and Convex's cloud body stay ISSUANCE-GATED.
- Six families now have step-3 handoffs for Beta.12: the four above plus
  the Tier A Daytona (R9) and ClickHouse Cloud handoffs, updated in place.

## Current coverage on `main`

This is the Tier A method, applied to the Tier B shapes.

- The CLI was built from `main`
  [`9ab0fa0`](https://github.com/redact-secret/redact-secret/commit/9ab0fa02f2aeeda16a2c99e04862ebb0f0e9b5e7)
  (`redact-secret` 0.1.0-beta.10, release build).
- One value per researched shape was generated at run time from a seeded
  generator. It was never written to disk.
- Each value was scanned in the nine Tier A contexts. Convex also got
  `Authorization: Convex` and fal also got `Authorization: Key`.
- Only finding metadata was kept.

This measures generic coverage today. It is not recall, precision or support
status.

| Shapes | env, `export` | Bearer | `X-API-Key`, JSON `api_key`, keyword argument | bare, chat, JSON `"token"` |
| --- | --- | --- | --- | --- |
| 1Password, NVIDIA, RunPod, Apify, PlanetScale, Cerebras, Resend, Cartesia, W&B (`wandb_v1_` and legacy 40-hex), Browserbase, Arcade (`arc_`, `arc_proj_`) | `contextual_secret` high, full | `bearer_token` high, full | `contextual_secret` high, full | **none** |
| Inngest `signkey-prod-` | `contextual_secret` **medium / warn** (`signing_key` is an ambiguous name) | `bearer_token` high, full | `contextual_secret` high, full | **none** |
| Convex, all six shapes | **none** (the `CONVEX_*_KEY` names are outside the vocabulary) | **none**, or `bearer_token` over the non-secret name only (self-hosted: 18 of 93 bytes) | `contextual_secret` high, full | **none** |
| fal `<uuid>:<hex32>` | **none** (the `FAL_KEY` name) | `bearer_token` over the first 36 bytes only | `contextual_secret` high, full | **none** |

Benign controls (none produced a finding):

- `CONVEX_DEPLOYMENT=dev:<name>`;
- `CONVEX_URL=https://<name>.convex.cloud`;
- `signkey-prod-<YOUR-SIGNING-KEY>`;
- `ops_...`;
- `op://vault/item/field`.

## Shared contract rules

The Tier A shared rules apply unchanged: output policy, boundary, no
`generic-token` deferral, JWT siblings stay with `jwt`, placeholders, tests
and cost. See the
[Tier A index](https://github.com/redact-secret/redact-secret/blob/270faf84dc12f6a4a4cf61fe3ffab7aadc4f7262/docs/audits/evidence/860/README.md#shared-contract-rules).

Tier B additions:

- **Open-ended bodies** (1Password, Apify) use `PrefixShape::at_least` with a
  post-check cap. An over-cap run is an intentional false negative, never
  truncated into a match.
- **Leading boundary exceptions.** W&B admits `-` before the prefix, so the
  on-prem `<host>-` label is left out of the span. Convex walks left from its
  `|` anchor.
- **Short-prefix guard.** Resend reuses Tier A's Composio `ak_` mixed-case
  post check.
- **Every new type** is `Specificity::Provider`, `Confidence::High` and in
  `ALWAYS_REDACT_TYPES`.

## Issuance checks for the gated families (structure only)

The Tier A protocol applies:

- the maintainer issues and inspects the key locally;
- only the structure is recorded;
- `rawValueRetained: false`;
- the key is revoked after inspection;
- the record is posted as a #860 comment.

A contradiction with the proposed grammar blocks the freeze and is recorded.
It is never averaged into a wider grammar.

| # | Issue | Record |
| ---: | --- | --- |
| 48 | one prod and one preview deploy key; optionally one dashboard admin key | see [convex.md](convex.md#issuance-checklist--gate-for-the-cloud-body-structure-only) |
| 01 | optional since R2 research: one NGC Personal key, one NGC Service key, one build.nvidia.com key | total length; body length after `nvapi-`; alphabet classes incl. `-` and `_` |
| 43 | one service token (and its ID) | suffix length after `pscale_tkn_`; alphabet classes incl. `=` `.` `-` `_`; ID length and classes |
| 09 | optional since R10: one All key and one Read Only key (optionally one S3 `rps_` secret) | body length after `rpa_`; the length of the leading run with no lowercase; tail length and classes; any `_` |
| 08 | optional since R10: one inference key; note whether the Management API key uses `csk-` | body length after `csk-`; alphabet classes |
| 17 | one standard and one admin key | presence and offset of `.`; both segment lengths; alphabet classes incl. `_` |
| 06 | optional for `bb_live_`; still the gate for `bb_test_`: one `bb_live_` key, and whether a `bb_test_` key can be created | body length; alphabet classes incl. `_` and `-` |
| 33 | one project key and one read-only project key | the literal sub-prefix after `arc_`; body length; alphabet classes |

After a check matches, each contract would be:

- the T1 prefix;
- the observed exact length (or observed segment lengths);
- the observed alphabet class, widened to the documented or R2 class where
  one exists;
- the Tier A boundary.

Each lands as a new detector with one finding type. The R3 date rule
applies: "as of" is the issuance date.

## Not selected (negative findings retained)

| Item | Reason |
| --- | --- |
| #33 bare `arc_` | shared by at least 3 other issuers; personal keys are deprecated; no length. Generic context covers `ARCADE_API_KEY=` |
| #37 legacy W&B 40-hex | SHA-1 and git-SHA shaped. Generic context covers `WANDB_API_KEY=`. A #868-style keyword-gated row is possible later, but is not proposed |
| #01 legacy NGC 84-alphanumeric key | no prefix; its structure is tool-inferred Base64 of `id:UUID` |
| #13 `apify_ui_`, Actor Run and other Apify token types | prefix only, or no shape |
| #50 Inngest event key; self-hosted bare-hex signing key | no shape, or not attributable |
| #43 PlanetScale `pscale_pw_` and `pscale_oauth_` siblings | out of this candidate's scope. `pscale_pw_` also names non-secret password IDs. They stay research leads |

## Tier C: rulings R4–R7 applied

| # | Ruling | Effect | Disposition |
| ---: | --- | --- | --- |
| 14, 21, 22, 30, 45 | R7 | a JWT the provider documents only as "a JWT" gets no family; `jwt` redacts it high in every probed context | **generic coverage sufficient** (unchanged; now ruled) |
| 16 Upstash | R4 | truncated examples fix only a varying visible lead, not a literal prefix | unchanged: generic coverage sufficient (contextual) |
| 18 Stability | R4 | `sk-` becomes T1 (OpenAPI placeholder); still identical to legacy OpenAI `sk-` + 48 | unchanged: existing `sk-` handling |
| 24 Luma | R4 | `luma-` (Dream Machine) and `luma-api-` (Agents API) become T1 prefixes; no length or alphabet | **changed**: from "contextual only" to **pending-unsupported** (a prefixed lead that needs issuance). Not selected now: the `luma-api-key` identifier collides |
| 27 Speechmatics | R5 | one docs example gives 31 alphanumerics, unprefixed | unchanged: no anchor, generic coverage sufficient |
| 36 Braintrust | R2 | `sk-` + at least 40 alphanumerics is T1 (authorship above) | unchanged: no independent signal against legacy OpenAI. `bt-st-` stays an open lead |
| 41 MongoDB Atlas | R5 (style guides excluded) | the private-key UUID shape stays non-T1 | unchanged. New lead retained: the service-account secret `mdb_sa_sk_` (OpenAPI prefix, T1) could be researched as its own candidate |
| 46 Redis Cloud | R5 | CLI `--help` examples become T1 by example: account key `A` + 50 `[a-z0-9]`, secret key `S` + 50 | unchanged: a one-letter lead cannot anchor bare detection. A #868-style keyword-gated row is now possible, but is not proposed |
| 47 Algolia | R1 + R5 | a full grammar (32 lowercase hex) is now T1, but Admin and Search-only keys stay lexically identical | unchanged: no Admin family (step 2) |
| 13, 17, 33 | R6 | covered in the re-rank above | — |

## Out-of-scope observations (generic detectors)

Two gaps showed up in the probe. They are not #860 families. Each deserves
its own issue, and [fal-contextual-gap.md](fal-contextual-gap.md) proposes
options.

1. **Credential variables ending in a bare `_KEY` are invisible.**
   `FAL_KEY`, `CONVEX_DEPLOY_KEY` and `CONVEX_SELF_HOSTED_ADMIN_KEY` produce
   no finding even for a random value. A general `*_key` rule would claim
   sort, cache and primary keys. The proposed fix is exact names, using the
   #823 mechanism.
2. **`bearer-token` redacts only the left half of `id:secret` and
   `name|secret` values.** It stops at the first non-`b64token` byte and
   emits that prefix, so the secret half stays in clear. Seen with fal
   (36 of 69 bytes) and the Convex self-hosted admin key (18 of 93).

## Product and benchmark split

This is the same split as Tier A. Each READY family becomes:

- a product issue: detector, finding type, unit and integration tests,
  inventory row, spec row on landing, and conformance-corpus entries;
- a linked benchmarks issue: independent contract, synthetic positive, twin
  and benign corpus, profile coverage, and a qualification run.

Draft issue texts go to the step-5 batch; no issue is opened by this record.
No support status is claimed.

## Acceptance for this step

- [x] Each Tier B candidate is re-ranked, with what each applicable ruling
  establishes and its readiness class.
- [x] Every R2 authorship check is recorded (#06, #09, #13, #36).
- [x] Each READY Tier B family has a handoff in the Tier A format:
  1Password, Inngest, Resend, Apify, W&B, and Convex (hex body).
- [x] Each gated family names its single blocking property and a
  structure-only checklist.
- [x] R4–R7 are applied to Tier C, and the dispositions that change are
  recorded (Luma).
- [x] The #03 fal gap is recorded as a contextual-extension note.
- [x] A final disposition for all 50 candidates, consolidating Tier A:
  [disposition.md](disposition.md).
- [x] No credential value or real-derived material appears.
- [x] Issuance-gate research frozen and rulings R9–R10 applied (2026-09-28):
  NVIDIA, Browserbase `bb_live_`, Cerebras and RunPod have handoffs.

## Authority

This record freezes proposed handoffs for review only. It does not authorize
implementation, support-status promotion, a version change, a tag,
publication or release.
