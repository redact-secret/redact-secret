---
decision_id: decision-freeze-precision-contracts-seven-provider-families
status: accepted
scope: workspace
title: Freeze reviewed precision contracts for seven provider families and refine their default rules in place
decided_at: 2026-09-17
spec: detector-families
aliases: decision-freeze-microsoft-entra-client-secret-grammar, decision-freeze-azure-devops-pat-grammar, decision-freeze-atlassian-api-token-grammar, decision-freeze-notion-integration-token-grammar, decision-freeze-discord-bot-token-grammar, decision-freeze-telegram-bot-api-token-grammar, decision-freeze-twilio-auth-token-api-key-secret-grammar, decision-freeze-datadog-api-application-key-grammar, decision-freeze-grafana-service-account-and-cloud-access-policy-token-grammar, decision-freeze-sentry-user-and-organization-auth-token-grammar, decision-freeze-new-relic-user-api-key-license-key-grammar, decision-freeze-openai-api-key-grammar, decision-freeze-docker-pat-oat-exact-length-grammar, decision-freeze-slack-bot-token-segment-grammar, decision-scope-supabase-legacy-anon-jwt-exclusion, decision-adopt-cloudflare-account-token-prefix, decision-adopt-huggingface-organization-token-prefix, decision-freeze-slack-user-and-rotation-token-grammar, decision-scope-supabase-management-token-and-secret-key-independence, decision-inventory-gitlab-token-families, decision-add-firebase-server-key-detection-and-client-config-discrimination, decision-add-terraform-cloud-enterprise-token-detection, decision-freeze-pulumi-access-token-grammar, decision-accept-truncated-and-nested-shapes-under-bearer-token-length-grammar
---

# Freeze reviewed precision contracts for seven provider families and refine their default rules in place

This record is the representative ADR for the detector-families
grammar-freeze cluster (issue [#598](https://github.com/redact-secret/redact-secret/issues/598),
DS6b, under epic [#591](https://github.com/redact-secret/redact-secret/issues/591)): the
one recorded policy that every per-family grammar freeze, prefix adoption, or
family-scope decision applies. [Folded records](#folded-records) lists the 24
decisions merged into this one under
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)'s
Merge grade; each one's `decision_id` is preserved in this record's
`aliases:` field above, and its full original text stays reachable at its
permalink. The current, present-tense grammar for every family --
including the seven this ADR originally froze -- lives in
[`docs/specs/detector-families.md`](../specs/detector-families.md), not
here; this record and the ones it folds explain why and when each family's
contract was decided.

## Decision

For issue #367, freeze one reviewed lexical contract per supported variant of
the `openai-token`, `digitalocean-token`, `docker-token`, `slack-token`,
`huggingface-token`, `cloudflare-token` and `linear-token` detectors, and
select **default-rule precision** as the approach: each detector's existing
default rule is refined in place until it enforces its contract. There is no
strict mode, no new public option, no new detector id, no new finding type and
no result-interface change. The contracts, their sources and the audit of
every existing fixture are recorded under `docs/audits/evidence/367/` and kept
consistent by `scripts/audit-precision-contracts.py` (`npm run
precision-contracts:check`, part of `npm run ci`).

The frozen contracts, with the reviewed source ordering "provider
documentation first, tool sources corroborate":

| Detector | Variant | Contract | Tier | What rests on support policy |
| --- | --- | --- | --- | --- |
| `openai-token` | legacy | `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}` | T2 | the 20/20 segment widths (gitleaks states them; trufflehog states none) |
| `openai-token` | proj, svcacct | `sk-proj-` / `sk-svcacct-` then `[A-Za-z0-9_-]{74|58}`, `T3BlbkFJ`, `[A-Za-z0-9_-]{74|58}` | T2 | the {58, 74} segment widths (single tool) |
| `digitalocean-token` | dop, doo, dor | `<prefix>_v1_[0-9a-f]{64}` | T1 (prefix), 64 corroborated by provider examples | the lowercase-hex alphabet (tools; provider examples are placeholders) |
| `docker-token` | pat | `dckr_pat_[A-Za-z0-9_-]{27}` | T2 | the exact width (single tool) |
| `docker-token` | oat | `dckr_oat_[A-Za-z0-9_-]{32}` | T2 | the exact width (single tool) |
| `slack-token` | bot | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{18,}` | T1 (structure) | numeric widths (tools) and the 18-byte secret floor |
| `slack-token` | user, app-level, workflow, refresh, rotating bot/user | beta.4 rule retained unchanged (`<prefix>` + `[A-Za-z0-9_-]{20,}`) as a separate interim guard per prefix | T3 / T0 | the whole interim rule; candidate grammars and evidence are recorded but not adopted |
| `huggingface-token` | user | `hf_[A-Za-z0-9]{34}` | T2 | the alphabet union (tools disagree: letters-only vs alphanumeric) |
| `cloudflare-token` | user | `cfut_[A-Za-z0-9]{40}[0-9a-f]{8}` | T1 (prefix, 40-byte body, checksum exists) | the 8-byte lowercase-hex checksum shape (single tool); lexical only |
| `linear-token` | api | `lin_api_[A-Za-z0-9]{40}` | T2 | none beyond tool agreement |
| `linear-token` | oauth | beta.4 rule retained unchanged as a separate interim guard | T0 | the whole interim rule; no source shows a `lin_oauth_` grammar |

Every contract keeps beta.4's boundary rule: no `[A-Za-z0-9_-]` byte
immediately before or after the match. Exact widths therefore reject a longer
run of the same alphabet rather than truncating it.

Forms recorded as pending (T0) and deliberately not added by this decision:
OpenAI `sk-admin-` and `sk-service-`; DigitalOcean system tokens and any
`_v2_` namespace; Slack legacy `xoxa`/`xoxr`/`xoxs`/`xoxo`; Hugging Face
`api_org_` and digit-bearing bodies as scored evidence; Cloudflare `cfat_` and
`cfk_` (provider-documented, so a coverage issue of their own); Linear's bare
64-hex OAuth access token. `docs/audits/evidence/367/precision-contracts.json`
records each with its reason.

Source conflicts were resolved explicitly, never by converting a disagreement
into an exact length by guesswork:

- **OpenAI segment widths** (gitleaks enumerates 74|58 and 20/20; trufflehog
  bounds nothing): the marker `T3BlbkFJ`, on which both tools agree, is the
  evidence-backed part of the rule. The enumerated widths are adopted as an
  explicit support-policy choice because they are the only stated widths and
  the measured twins differ only in width. A provider-issued key of another
  width is a recorded intentionally-unsupported form, to be revisited if
  provider documentation appears.
- **Hugging Face alphabet** (gitleaks letters-only, trufflehog alphanumeric,
  provider silent): the default rule accepts the union to avoid a false
  negative if the letters-only source is the incomplete one; scored evidence
  stays on letters-only positives and the benchmark's digit-body samples stay
  pending. The exclusion of `_` and `-`, on which both tools agree, is
  evidence-backed.
- **Slack bot separator** (provider: sections are `-`-separated and the final
  section is the secret; both tools accept a tail with no separator): provider
  documentation wins. This is why all three baseline scanners flag the twin and
  why competitor agreement is not the negative oracle.
- **DigitalOcean alphabet** (provider examples contain placeholder text; tools
  say lowercase hex; one gitleaks rule is case-insensitive): the examples
  establish length only; the alphabet is tool-corroborated; the single
  case-insensitive rule is a tool artifact and is not adopted.
- **Cloudflare checksum** (provider: a checksum follows the 40-byte body;
  width and alphabet unstated; one tool: 8 lowercase-hex bytes): the existence
  of the segment is provider evidence, so a bare 40-byte body is malformed;
  the width and alphabet are a support-policy adoption of one tool's shape,
  validated lexically only. No checksum algorithm is computed or claimed.
- **Docker widths** (one tool; gitleaks has no rule; provider publishes no
  grammar): adopted as support policy with the single-source caveat recorded.

No classification correction was needed: every one of the 24 frozen twins is
silent under its contract for the property its construction mutated, and
every paired positive matches at exactly its expected bytes. The baseline
view (`assessment`, `expected`, `actualBeta4`) and the corrected-contract
view (`contractView`) are stored separately so that a future reclassification
can never be presented as a detection gain.

## Rationale

The beta.4 rules for all seven families are "documented prefix plus a
20-byte minimum of `[A-Za-z0-9_-]`", inherited from one shared
`KnownFormatProviderDetector` shape (`crates/secret-scan-core/src/detectors/additional_providers.rs`)
and the equivalent `openai.rs` branch. That shape cannot express a marker, an
exact width, a per-segment alphabet or a segment separator, so it flags every
near-miss twin in the beta.4 `common-formats` snapshot: 24 of 50
must-not-flag/T2 files, which are all 24 must-not-flag/T2 flags across the
whole corpus (run `2026-09-17T21:26:02.204Z-3390af`, corpus SHA-256
`19ca47f5…`, published `@redact-secret/core@0.1.0-beta.4`). Issues #317, #320
and #321 expanded the test surface but explicitly left the discriminating
boundaries unfinished; they did not review the formats themselves.

Refining the default rules is preferred to a strict mode because a strict
mode would leave the default rule broad, split the corpus into two truths and
add public surface for a defect the default rule causes. Reclassifying the
twins is rejected because it hides false alarms instead of removing them.

Contracts are frozen before any detector changes so that the seven fixes
(#368–#374) implement one reviewed target, the shared context/streaming matrix
(#375) can be designed against it, and the beta.5 gate (#376) can compare a
frozen baseline against a candidate rather than against moving expectations.
Provider documentation is ranked above tool sources because a tool rule
records what one scanner chose to accept, not what a provider issues; the
consulted tool revisions (gitleaks `v8.30.1`, trufflehog `v3.97.4`) are
pinned by tag and commit, consulted only as behavioral references per
`AGENTS.md`, and no code from either is reproduced.

## Consequences

- `docs/audits/evidence/367/` holds `precision-contracts.json` (the
  contracts, sources with URL/revision/observation date and what each
  establishes, conflicts, pending and excluded forms, and the audit of the
  twelve beta.4 mutations), `beta4-twin-baseline.json` (the 24 twins and 24
  paired positives frozen by construction recipe, content SHA-256, byte
  length, assessment, expected and beta.4-actual ranges, with the contract
  view derived separately) and `corpus-audit.json` (every existing fixture
  for the seven detectors and its disposition). The literal credential-shaped
  strings are reconstructed from the recipe on demand and are not committed,
  so the repository carries no push-protected lookalikes; the child issues
  keep the same 48 fixtures as literal snapshots.
- `scripts/audit-precision-contracts.py --check` fails CI when the derived
  evidence is stale. The contract grammars are review oracles, not a second
  detector implementation; the Rust core stays authoritative.
- Public interfaces are unchanged. The behavioral compatibility change the
  contracts require, to be delivered by #368–#374, is that a value carrying
  a supported prefix but not the contracted shape stops producing a provider
  finding. Concretely, under the contract, 116 existing expectations across
  the conformance, incremental, accuracy and coverage-inventory fixtures for
  these families no longer match (`corpus-audit.json`, disposition
  `broad-shape`), 9 match unchanged and 80 negatives stay silent. Each child
  fix must re-author its positives to the contract and keep every superseded
  input as an intentionally-unsupported boundary fixture; nothing is deleted,
  no namespace is allowlisted and no ground truth is changed to fit output.
  The `reconciliationTrigger` values for the seven finding types in
  `docs/coverage/detector-inventory.json` are among the values to re-author.
- A malformed provider shape under `api_key=`, `Bearer` or another
  credential context can still be classified by `generic-token` or
  `bearer-token`; the contracts remove the provider finding, not the policy
  outcome, and the overlap fixtures listed in the audit must be re-authored
  with the outcome that follows rather than globally suppressed.
- In the benchmark, the policy/T3 samples that keep a random body after a
  supported prefix (`openai-token-shape-1..3`, `slack-token-shape-1`,
  `docker-token-shape-1`, `cloudflare-token-shape-1`) will lose their
  provider finding; that is the intended behavior change, to be reported
  by #376 as a policy change and never hidden by deleting the cases. The
  interim Slack and Linear guards keep `slack-token-shape-2..7` and
  `linear-token-shape-2` flagged; `huggingface-token-shape-1` and
  `slack-token-shape-4` stay pending and unscored.
- Known false negatives under the contracts, all recorded as pending rather
  than silently dropped: OpenAI `sk-admin-`/`sk-service-` (which beta.4
  matched through its bare branch), Cloudflare `cfat_`/`cfk_`, Hugging Face
  `api_org_`, and any provider-issued value whose width or alphabet differs
  from the single-tool properties listed in the table above.

## Folded records

Each row is a decision merged into this one (Merge grade). The `decision_id`
column is preserved verbatim in this record's `aliases:` frontmatter field so
an old reference still resolves; the permalink is the folded record's last
text on `main` before this merge, at
`54c9ab35cb693e0cd3aedc8f858ca19ab77e4363`.

| Original `decision_id` | Date | Issue | Decision | Full record |
| --- | --- | --- | --- | --- |
| `decision-freeze-microsoft-entra-client-secret-grammar` | 2026-09-16 | [#297](https://github.com/redact-secret/redact-secret/issues/297) | Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-microsoft-entra-client-secret-grammar.md) |
| `decision-freeze-azure-devops-pat-grammar` | 2026-09-16 | [#298](https://github.com/redact-secret/redact-secret/issues/298) | Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-azure-devops-pat-grammar.md) |
| `decision-freeze-atlassian-api-token-grammar` | 2026-09-16 | [#299](https://github.com/redact-secret/redact-secret/issues/299) | Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-atlassian-api-token-grammar.md) |
| `decision-freeze-notion-integration-token-grammar` | 2026-09-16 | [#300](https://github.com/redact-secret/redact-secret/issues/300) | Freeze the Notion integration token grammar as two exact-length prefixed shapes. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-notion-integration-token-grammar.md) |
| `decision-freeze-discord-bot-token-grammar` | 2026-09-16 | [#301](https://github.com/redact-secret/redact-secret/issues/301) | Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-discord-bot-token-grammar.md) |
| `decision-freeze-telegram-bot-api-token-grammar` | 2026-09-16 | [#302](https://github.com/redact-secret/redact-secret/issues/302) | Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-telegram-bot-api-token-grammar.md) |
| `decision-freeze-twilio-auth-token-api-key-secret-grammar` | 2026-09-16 | [#303](https://github.com/redact-secret/redact-secret/issues/303) | Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-twilio-auth-token-api-key-secret-grammar.md) |
| `decision-freeze-datadog-api-application-key-grammar` | 2026-09-16 | [#304](https://github.com/redact-secret/redact-secret/issues/304) | Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-datadog-api-application-key-grammar.md) |
| `decision-freeze-grafana-service-account-and-cloud-access-policy-token-grammar` | 2026-09-16 | [#305](https://github.com/redact-secret/redact-secret/issues/305) | Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-grafana-service-account-and-cloud-access-policy-token-grammar.md) |
| `decision-freeze-sentry-user-and-organization-auth-token-grammar` | 2026-09-16 | [#306](https://github.com/redact-secret/redact-secret/issues/306) | Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-sentry-user-and-organization-auth-token-grammar.md) |
| `decision-freeze-new-relic-user-api-key-license-key-grammar` | 2026-09-16 | [#307](https://github.com/redact-secret/redact-secret/issues/307) | Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-16-freeze-new-relic-user-api-key-license-key-grammar.md) |
| `decision-freeze-openai-api-key-grammar` | 2026-09-17 | [#368](https://github.com/redact-secret/redact-secret/issues/368) | Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-17-freeze-openai-api-key-grammar.md) |
| `decision-freeze-docker-pat-oat-exact-length-grammar` | 2026-09-17 | [#370](https://github.com/redact-secret/redact-secret/issues/370) | Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-17-freeze-docker-pat-oat-exact-length-grammar.md) |
| `decision-freeze-slack-bot-token-segment-grammar` | 2026-09-17 | [#371](https://github.com/redact-secret/redact-secret/issues/371) | Freeze the Slack bot token grammar as a three-section dash-separated shape. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-17-freeze-slack-bot-token-segment-grammar.md) |
| `decision-scope-supabase-legacy-anon-jwt-exclusion` | 2026-09-20 | [#472](https://github.com/redact-secret/redact-secret/issues/472) | Scope a payload-trusting exclusion for the legacy Supabase anon JWT to iss+role together. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-scope-supabase-legacy-anon-jwt-exclusion.md) |
| `decision-adopt-cloudflare-account-token-prefix` | 2026-09-20 | [#481](https://github.com/redact-secret/redact-secret/issues/481) | Adopt the Cloudflare account-token prefix under the frozen cfut_ contract. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-adopt-cloudflare-account-token-prefix.md) |
| `decision-adopt-huggingface-organization-token-prefix` | 2026-09-20 | [#485](https://github.com/redact-secret/redact-secret/issues/485) | Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-adopt-huggingface-organization-token-prefix.md) |
| `decision-freeze-slack-user-and-rotation-token-grammar` | 2026-09-20 | [#512](https://github.com/redact-secret/redact-secret/issues/512) | Complete the Slack credential family by freezing the user-token grammar and the rotation family's version section. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-freeze-slack-user-and-rotation-token-grammar.md) |
| `decision-scope-supabase-management-token-and-secret-key-independence` | 2026-09-20 | [#515](https://github.com/redact-secret/redact-secret/issues/515) | Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-scope-supabase-management-token-and-secret-key-independence.md) |
| `decision-inventory-gitlab-token-families` | 2026-09-20 | [#518](https://github.com/redact-secret/redact-secret/issues/518) | Inventory the GitLab token-prefix table and contract the two undeclared prefixes. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-inventory-gitlab-token-families.md) |
| `decision-add-firebase-server-key-detection-and-client-config-discrimination` | 2026-09-20 | [#520](https://github.com/redact-secret/redact-secret/issues/520) | Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-20-add-firebase-server-key-detection-and-client-config-discrimination.md) |
| `decision-add-terraform-cloud-enterprise-token-detection` | 2026-09-21 | [#521](https://github.com/redact-secret/redact-secret/issues/521) | Add Terraform Cloud/Enterprise API token detection. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-21-add-terraform-cloud-enterprise-token-detection.md) |
| `decision-freeze-pulumi-access-token-grammar` | 2026-09-21 | [#522](https://github.com/redact-secret/redact-secret/issues/522) | Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-21-freeze-pulumi-access-token-grammar.md) |
| `decision-accept-truncated-and-nested-shapes-under-bearer-token-length-grammar` | 2026-09-21 | [#553](https://github.com/redact-secret/redact-secret/issues/553) | Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar. | [full record](https://github.com/redact-secret/redact-secret/blob/54c9ab35cb693e0cd3aedc8f858ca19ab77e4363/docs/decisions/2026-09-21-accept-truncated-and-nested-shapes-under-bearer-token-length-grammar.md) |
