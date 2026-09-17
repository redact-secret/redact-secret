---
decision_id: decision-freeze-precision-contracts-seven-provider-families
status: accepted
scope: workspace
title: Freeze reviewed precision contracts for seven provider families and refine their default rules in place
decided_at: 2026-09-17
---

# Freeze reviewed precision contracts for seven provider families and refine their default rules in place

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
