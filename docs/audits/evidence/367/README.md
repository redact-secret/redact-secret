# Issue #367 — frozen precision contracts for seven provider families

[Audit archive](../../README.md) ·
[Decision record](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Issue #367](https://github.com/redact-secret/redact-secret/issues/367)

Reviewed 2026-09-17 against published `@redact-secret/core@0.1.0-beta.4`
(default detectors, measurement protocol v4). This directory is the evidence
the seven provider fixes (#368–#374), the shared context/streaming matrix
(#375) and the beta.5 precision gate (#376) build on. It changes no detector.

The reviewed contract text itself is a live input CI reads on every run, so
per `decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`
it lives outside this frozen archive, at
[`docs/contracts/precision/precision-contracts.json`](../../../contracts/precision/precision-contracts.json)
(moved by #596). The two files below stay here: they are derived, frozen
evidence the script below verifies for staleness, not a live contract a
detector or policy reads.

## Files

| File | Contents | Maintained by |
| --- | --- | --- |
| [`beta4-twin-baseline.json`](beta4-twin-baseline.json) | The 24 must-not-flag twins and their 24 paired positives from the beta.4 `common-formats` snapshot, frozen by construction recipe, content SHA-256, byte length, assessment, expected ranges and the ranges beta.4 actually produced. The corrected-contract view is derived separately under `contractView`. | `scripts/audit-precision-contracts.py --write` (derived fields) |
| [`corpus-audit.json`](corpus-audit.json) | Every fixture in this repository that names one of the seven detectors, evaluated against its frozen contract, with a disposition and the exact ranges retained or lost. Never contains inputs. | `scripts/audit-precision-contracts.py --write` |

`npm run precision-contracts:check` (part of `npm run ci`) runs the unit
tests and `--check`, which reconstructs every frozen fixture from its recipe
and fails if a hash, range, count or disposition no longer matches the
committed files. `python3 -B scripts/audit-precision-contracts.py
--print-fixture <id>` prints one frozen fixture's literal content locally;
the literals are deliberately not committed (they are realistic enough to
trip push protection) and the child issues carry them as self-contained
snapshots.

## Measurement provenance

| Item | Value |
| --- | --- |
| Package | `@redact-secret/core@0.1.0-beta.4`, default detectors |
| Protocol | measurement protocol v4 |
| Benchmark run cited by the issues | `2026-09-17T21:26:02.204Z-3390af` (local; not persisted as a baseline in the benchmark repository, whose persisted beta.4 baseline is `2026-09-17T18:58:05.028Z-fe936e` over the same corpus hash) |
| `common-formats` corpus SHA-256 | `19ca47f5dbf21acc94c6712a51d6586c9fd1653b3da132172622c0e7c4b08fb8` |
| Benchmark revision | `2f3d1c051e3a9f4c776835c939cd0b3c5d560533` **with uncommitted modifications** |
| Scanners | redact-secret 0.1.0-beta.4, gitleaks 8.30.1, trufflehog 3.97.4 |
| Corpus totals | must-not-flag T1 0/6, T2 24/114, T3 0/104 flagged; must-redact T1 0/135 and T2 0/60 leaked spans; `common-formats` alone T2 24/50 |
| Live verification | none; every value is synthetic and never provider-issued |

Tiers are never aggregated into a product accuracy score. The revision alone
is not claimed to reproduce the run.

## Source ledger

Provider documentation comes first; tool sources corroborate and never prove
issuance or liveness. Full detail, including what each source does *not*
establish, is in `precision-contracts.json#sources`.

| Source | Kind | Revision / date | Establishes |
| --- | --- | --- | --- |
| docs.slack.dev/authentication/tokens | provider | no page date; read 2026-09-17 | `xoxb-`/`xoxp-`/`xwfp-`/`xapp-` prefixes; sections separated by `-`, final section is the secret; user secrets 32 characters (6/10 pre-2016, rotatable) |
| docs.slack.dev/authentication/using-token-rotation | provider | no page date; read 2026-09-17 | `xoxe.xoxb-1-…`, `xoxe.xoxp-1-1234-…` access and `xoxe-1-…` refresh prefixes (bodies elided) |
| docs.digitalocean.com/release-notes/api | provider | entry 2022-03-29 | `dop_v1_`, `doo_v1_`, `dor_v1_` prefixes |
| docs.digitalocean.com/reference/api/oauth | provider | last updated 2026-09-03 | example `doo_v1_`/`dor_v1_` values with 64-character bodies; the bodies contain placeholder text, so length only |
| developers.cloudflare.com …/token-formats | provider | last updated 2026-04-20 | `cfut_`/`cfat_`/`cfk_` + 40 characters + checksum; pre-2026 unprefixed shapes |
| developers.cloudflare.com …/create-token, …/account-owned-tokens | provider | 2026-04-20, 2026-09-02 | `cfut_` and `cfat_` scannable prefixes |
| huggingface.co/docs/hub/security-tokens | provider | no page date | `hf_…` placeholder only; no grammar |
| linear.app/developers/graphql, …/oauth-2-0-authentication, linear.app/docs/api-and-webhooks | provider | no page dates; OAuth page notes the 2026-04-01 refresh-token migration | header usage only; OAuth example is a bare 64-hex token with no `lin_oauth_` prefix |
| docs.docker.com/security/access-tokens, …/for-admins/access-tokens | provider | no page dates | PAT and OAT exist; no grammar |
| help.openai.com article 4936850, platform.openai.com api-reference/authentication | provider | HTTP 403 to automated fetch on 2026-09-17 | nothing reviewable |
| gitleaks `config/gitleaks.toml` | tool | v8.30.1 = `83d9cd68…` | rule patterns quoted per family in the contracts file |
| trufflehog `pkg/detectors/*` | tool | v3.97.4 = `363923b9…` | detector patterns quoted per family in the contracts file |
| GitHub supported secret-scanning patterns | corroboration | read 2026-09-17 | which token types each provider registers; no grammar |
| redact-secret-benchmarks `fixtures/generated/common-formats.mjs` | corroboration | `2f3d1c0` dirty | the synthetic construction of every frozen fixture |

## The twelve beta.4 mutations

All twelve are retained as must-not-flag under the frozen contracts, and
each paired positive still matches at exactly its expected bytes
(`beta4-twin-baseline.json#counts`: 24 twins, 12 unique mutations, 24 flagged
by beta.4, 0 flagged by the contract, 24 positives preserved). No
classification was corrected. "Basis" says what the distinguishing property
rests on; where it is a support-policy adoption of a single tool's width,
the twin is still a valid negative under the frozen contract, but the
contract records that a provider-issued value of that width would be an
intentionally unsupported form rather than proof of invalidity.

| # | Family | Variant | Mutation | Distinguishing property | Basis |
| --- | --- | --- | --- | --- | --- |
| 1 | openai-token | legacy | marker `T3BlbkFK` vs `T3BlbkFJ` | marker literal | tool agreement |
| 2 | openai-token | proj | 73-byte left segment vs 74 | width in {58, 74} | single tool, adopted as policy |
| 3 | openai-token | svcacct | 73-byte left segment vs 74 | width in {58, 74} | single tool, adopted as policy |
| 4 | digitalocean-token | dop | 63 vs 64 | exact 64 | provider examples + tool agreement |
| 5 | digitalocean-token | doo | 63 vs 64 | exact 64 | provider examples + tool agreement |
| 6 | digitalocean-token | dor | 63 vs 64 | exact 64 | provider examples + tool agreement |
| 7 | docker-token | pat | 26 vs 27 | exact 27 | single tool, adopted as policy |
| 8 | docker-token | oat | 31 vs 32 | exact 32 | single tool, adopted as policy |
| 9 | slack-token | bot | missing `-` before the secret section | provider-documented section structure | provider |
| 10 | huggingface-token | user | 33 vs 34 | exact 34 | tool agreement |
| 11 | cloudflare-token | user | non-hex eight-byte suffix | checksum segment exists (provider); 8 lowercase-hex bytes (single tool) | provider + single tool |
| 12 | linear-token | api | 39 vs 40 | exact 40 | tool agreement |

Each mutation is frozen in two contexts (plain, and Unicode heading with
CRLF), giving the 24 twins.

## Existing fixtures under the contracts

`corpus-audit.json` evaluates the conformance synchronous and incremental
corpora, the assessment accuracy corpus and the coverage inventory's
`reconciliationTrigger` values. Dispositions per detector (rows, not files;
a fixture that names two detectors appears twice):

| Detector | retained | broad-shape | silent | review |
| --- | --- | --- | --- | --- |
| openai-token | 0 | 19 | 10 | 0 |
| digitalocean-token | 0 | 17 | 12 | 0 |
| docker-token | 7 | 10 | 12 | 0 |
| slack-token | 1 | 18 | 11 | 0 |
| huggingface-token | 0 | 18 | 11 | 0 |
| cloudflare-token | 0 | 16 | 13 | 0 |
| linear-token | 1 | 18 | 11 | 0 |

- **retained**: the expectation matches the contract at the same bytes. The
  Docker rows survive because their synthetic body happens to be exactly 27
  bytes; the Slack and Linear rows are the `*-positive-all-prefixes`
  fixtures covered by the interim guards.
- **broad-shape**: an existing positive whose synthetic value has the
  supported prefix but not the contracted shape (no marker, wrong width,
  `_` in an alphanumeric body, non-hex body, no section grammar). These are
  the "broad-shape positives" the issue asks to audit before narrowing. Each
  child fix re-authors the value to its contract and keeps the superseded
  input as an intentionally-unsupported boundary fixture; nothing is
  deleted. The `overlap` rows (`*-overlap-context`,
  `contextual-overlap-provider`) and the accuracy-corpus rows carry a
  `policyOutcome` and must be re-authored with the outcome that follows
  once the provider finding is gone (a `generic-token` contextual finding
  may take its place); they are policy-context cases, not evidence for
  global suppression.
- **silent**: negatives and boundary fixtures that stay silent.
- **review** (none): a contract match the fixture does not expect.

The benchmark's own T3 policy and T0 pending samples for these families
(`detector-coverage` corpus, not stored here) were audited from the same
contracts:

| Benchmark fixtures | Tier | Under the contract |
| --- | --- | --- |
| `openai-token-shape-1..3-*` (48-byte random bodies, no marker) | policy/T3 | provider finding removed; intended policy change, reported by #376, cases kept |
| `slack-token-shape-1-*` (`xoxb-` random body) | policy/T3 | provider finding removed; intended policy change |
| `slack-token-shape-2,3,5,6,7-*` (`xoxp-`, `xapp-`, `xoxe-`, `xoxe.xoxb-`, `xoxe.xoxp-`) | policy/T3 | still flagged by the interim guards; unchanged |
| `slack-token-shape-4-*` (`xwfp-`) | pending/T0 | still flagged by the interim guard; stays unscored |
| `huggingface-token-shape-1-*` (34-byte body with digits) | pending/T0 | accepted by the union alphabet as policy; stays unscored |
| `docker-token-shape-1-*` (`dckr_pat_` + 32 bytes) | policy/T3 | provider finding removed (PAT is 27); intended policy change |
| `docker-token-shape-2-*` (`dckr_oat_` + 32 bytes) | must-redact/T2 | retained |
| `cloudflare-token-shape-1-*` (`cfut_` + 40 bytes, no checksum) | policy/T3 | provider finding removed; intended policy change |
| `digitalocean-token-shape-1..3-*` (64 hex) | must-redact/T1 | retained |
| `linear-token-shape-1-*` (`lin_api_` + 40) | must-redact/T2 | retained |
| `linear-token-shape-2-*` (`lin_oauth_` + 40) | pending/T0 | still flagged by the interim guard; stays unscored |
| `*-prefix-only`, `*-short-body`, `negative-controls/prefix-only`, `negative-controls/short-slack` | must-not-flag/T2 | silent |
| `credential-formats/slack-1..3` (`SLACK_TOKEN=xoxb-<12>-<12>-<24>`) | must-redact/T1 | retained under the bot grammar |

## What this evidence does not claim

It does not verify any credential against a provider, does not claim that a
contract describes every shape a provider issues, does not compute
Cloudflare's checksum, and does not rank scanners. Tier T1 means a
provider-documented lexical shape, not issuance. The twin baseline is a
local synthetic draft corpus whose review status is "draft — independent
human review required" in the benchmark repository.
