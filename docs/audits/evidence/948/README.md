# Evidence: #948, the `generic-token` fallback under provider-named credential names

**Result:** a provider prefix (`OPENAI_`, `STRIPE_`, `GITHUB_`, `DD_`, every
entry of the rule-2 list) no longer disqualifies a high-signal credential
name. An off-grammar value under `OPENAI_API_KEY=` now gets the finding and
action it already got under `MYAPP_API_KEY=`, and an on-grammar value is
still exactly one typed provider finding. The decision is the amendment to
[`decision-redact-provider-named-credential-assignments`](../../../decisions/2026-09-24-redact-provider-named-credential-assignments.md#amendment-a-provider-named-high-signal-name-falls-back-to-generic-token-948).
Every measurement below compares `main` at `8f97f14d` with the change on
`beta11/948-provider-fallback`, on the same host.

Issue [#948](https://github.com/redact-secret/redact-secret/issues/948).

## What changed

`generic_token.rs` splits the prefix rule into two helpers. The high-signal
bucket (`has_prefixed_credential_name`) rejects only the non-secret leads
(`redacted_`, `masked_`, `publishable_`, ...). The ambiguous bucket
(`has_prefixed_name`) also rejects a provider prefix, as before. The
request-scoped `_token` exclusion now matches its suffix whatever the
prefix, so `GITHUB_CSRF_TOKEN` stays excluded. No other detector and no
resolver key changed. An on-grammar value keeps its provider type because
provider specificity outranks the contextual candidate in
`RankedCandidate::priority`, and a keyword-gated provider already reports a
provider-named assignment `high` (section 1 of the ADR).

The retention hint `has_open_contextual_assignment` and the ruleset
reserved-name check read the same classifier. A streamed session therefore
holds a provider-named line open the way it holds a generic one, and a
ruleset name such as `stripe_api_key` is now a reserved built-in name, so it
is a no-op.

## Canonical corpus (`conformance/fixtures/synchronous-corpus.json`)

46 fixtures change, and every input is unchanged. A `negative` fixture
becomes `overlap`, and a `boundary` fixture stays `boundary`. Every changed
fixture becomes `support: supported`, and its note records #948. Two new
Datadog boundary fixtures
(`datadog-api-key-boundary-{wrong-length,key-record-id}-keyword-context`)
put the same two values under a same-line `datadog` keyword and a
non-credential `key:` name. There the whole registry is still silent, so
`datadog_api_key` keeps its boundary and malformed evidence.

- **44 values that the provider's grammar declines, under that provider's own
  variable.** They now expect one `generic-token` `contextual_secret` finding
  (41 `high`/redact, 3 `medium`/warn).
  - Malformed twins (#375 context pairing, #370, #523, #524, #738, #740,
    #742): Hugging Face ×5, Cloudflare ×5, Linear ×4, Slack bot grammar ×2,
    Supabase ×3, Confluent checksum ×3, Docker ×2, Neon ×2, Travis CI ×2,
    Datadog wrong length, DigitalOcean length twin, Netlify, Fireworks
    `fpk_`, OpenAI `sk-admin-` one short, Heroku `HRKU` ×2 (`medium`).
  - Shapes an earlier contract narrowed away (#368, #371): the marker-less
    `openai-positive-{yaml,shell-quoted,yaml-crlf}` and the digitless
    `slack-positive-{yaml,shell-quoted,yaml-crlf}`.
  - Legacy unprefixed tokens that the provider detector leaves to
    `generic-token` by design: `atlassian-api-token-negative-legacy-unprefixed`
    and `sentry-user-auth-token-negative-legacy-unprefixed`.
  - **One benign value:** `datadog-api-key-boundary-key-record-id`
    (`DD_API_KEY=` and a 10-byte public key record id) now warns (`medium`).
    `MYAPP_API_KEY=` and the same value also warns. It is the one changed
    fixture whose value is not credential material.
- **2 overlaps** (`openai-negative-marker-dotenv`, `-toml`): the value used
  to be claimed by the bare vendor-prefixed layer (`vendor_prefixed_credential`,
  `medium`, redact). The name-anchored contextual match (`contextual_secret`,
  `high`, redact) now claims it. The span and the action do not change.

The `common` profile has no provider detectors, so its regenerated
expectations (`common-profile-expectations.json`) gain 244 findings: every
provider-named positive, overlap and twin is now redacted or warned by
`generic-token` instead of passing through.

## Resolver sweep (`tests/provider_named_fallback_948.rs`)

The sweep takes the 244 distinct single-line provider positives of the
canonical corpus and places each under
`<PREFIX>_API_KEY=` for all 61 rule-2 prefixes (14,884 inputs):

| Outcome | Inputs |
| --- | ---: |
| A `high` provider candidate: exactly one typed provider finding, no contextual duplicate | 13,398 |
| A `medium` keyword-gated candidate under another provider's name: the `high` contextual candidate wins on resolved action (redact over warn), as under `MYAPP_API_KEY` | 60 |
| No provider candidate (a keyword-gated grammar without its keyword): one `generic-token` finding | 1,426 |
| Under the provider's own prefix (subset of the above): always typed | 160 |

## Benchmark construction negatives

The benchmark corpus generators were run locally at
`redact-secret-benchmarks` `7af585a` and again at `develop` `7598bf1`, with
the same result (`fixtures/generated/build.mjs`, plus
the committed `accuracy`, `real-world-shapes`, `token-contexts` and
`shadow-scoring-authored` corpora; 4,992 fixtures). Each fixture was scanned
with the default registry before and after the change. This is not a
benchmarks workflow run. It is only an estimate of what the next run will
show.

- **203 fixtures with no authored secret span** now get a finding: 190
  redact and 14 warn, across 204 findings. By corpus: `context-edges` 42,
  `beta8-207` 35, `detector-coverage` 33, `beta8-259` 12, `beta8-208` 11,
  `beta8-263` 10, `beta8-211` 9, `beta8-212` 7, `beta8-213d` 7, `beta8-213f` 7,
  `credential-formats` 6, `sendgrid-regressions` 6, `negative-controls` 4
  (`short-github`, `short-gitlab`, `short-npm` warn; `short-slack` redacts),
  `token-contexts` 4 (`must-not-flag`), `beta8-209` 3, `beta8-210` 3,
  `beta8-379` 3, `beta8-384a` 1.
- **All 203 are the generic rule, not a new one.** The same 203 inputs with
  the provider prefix rewritten to `MYAPP_` produce the same actions, 203 of
  203.
- **The benign values among them** were placeholders, masks, public keys
  and public ids that the generic rule already reported under any name.
  [#993](https://github.com/redact-secret/redact-secret/issues/993), on the
  same branch, excludes them under every name
  ([evidence](../993/README.md)). After #993, 26 of the 203 are silent
  again, including the four `negative-controls` (`short-github`,
  `short-gitlab`, `short-npm`, `short-slack`).
- **177 remain after #993, all intended by #948.** Each is random or
  secret-shaped material under the provider's own credential variable: a
  malformed twin, a near miss, a truncated or glued value. 176 redact and 1
  warns (`mailgun-api-key-short-body`). By corpus: `context-edges` 42,
  `detector-coverage` 30, `beta8-207` 28, `beta8-208` 11, `beta8-259` 10,
  `beta8-263` 10, `beta8-212` 7, `beta8-213f` 7, `credential-formats` 6,
  `sendgrid-regressions` 6, `beta8-211` 6, `beta8-213d` 4, `token-contexts` 4
  (`must-not-flag`), `beta8-209` 3, `beta8-210` 2, `beta8-384a` 1. These
  benchmark labels need relabelling in `redact-secret-benchmarks`. The rescan
  found no false positive left among them.
- **The 3 collateral findings on positives are gone after #993.** The
  Confluent key id is no longer redacted beside its typed secret, so
  positives match `main` again.

## Performance

Measured with the #981 harness,
`cargo bench -p redact-secret --bench scan_cost -- --no-detectors --filter <w>`,
21 runs per figure. Host: Apple M4, macOS, load average 4 to 8.
Two before/after pairs were run in opposite order.

| Workload | Path | Before (ms) | After (ms) |
| --- | --- | ---: | ---: |
| `scale-logs-64k` | whole | 1.752 / 1.958 | 1.826 / 1.776 |
| `scale-logs-64k` | incremental-fixed65536 | 2.414 / 2.345 | 2.406 / 2.371 |
| `mixed-10m` | whole | 310.3 / 312.1 | 315.4 / 311.6 |
| `mixed-10m` | incremental-fixed65536 | 434.2 / 435.0 | 446.6 / 440.3 |

The differences are within run-to-run noise. The before figures alone differ
by 12% on `scale-logs-64k` whole. The change adds no work to a line without a
provider-prefixed credential name. The `mixed-10m` finding count stays at
10,239.
