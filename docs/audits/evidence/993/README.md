# Evidence: #993, non-secret value shapes that `generic-token` reported under credential names

**Result:** placeholders, masked and elided key displays, Make-escaped
substitutions, documented public keys and the Confluent public key id are
now silent under every contextual name. Before this change they were
reported under generic names such as `MYAPP_API_KEY` too; #948 made them
reachable under provider names as well. On the benchmark construction
negatives, this change silences 26 of the 203 fixtures that #948 had newly
flagged, and one negative `main` already flagged
(`trigger-dev-token-public-key-prefix-twin`). No benchmark positive and no
canonical fixture expectation changes.

Issue [#993](https://github.com/redact-secret/redact-secret/issues/993).
The rule is the #993 row of
[`contextual-detection.md`](../../../specs/contextual-detection.md).
Measured on `beta11/948-provider-fallback` against `main` at `8f97f14d`.

## Rules

All of these rules live in `crates/secret-scan-core/src/detectors/generic_token.rs`
(`is_non_secret_reference`, `is_vendor_prefixed_placeholder`,
`is_prefixed_filler`) and `detectors/text.rs` (the placeholder vocabulary).

| Shape | Silent | Stays reported |
| --- | --- | --- |
| Placeholder vocabulary: rule-2 provider segments as provider words; `account`, `admin`, `bot`, `deploy`, `integration`, `internal`, `org`, `project`, `signing`, `webhook` as qualifiers | `your-bot-token-here`, `YOUR_MAILGUN_API_KEY`, `whsec_YOUR_SIGNING_SECRET`, `ntn_yourinternalintegrationtokenhere` | `YOUR_ACMECLOUD_API_KEY`, `your-bot-token-<random>`, `…tokenherex` |
| `<...>` behind an uppercase vendor prefix | `PMAK-<your-api-key>` | `PMAK-<your-api-key><random>`, `KEY_YOUR_API_KEY` |
| Counting-run body, 6–12 bytes, behind a vendor prefix | `ghp_abc123`, `glpat-abc123`, `xoxb-123-456-abc` | `ghp_abd123`, `ghp_abc124`, `re_123`, `key-abcdefghijklmnopqrstuvwxyz012345` |
| Masked key display (≥16 mask characters, head ≤12, label ≤4) | `********-****-****-****-************`, `00••••…`, `3518930973:AA****…`, `ATATT3xFfGF0****…=********`, `********…-us6` | `********x`, `x********`, a 20-byte head, material between mask runs, a mixed mask, a 12-byte tail |
| Filler with a region label | `xxxx…-usX` | — |
| Elided display (head ≤12, then only `...`/`…`) | `ATATT3xFfGF0...`, `sntrys_eyJ...` | a 24-byte head, material after the ellipsis |
| Make-escaped reference | `$$(heroku auth:token)`, `$${VAR}`, `$$VAR` | `$(` + material without its `)` (unchanged) |
| Documented public key | `pk_live_`, `pk_test_`, `sb_publishable_`, `pk-lf-`, `phc_`, `pk_<env>_` + body | `sk-lf-…`, `xpk_live_…`, `pk_livex…` |
| Confluent API key id, Confluent-named key only | `CONFLUENT_CLOUD_API_KEY=ABCD1234567890AB` | the same id under `KAFKA_API_KEY`, 18 bytes, mixed case |

Tests: `tests/non_secret_values_993.rs` checks both sides of every row,
under generic and provider names, plus whole-input and incremental parity.
It also checks that a Confluent key/secret pair redacts only the secret. The
existing #264, #756 and #949 near-miss tests still pass unchanged, except
one example: the one-word-off provider is now `YOUR_ACMECLOUD_API_KEY`,
because `mailchimp` is a rule-2 provider word. Nine canonical fixtures were
added, eight negatives and one glued-material positive twin.

## Benchmark rescan

The benchmark corpora were regenerated locally from `redact-secret-benchmarks`
`develop` `7598bf1` (`fixtures/generated/build.mjs` plus the four committed
corpora, 4,992 fixtures) and scanned with the default registry. This was not
a benchmarks workflow run.

- **The 26 silenced negatives:** `short-github`, `short-gitlab`, `short-npm`,
  `short-slack`, `confluent-cloud-api-secret-public-id`,
  `confluent-cloud-api-secret-legacy-api-key-id-public-id`,
  `heroku-api-key-legacy-mask`, `mailchimp-api-key-mask`,
  `mailchimp-api-key-usx-template-placeholder`,
  `atlassian-api-token-masked-placeholder`,
  `atlassian-api-token-docs-ellipsis-placeholder`,
  `sentry-org-auth-token-docs-ellipsis-placeholder`,
  `telegram-bot-token-masked-placeholder`,
  `okta-api-token-masked-console-placeholder`,
  `postman-api-key-masked-settings-placeholder`,
  `postman-api-key-docs-template-placeholder`,
  `discord-bot-token-your-token-here-placeholder`,
  `stripe-webhook-signing-secret-fill-in-placeholder`,
  `notion-integration-token-words-placeholder-placeholder`,
  `travisci-api-token-env-example-placeholder`,
  `mailgun-api-key-triplet-your-key-placeholder`,
  `heroku-api-key-legacy-makefile-auth-token-reference`,
  `supabase-token-publishable-prefix-twin`, `stripe-token-publishable-prefix-twin`,
  `stripe-webhook-signing-secret-dotenv-webhook-secret-public-prefix-twin`,
  `langfuse-secret-key-public-key-twin`.
- **The 177 still flagged** are random or secret-shaped values under a
  provider credential variable, which is the #948 behaviour (see
  [`../948/README.md`](../948/README.md)). No false positive is left among
  them.
- **Positives:** none changes against `main`. The three collateral findings
  #948 added on Confluent key ids are gone.

## Performance

The #981 harness (`--no-detectors`, 21 runs, Apple M4, load average 6 to 7)
ran three interleaved rounds, alternating `main` `8f97f14d` and the final
branch code (#948 and #993). Medians in ms, in round order:

| Workload | Path | `main` | Branch |
| --- | --- | --- | --- |
| `scale-logs-64k` | whole | 1.82 / 1.79 / 2.15 | 1.80 / 2.30 / 1.88 |
| `scale-logs-64k` | incremental-fixed65536 | 2.56 / 2.41 / 2.77 | 2.63 / 3.08 / 2.55 |
| `mixed-10m` | whole | 370.9 / 355.8 / 359.8 | 357.6 / 346.4 / 357.3 |
| `mixed-10m` | incremental-fixed65536 | 469.9 / 477.0 / 479.8 | 472.5 / 480.4 / 437.0 |

The two sides overlap within run-to-run noise. The new checks run only on a
value that is already under a credential name, and the `mixed-10m` finding
count stays at 10,239.
