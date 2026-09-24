# Changelog

This file records the released product contract and notable changes. Release
evidence is linked from each published version.

## Unreleased

### Changed

- `confluent-cloud-api-secret` now validates the checksum Confluent documents
  for `cflt` secrets. The last 6 characters must be the first 6
  standard-Base64 characters of the little-endian CRC-32 of the 54 body
  characters after `cflt`. A `cflt` value with the right length and alphabet
  but a different checksum (a changed character, big-endian bytes, or a CRC
  that includes the prefix) is no longer reported. The unprefixed legacy shape
  is unchanged (#738).

### Changed detection

- `heroku-api-key` now also detects the 41-character `HRKU-` OAuth access
  token generation: `HRKU-` followed by a lower-case `8-4-4-4-12` hex UUID,
  granted from 2024-04-01 through 2025-04-22 and valid until regenerated
  (Heroku changelog items 2842 and 3175). Like the 65-character `HRKU-AA`
  form, it is always redacted and needs no surrounding context. A 35-byte
  body, an upper-case body, or an `HRKU_` separator is not this shape (#740).
- `heroku-api-key-legacy` now also reports a bare-UUID token in two
  documented multi-line layouts where `heroku` is not on the token's line: the
  `password` of a `.netrc` entry whose `machine` host names heroku (with at
  most two `login`/`account` lines between them), and the line after a
  `heroku auth:token` command that holds only the token. The incremental
  session holds such a unit open until the token's line arrives, so chunked
  and whole-input results match. A UUID after any other line stays clean. A
  UUID that is a URL path segment (`https://api.heroku.com/apps/<uuid>/...`)
  is now treated as a public resource id and never reported, even on a line
  that names heroku (#743).

### Internal, tooling, and qualification

- The CHANGELOG `### Support status` section is now generated. A release
  commits `docs/releases/<version>/support-status.md`, and
  `npm run support-matrix:check` fails when the dated entry's section differs.
  The fragment states a stable delta only against a like-for-like baseline (the
  previous release's published package, same benchmarks revision); otherwise
  it says the previous pinned matrix is not comparable. Beta.7's section now
  says so instead of listing 48 moves against beta.6's earlier measurement
  (#724).
- `Release` now records the npm facade's identity after the package is built,
  and publishes that exact packed tarball. It used to pack a
  `packages/javascript` tree with no `dist/` before `release:check` built it,
  so beta.7's `Verify npm publication` compared a correct publish against a
  3-file tarball and failed. That also skipped registry install verification
  and tagging, which `Reconcile Release` then completed. `release-gate:check`
  now fails if the identity step comes before the build or the publish step
  does not publish the recorded tarball (#732).
- The vendored `benchmarks/pin-manifest.json` and
  `benchmarks/support-matrix-schema.json` are re-synced from
  `redact-secret-benchmarks` `main`, which now pins the published 0.1.0-beta.7
  (`2b98027`). The schema only gains an optional `product` object describing
  a candidate-build measurement.

## 0.1.0-beta.7 — 2026-09-24

[Publication and qualification evidence](docs/releases/0.1.0-beta.7/README.md).

Beta.7 moves Epic A's 15 existing families to `stable` and adds Okta,
Mailgun, Mailchimp, Heroku, Netlify, Postman, Databricks and Confluent
detection. It splits the legacy Datadog application key into its own finding
type and fixes Microsoft Entra and Docker token grammars. For adoption, it
adds a qualified five-minute clean install, a tested MCP/AI-context golden
path, a browser-prevention and server-enforcement reference, and a
generated support guide. Against the published beta.6 package, on the same
corpus and scanner pins, `stable` goes from 43 to 51 with no regression
(#584). The generated section below states no delta: the matrix shipped with
beta.6 was measured under an earlier corpus and ledger, so it is not a
like-for-like baseline (#724).

The Release run published every artifact correctly but failed its facade
checksum check on a defect in the check itself (#732). `Reconcile Release`
then verified every artifact without republishing anything, ran the registry
install checks, and created the tag. See the evidence record.

### Support status

42 providers, 93 credential families: stable 51, provisional 21, pending 2, unsupported 19. See the [support matrix](/docs/support-matrix.md).

The previous pinned matrix is not comparable, so no stable delta is stated: it was measured at benchmarks revision a502fdd715c5, not the candidate's 28fc818966d9, so corpus and scanner pins differ.

### Breaking and compatibility changes

- `datadog_application_key` no longer covers the legacy, bare 40-byte
  lowercase-hex Datadog Application Key shape; that shape now reports under
  its own `datadog_application_key_legacy` type (detector id
  `datadog-application-key-legacy`), unchanged in every other respect
  (still confidence-gated on the same-line marker/keyword signals it always
  required) (#671, [`docs/specs/detector-families.md`](docs/specs/detector-families.md)).
  Code that filters findings by `type === "datadog_application_key"` for the
  legacy shape must match `datadog_application_key_legacy` as well.

### Changed

- The pinned [support matrix](docs/support-matrix.md) was re-measured for the
  beta.7 candidate: product `main` (`6a2dca0`, candidate mode, core artifact
  `8b6e759b`) against benchmarks `develop` (`28fc818`, run `d87f63dd`), with
  gitleaks 8.30.1 and trufflehog 3.97.4. Epic A's 15 existing families move
  from `provisional` to `stable`: anthropic, linear, notion, New Relic user
  and license, both Grafana families, Azure DevOps, Google, both Datadog
  families, Hugging Face, Microsoft Entra, and both Docker families. 51 of 93
  families are now `stable`. The published beta.6 package, measured on the
  same corpus with the same scanner pins, reads 43, and no family left
  `stable` (#575, #584, [evidence](docs/audits/evidence/584/README.md)). The
  matrix shipped with beta.6 read 3 `stable` under an earlier benchmark
  corpus and ledger, so it is not a like-for-like baseline.
- `microsoft-entra-client-secret` now detects a client secret whose first
  three characters include `-`, including one that starts with `-`. The
  three bytes before the `<digit>Q~` marker now accept the same
  `[A-Za-z0-9_.~-]` alphabet as the rest of the secret. The outer boundary is
  unchanged, so a run joined to a wider token is still rejected (#707).
- `docker-token` now accepts a `dckr_oat_` organization access token with
  exactly 27 body bytes, the width shown in Docker's own Hub API reference, as
  well as exactly 32. Other widths are still rejected, and `dckr_pat_` still
  takes exactly 27 (#708).
- The pinned [support matrix](docs/support-matrix.md) was re-measured after
  the beta.7 committed families' differential ledger sweep
  (redact-secret-benchmarks#175, #176): `netlify:personal-access-token` and
  `confluent:cloud-api-secret` move from `provisional` to `stable` (#574).
  Postman, Databricks and Okta stay `provisional` at T2; no provider source
  states their grammar. The beta.7 candidate measurement still records
  unresolved differential items for Databricks (6) and Okta (9)
  ([#584 evidence](docs/audits/evidence/584/README.md#open-items)).
- `Package Release Rehearsal` now qualifies a throwaway, never-published
  `<X.Y.Z>-beta.<run id>` version instead of the branch's already-published
  one, moved onto its own uncommitted checkout after proving npm, crates.io,
  and PyPI carry no such version, so unpublished-version release-path defects
  (beta.6's #607 and #608) surface before an RC exists (#632,
  [`docs/audits/release-rehearsal-coverage.md`](docs/audits/release-rehearsal-coverage.md)).
- The [safe browser/server integration example](examples/safe-integration/README.md)
  now documents why the browser's default policy and the server's explicit
  `serverPolicy` are declared independently, states that the server never
  treats a client decision as proof of enforcement, and clarifies that
  finding offsets index the original scanned input, not the sanitized output
  (#588).
- `INITIALIZATION_FAILED`'s fixed message now names what failed to load and
  links the troubleshooting guide, instead of only
  `redact-secret failed to initialize.` (#586). The code is unchanged; match
  on `error.code`, not the message.
- Python raises one fixed, actionable `ImportError` when its native extension
  cannot load, instead of the loader's own error with host paths and ABI
  details (#586).

### Added

- Added an `okta-api-token` detector (finding type `okta_api_token`)
  recognizing Okta management API tokens: the literal `00` followed by
  exactly 40 bytes of `[A-Za-z0-9_-]`, 42 bytes in total, reported only with
  a same-line `okta` signal (confidence-gated, so the default policy warns
  rather than redacts) (#315,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)).
  Okta's own guide states neither a length nor a complete alphabet, so the
  body grammar rests on two independently maintained external tools that
  agree on the `00` prefix and the 40-byte length.
- Added a `mailgun-api-key` detector (finding type `mailgun_api_key`)
  recognizing Mailgun private API keys and HTTP webhook signing keys: the
  literal `key-` followed by exactly 32 lowercase-alphanumeric bytes,
  confidence-gated on a same-line `mailgun` signal (#314,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)). The
  two shapes are structurally identical, so they report under one type.
- Added a `mailchimp-api-key` detector (finding type `mailchimp_api_key`)
  recognizing Mailchimp Marketing API keys: 32 lowercase-hex bytes, the
  literal `-us`, then one or two digits naming the data-center subdomain,
  confidence-gated on a same-line `mailchimp` signal (#313,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)). The
  one-digit form is accepted because Mailchimp's own worked example uses it.
- Added a `netlify-token` detector (finding type
  `netlify_personal_access_token`) recognizing Netlify personal access
  tokens: the literal `nfp_` followed by exactly 36 bytes of `[A-Za-z0-9_]`,
  40 bytes in total, matching the capacity Netlify's own token-format
  announcement states. It is reported unconditionally (always redacted),
  since the prefix is self-identifying (#311,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)).
- Added a `postman-api-key` detector (finding type `postman_api_key`)
  recognizing Postman API keys: the literal `PMAK-`, 24 lowercase-hex bytes,
  a literal `-`, then 34 lowercase-hex bytes — a 59-byte body whose dash is
  pinned to its documented offset. A body missing that dash, or carrying it
  elsewhere, is an intentional false negative. Reported unconditionally
  (always redacted) (#310,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)).
- Added `heroku-api-key` and `heroku-api-key-legacy` detectors (finding types
  `heroku_api_key`, `heroku_api_key_legacy`) (#312,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)):
  - the current shape is the literal `HRKU-AA` followed by exactly 58 bytes
    of `[A-Za-z0-9_-]`, 65 bytes in total as Heroku's own changelog states,
    reported unconditionally (always redacted);
  - the legacy shape is a bare `8-4-4-4-12` lowercase-hex UUID, which carries
    no marker of its own and is therefore reported only with a same-line,
    case-insensitive `heroku` signal, confidence-gated so the default policy
    warns rather than redacts. A UUID assigned to an identifier-shaped key
    (one whose last word is `id` or `uuid`, such as `HEROKU_APP_ID`,
    `app_id` or `herokuAppId`) is a public app or release id and is not
    reported, even on a line that names heroku; a legacy token stored under
    such a key name is an accepted false negative (#714).
- `new_relic_license_key` now also detects the currently issued New Relic
  license key generation: 32 lowercase-hex bytes followed by the literal
  `FFFFNRAL`, and its EU-region form (`eu01xx`, 26 lowercase-hex bytes,
  `FFFFNRAL`), 40 bytes each. Previously only the legacy 40-byte all-hex
  shape was recognized and current keys produced no finding. Both new shapes
  keep the same-line `newrelic`/`new_relic`/`new-relic`/`new relic` keyword
  gate and `Medium` confidence (warn, not redact), so existing behavior of the
  legacy shape is unchanged. The first `NRAL` generation (36 hex bytes then
  `NRAL`) and region prefixes other than `eu01xx` remain documented gaps
  (#672, evidence in #656,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)).
- A [five-minute quickstart](docs/quickstart.md) for Node.js, Python, and a
  Vite browser bundle, starting from an empty directory. The
  `clean-install` qualification job runs its commands and files verbatim
  against each candidate's exact artifacts and records the result in the
  artifact inventory (#586).
- Added a `databricks-personal-access-token` detector (finding type
  `databricks_personal_access_token`) recognizing Databricks personal access
  tokens: the documented `dapi` prefix followed by an exact 32-byte
  lowercase hex body, optionally followed by a token-rotation suffix (a
  literal `-` and a single digit), corroborated by two independent external
  tools rather than provider-documented (#308,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)). A
  body shorter or longer than 32 bytes, in uppercase hex, or a rotation
  suffix with more than one digit is a documented out-of-scope gap. The new
  detector is always-redact and provider-specific.
- Two `confluent-cloud-api-secret` detectors covering Confluent Cloud API
  secrets across both documented generations (#309,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)):
  `confluent_cloud_api_secret` recognizes the current, documented `cflt`
  prefix plus an exact 60-byte base64-body shape and is always-redact; the
  legacy pre-2025-07-30 unprefixed 64-byte form is only ever ambiguous by
  shape alone, so `confluent_cloud_api_secret_legacy` requires a
  case-insensitive `confluent` substring on the same line and stays
  confidence-gated (warn unless corroborated at high confidence). The API
  Key ID (the non-secret half of the pair) is never itself a finding.
- `datadog-application-key` now recognizes the current, provider-documented
  `ddapp_`-prefixed Datadog Application Key shape (`ddapp_` plus an exact
  34-byte alphanumeric body, 40 bytes total) unconditionally at
  always-redact, corroborated by Datadog's own Agent validator, CloudFormation
  and ARM templates, and AWS's Secrets Manager partner documentation (#671,
  [`docs/specs/detector-families.md`](docs/specs/detector-families.md)). See
  "Breaking and compatibility changes" above for the legacy shape's new type
  name.

### Documentation

- The README, documentation home, and every registry-facing README and
  manifest description (npm, PyPI, crates.io, CLI) now share one product
  position: deterministic secret detection and redaction for runtime data and
  AI context (#585). The README opens with the runtime boundary, names logs,
  persistence, telemetry, tool output, and model context as use cases, keeps
  client-side prevention and server-side enforcement distinct, and states
  what the library does not replace: DLP platforms, complete secret coverage,
  and repository/history scanners. Installation and a first working example
  now precede the architecture, and the README's hand-maintained provider
  list gives way to the generated support matrix. `npm run
  product-positioning:check` keeps those surfaces from drifting apart.
- The README no longer says the host-integration adapters are unpublished.
  `@redact-secret/adapter`, `@redact-secret/adapter-pino`,
  `@redact-secret/adapter-otel` and PyPI `redact-secret-adapters` 0.1.0 were
  published on 2026-09-22. [Release status](docs/releases/status.md#host-integration-adapters)
  now lists their versions, core ranges and install commands, each re-run
  from an empty directory against the public registries. Getting started no
  longer tells readers to select beta.6 above beta.7 install commands.


## 0.1.0-beta.6 — 2026-09-22

[Publication and qualification evidence](docs/releases/0.1.0-beta.6/README.md).

Beta.6 adds declarative rulesets on every surface, four provider detectors
(Pulumi, Supabase management, Firebase server key, Terraform Cloud), and
extra prefixes for Stripe and GitLab. It narrows Slack's user and rotation
grammars, exempts Firebase's public client-config `apiKey`, and splits
GitHub findings into one type per token family. It also fixes three
`generic-token` Markdown and bare-prefix gaps and a glued-suffix boundary
defect shared by Slack and Linear. The support matrix is re-measured and
re-pinned from clean mains. Grammar provenance, measurements, and
intentional false negatives stay in the linked decision records and
`docs/audits/evidence/`.

### Breaking and compatibility changes

- `github-token` now reports a separate finding type for each GitHub token
  family instead of `github_token` for every prefix (#517,
  `decision-map-github-token-families-onto-independent-finding-types`).
  `ghp_` keeps `github_token`; `gho_` is now `github_oauth_token`, `ghu_`
  `github_app_user_to_server_token`, `ghs_` `github_app_installation_token`,
  `ghr_` `github_app_refresh_token`, and `github_pat_`
  `github_fine_grained_personal_access_token`. Code that filters, allowlists,
  or counts findings by `github_token` stops seeing the other five families.
  The detector id, prefixes, body grammars, byte spans, and always-redact
  action are unchanged for all six.
- Rust: `SecretScanErrorCode` gains `InvalidRuleset` and is still not
  `#[non_exhaustive]`, so an exhaustive `match` needs a new arm. The
  TypeScript `SecretScanErrorCode` union gains `"INVALID_RULESET"`, which
  breaks an exhaustive `switch`. Python adds `InvalidRulesetError`, a
  subclass of `SecretScanError`.

### Added

- Declarative rulesets (#441, #483, #495, #484,
  `decision-define-declarative-detector-ruleset-contract`): a caller-supplied
  internal credential format, described as small UTF-8 text (no code), can
  now be detected on every surface. A ruleset detector matches through the
  same linear-time `pattern.rs` engine every built-in detector already uses
  (no regex, no new engine), always carries `Confidence::Medium`, and
  registers after every built-in — it can add detections but can never
  outrank a built-in's resolved finding. A malformed ruleset is rejected as
  a whole with the new `INVALID_RULESET` code and one of a closed set of
  content-free rejection classes; see `README.md`'s "Declarative rulesets"
  section for the wire grammar.
  - A `names: ambiguous` block adds an in-house assignment keyword
    (`corp_token`) to `generic-token`'s ambiguous-name bucket, normalized the
    same way a scanned input's captured name already is. A caller cannot add
    to the high-signal bucket, remove or override a built-in name, or change
    a built-in's entropy threshold or confidence; a name that already
    normalizes to a built-in name is a silent no-op. A names-only ruleset
    (no `detector:` blocks) is valid.
  - Rust: `load_ruleset`, `RulesetError`, `RulesetErrorClass`, and
    `SecretScanErrorCode::InvalidRuleset`. Register the result the same way
    as a native custom detector (`DetectorRegistry::with_built_in`).
  - CLI: `--ruleset <path>`, available in both check and redact mode against
    an explicit file source. Standard input's streaming session still
    accepts no custom detector, ruleset or otherwise.
  - Node addon and `@redact-secret/wasm`: a `ruleset` argument on `scan`/
    `scanAndRedact` (`Buffer`/`Uint8Array`).
  - `@redact-secret/core`: a `ruleset` option (`Uint8Array | string`) on
    `scan`/`scanAndRedact`.
  - Python: a `ruleset` keyword argument (`bytes | bytearray | str`) on
    `scan`/`scan_and_redact`, and the new `InvalidRulesetError` exception.
  - Reference conformance fixture:
    `conformance/fixtures/ruleset-reference.json`, run by the Rust core and
    the Python binding.

### Changed detection

- `generic-token` no longer reads the closing backtick of a Markdown
  inline-code span into an unquoted assignment value (#548, found by
  `redact-secret-benchmarks`' `context.markdown` metamorphic sweep). A masked
  filler such as `` `password=********` `` stays excluded as it already did
  bare, and an unquoted value inside backticks is redacted at its exact bytes
  instead of one byte long. A value whose own first byte is an unmatched
  backtick (an unterminated template literal or command substitution) is still
  reported; a real secret containing a literal backtick, unquoted, is the
  accepted false negative. Evidence: `docs/audits/evidence/548/README.md`.
- `generic-token` now also redacts a bare, marker-less `sk-`/`sk-proj-`/
  `sk-svcacct-`/`sk-admin-` value at OpenAI's documented legacy/early-project
  body width (exactly 48 `[A-Za-z0-9]` bytes) with no surrounding context at
  all — a pre-2024 legacy key that never carried the `T3BlbkFJ` marker, or a
  near-miss that mutated it, the credential most likely to leak bare in a
  notebook, `.env` file, or chat log (#552,
  `decision-govern-bare-vendor-prefixed-policy-layer`). Classified
  `vendor_prefixed_credential`, never `openai_api_key`: `decision-freeze-
  openai-api-key-grammar`'s marker-gated contract is unchanged, and this new
  layer is registered at a specificity below every provider contract so a
  genuine `openai-token` match always wins overlap and keeps its own
  finding. Always-redact despite the deliberately medium confidence, the
  same way `authorization_credential` already is.
- Added a `pulumi-access-token` detector recognizing Pulumi Cloud personal,
  organization, and team access tokens: the documented `pul-` prefix
  (Pulumi's own Cloud REST API reference) followed by an exact 40-byte
  lowercase hex suffix, corroborated by two independent external tools
  rather than provider-documented (#522,
  `decision-freeze-pulumi-access-token-grammar`). All three token kinds
  share one shape, since Pulumi's reference documents no kind-specific
  prefix. A body shorter or longer than 40 bytes, in uppercase hex, or using
  any other undocumented character is a documented out-of-scope gap. The new
  detector is always-redact, provider-specific, and wins any overlap with
  the generic contextual detector.
- Added a `supabase-management-token` detector (finding type
  `supabase_personal_access_token`) for the Supabase personal access tokens
  that authenticate the Management API, CLI, and MCP server: `sbp_` or the
  versioned `sbp_v0_`, followed by exactly 40 lowercase `[a-z0-9]` bytes
  (#515,
  `decision-scope-supabase-management-token-and-secret-key-independence`).
  Supabase documents the prefixes but no body grammar. The 40-byte body is
  trufflehog's shipped `sbp_` rule, applied to `sbp_v0_` as well, which
  trufflehog's own regex cannot reach. A body shorter or longer than 40
  bytes, or one containing an uppercase byte, is an intentional false
  negative. The detector is always-redact and in the provider pack only.
  `supabase-token`'s `sb_secret_` shape is unchanged: its 20-byte-minimum
  body stays open because the two available sources disagree on an exact
  length.
- Added a `firebase-server-key` detector (finding type `firebase_server_key`)
  for the legacy Firebase Cloud Messaging server key: the literal `AAAA`,
  exactly 7 `[A-Za-z0-9_-]` bytes, a literal `:`, then exactly 140
  `[A-Za-z0-9_-]` bytes, 152 bytes in all (#520,
  `decision-add-firebase-server-key-detection-and-client-config-discrimination`).
  Two independent write-ups of exposed keys corroborate the prefix. The
  exact widths come from a single tool source (a nuclei template); neither
  gitleaks nor trufflehog ships a rule. Google retired the send APIs this
  key authenticates in 2024, but a leaked key is still redacted. A tail
  shorter or longer than 140 bytes, or a separator other than `:`, is an
  intentional false negative. The detector is always-redact and in the
  provider pack only. Evidence: `docs/audits/evidence/520/README.md`.
- Added a `terraform-cloud-token` detector (finding type
  `terraform_cloud_token`) for HCP Terraform and Terraform Enterprise user,
  team, and organization API tokens: exactly 14 `[A-Za-z0-9]` bytes, the
  literal `.atlasv1.`, then exactly 67 `[A-Za-z0-9]` bytes, 90 bytes in all,
  with no alphanumeric byte directly before or after (#521,
  `decision-add-terraform-cloud-enterprise-token-detection`). The widths
  come from three of HashiCorp's own API-reference examples and match
  trufflehog's rule. Gitleaks' looser 60-70-byte range over a wider
  alphabet is not adopted. The three token kinds share one shape and are
  not told apart. An intentional false negative: a segment one byte short
  or long, a malformed marker (`.atlasv2.`, `.ATLASV1.`), a masked value, or
  HashiCorp's short `xxxxxx.atlasv1.` documentation placeholder. The
  detector is always-redact and in the provider pack only. Evidence:
  `docs/audits/evidence/521/README.md`.
- `stripe-token` now also detects organization API keys (`sk_org_`) and
  webhook signing secrets (`whsec_`), each followed by 20 or more
  `[A-Za-z0-9]` bytes, the same floor and alphabet `sk_`/`rk_` already use
  (#513). Both prefixes rest on Stripe's documentation alone, because
  neither gitleaks nor trufflehog has a rule for them. Stripe documents no
  length, so the 20-byte floor is this family's support-policy choice. An
  intentional false negative: `rk_org_` (Stripe states it does not exist),
  an environment segment after `sk_org_` (a hypothetical `sk_org_live_…`),
  or gitleaks' undocumented `sk_prod_`/`rk_prod_`. Publishable `pk_live_`
  and `pk_test_` keys, which Stripe marks safe to expose, stay unflagged.
  Evidence: this issue's `stripe-token`-only view (11 positive / 13 negative
  fixtures across 6 host contexts) was recorded at
  [`fp-fn-summary-513.json`](https://github.com/redact-secret/redact-secret/blob/b00b96ed3f4cf0eac485f0f0d343cf65717e152d/docs/coverage/fp-fn-summary-513.json),
  removed by issue #595 as a redundant snapshot of the live, all-detector
  `docs/coverage/fp-fn-summary.json`.
- `gitlab-token` now also detects SCIM tokens (`glsoat-`) and Feature Flags
  client tokens (`glffct-`). They were the only rows of GitLab's
  token-prefix table without a matching prefix. Both use the same 20-byte
  minimum over `[A-Za-z0-9_-]` as the other eleven prefixes (#518,
  `decision-inventory-gitlab-token-families`), because GitLab documents no
  length for any prefix. The finding type stays `gitlab_token`. These gaps
  are recorded, with unchanged behavior: a routable runner token
  (`glrt-`/`glrtr-` with a `.`-delimited payload) is redacted only up to
  its first `.`, which leaves its version and checksum tail in the output,
  and is missed when that payload is under 20 bytes. The unprefixed legacy
  runner registration token and the `_gitlab_session` cookie are not
  detected.
- `generic-token` now detects a quoted assignment wrapped in Markdown inline
  code, such as `` `api_key="…"` `` (#552, found by
  `redact-secret-benchmarks`' `context.markdown` metamorphic sweep). A
  backtick is now accepted as the boundary before the assignment name and
  after the value's closing quote. Before, the whole assignment was missed
  instead of merely mis-spanned. Evidence: `docs/audits/evidence/552/README.md`.
- `slack-token` now requires Slack's documented section structure for the
  user token and the three rotation-family prefixes (#512,
  `decision-freeze-slack-user-and-rotation-token-grammar`). Beta.5 accepted
  any body of 20 or more `[A-Za-z0-9_-]` bytes after these prefixes.
  `xoxp-` now needs three `-`-separated sections of 10-13 digits, then a
  secret of 28 or more `[A-Za-z0-9]` bytes, the same structure `xoxb-`
  already requires. `xoxe-`, `xoxe.xoxb-`, and `xoxe.xoxp-` now need a
  single-digit version section (`xoxe-1-…`) before their opaque body. This
  narrows detection: a value that reached the old 20-byte minimum without
  these sections is no longer a `slack-token` finding, although a
  contextual assignment can still surface through `generic-token`. Also
  intentional false negatives: a pre-2016 6- or 10-character user secret, a
  numeric section outside 10-13 digits, a user secret containing `_` or
  `-`, and a version section of zero or two or more digits. This entry
  leaves `xoxb-`, `xapp-`, and `xwfp-` unchanged. The deprecated `xoxa-`,
  `xoxr-`, `xoxs-`, and `xoxo-` tokens stay unsupported.
- `slack-token`'s `xapp-` and `xwfp-` bodies, the opaque bodies of its
  `xoxe-`, `xoxe.xoxb-`, and `xoxe.xoxp-` rotation prefixes, and
  `linear-token`'s `lin_oauth_` body still accept 20 or more `[A-Za-z0-9_-]`
  bytes. They now reject the value when the byte right after the 20th body
  byte is `-` or `_` (#551, #570). The body alphabet equals the boundary
  alphabet, so beta.5 read a directly glued identifier (`…_backup`, `…-1`)
  into the finding as more secret. Now a suffix that starts at exactly the
  21st byte ends the body, and the boundary check rejects the value. It no
  longer gets a `slack-token` or `linear-token` finding at all, where beta.5
  redacted it together with its suffix. A body that continues past 20 bytes
  in `[A-Za-z0-9]` is still read in full, as in beta.5. Two tradeoffs
  remain. A real token on these prefixes whose 21st body byte is `-` or `_`
  is a false negative. A glued suffix after a longer alphanumeric body is
  still absorbed. An unreleased interim fix that required exactly 20 bytes
  (#551) missed every real-length token on these prefixes. It was replaced
  before release.
- An `AIza`-shaped value (`google-api-key`'s exact 39-byte shape) is no
  longer reported when at least two Firebase Web SDK config keys
  (`authDomain`, `databaseURL`, `storageBucket`, `messagingSenderId`,
  `appId`, `measurementId`, `projectId`) appear as object keys within 512
  bytes of it, on either side (#520,
  `decision-add-firebase-server-key-detection-and-client-config-discrimination`).
  Firebase documents that config's `apiKey` as safe to publish. This
  narrows detection. The exemption runs in the pipeline on the matched
  text, so it also drops `generic-token`'s `contextual_secret` finding for
  `apiKey`, and any custom or ruleset candidate with that shape. An
  unrestricted Google API key pasted into such an object is now missed. An
  `AIza` value with one or no such neighbour, or outside that window, is
  still reported as in beta.5.

### Internal, tooling, and qualification

- README and a new [support matrix](docs/support-matrix.md) now render from a
  pinned copy of `redact-secret-benchmarks`' generated evidence
  (`benchmarks/support-matrix.json`) instead of stating detector support by
  hand (#510, `decision-project-support-matrix-into-docs-and-release-notes`).
  `npm run support-matrix:check` (wired into `npm run ci`) fails the build if
  either surface drifts from the pinned matrix. Artifact qualification's
  `support-matrix-drift` job fails a candidate on any unacknowledged
  regression out of `stable` against the previous release's pin (#511,
  `decision-gate-releases-on-support-matrix-drift`), and the pin itself was
  re-measured from clean product and benchmarks mains for this release
  (#573). Release notes gain a
  generated status-distribution fragment
  (`generate-support-matrix-docs.py --release-note`); see
  [the release runbook](docs/releasing.md#close-out).
- [CONTRIBUTION.md](CONTRIBUTION.md#new-detector-family-checklist) documents
  the evidence arrival contract every new detector family must satisfy —
  provider or tool evidence, canonical positives, negative twins, benign
  controls, metamorphic cases, mutation cases, and differential
  observation — so a contributor or agent can satisfy the check
  `redact-secret-benchmarks` enforces (`scripts/check-evidence-arrival.mjs`,
  issue #52 there) without reading the checker itself (#525).
- Recorded the [0.1.0-beta.5 release retrospective](docs/audits/beta5-release-retrospective.md)
  (#531, closing Epic #526): what published, the three release-engineering
  failures (npm propagation false negatives, the forced recovery run, and the
  non-byte-identical qualified/published Python wheel), how #527/#528/#529
  resolved them, and what remains open (the Reconcile Release path has never
  been deliberately exercised; the wheel build itself is not yet proven
  reproducible). Added the [v0.1.0 release-readiness checklist](docs/releases/release-readiness-v0.1.0.md),
  referenced from [the release runbook](docs/releasing.md#review-and-approval),
  stating six checkable criteria a future stable-release decision is made
  against; this work approves no release itself.
- Recorded that `bearer-token` still redacts a `Bearer` value cut short by
  a byte outside its token alphabet whenever the part before that byte
  reaches its 16-byte minimum. It also still redacts a value shaped like
  another provider's token that the other provider's detector rejects, such
  as a SendGrid-shaped key one byte short (#553,
  `decision-accept-truncated-and-nested-shapes-under-bearer-token-length-grammar`).
  Detection is unchanged. The new pinned test also records that bytes after
  the break fall outside the redacted span. The #553 benchmark twin
  failures are fixture expectations, to be corrected in
  `redact-secret-benchmarks#66`. Evidence: `docs/audits/evidence/553/README.md`.

## 0.1.0-beta.5 — 2026-09-20

[Publication and qualification evidence](docs/releases/0.1.0-beta.5/README.md).

Beta.5 narrows seven provider grammars for precision, closes two detection
gaps and an unbounded-input default, and adds the opt-in `common` detector
profile, a Node WebAssembly fallback, musl Node packages, and Cloudflare
Workers support. It also adds two provider-token coverage variants and
closes four false-positive gaps in `generic-token`, `bearer-token`,
`connection-string`, and `jwt`. Grammar provenance, measurements, and
intentional false negatives stay in the linked decision records and
`docs/audits/evidence/`.

### Breaking and compatibility changes

- Whole-input `scan`, `redact`, and `scan_and_redact` on every binding now
  default to 64 MiB of input and 50,000 findings, and fail closed beyond them
  with `INPUT_LIMIT_EXCEEDED` or the new `FINDING_LIMIT_EXCEEDED` (#439,
  `decision-bound-whole-input-operations-by-default`). Raise the limits with
  `scan_with_limits`/`redact_with_limits`/`scan_and_redact_with_limits` and
  `WholeInputLimits` in Rust, a `limits: { maxInputBytes, maxFindings }`
  option in JavaScript, or `limits=redact_secret.WholeInputLimits(...)` in
  Python, or chunk through the incremental API. The CLI's 64 MiB read bound
  is unchanged; its file scans now also stop at 50,000 findings. The messages
  for `INVALID_LIMITS` and `INPUT_LIMIT_EXCEEDED` now describe both whole-input
  and incremental limits. JavaScript rejects a negative, fractional, or
  larger-than-`u32` limit with `INVALID_LIMITS` instead of letting the binding
  wrap it (for example `-1` to 4 GiB); this also applies to incremental limits.
- Every finding now carries `obfuscation` (#447, below). `redact()` on the
  Node addon rejects a finding without it with `INVALID_FINDINGS`, and
  TypeScript requires it on `SecretFinding`. Findings returned by `scan()`
  for the same input, the documented contract, are unaffected; a hand-built
  finding or one serialized from beta.4 is not. The CLI text report inserts
  `obfuscation=` before `id=`.
- Rust: `SecretScanErrorCode` gains `FindingLimitExceeded` and is not
  `#[non_exhaustive]`, so an exhaustive `match` needs a new arm.
- `@redact-secret/wasm` now declares an `exports` map (`.`, `./common`, the two
  `.wasm` binaries, and `./package.json`). Deep imports of its other files no
  longer resolve. The package is an implementation dependency of
  `@redact-secret/core` and is not meant for direct use.

### Security fixes

- Overlap resolution ranks candidates by resolved action (`Block > Redact >
  Warn > Allow`) before specificity (#450,
  `decision-resolve-overlap-precedence-by-resolved-action-severity`). A
  medium-confidence `new_relic_license_key`, `twilio_auth_token`,
  `twilio_api_key_secret`, `datadog_api_key`, or `datadog_application_key`
  candidate could previously displace a stricter-resolving candidate on the
  same span, such as `bearer_token`, and leave the credential warned but
  unredacted. Only inputs with that overlap change.
- An invisible code point inside a credential no longer defeats detection
  (#438, #445, `decision-normalize-invisible-characters-before-detection`).
  The core removes `Default_Ignorable_Code_Point ∪ Cf` (pinned UCD 17.0.0)
  into a scan copy before detection and translates every range back to the
  original input in each binding's unit. A removed code point inside a value
  is redacted with it. Text that is credential-shaped only after removal is
  now a finding, and an invisible character no longer acts as a token
  boundary. Custom Rust detectors also receive the scan copy.

### Added

- The opt-in `common` detector profile in Rust, the Node addon, WebAssembly,
  and `@redact-secret/core`, but not Python or the CLI (#377: #380, #381,
  #382, #416, `decision-define-detector-profile-and-pack-contract`).
  `full` stays the default and is unchanged. `common` omits the provider-pack
  detectors, so a bare provider token is not detected, and one inside a
  `Bearer` header or contextual assignment is reported under that detector's
  type and confidence, for example warned where `full` redacts. Its reviewed
  corpus expectations are pinned in
  `conformance/fixtures/common-profile-expectations.json`. The `common`
  WebAssembly artifact is 15.8% smaller (brotli) and scans 2.9–6.1× faster in
  the three browser engines ([evidence](docs/audits/evidence/381/README.md)).
  - Rust: `Profile`, `DetectorRegistry::with_common_built_in` and `profile()`,
    and `IncrementalSanitizer::with_common_built_in`,
    `with_common_built_in_policy_and_formatter`, and `profile()`. A profile
    constructor rejects a custom detector that reuses a `full` built-in id;
    `DetectorRegistry::register` clears `profile()` to `None`.
  - Node addon: `profile()` and `initializeCommon`, `scanCommon`,
    `scanAndRedactCommon`, `createIncrementalSanitizerCommon`, and
    `profileCommon`, served by the same compiled addon.
  - `@redact-secret/wasm`: `profile()` and a `common` subpath shipping that
    build's own glue and `.wasm`.
  - `@redact-secret/core`: `./common`, `./common/node-stream`,
    `./common/web-stream`, and a `PROFILE` constant. `initialize()` rejects
    with `INITIALIZATION_FAILED` when the loaded artifact reports a different
    profile. The `./common` stream subpaths never load the `full` artifact.
  - The release workflow checks that the root `@redact-secret/wasm` artifact
    reports `full` and the companion reports `common` before publishing (#417).
- `obfuscation` on every finding (#447): `"invisible-characters"` when the
  finding's range strictly contains a code point the normalization removed,
  otherwise `"none"`. It carries no value or offset. Rust `Obfuscation` with
  `Finding::obfuscation()` and `DetectedFinding::obfuscation()`; the CLI's
  `obfuscation` JSON and `obfuscation=` text fields; and an `obfuscation`
  property on Node, WebAssembly, Python, and `@redact-secret/core` findings
  (typed `SecretObfuscation`).
  `DefaultPolicy` does not act on it.
- Node WebAssembly fallback (#443, `decision-add-node-wasm-fallback`): when
  the native addon is unavailable — an unsupported platform, a failed
  optional-dependency install, or an unloadable addon — `initialize()` loads
  the `@redact-secret/wasm` artifact for the same profile instead of rejecting.
  A version or profile mismatch still rejects. The new `artifact()` export
  (`ArtifactKind`) reports `"addon"` or `"wasm"`.
- musl Linux Node packages `@redact-secret/node-linux-x64-musl` and
  `@redact-secret/node-linux-arm64-musl` (#443,
  `decision-publish-musl-node-addons`). On Linux the loader picks the glibc or
  musl package by the detected libc. npm now carries ten package identities.
  The CLI still ships no musl binary.
- Cloudflare Workers support (#462, `decision-verify-edge-runtimes`): a
  `workerd` import condition loads the WebAssembly binary through new
  `@redact-secret/wasm/redact_secret_wasm_bg.wasm` and
  `redact_secret_wasm_common_bg.wasm` subpath exports. Vercel Edge was tested
  and remains unsupported.

### Changed detection

- Seven provider detectors now match only their reviewed grammars (#367–#374,
  `decision-freeze-precision-contracts-seven-provider-families`). Each rejects
  the near-miss twins beta.4 flagged, and every paired positive keeps its
  exact range. Fixed-corpus twin discrimination rose from 32/56 to 56/56 with
  every required positive preserved
  (`decision-gate-beta5-on-precision-gains-and-positive-preservation`).
  Detector ids, finding types, confidence, specificity, and default policy
  are unchanged.
  - `openai-token`: the `T3BlbkFJ` marker between exact-length segments —
    `sk-` 20 + 20, or `sk-proj-`/`sk-svcacct-`/`sk-admin-` 74 or 58 on each
    side (`decision-freeze-openai-api-key-grammar`). Marker-less `sk-` values
    surface only through `generic-token` or `bearer-token` context.
  - `digitalocean-token`: `dop_v1_`, `doo_v1_`, or `dor_v1_` and exactly 64
    lowercase hex characters.
  - `docker-token`: `dckr_pat_` and 27, or `dckr_oat_` and 32, characters of
    `[A-Za-z0-9_-]` (`decision-freeze-docker-pat-oat-exact-length-grammar`).
  - `slack-token` `xoxb-`: `<10–13 digits>-<10–13 digits>-<18+ alphanumerics>`
    (`decision-freeze-slack-bot-token-segment-grammar`). Other Slack prefixes
    keep beta.4's rule, and a rotating `xoxe.xoxb-` value is still one finding.
  - `huggingface-token`: `hf_` and exactly 34 characters of `[A-Za-z0-9]`;
    `api_org_` over the identical body grammar, re-tiered from a known false
    negative to a supported variant (#485,
    `decision-adopt-huggingface-organization-token-prefix`).
  - `cloudflare-token`: `cfut_`, 40 characters of `[A-Za-z0-9]`, and an 8-character
    lowercase-hex checksum, validated lexically only; `cfat_` over the
    identical body and checksum grammar, likewise adopted from a known false
    negative (#481, `decision-adopt-cloudflare-account-token-prefix`). The
    third documented prefix, `cfk_`, stays unsupported pending checksum
    evidence (#486).
  - `linear-token` `lin_api_`: exactly 40 characters of `[A-Za-z0-9]`;
    `lin_oauth_` is unchanged.

  Per-family provenance, the beta.4 negative-twin baseline, and fixture
  reclassifications are in `docs/audits/evidence/367/` and
  `docs/audits/evidence/376/`.

### Reduced false positives

- `generic-token` no longer reports a complete or argument-truncated source-code
  call expression assigned to a credential-named variable (#467,
  `decision-exclude-closed-call-code-expressions-as-contextual-values`).
  Previously an expression like `secret = getSecretOrThrow(SECRET_NAME)` was
  redacted at high confidence; a truncated call boundary
  (`crypto.createPrivateKey({ key: pem })`) produced corrupted output by
  splitting the redaction mid-expression. A quoted literal that merely
  resembles a call, or an interpolation fragment opened on punctuation
  (`$(...)`, `#{...}`, `{{...}}`), is unaffected and still detected.
- `bearer-token` now excludes repeated-character filler
  (`xxxxxxxxxxxxxxxxxxxx`) and whole-value placeholder vocabulary
  (`PASSWORD_SECRET_EXAMPLE`) the same way `generic-token` already does for
  `Basic`/`Token` schemes, so all three `Authorization` schemes agree on a
  masked or placeholder value (#468,
  `decision-exclude-filler-and-placeholder-bearer-values`).
- `connection-string` now excludes an environment-variable-reference password
  (`$DB_PASSWORD`, `$(db_password)`, `$env:DB_PASSWORD`, `{{ db_password }}`,
  `#{ENV['DB_PASSWORD']}`, `{env:DB_PASSWORD}`, `%DB_PASSWORD%`) the same way
  `generic-token` already does for a contextual `password=` assignment,
  sharing the predicates through `super::text` (#469,
  `decision-share-non-secret-reference-exclusions-with-connection-string`).
  Previously only the braced `${...}` form was recognized; a connection URL
  whose password was one of these idioms — the default in `docker-compose.yml`,
  `.env` templates, and Kubernetes manifests — was redacted.
- `jwt` no longer reports a legacy-format Supabase anonymous key: a
  structurally valid three-segment JWT is excluded only when its payload
  decodes to text containing both `"iss":"supabase"` and `"role":"anon"`
  (#472, `decision-scope-supabase-legacy-anon-jwt-exclusion`). Every other
  claim, including `service_role`, is still reported; the detector's
  signature is not and cannot be verified.

### Internal, tooling, and qualification

- Overlap resolution selects the disjoint candidate subset with the greatest
  total evidence instead of a greedy pass (#451,
  `decision-select-optimal-disjoint-candidates-by-total-evidence-weight`). No
  canonical fixture changes.
- Confirmed `connection-string` and `jwt` need no incremental `has_open_*`
  retention hint of their own (#480,
  `decision-connection-string-and-jwt-need-no-retention-hint`): neither
  detector's value grammar can span a line terminator, so the incremental
  scanner's existing closed-line-only dispatch already covers them. No
  behavior change.
- Artifact qualification now runs the Node WebAssembly fallback and the
  Cloudflare Workers path for both profiles. The Node consumer lanes require
  `artifact()` to report `"addon"`, so a silent fallback cannot pass them. The
  release and reconcile workflows publish, repair, and registry-install-verify
  all eight native packages, the musl lanes in Alpine containers.
  `check-artifact-matrix.py` enforces those matrices against
  `node-publish-targets`, and `check-rust-workspace.py` enforces the facade's
  exact runtime-package pins.
- `npm run benchmark:candidate` (#390), a benchmark pin drift check and
  regression ledger (#426–#429), a re-pinned release accuracy corpus (#376),
  and a dated macOS performance waiver asserted by the acceptance test
  (#415). Development tooling only.
- Decision records for a declarative detector ruleset contract (#441; not yet
  implemented) and for moving the pino, Python `logging`, and OpenTelemetry
  adapters to the separate `redact-secret-adapters` repository (#442). No
  package in this repository changes.

## 0.1.0-beta.4 — 2026-09-17

[Publication and qualification evidence](docs/releases/0.1.0-beta.4/README.md).

- Fixed the pino logging example (`examples/logging-redaction/pino-hook.mjs`)
  to redact a secret split across a `msg` format string and its printf-style
  interpolation values, or across two interpolation values, within one log
  call. The hook previously scanned `msg` and each interpolation value as
  independent leaves, before pino ever formats them together, so a value
  like `logger.info("api_key=%s", token)` was never joined and never seen as
  one string by the scanner. `msg` and its interpolation values are now
  joined into the exact string pino's own `quick-format-unescaped`
  dependency would produce (`examples/logging-redaction/format-pino-message.mjs`,
  a byte-for-byte vendored port, verified against the real package) before
  redaction runs. `pino` and `quick-format-unescaped` are now pinned
  `devDependencies`, exercised by a real, pinned pino `10.3.1` consumer test
  asserting on exact destination bytes
  (`examples/logging-redaction/pino-consumer.test.mjs`). This is an example
  integration fix, not a change to the Rust core's detection. Python's
  `logging.Filter` integration already formatted `msg`/`args` before
  scanning and was not affected.
- Preserve `__proto__` and other prototype-named JSON keys as own data in
  tracing, logging, and MCP redaction examples, without changing prototypes.
- Sanitize cached Python logging exception text and emit a fixed marker when
  exception traversal reaches its depth limit.

- Added `new-relic-user-api-key` and `new-relic-license-key` detectors
  recognizing New Relic User API Keys and (ingest) License Keys. The User API
  Key is New Relic's own documented `NRAK-` prefix plus an exact 27-byte
  uppercase-alphanumeric body (32 bytes total, converging with gitleaks's and
  trufflehog's independent detectors), always redacted at high confidence.
  The License Key is documented only as "a 40-character hexadecimal string"
  with no marker of its own, so -- following the same reliable-context
  requirement Twilio's bare hex formats already use -- it is only classified
  when a `newrelic`/`new_relic`/`new-relic`/`new relic` substring shares its
  physical line, at medium confidence. A masked placeholder of a single
  repeated character is excluded from both formats. The Browser Key and
  Mobile App Token are explicitly reviewed and excluded: New Relic's own
  documentation designs both for public client embedding, not as secrets.
  The legacy Insights Insert/Query Keys, the deprecated Admin Key, and the
  bare account-scoped "user API id" are documented out-of-scope gaps, not
  silently dropped.
- Added `sentry-user-auth-token` and `sentry-org-auth-token` detectors
  recognizing Sentry's documented-in-practice prefixed token formats: a
  user auth token is the literal `sntryu_` followed by an exact 64-byte
  lowercase-hex secret; an organization auth token is the literal
  `sntrys_eyJ` (`eyJ` being the base64 encoding of a JSON object's opening
  `{"`), a documented-minimum base64 payload, an optional trailing base64
  padding, a literal `_`, and an exact 43-byte base64 signature. Sentry's
  own documentation publishes no grammar for either value; the shapes are
  cross-referenced from gitleaks's and trufflehog's independent rules (no
  code reproduced from either). Both prefixes are unambiguous provider
  markers, so neither detector requires surrounding context, unlike
  Twilio's unmarked Auth Token/API Key Secret above. Sentry's legacy,
  pre-2024 unprefixed 64-byte hex token is indistinguishable from an
  ordinary hex digest without reliable context and is intentionally out of
  scope for a dedicated detector; a qualified `name=value` assignment of it
  still gets a lower-confidence contextual finding through the generic
  detector. A public Sentry DSN shares no shape with either grammar and is
  not classified. Both new types are always-redact and provider-specific.
- Added `grafana-service-account-token` and `grafana-cloud-access-policy-token`
  detectors. The service account detector matches the documented `glsa_`
  prefix, an exact 32-byte alphanumeric body, a literal `_` separator, and an
  exact 8-byte hex checksum -- a shape shown in Grafana's own example request
  and corroborated by gitleaks's and trufflehog's independent Grafana rules
  (consulted only as external behavioral references; no code copied from
  either project). The Cloud access policy detector matches the documented
  `glc_` prefix followed by a minimum 32-byte base64 body (`[A-Za-z0-9+/]`),
  the same floor gitleaks's rule uses; trufflehog's narrower `glc_eyJ`-anchored
  variant, which encodes a single tool's implementation detail rather than a
  confirmed provider fact, was deliberately not adopted. Grafana's legacy
  (pre-service-account) API key -- an unprefixed base64-encoded JSON blob --
  is an explicit, documented out-of-scope gap: it is deprecated by Grafana in
  favor of service accounts and carries no Grafana-owned marker beyond a
  generic base64/JSON convention this crate's `jwt` and generic-token
  detectors already cover the same false-positive risk for. Both new
  detectors are always-redact, provider-specific, and win any overlap with
  the generic contextual detector.
- Added `datadog-api-key` and `datadog-application-key` detectors recognizing
  Datadog API Keys and Application Keys: community-observed (gitleaks,
  trufflehog) bare lowercase-hex values -- 32 bytes for an API Key, 40 bytes
  for an Application Key -- with no vendor-documented character-class grammar
  of their own, though Datadog's own docs publish the `DD-API-KEY` /
  `DD-APPLICATION-KEY` header names and `DD_API_KEY` / `DD_APPLICATION_KEY`
  environment variable names. Neither key carries a paired public identifier
  the way a Twilio Account SID or API Key SID does, so each detector requires
  reliable Datadog context on the same line as the candidate: a specific
  same-line marker naming the key type (`dd_api_key`, `dd-application-key`,
  and similar `-`/`_`-joined spellings of the documented header/env-var
  names, high confidence) or, absent that, a bare case-insensitive `datadog`
  substring (medium confidence). The bare two-letter `dd` form is never
  checked as an unanchored keyword, since it collides with ordinary English
  inside `address`, `middleware`, and similar words; it remains reachable
  only as part of the longer specific markers. Both types are
  provider-specific and confidence-gated (redact at high confidence, warn at
  medium) rather than unconditionally always-redact. A specific marker or the
  bare vendor word on a *different* line from the value is a documented,
  known false negative: context is scoped to a single line so whole-input and
  incremental (line-at-a-time) scanning agree. The two distinct finding types
  record, in metadata, the issue's requested distinction between an
  ingestion credential (API Key) and broader application-API authority
  (Application Key).
- Added `twilio-auth-token` and `twilio-api-key-secret` detectors recognizing
  Twilio Auth Tokens and API Key Secrets: community-observed (gitleaks,
  trufflehog) bare 32-byte values -- lowercase hex for an Auth Token,
  mixed-alphanumeric for an API Key Secret -- with no vendor-documented
  format of their own. Neither value carries a marker distinguishing it from
  ordinary opaque text (an Auth Token's shape is indistinguishable from an
  MD5 digest), so each detector requires reliable Twilio context on the same
  line as the candidate: the paired identifier (an `AC`-prefixed Account SID
  or `SK`-prefixed API Key SID, high confidence) or, absent that, a
  case-insensitive `twilio` substring (medium confidence). Account SIDs and
  API Key SIDs are never themselves flagged as findings -- they identify an
  account or a key, not a secret, matching the issue's explicit rejection of
  treating a bare identifier as equivalent credential coverage. Both types
  are provider-specific and confidence-gated (redact at high confidence,
  warn at medium) rather than unconditionally always-redact, since the
  keyword-only signal is real but weaker evidence than the paired
  identifier. A paired identifier on a *different* line from the value is a
  documented, known false negative: context is scoped to a single line so
  whole-input and incremental (line-at-a-time) scanning agree.
- Added a `telegram-bot-token` detector recognizing Telegram Bot API tokens:
  a minimum 5-digit numeric id, a literal `:` separator, and a minimum
  34-byte secret from `[A-Za-z0-9_-]`, both lengths taken as documented
  minimums (Telegram's own docs disclaim no fixed length but publish only
  one worked example) rather than exact matches. A token glued directly onto
  the documented Bot API request URL's `/bot` path segment
  (`https://api.telegram.org/bot<token>/METHOD_NAME`) is also detected, with
  only the id:secret token bytes selected. A bare numeric chat/user/bot id
  with no secret, a public bot username handle, and Telegram's separate
  MTProto `api_id`/`api_hash` client credentials are documented out-of-scope
  gaps sharing no `id:secret` shape with this grammar. The new detector is
  always-redact, provider-specific, and wins any overlap with the generic
  contextual detector.
- Added a `discord-bot-token` detector recognizing Discord bot tokens: three
  dot-separated segments of exactly 24, 6, and 27 bytes from
  `[A-Za-z0-9_-]`, matching the single example in Discord's own developer
  reference and corroborated by gitleaks's and trufflehog's independent
  Discord bot-token rules (consulted only as external behavioral
  references; no code copied from either project). The first segment must
  also decode, as unpadded base64url, to an all-ASCII-digit string -- the
  shape of a Discord snowflake ID -- which anchors the detector to
  Discord's specific token shape without overlapping the structurally
  identical JWT grammar. Webhook URL tokens, OAuth2 client secrets, and
  `mfa.`-prefixed user/self-bot tokens are documented out-of-scope gaps,
  each a separate credential family. The new detector is always-redact,
  provider-specific, and wins any overlap with the generic contextual
  detector.
- Added an `atlassian-api-token` detector recognizing Atlassian Cloud (Jira /
  Confluence) API tokens: the community-forum-confirmed `ATAT` prefix
  followed by a minimum 100-byte suffix from `[A-Za-z0-9_-]`. The length is a
  minimum, not an exact match, because Atlassian's own documentation
  explicitly disclaims a fixed token length. The legacy, pre-2022 unprefixed
  24-character token is a documented out-of-scope gap, indistinguishable from
  ordinary opaque text without reliable context; it is left to the generic
  contextual detector. `ATCT`-prefixed access tokens and `ATBB`-prefixed app
  passwords are separate Atlassian credential families, also out of scope.
  The new detector is always-redact, provider-specific, and wins any overlap
  with the generic contextual detector.
- Added a `notion-token` detector recognizing Notion's documented and
  community-converged integration token shapes: the legacy `secret_` prefix
  followed by an exact 43-byte alphanumeric suffix, and the current `ntn_`
  prefix (rolled out 2024-09-25 per Notion's own changelog) followed by an
  exact 11-digit run and a 35-byte alphanumeric suffix. Both total exactly 50
  bytes. Notion's OAuth refresh tokens (`nrt_`), OAuth access tokens, and
  page/database/block IDs are documented out-of-scope gaps: no reliable
  grammar for the former two could be confirmed at implementation time, and
  the latter are public identifiers, not secrets. The new detector is
  always-redact, provider-specific, and wins any overlap with the generic
  contextual detector.
- Added a `google-api-key` detector recognizing Google Cloud/Gemini's
  documented legacy "standard" API key shape: the `AIza` prefix followed by
  an exact 35-byte suffix from `[A-Za-z0-9_-]`. This is the key string used
  to authenticate requests, not the administrative key ID shown in Cloud
  console URLs, which carries no `AIza` prefix and is out of scope. Google's
  newer service-account-bound "Auth key" shape is a documented future gap:
  no authoritative grammar for it could be confirmed at implementation time.
  The new detector is always-redact, provider-specific, and wins any overlap
  with the generic contextual detector.
- Correct assessment performance to require a release-built Rust adapter; keep
  historical debug timings separate from optimized comparisons. Clarify corpus
  coverage, measured reliability, public beta availability, and security support.

## 0.1.0-beta.3 — 2026-09-16

[Publication and recovery evidence](docs/releases/0.1.0-beta.3/README.md).

- Added a `sendgrid-token` detector recognizing SendGrid's documented
  `SG.<22-byte id>.<43-byte secret>` API key shape, both segments drawn from
  the URL-safe base64 alphabet. Previously this shape was detected only when
  assigned to a recognized generic field name like `api_key`; a bare token
  or one assigned to an unrecognized name such as `SENDGRID_TOKEN` produced
  no finding. The new detector is always-redact, provider-specific, and wins
  any overlap with the generic contextual detector.
- The `generic-token` detector no longer reports a value fully delimited by
  an interpolation or command-substitution syntax as a secret: a
  shell/`Makefile`/Kustomize `$(...)` variable or command substitution
  (`$(registryPassword)`, `$(pass show db/prod)`), an Azure Pipelines
  `$[...]` runtime expression (`$[variables.x]`), a Ruby `#{...}` string
  interpolation (`#{ENV['DB_PASSWORD']}`), an opencode `{env:...}`/
  `{file:...}` substitution (`{env:ANTHROPIC_API_KEY}`), or a
  backtick-quoted command substitution / JS template literal
  (`` `${process.env.X}` ``). This is the same class of non-secret reference
  as the existing `${...}`/`{{...}}` exclusions, and previously the default
  policy's `redact` action would rewrite the literal reference in a pipeline
  definition, shell script, or tool config. A value that only starts with
  one of these delimiters, or that has a delimited pair embedded inside a
  larger value, is unaffected and continues to be reported.
- The `generic-token` detector no longer reports an unquoted value that is a
  source-code expression as a secret: a known reference root
  (`settings.DATABASE_PASSWORD`, `config.anthropicApiKey`, `self.foo`,
  `this.bar`), a Terraform-shaped `var`/`local`/`data`/resource attribute
  chain (`random_password.db.result`,
  `data.aws_secretsmanager_secret_version.db.secret_string`), generic-type or
  subscript syntax (`Option<String>`, `Optional[str`), or a call/subscript
  expression truncated at its string-literal argument
  (`os.environ["OPENAI_API_KEY"]`, previously captured only as
  `os.environ[`). Such a value names *where* a secret lives at runtime, not
  the secret itself, and the default policy's `redact` action previously
  rewrote it as if it were a literal credential. A dotted value with no
  known root and no `lower_snake_case` segment (`SYNTHETIC.REVOKED.CONTEXT_VALUE`)
  continues to be reported.
- A `generic-token` contextual assignment's value can no longer cross a line
  terminator. Previously, a key with no value before end-of-line (a YAML
  `secret:` block opening a nested mapping, an interactive `Password:`
  prompt) could consume the next line's key name as if it were the value,
  which both produced false positives on unrelated nested keys and — the
  more serious direction — advanced the scan past that nested key's own
  boundary, so a real credential nested directly under a parent key
  (`database:\n  password: <value>`) was silently missed. Whole-input and
  incremental scanning (single chunk or split at any boundary) now agree on
  every such shape.
- The `generic-token` detector no longer reports a value made of the same
  character repeated three or more times (`********`, `••••••••`) as a
  secret — classic redaction-style filler that masked CLI prompts, config
  dumps, and `env` listings echo back in place of a real password. The
  `connection-string` detector already excluded this shape; both detectors
  now share one implementation. A value with even one differing character
  (`********x`) continues to be reported.
- The `generic-token` detector no longer reports a value fully delimited by
  `{{` and `}}` (`{{ vault_db_password }}`, `{{ .Values.postgresql.auth.password }}`,
  `{{ .ClientSecretRef }}`) as a secret, quoted or unquoted. This is the
  idiomatic reference syntax Ansible, Helm, Salt, and Go templates use to
  point at a vaulted or injected value, and previously the default policy's
  `redact` action would rewrite the literal template placeholder, corrupting
  the playbook or chart it appeared in. A value that only starts with `{{`,
  or that has a `{{...}}` pair embedded inside a larger value, is unaffected
  and continues to be reported.
- The `generic-token` and `connection-string` detectors' placeholder-word
  exclusion (`changeme`, `redacted`, `example`, and similar hardcoded
  non-secret values) now matches on token boundaries instead of whole-value
  exact-string equality. A leading/trailing separator (`" changeme"`), a
  digit appended to a distinctive placeholder word (`changeme2`), and two
  already-excluded words joined with `-`/`_` (`REDACTED-EXAMPLE`) are now
  excluded like the literal word already was; a real secret that merely
  contains a placeholder word as a substring, or alongside unrelated tokens,
  continues to be reported.
- AWS's own documented example credentials — the access key ID
  `AKIAIOSFODNN7EXAMPLE` and its paired secret access key
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — are no longer reported as
  findings. An exact-literal carve-out in the detector pipeline drops a
  candidate whose full matched text equals one of these two vendor-published
  placeholder values, regardless of which detector proposed it; no other
  detection behavior changes.
- The `generic-token` detector no longer reads a YAML flow mapping's or flow
  sequence's opening `{`/`[` as the start of an unquoted scalar. Previously,
  a credential-like key followed by inline flow syntax (`secret: {secretName:
  web-tls-cert}`) captured the nested key as if it were the value. An
  unquoted value beginning with either character is now treated as no value
  at all; a value on the same line in ordinary block style (`secret:
  <value>`) is unaffected and continues to be reported.
- The `generic-token` detector no longer reports a secret-manager reference
  string as a secret: a 1Password `op://<vault>/<item>/<field>` reference, a
  LiteLLM `os.environ/<VAR_NAME>` reference, a GCP Secret Manager resource
  name (`projects/<id>/secrets/<name>(/versions/<v>)?`), a `vals`
  `ref+<backend>://<path>#<key>` reference, a bank-vaults/Vault Agent
  injector `vault:<path>#<key>` reference, an AWS Secrets Manager ARN, or an
  Azure App Service `@Microsoft.KeyVault(...)` reference. Each of these
  names where a secret lives at runtime rather than containing one, and
  previously the default policy's `redact` action would rewrite the literal
  reference in place, corrupting the env file, config, or manifest it
  appeared in. A value with a matching scheme prefix that does not satisfy
  that scheme's full grammar (wrong segment count, an invalid identifier, a
  missing delimiter, a non-12-digit account id, and similar) is unaffected
  and continues to be reported.

## 0.1.0-beta.2 — 2026-09-14

[Publication evidence](docs/releases/0.1.0-beta.2/README.md).

- JavaScript and Python incremental sanitizers now treat host-side invalid
  append input as terminal: retained plaintext and offset state are discarded,
  the session reports `failed`, and later operations raise `INVALID_STATE`.
- Artifact qualification inventories now carry release-readiness pointers for
  the public API/changelog review and the post-publication registry-install
  verification boundary, keeping issue #203 evidence tied to one source
  revision without granting release authority.
- Executable browser and server integration examples now demonstrate
  preventive client scanning, authoritative block and warning enforcement,
  fail-closed downstream handling, and explicit transport, input, output,
  finding-count, and concurrency limits. Candidate qualification runs them
  against clean installs of the packed Node and browser WebAssembly artifacts.
- Fixed performance and resource thresholds, derived from the first complete
  cross-surface baseline, can now evaluate five-repetition RC evidence for the
  qualified macOS arm64 environment without treating unavailable or overlapping
  host memory metrics as zero.
- A complete assessment command and manually triggered CI workflow now evaluate
  Rust, installed Python, Node, browser WebAssembly, and CLI artifacts against
  shared whole-input and incremental profiles, fail closed on missing or
  inconsistent results, and preserve raw samples plus consolidated JSON and
  Markdown baseline evidence with explicit measurement limitations.
- Assessment tooling now includes a CLI binary runner, self-test command, and
  first checked-in correctness/performance baseline with explicit process
  startup, process-inclusive processing, and whole-process RSS measurements.
- The fixed, separate beta.2 detection assessment now records source-, corpus-,
  runtime-, and artifact-bound Node and browser results with explicit
  denominators, safe mismatch details, and linked limitation dispositions;
  conformance coverage is not presented as accuracy.
- Assessment tooling now evaluates an installed Python package through both
  whole-input and incremental APIs, normalizes code-point ranges to canonical
  UTF-8 byte spans, and records the first correctness, timing, Python-allocation,
  and whole-process RSS baseline with explicit sampling limits.
- Assessment tooling now includes a Rust library runner, self-test command,
  and first checked-in correctness/performance baseline for the `rust-core`
  surface.
- Node.js and browser packages now expose working bounded incremental
  sanitization plus Node `Transform` and Web `TransformStream` adapters.
  Candidate qualification installs packed packages outside the checkout,
  exercises those public APIs on Node.js 20, 22, and 24 and in Chromium,
  Firefox, and WebKit, and records revision- and digest-bound results.

## 0.1.0-beta.1 — 2026-09-11

[Publication evidence](docs/releases/0.1.0-beta.1/README.md).

### Product and packages

- Redact Secret provides deterministic secret detection and redaction through
  one side-effect-free Rust core, shared by JavaScript, Python, Rust, and CLI
  consumers. The canonical `conformance/` corpus defines cross-language behavior.
- The first release artifact set comprises the `redact-secret` Rust library,
  `redact-secret-cli` crate and `redact-secret` binary, the `redact-secret` PyPI
  distribution (import `redact_secret`), and the `@redact-secret/core` npm
  package with `@redact-secret/wasm` and six `@redact-secret/node-<platform>`
  runtime dependencies. All share one version and source revision.
- The TypeScript detector implementation has been removed. JavaScript exposes
  policy and placeholder formatter callbacks over safe metadata; it does not
  restore the retired custom-detector API. Rust retains its native detector
  traits and registry; custom detector callbacks do not cross language bindings.

### Public behavior and support

- Whole-input scan, redaction, and combined operations return finding metadata
  without matched values. Ranges refer to the original input: UTF-8 bytes in
  Rust and CLI, UTF-16 code units in JavaScript, Unicode code points in Python.
- Default policy blocks private keys, redacts known credential structures and
  other high-confidence findings, and warns on other findings. Redaction
  replaces `redact` and `block` spans; `warn` and `allow` preserve text. Hosts
  enforce `block`. Caller-supplied overlapping redaction ranges are rejected.
- Built-in coverage includes private keys, provider token families,
  authorization/JWT credentials, contextual assignments, credential-bearing
  connection URLs, and OTP shared-secret URIs. See the
  [detection reference](docs/reference/detection.md) for supported formats and
  precision/recall limits. Entropy alone is not a detection signal sufficient
  to classify arbitrary text.
- Rust, Python, and CLI standard input support bounded incremental sanitization.
  JavaScript session and stream factories fail with `INCREMENTAL_UNAVAILABLE`
  on both current artifacts; exported adapter contracts do not imply support.
- JavaScript is ESM with explicit `await initialize()`. Node.js 20, 22, and 24
  support glibc Linux, macOS, and Windows on x64 and arm64. npm and CLI ship six
  non-musl targets. The two additional musl addons are qualified only, with no
  npm publication path. Browsers require ES2022 and WebAssembly; qualification
  covers Chromium, Firefox, and WebKit.
- Python provides typed CPython 3.10+ abi3 wheels for eight targets: manylinux,
  musllinux, macOS, and Windows on x64 and arm64. Source builds require Rust;
  the workspace MSRV is 1.88. See the [qualification matrix](docs/qualification.md).
- CLI check mode reports safe metadata with exit codes 0 (clean), 1 (findings),
  and 2 (failure); redaction returns 0 or 2. Text source labels escape control
  characters and backslashes, and JSON preserves source identity.

### Security and release evidence

- The core has no runtime I/O, environment lookup, telemetry, or secret storage.
  Errors use fixed, input-free codes and messages; callback errors and unsafe
  placeholders fail closed. Client scanning is preventive UX; server scanning
  is authoritative. Hosts must bound whole-input resources and Python chunks.
- Version lockstep includes the private root manifest, every Cargo member,
  JavaScript facade, and all native/Wasm manifests. The legacy-identifier gate
  rejects unintended old identities, including in this changelog.
- The pinned OpenGrep engine and vendored rules are verified against the reviewed
  baseline. The CI gate fails on unresolved findings or unacknowledged scan
  errors independently of best-effort SARIF upload. A baseline pass is not a
  claim of zero findings or complete parser coverage.
- Qualification, package-content checks, and clean packed-package consumer
  tests precede publication. The release graph verifies all seven npm runtime
  dependencies before publishing the facade and records durable manifests for
  successful and failed runs. Reconciliation requires separate authorization.
- This first beta consolidates the unpublished development history; the former
  dated entry was not a published release. All packages were published from
  the original qualified RC source; recovery verified existing content before
  skipping it, and all seven registry-install lanes passed.
