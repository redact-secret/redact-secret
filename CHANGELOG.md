# Changelog

This file records the released product contract and notable changes. Release
evidence is linked from each published version.

## Unreleased

- Narrowed `linear-token`'s `lin_api_` variant to Linear's reviewed API-key
  contract: `lin_api_` followed by exactly 40 bytes of `[A-Za-z0-9]`, bounded
  by the existing `[A-Za-z0-9_-]` boundary alphabet (issue #374, contract
  review #367). gitleaks v8.30.1's `linear-api-key` rule and trufflehog
  v3.97.4's `linearapi` rule independently pin the body to this exact length
  and agree it excludes `_`/`-`. The previous rule accepted any
  20-or-more-byte `[A-Za-z0-9_-]` suffix, so `@redact-secret/core@0.1.0-beta.4`
  flagged a 39-byte twin of the benchmark's paired positive; that twin is now
  rejected while the paired positive keeps its exact byte range. Intentional
  behavior changes: a body one byte short of or past 40 bytes, or an
  underscore or dash inside an otherwise documented-length body, no longer
  match. `lin_oauth_` is unaffected: no consulted provider or tool source
  documents its grammar (Linear's own OAuth example is a bare 64-character
  hex string), so it keeps beta.4's 20-byte-minimum `[A-Za-z0-9_-]` rule
  unchanged as a separate interim guard, and the 40-byte API-key length is
  deliberately not reused for it. The detector moved out of the shared
  `KnownFormatProviderDetector` shape in `additional_providers.rs` into its
  own `linear.rs` module, composed directly from the shared `pattern`
  primitives, because the two prefixes now need different suffix alphabets
  that single shared type cannot express — the same way `slack-token` and
  `cloudflare-token` moved out for their own per-prefix needs.
- Narrowed `cloudflare-token` to Cloudflare's reviewed scannable user-token
  contract: `cfut_` followed by exactly 40 bytes of `[A-Za-z0-9]` (the body)
  and then exactly 8 bytes of `[0-9a-f]` (the checksum), bounded by the
  existing `[A-Za-z0-9_-]` boundary alphabet (issue #373, contract review
  #367). Cloudflare's token documentation establishes the `cfut_` prefix and
  the 40-byte alphanumeric body; trufflehog v3.97.4's `cloudflareapitoken` v2
  rule additionally corroborates the 8-byte lowercase-hex checksum segment
  that follows it — the provider states a checksum follows the body but does
  not publish its width or alphabet, so its existence is provider evidence
  (a bare 40-byte body is malformed) while its width and alphabet are a
  single-tool-corroborated support-policy adoption, validated lexically only:
  no checksum algorithm is computed or claimed. The previous rule accepted
  any 20-or-more-byte `[A-Za-z0-9_-]` suffix, so
  `@redact-secret/core@0.1.0-beta.4` flagged an eight-byte non-hex twin of the
  benchmark's paired positive; that twin is now rejected while the paired
  positive keeps its exact byte range. Intentional behavior changes: a body
  one byte short of or past 40 bytes, an underscore or dash inside an
  otherwise documented-length body, a checksum one byte short of or past 8
  bytes, or an uppercase-hex checksum no longer match. The detector moved out
  of the shared `KnownFormatProviderDetector` shape in
  `additional_providers.rs` into its own `cloudflare.rs` module, composed
  directly from the shared `pattern` primitives plus a post-hoc checksum
  check, the same way `grafana-service-account-token` and `sendgrid-token`
  already handle their own two-segment shapes. The earlier broad-shape
  positives in the conformance corpus were re-authored with a contracted
  body and checksum; the repeated-`x` filler placeholder
  (`cloudflare-positive-doc-style-placeholder`) and the retired minimum-length
  positive (`cloudflare-positive-min-length`) are now reclassified as
  intentional false negatives in favor of a dedicated
  `cloudflare-token-checksum-suffix` grammar-mutation family (identity,
  body-one-short, body-one-long, body-invalid-alphabet, checksum-one-short,
  checksum-one-long, checksum-non-hex, checksum-uppercase-hex —
  `conformance/fixtures/cloudflare-token-mutations.ts` reproduces every case
  byte-for-byte), and the `cloudflare-adversarial-long-suffix` input now
  yields exactly one finding bounded to the documented 48-byte suffix instead
  of matching the whole 11251-byte run. No detector id, finding type,
  confidence, specificity, default policy, or public interface changed. The
  fixed release-qualification accuracy corpus is deliberately not rewritten:
  its `logs-additional-provider-tokens-one` fixture's underscore-bearing
  Cloudflare value now records as a false negative until the beta.5
  precision gate (#376) re-versions that corpus.

- Narrowed `huggingface-token` to Hugging Face's reviewed user-access-token
  contract: `hf_` followed by exactly 34 bytes, matched case-sensitively and
  bounded by the existing `[A-Za-z0-9_-]` boundary alphabet (issue #372,
  contract review #367). gitleaks v8.30.1 and trufflehog v3.97.4 independently
  agree on the 34-byte length; the two tools disagree on the body alphabet
  (gitleaks: letters only; trufflehog: letters and digits), and that conflict
  is resolved as a support-policy choice for the union `[A-Za-z0-9]` rather
  than guessed into the letters-only intersection, so a digit-bearing body is
  still accepted even though it stays unscored (T0) in the benchmark corpus
  pending independent review. The previous rule accepted any 20-or-more-byte
  `[A-Za-z0-9_-]` suffix, so `@redact-secret/core@0.1.0-beta.4` flagged a
  33-byte twin of the benchmark's paired positive; that twin is now rejected
  while the paired positive keeps its exact byte range. Intentional behavior
  changes: an underscore or dash inside an otherwise documented-length body,
  or a body one byte short of or past 34 bytes, no longer matches — both tools
  agree the body excludes `_`/`-`, so that acceptance under the retired shared
  rule was a shared-rule artifact, not evidence. The earlier broad-shape
  positives in the conformance corpus were re-authored with contracted
  bodies; the repeated-`x` filler placeholder
  (`huggingface-positive-doc-style-placeholder`) and the retired minimum-length
  positive (`huggingface-positive-min-length`) are now reclassified as
  intentional false negatives in favor of a dedicated
  `huggingface-token-exact-length` grammar-mutation family (identity,
  one-short, one-long, invalid-alphabet, underscore-in-body, dash-in-body,
  digit-bearing — `conformance/fixtures/huggingface-token-mutations.ts`
  reproduces every case byte-for-byte), and the
  `huggingface-adversarial-long-suffix` input now yields exactly one finding
  bounded to the documented 34-byte body instead of matching the whole
  11250-byte run. No detector id, finding type, confidence, specificity,
  default policy, or public interface changed. The fixed release-qualification
  accuracy corpus is deliberately not rewritten: its `code-additional-provider-tokens-one`
  fixture's underscore-bearing Hugging Face value now records as a false
  negative until the beta.5 precision gate (#376) re-versions that corpus.

- Narrowed the `slack-token` detector's `xoxb-` bot form (issue #371,
  `docs/decisions/2026-09-17-freeze-slack-bot-token-segment-grammar.md`) from
  one shared 20-byte minimum of `[A-Za-z0-9_-]` to the reviewed three-section
  shape `xoxb-<10-13 digits>-<10-13 digits>-<18+ alphanumeric>`: the
  provider documents sections as `-`-separated with the final section as the
  secret, so a value whose second numeric section runs straight into the
  secret with no separator is now an intentional false negative, not a
  fuzzy match. The published beta.4 package flagged the benchmark's two
  missing-separator twins of this shape; both are now silent, and both
  paired positives are preserved. Every other documented prefix (`xoxp-`,
  `xapp-`, `xwfp-`, `xoxe-`, `xoxe.xoxb-`, `xoxe.xoxp-`) keeps beta.4's rule
  unchanged as a separate interim guard. Thirteen synchronous and two
  incremental conformance fixtures that had been authored to the retired
  shared minimum with no digit sections keep their inputs and have their
  expectations corrected in place, each note naming the decision; a
  full-grammar value under a generic assignment key
  (`slack-overlap-context-bot-grammar`) still resolves to `slack-token`
  over `generic-token`'s contextual candidate, while a body with no digit
  sections under the same key (`slack-overlap-context`) is now owned by
  `generic-token` instead, and the same body after a literal `Bearer`
  scheme (`slack-positive-unicode-byte-offset`) is now owned by
  `bearer-token`. Detector id, finding type, confidence, specificity,
  default policy, and every public interface are unchanged. Internally,
  Slack moved out of the shared `KnownFormatProviderDetector` shape into
  its own module (`crates/secret-scan-core/src/detectors/slack.rs`), since
  the bot section grammar needs a `-`-separated section shape the shared
  prefix-plus-run primitives cannot express; its other prefixes keep the
  same interim shape, composed directly from the shared `pattern`
  primitives.

- Narrowed the `docker-token` detector (issue #370,
  `decision-freeze-docker-pat-oat-exact-length-grammar`) from one shared
  20-byte minimum under either prefix to two separately validated
  exact-length shapes: `dckr_pat_` followed by exactly 27 bytes of
  `[A-Za-z0-9_-]` (personal access token) and `dckr_oat_` followed by
  exactly 32 bytes of the same alphabet (organization access token), the
  lengths trufflehog's `dockerhub` v2 detector (`v3.97.4`) enforces. The
  published beta.4 package flagged the benchmark's 26-byte and 31-byte
  near-miss twins of both shapes; those, a one-byte-long suffix, and either
  length under the other prefix are now intentional false negatives. Every
  previously supported 27-byte fixture is preserved, and both exact shapes
  are now covered bare, quoted, in JSON/dotenv/YAML/log/Markdown, after
  Unicode/CRLF, repeated, adjacent to their twins, under contextual
  assignment keys, and across every incremental chunk split
  (`conformance/fixtures/docker-token-mutations.ts` reproduces the
  boundary mutations byte-for-byte). Seven synchronous and two incremental
  conformance fixtures that had been authored to the retired minimum with
  20-, 25-, 36-, or 11250-byte suffixes keep their inputs and have their
  expectations corrected in place, each note naming the decision; a 36-byte
  value under a generic assignment key (`docker-overlap-context`) is now
  owned by `generic-token` as a `contextual_secret` and is still redacted.
  Detector id, finding type, confidence, specificity, default policy, and
  every public interface are unchanged. The fixed release-qualification
  accuracy corpus is deliberately not rewritten: its one 26-byte Docker
  value (`logs-additional-provider-tokens-one`) now records as a false
  negative (Rust adapter 21/1/5 to 20/1/6) until the beta.5 precision gate
  (#376) re-versions that corpus. Internally, `pattern.rs` gains
  `PrefixShape` and `scan_prefixed_shapes` so one detector can carry a
  different run length per prefix; every other prefix-run detector's
  behavior is unchanged.

- Narrowed `openai-token` to OpenAI's actual key grammar (issue #368,
  `docs/decisions/2026-09-17-freeze-openai-api-key-grammar.md`). A value is
  now classified only when it carries the literal `T3BlbkFJ` marker (base64
  `OpenAI`) between two segments of a source-documented exact length:
  `sk-` + 20 + marker + 20 alphanumerics (legacy), or
  `sk-proj-`/`sk-svcacct-`/`sk-admin-` + 74 or 58 + marker + 74 or 58 bytes
  of `[A-Za-z0-9_-]`, each variant validated independently with no fallback
  from a malformed namespaced form to the legacy form. The previous rule
  accepted any `sk-` value with a 20-byte minimum suffix, which flagged the
  six beta.4 benchmark controls that differ from a real key by one marker
  byte or one segment byte. Marker-less `sk-` values are no longer
  classified by this detector; an assignment such as `api_key=` or a Bearer
  credential carrying one still surfaces through `generic-token` or
  `bearer-token`. `sk-admin-` is newly named as a supported namespace (it
  was already caught by the old bare branch); `sk-service-` is documented
  as unsupported. Detector id, finding type, confidence, policy class, and
  the public API are unchanged. The fourteen pre-existing marker-less
  corpus positives are kept and reclassified in place, with
  contract-conformant counterparts, the issue's twelve inputs, and
  one-byte-off boundary mutations added to the synchronous and incremental
  corpora. The assessment accuracy corpus's `code-openai-api-key` fixture is
  intentionally left for the next evidence re-pin (see the decision record).

- Narrowed `digitalocean-token` to DigitalOcean's reviewed v1 token contract:
  each documented prefix (`dop_v1_` personal access token, `doo_v1_` OAuth
  access token, `dor_v1_` OAuth refresh token) followed by exactly 64
  lowercase hexadecimal bytes, matched case-sensitively and bounded by the
  existing `[A-Za-z0-9_-]` boundary alphabet (issue #369, contract review
  #367). DigitalOcean's API release notes (2022-03-29) establish the prefixes;
  gitleaks v8.30.1 and trufflehog v3.97.4 independently pin the body to
  `[a-f0-9]{64}`. The previous rule accepted any 20-or-more-byte
  `[A-Za-z0-9_-]` suffix, so `@redact-secret/core@0.1.0-beta.4` flagged a
  63-byte twin of every paired positive (six must-not-flag benchmark files);
  those twins are now rejected while every paired positive keeps its exact
  byte range. Intentional behavior changes: a 65-byte or wider hex run, an
  uppercase hex digit, a non-hex body byte, or a body shorter than 64 bytes no
  longer matches, so the earlier broad-shape positives in the conformance
  corpus were re-authored with contracted bodies; the repeated-`x` filler
  placeholder (`digitalocean-positive-doc-style-placeholder`) is now the
  negative `digitalocean-negative-doc-style-placeholder`, the minimum-length
  positive `digitalocean-positive-min-length` was retired in favor of the
  `digitalocean-v1` identity/short-length mutation pair, and the
  `digitalocean-adversarial-long-suffix` input now yields zero findings. No
  detector id, finding type, policy class, public option, or result shape
  changed. The `assessment/fixtures/accuracy-corpus.json` fixture
  `logs-additional-provider-tokens-one` still carries a pre-contract
  DigitalOcean value with a `redact` expectation; that corpus is
  hash-pinned to the committed acceptance results, so it is left for the
  beta.5 qualification pass (#376) to re-version rather than edited here.

- Froze reviewed precision contracts for the `openai-token`,
  `digitalocean-token`, `docker-token`, `slack-token`, `huggingface-token`,
  `cloudflare-token` and `linear-token` detectors (issue #367, decision
  `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`).
  This is evidence and tooling only: `docs/audits/evidence/367/` records each
  family's supported variants, segment grammar, lengths, alphabets, markers,
  source provenance and resolved source conflicts, freezes the beta.4
  negative-twin baseline by construction recipe and content hash, and audits
  every existing fixture for those families against the contract.
  `npm run precision-contracts:check` (now part of `npm run ci`) keeps the
  derived evidence consistent. No detector behavior, public interface,
  detector id or finding type changes in this entry; the behavior changes
  the contracts call for land with issues #368-#374 and are described in the
  decision record.

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

[Publication status and recovery evidence](docs/releases/status.md).

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

## 0.1.0-beta.2 — 2026-09-13

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
