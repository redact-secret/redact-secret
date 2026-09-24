# Issue #726 — Beta.8 family-contract freeze

[Audit archive](../../README.md) ·
[Issue #726](https://github.com/redact-secret/redact-secret/issues/726) ·
[Benchmark research index #215](https://github.com/redact-secret/redact-secret-benchmarks/issues/215) ·
[Spec: detector families](../../../specs/detector-families.md)

Written 2026-09-24 on branch `chore/726-freeze-family-contracts`. This is the
mandatory selection and lexical-separability gate for the 15 Beta.8 arrival
families. It freezes product intent before #727–#730 implement or refine any
detector. It changes no detector, fixture, taxonomy, support status, package,
version, or release record.

## Verdict

All 15 proposed families have an honest offline contract. No replacement from
#523 or #524 is required. The first ten remain the first wave and the final
five remain the second wave. A qualification route below is the route a family
must satisfy before becoming `stable`; it is not a support-status promotion.

The contracts consume the completed broad-discovery research routed by
[benchmarks#215](https://github.com/redact-secret/redact-secret-benchmarks/issues/215#issuecomment-5813551130)
and the integrated, synthetic arrival evidence in benchmark PR #238. The
durable measurement records are:

- [AI inference families (#208)](https://github.com/redact-secret/redact-secret-benchmarks/blob/722378e09ae87175296d2e579a08c8da3ceb6f72/docs/reports/2026-09-24-beta8-208-first-run.md)
- [LangSmith and Langfuse (#210)](https://github.com/redact-secret/redact-secret-benchmarks/blob/722378e09ae87175296d2e579a08c8da3ceb6f72/docs/reports/2026-09-24-beta8-210-first-run.md)
- [developer credentials (#211)](https://github.com/redact-secret/redact-secret-benchmarks/blob/722378e09ae87175296d2e579a08c8da3ceb6f72/docs/reports/2026-09-24-beta8-211-first-run.md)
- [second-wave families (#212)](https://github.com/redact-secret/redact-secret-benchmarks/blob/722378e09ae87175296d2e579a08c8da3ceb6f72/docs/reports/2026-09-24-beta8-212-first-run.md)

Those records were produced in **published** mode against
`@redact-secret/core@0.1.0-beta.7`, gitleaks 8.30.1, TruffleHog 3.97.4 (version
checked in the run shell), and flare-redact 1.6.1. Benchmark measurements stay
in `redact-secret-benchmarks`; they are linked here and are not copied into
this repository.

## Frozen portfolio and grammar

`documented` means the stable route may use the provider-documented profile.
`empirical` means the family keeps its T2 or mixed provenance and must meet
the safe-observation and stronger fixture gates in benchmarks#177, #205 and
#206. A provisional or unresolved field is deliberately not a negative rule.

| Wave | Family and role | Frozen supported grammar | Evidence and qualification route | Supported contexts |
| --- | --- | --- | --- | --- |
| 1 | `replicate:api-token` — inference API bearer/token credential | `r8_` plus 37 bytes; 40 total. Body admits `[A-Za-z0-9_-]`; the alphabet is provisional, so `-` and `_` are not negative twins. | T1 prefix and total length; alphabet tool-corroborated. **documented**. | Bare, `REPLICATE_API_TOKEN`, Bearer and legacy Token headers, SDK/config, structured files, prose and tool output. |
| 1 | `groq:api-key` — inference API credential | `gsk_` plus exactly 52 alphanumeric bytes. The reported internal `WGdyb3FY` segment is not required. | T2 tool-corroborated; provider pages show only a prefix placeholder. **empirical**. | Bare, `GROQ_API_KEY`, Bearer/OpenAI-compatible clients, SDK/config, structured files, prose and tool output. |
| 1 | `xai:api-key` — inference API credential | `xai-` plus exactly 80 bytes from the provisional union `[A-Za-z0-9_-]`. | Prefix is T1; length is provider-example plus tool evidence; alphabet remains provisional. **empirical**. | Bare, `XAI_API_KEY`, Bearer, OpenAI-compatible/LangChain/Vercel configuration, structured files, prose and tool output. |
| 1 | `openrouter:api-key` — inference API credential | `sk-or-v1-` plus exactly 64 lowercase hexadecimal bytes; 73 total. `sk-or-mgmt-` is a separate, unclaimed secret family. | T1 provider guardrail documentation and create-key example, tool-corroborated. **documented**. | Bare, `OPENROUTER_API_KEY`, Bearer/OpenAI-compatible clients, SDK/config, structured files, prose and tool output. |
| 1 | `langsmith:api-key` — observability PAT or service key | `lsv2_(pt|sk)_` + 32 lowercase hex + `_` + 10 lowercase hex. Legacy `ls__`, license, SCIM, OAuth, deployment and `X-Service-Key` JWT credentials are unclaimed siblings. | T2 tools; provider docs establish roles and contexts, not the lexical segments. **empirical**. | Bare, `LANGSMITH_` and legacy `LANGCHAIN_` variables, `X-API-Key`, OTLP header lists, SDK/profile JSON and nested observability metadata. |
| 1 | `langfuse:secret-key` — issuer-minted observability secret key | `sk-lf-` plus a lowercase UUIDv4 body (42 total). `pk-lf-` is public. Arbitrary self-hosted values and `sk-lf-gw-` are outside the claim. | T2 provider-code minted shape; provider docs establish prefixes and roles. **empirical**. | Bare, env/SDK configuration, Basic-auth pair, OTLP headers and nested observability metadata; encoded Basic-auth blobs remain unclaimed. |
| 1 | `github:fine-grained-personal-access-token` — repository/API user credential | `github_pat_` + 22 alphanumeric + `_` + 59 alphanumeric. No checksum or fixed `11` lead is claimed. | T2: prefix provider-documented; segments community/staff-endorsed and tool/implementation-corroborated. **empirical**. | Bare, `GH_TOKEN`, Authorization headers, CLI/config, structured files, prose and tool output. |
| 1 | `slack:app-level-token` — app/Socket Mode credential | `xapp-` followed by four dash-separated sections in digit/alphanumeric/digit/alphanumeric order. Section widths and alphabets stay open. | T2: prefix provider-documented; section anatomy is provisional provider-code/tool evidence with contradictory peers. **empirical**. | Bare, Socket Mode/Bearer, env/SDK/JSON configuration, structured files, prose and tool output. |
| 1 | `stripe:webhook-signing-secret` — webhook authenticity credential | Context-gated `whsec_` + at least 32 Base64-alphabet bytes with optional terminal padding. `+`, `/`, and `=` are admitted; no fixed width, checksum or mode marker is claimed. | T1 provider prefix/configuration context; body breadth is provider-code/example plus tools. **documented, context-constrained**. | Stripe dashboard/API/CLI configuration, webhook verification code, rolling-secret pairs and named assignments; bare prefix matches are not the sole qualification claim. |
| 1 | `notion:integration-token` — current integration/PAT-like API credential | `ntn_` + 11 digits + 35 alphanumeric bytes. `secret_` is the separately supported legacy family; `nrt_` and `development_ntn_` are unclaimed. | T2: prefix provider-documented; body segmentation tool-corroborated. **empirical**. | Bare, env, Bearer, SDK/config, internal integration/PAT/OAuth contexts, structured files, prose and tool output. |
| 2 | `perplexity:api-key` — inference API credential | `pplx-` + exactly 48 alphanumeric bytes; 53 total. Analytics and MCP OAuth shapes are unclaimed. | T2: provider-visible prefix; body width/alphabet tool-only. **empirical**. | Bare, `PERPLEXITY_API_KEY`, Bearer, console/SDK/config, structured files, prose and tool output. |
| 2 | `fireworks-ai:api-key` — inference/training API credential | `fw_` + either 22 or 24 alphanumeric bytes. These widths are positive hypotheses, not exhaustive negative boundaries. `fpk_` Fire Pass and possible unprefixed legacy keys are unclaimed. | T1 prefix, provider-code prefix check, provisional aggregate observation for widths/alphabet. **empirical**. | Bare, `FIREWORKS_API_KEY`, Bearer, console, `firectl`, SDK/config, structured files, prose and tool output. |
| 2 | `pinecone:api-key` — vector database control/data-plane credential | `pcsk_` + 5–6 alphanumeric label + `_` + 63 alphanumeric secret. Documented `pckey_` remains unresolved, not a negative. Legacy UUID keys are a separate context-only candidate. | T2 provider-code segments plus tool widths; provider documentation contradicts the observed prefix. **empirical**. | Bare current keys, `PINECONE_API_KEY`, `Api-Key` headers, Admin API/CLI/SDK configuration, structured files, prose and tool output. |
| 2 | `slack:user-token` — user-impersonating Slack API credential | `xoxp-` + three numeric sections + a final secret section, dash-separated. Exact numeric widths and secret width/alphabet are not frozen. Rotation, service-token and browser-session siblings are unclaimed. | T1 prefix and section semantics; provider example supplies section count. **documented**. | Bare, OAuth response, Authorization header, env/SDK/config, structured files, prose and tool output. |
| 2 | `gitlab:runner-authentication-token` — runner registration/authentication credential | `glrt-` + 20-byte friendly-token body, optionally `t<hex>_`-partitioned; or the routable `<payload>.<2 base36>.<2 base36 length><7 base36 CRC32>` form, whose length holder and CRC32 are validated offline. | T2: prefix provider-documented; legacy body, routable grammar and checksum provider-code-backed. **empirical**. | Bare, CLI/API responses, `config.toml`, env/structured configuration, logs and tool output. `glrtr-`, instance prefixes and unversioned routable forms are unclaimed. |

## Collision boundary, measured overlap and trade-offs

The “current overlap” column is the published beta.7 measurement from the
four linked benchmark reports. It is not an estimate. “None observed” means
the arrival corpus did not rely on `authorization_credential`, JWT or
connection-string detection for coverage; it does not claim those generic
detectors can never encounter the byte sequence.

| Family | Public identifiers and safe confusables | Bare or context requirement | Current generic/provider overlap | Principal FP/FN trade-off |
| --- | --- | --- | --- | --- |
| Replicate | `r8.im/` registry paths, model/version IDs, masks and placeholders | Bare supported | 2/9 positives through bearer/generic; no authorization/JWT/connection overlap observed | Union alphabet avoids charset FN; exact total length may miss format drift. |
| Groq | project/model IDs, prefix placeholders and masks | Bare supported | 2/9 through bearer/generic only | Exact tool width buys precision but requires empirical confirmation; the internal observed segment is intentionally ignored. |
| xAI | API-key/team UUIDs, ACL strings, model IDs and masks | Bare supported | 5/9 through bearer/generic; one public ACL string currently false-alarms via generic-token | Broad alphabet avoids tool-disagreement FN; exact example-derived width may age. |
| OpenRouter | public 64-hex key hash, model IDs, masks; management keys are secrets, not controls | Bare supported | 3/9 through bearer/generic only | Exact provider shape is precise; management and uppercase variants remain intentional gaps. |
| LangSmith | workspace/org IDs, endpoints, masks, OAuth/SCIM identifiers; sibling credentials are secrets | Bare supported | 2/8 through generic-token only | Exact tool segments separate well but can miss legacy/self-hosted or future keys. |
| Langfuse | public `pk-lf-`, project/org/trace IDs, hosts, masks and self-hosting placeholders | Bare only for issuer-minted shape | 3/8 through generic/bearer | Minted UUIDv4 rule protects the public sibling; arbitrary self-hosted secrets remain out of scope. |
| GitHub fine-grained PAT | token IDs, audit-log hashes, classic PAT and `ghs_` JWT siblings, masks/placeholders | Bare supported | 10/10 exact through existing `github-token`; one case twin co-detected by bearer | Strict segments reduce prefix-only FP but rest below provider-documentation grade. |
| Slack app token | app/workspace/team IDs, bot/refresh siblings, masks/placeholders | Bare supported | 10/10 exact through current interim `slack-token`; `_` separator and letter-in-digit twins are also flagged | Freezing only anatomy avoids false exclusions; the open widths make the interim detector overbroad until #729. |
| Stripe webhook secret | endpoint/destination/event IDs, publishable keys, signature digests, masks; non-Stripe `whsec_` is unresolved | Context mandatory for qualification | 11/11 exact through existing `stripe-token`; no generic reliance | Broad Base64/open width avoids Stripe-code disagreement FN but can classify another issuer's `whsec_`; context contains that FP risk. |
| Notion integration | page/database/bot/workspace/connection IDs, masks/placeholders; legacy/current and refresh siblings | Bare supported | 10/10 exact through existing `notion-token`; two twins co-detected by generic/bearer | Tool-only body gives precision; provider warns formats may change and roles sharing `ntn_` must not be merged. |
| Perplexity | `pplx-` model/package/host names, masks/placeholders, OpenRouter keys stored under the env name | Bare supported | 4/8 through bearer/generic only | Exact tool width separates public names but is unconfirmed and may miss other generations. |
| Fireworks | `fw_id`, `fw_version`, `fw_spec`, keychain references, masks and account/key IDs | Bare supported only for the two observed widths | 3/8 through bearer/generic; keychain reference currently false-alarms via generic-token | Prefix alone collides broadly; two observed widths limit FP but must not be treated as exhaustive. |
| Pinecone | project/index/key/service-account UUIDs, index hosts, environments, masks/placeholders | Bare for `pcsk_`; legacy UUID requires Pinecone key context | 3/8 current positives through generic-token; placeholder currently false-alarms. Legacy UUID: 3/12 through generic | Current segmented form is separable; `pcsk_`/`pckey_` contradiction and lexically indistinguishable legacy UUIDs remain explicit. |
| Slack user | team/user/bot IDs, `xoxb-`, masks/placeholders; rotation/service/browser tokens are secrets | Bare supported | 7/8 exact through existing `slack-token`; documented pre-2016 short secret missed | Open widths avoid rejecting provider-valid generations; structural rule is broader than tool-specific widths. |
| GitLab runner auth | runner/system IDs, short SHAs, masks/references and registration-token identifiers | Bare supported | legacy/partitioned 3/3 exact through `gitlab-token`; routable 4/4 partial, leaving 13 bytes after the first dot exposed | Offline checksum sharply reduces FP; parser/retention cost is higher, and unverified `glrtr-`/instance prefixes stay FN. |

No contract treats a sibling credential as a benign value. JWT-shaped siblings
(for example GitHub `ghs_` or LangSmith `X-Service-Key`) remain separate secret
families, not allowlisted controls. No family is justified by assumed
connection-string coverage.

## Expected implementation and ledger cost

These are relative design estimates, not artifact measurements. #727–#730
must run the repository's detector-cost and WASM-profile checks after code
exists.

| Family group | Expected binary/WASM work | Evidence and ledger cost already paid |
| --- | --- | --- |
| Replicate, Groq, xAI, OpenRouter | Low: fixed-prefix table shapes; no checksum or context state | 24 fixtures each; #208 currently has 59 open product rows, primarily missing provider coverage. |
| LangSmith, Langfuse | Low–medium: segmented fixed shapes; Langfuse UUIDv4 validation | 24 fixtures each; #210 has 22 open rows. |
| GitHub, Slack app, Stripe, Notion | Low for GitHub/Notion classification; medium for Slack section refinement and Stripe context/breadth | 24–25 fixtures each; #211 has 9 open rows, including Slack shared-detector twins. Existing detectors already cover every positive span. |
| Perplexity, Fireworks | Low: prefixed table shapes, with Fireworks' two provisional widths | 24 fixtures each; their gaps are included in #212's 45 open rows. |
| Pinecone | Medium: segmented current key plus a separate context-gated legacy UUID path | 24 current-key fixtures plus a separate 48-case legacy profile; included in #212's 45 open rows. |
| Slack user | Medium: reuse/refine the existing section parser and split taxonomy without a second detector implementation | 24 fixtures; one documented short-token miss, included in #212. |
| GitLab runner | High relative to this portfolio: full dotted-span retention, base36 length and CRC32 verification, while remaining dependency-free | 24 fixtures with checksum-valid synthetic routable cases; partial-span and integrity gaps are included in #212's 45 open rows. |

## Empirical observation plan

Every family routed to **empirical** above uses the same fail-closed plan from
[benchmarks#177](https://github.com/redact-secret/redact-secret-benchmarks/issues/177)
and [#205](https://github.com/redact-secret/redact-secret-benchmarks/issues/205):

1. Collect at least five provider-issued observations across at least two
   pseudonymous accounts/projects and two issuance dates.
2. Record only structural metadata: family, date, issuance route, pseudonymous
   account/project, total and segment lengths, alphabet classes, separators,
   checksum behavior, revocation state, independence class, and
   `rawValueRetained: false`.
3. Never store, hash, log, transmit, screenshot, paste or derive a fixture from
   the credential. Author synthetic fixtures independently.
4. Require two independent corroboration classes and the 40-fixture empirical
   profile (48 for a context-constrained opaque value), with zero critical
   twin, benign, mutation, metamorphic or differential failures.
5. Preserve contradictions and block qualification; never average them into a
   broader grammar or relabel T2 evidence as T1.

The family-specific hands-on checklists remain in benchmarks#216–#230. They
target the unresolved fields named above: character sets, widths and internal
segments; sibling or legacy issuance; display/masking behavior; and, for
GitLab, self-managed `glrtr-`/instance prefixes. Fireworks `fpk_` requires a
paid Fire Pass. No new credential can be issued for a legacy Pinecone UUID
shape; that family remains context-constrained unless existing-key evidence is
available under the safe intake.

## Acceptance checklist

- [x] All 15 families have a frozen contract; no replacement is required.
- [x] The first-wave ten and second-wave five are published in the detector-family spec before implementation.
- [x] Incomplete lexical evidence stays provisional, unresolved or context-constrained; no broad detector is forced.
- [x] Every empirical-route family carries the benchmarks#177/#205 observation plan.
- [x] Existing generic/shared-detector coverage is recorded from the published beta.7 benchmark runs rather than assumed.
- [x] No implementation ships from this issue.
- [x] This record contains no credential value or real-derived fixture material.

## Authority

This record freezes product intent and evidence routing only. It does not
authorize implementation, support-status promotion, a version change, a tag,
publication or release.
