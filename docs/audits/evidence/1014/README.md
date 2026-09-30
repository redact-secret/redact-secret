# Issue #1014: Beta.12 broad discovery, 50 new provider credential candidates

[Audit archive](../../README.md) ·
[Issue #1014](https://github.com/redact-secret/redact-secret/issues/1014) ·
[Previous wave #860](../860/README.md) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen record of step 1 (broad discovery) and a first step 3 (deep handoffs)
for #1014, written 2026-09-29. It ranks 50 provider credential candidates by
how likely each is to reach T1 under the maintainer rulings R1–R10 recorded on
[#860](https://github.com/redact-secret/redact-secret/issues/860), and it
writes handoffs for the ten candidates whose supported grammar is already T1.

This is a research funnel, not a promise to ship 50 detectors. It changes no
detector, fixture, finding type, support status, package, version or release
record, and it does not authorize implementation. Step 5 of #1014 opens
separately scoped product and benchmarks issues only after the maintainer
reviews these handoffs.

Addendum, 2026-09-30: the ten "T1 without a handoff" candidates of the
[2026-09-30 status](https://github.com/redact-secret/redact-secret/issues/1014)
(ranks 11, 14–17, 19, 20, 24, 26, 28) now have step-3 records, every one of
the 50 candidates has an explicit step-4 disposition, and step 5 is drafted
(see [Step 4](#step-4-disposition-of-all-50-candidates) and
[Step 5](#step-5-implementation-issues-to-open)). The ranked table above is the
frozen step-1 state and is not rewritten.

No key was issued for this research. No value here is, or is derived from,
an issued or leaked credential, and no complete key-shaped example appears:
shapes are given by prefix, length, alphabet and separators only. Provider
fixtures and documentation examples are described, not reproduced.

## Scope and exclusions

The 50 candidates exclude every family in the
[built-in inventory](../../../reference/detection.md) and in
`benchmarks/support-matrix.json` (152 families) at `main`
[`b9e9091`](https://github.com/redact-secret/redact-secret/commit/b9e909155a3d1cbad29afa617dd8dd4cc72599d2),
the 50 candidates of [#860](https://github.com/redact-secret/redact-secret/issues/860)
and the 15 of [#774](https://github.com/redact-secret/redact-secret/issues/774).
CircleCI and Buildkite were named as follow-up candidates in the
[#523 CI-provider ranking](../523/README.md); they are researched here for the
first time.

## Method

Discovery started broad and labelled source classes afterwards:

- the GitHub secret-scanning partner list (`github/docs`
  `src/secret-scanning/data/pattern-docs/fpt/public-docs.yml` at
  [`f187b6c`](https://github.com/github/docs/blob/f187b6c1617910ea799e8f84ad7e2b4c8697672c/src/secret-scanning/data/pattern-docs/fpt/public-docs.yml),
  2026-09-29), used as the first candidate pool;
- scanner rule sets, pinned: gitleaks
  [`b58d3f1`](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml),
  trufflehog
  [`48b58d3`](https://github.com/trufflesecurity/trufflehog/tree/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors),
  noseyparker
  [`2e6e7f3`](https://github.com/praetorian-inc/noseyparker/tree/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules),
  betterleaks
  [`fa62e6a`](https://github.com/betterleaks/betterleaks/tree/fa62e6aaad9de6da71de49e7114234700c84006e),
  CredSweeper and Google osv-scalibr Veles (Kingfisher now imports the
  betterleaks and Veles rules and was not counted separately);
- provider documentation, changelogs and provider-authored code (server
  generators and validators, SDK and CLI parsers, provider-authored redaction
  or lint rules), then forums and community posts.

Each fact is graded with the #860 rulings. T1: provider documentation,
provider code (R1, dated per R9), a provider-authored scanner or redaction
rule (R2), a dated staff statement (R3), docs placeholders for the prefix
only (R4), a docs example plus SDK fixtures for length and alphabet (R5), and
runtime `startsWith` checks for the prefix (R6). T2: code comments, third-party
scanner rules, partner-list presence, and empirical observation. T3: no
grammar beyond role and existence, or an unprefixed shape. A candidate's
**likely tier** is its weakest fact that a distinct detector would need.

**Ranking.** Candidates are ordered first by likely tier, then by how much of
the grammar is T1 without a new ruling, and then by agent-runtime risk
(blast radius of a leak in a prompt, log or tool call), benign-collision risk
and scanner-coverage gap.

The per-candidate research tables are issue comments on #1014 (step 1),
linked from the [Research inputs](#research-inputs) section. The ten
handoff families were re-checked at their cited revisions on 2026-09-29.

## Current coverage on `main` (synthetic probe, 2026-09-29)

**Method.** The CLI was built from `main` at
[`b9e9091`](https://github.com/redact-secret/redact-secret/commit/b9e909155a3d1cbad29afa617dd8dd4cc72599d2)
(`redact-secret` 0.1.0-beta.11, release build). One value per candidate was
generated at run time from a seeded random generator in the claimed shape,
piped to the CLI and never written to disk. Each value was scanned in four
contexts: bare in prose; `PROVIDER_ENV=value` under the provider's documented
variable name; JSON `{"token": "value"}`; and a chat sentence. Only finding
metadata was kept. This measures today's generic coverage. It is not a
recall, precision or support-status measurement.

**Result.**

| Context | Finding today |
| --- | --- |
| bare prose, JSON `"token"`, chat sentence | **none** for all 50 |
| `PROVIDER_ENV=value` | `contextual_secret`, high, redact, full span, for 46 of 50 |

The four env-context misses are side findings for `generic-token`, not
reasons to rank a candidate higher:

- `UNKEY_ROOT_KEY=`, `DEVCYCLE_SERVER_SDK_KEY=` and `AZURE_STORAGE_KEY=` (also
  `AZURE_STORAGE_ACCOUNT_KEY=`) are not recognized as credential names, even
  for a 40-byte random alphanumeric value. The same Unkey value under
  `API_KEY=` is found.
- `FLY_API_TOKEN=FlyV1 fm2_…` unquoted is missed, because the value contains
  the `FlyV1 ` scheme and a space. The quoted form and the form without the
  scheme are found.

One overlap was also measured: a Polar webhook secret (`whsec_` + 43 base62,
Polar's own generator) is reported today as `stripe_webhook_signing_secret`
by `stripe-token`. It is redacted, but it is attributed to the wrong provider.
The [Polar handoff](polar.md) records it.

As with #860, the gap every candidate shares is the **bare, chat and JSON
`"token"`** occurrence, which is the LLM and agent-context case this work
targets.

## Ranked candidates

Tier columns are prefix / length / alphabet, then the likely tier. "Handoff"
names a step-3 document in this folder. Collision risks name existing
families or common benign strings. Provider example values are never
reproduced; quotes are cut at the prefix.

| Rank | # | Candidate | Claimed shape | Best evidence (quote · source · date · class) | P / L / A → likely | Collision risks | Disposition hint |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 1 | 30 | `bitwarden:secrets-manager-access-token` | `0.` + UUID + `.` + 30 `[A-Za-z0-9]` + `:` + 22 std-Base64 + `==` (16-byte key) | "`if version != "0"`" … "`expected: 16`" · [sdk-internal `access_token.rs`](https://github.com/bitwarden/sdk-internal/blob/824c1cf06636daa2778d53435cdbf354ab58eff2/crates/bitwarden-core/src/auth/access_token.rs#L50-L80) · 2025-09-30 · provider code; generator `_clientSecretMaxLength = 30` · [server](https://github.com/bitwarden/server/blob/bb3a9daf9883353fa942a17ba5d8c2b1f642960b/bitwarden_license/src/Commercial.Core/SecretsManager/Commands/AccessTokens/CreateAccessTokenCommand.cs#L14-L29) · provider code | T1 / T1 / T1 → **T1** | none; not a JWT; no scanner or partner rule covers it | **distinct family** · [handoff](bitwarden.md) READY |
| 2 | 48 | `polar:organization-access-token` | `polar_oat_` (+ OAuth/session siblings) + 37 `[A-Za-z0-9]` + 6-char base62 CRC32 = 43 | "`secrets.choice(string.ascii_letters + string.digits) for _ in range(37)`" · [polar `kit/crypto.py`](https://github.com/polarsource/polar/blob/6a4f2f6d6083ef503cd23cb7f432ab2c60515973/server/polar/kit/crypto.py#L11-L32) · 2026-09-21 · provider code | T1 / T1 / T1 → **T1** (checksum verifiable) | Polar `whsec_` webhook secrets already hit `stripe-token`; `polar_ci_` is a public client id | **distinct family** · [handoff](polar.md) READY |
| 3 | 15 | `sonarqube:token` | `sq` + `u`/`a`/`p` + `_` + 40 lowercase hex | "`SONARQUBE_TOKEN_PREFIX = "sq"`" … "`new byte[20]`" `Hex.encodeHexString` · [TokenGeneratorImpl](https://github.com/SonarSource/sonarqube/blob/9ec5e86425011f6c1ffa0eb2db08880e3b347271/server/sonar-webserver-auth/src/main/java/org/sonar/server/usertoken/TokenGeneratorImpl.java#L29-L46) · 2026-04-17 · provider code | T1 / T1 / T1 → **T1** | `sqb_` badge tokens are public in README badge URLs; legacy 40-hex is a git-SHA shape | **distinct family** · [handoff](sonarqube.md) READY |
| 4 | 21 | `rubygems:api-key` | `rubygems_` + 48 lowercase hex | "`"rubygems_#{SecureRandom.hex(24)}"`" · [rubygems.org `api_keyable.rb`](https://github.com/rubygems/rubygems.org/blob/d4cfcc961d08cb5f661f2e5dc0081736233b97ec/app/controllers/concerns/api_keyable.rb#L19-L21) · 2026-03-03 · provider code | T1 / T1 / T1 → **T1** | none | **distinct family** · [handoff](rubygems.md) READY |
| 5 | 23 | `clojars:deploy-token` | `CLOJARS_` + 60 lowercase hex | "`#"^CLOJARS_[0-9a-f]{60}$"`" (server validator) · [clojars-web `db.clj`](https://github.com/clojars/clojars-web/blob/442eb895e7ab3449161848d8c368d4783c5f0067/src/clojars/db.clj#L847-L853) · 2026-09-16 · provider code | T1 / T1 / T1 → **T1** | `CLOJARS_USERNAME`-style env names (fail the 60-hex body) | **distinct family** · [handoff](clojars.md) READY |
| 6 | 22 | `crates-io:api-token` | `cio` + 32 `[A-Za-z0-9]`; sibling `cio_tp_` + 31 + 1 checksum char | "`const TOKEN_PREFIX: &str = "cio";`" "`const TOKEN_LENGTH: usize = 32;`" · [crates.io `token.rs`](https://github.com/rust-lang/crates.io/blob/7b2475e26337856ab054844c9078bb23c11b2f19/crates/crates_io_database/src/utils/token.rs#L10-L14) · 2025-12-01 · provider code | T1 / T1 / T1 → **T1** | `cio` is a 3-letter trigram: exact length and boundary are load-bearing | **distinct family** · [handoff](crates-io.md) READY |
| 7 | 31 | `dynatrace:api-token` | `dt0` + `c`/`s` + 2 digits + `.` + 24 + `.` + 64, base32 `[A-Z2-7]` | "The secret portion of the token is a 64-character string" · [Dynatrace docs](https://docs.dynatrace.com/docs/dynatrace-api/basics/dynatrace-api-authentication) · updated 2026-08-04 · provider docs; `base32.StdEncoding` generator · [dynatrace-operator `dttoken`](https://github.com/Dynatrace/dynatrace-operator/blob/2a39d88a0ee1fbb61e2d22db02520b3dc92ffc80/pkg/util/dttoken/token.go#L14-L58) · provider code | T1 / T1 / T1 → **T1** | the two-part token identifier is documented as safe to log and stays unclaimed | **distinct family** · [handoff](dynatrace.md) READY |
| 8 | 42 | `paddle:api-key` | `pdl_(live\|sdbx)_apikey_` + 26 `[a-z0-9]` + `_` + 22 `[A-Za-z0-9]` + `_` + 3 = 69 | "They're 69 characters in length and always contain five underscores. You can use regex to match API keys" · [Paddle docs](https://developer.paddle.com/api-reference/about/api-keys) · observed 2026-09-29 · provider docs | T1 / T1 / T1 → **T1** | the `apikey_` + 26 key id is a non-secret identifier; pre-2025-05-06 keys are unprefixed 50 `[a-z0-9]` | **distinct family** · [handoff](paddle.md) READY |
| 9 | 32 | `honeycomb:api-key` | ingest `hc[a-z]ik_`/`hc[a-z]ic_` + 58 `[a-z0-9]` (64); management `hc[a-z]mk_` + 26 + `:` + 32 | "The key value is the Key ID and Secret concatenated with no separator" · [Honeycomb docs](https://docs.honeycomb.io/api/authentication) · observed 2026-09-29 · provider docs; "`^hc[a-z]ic_[a-z0-9]*$`" gated on `len(key) == 64` · [libhoney-go](https://github.com/honeycombio/libhoney-go/blob/02e9dbf361012fafbe8698f429b65630500dc10a/libhoney.go#L74-L178) · 2026-04-14 · provider code | T1 / T1 / T1 (ingest) → **T1**; management alphabet T2 | `hc?en_`/`hc?lk_` ids are non-secret; 22-char configuration and 32-hex classic keys are unprefixed | **distinct family** · [handoff](honeycomb.md) READY (ingest); management ISSUANCE-GATED |
| 10 | 33 | `axiom:api-token` | `xaat-` / `xapt-` + lowercase UUID (41) | "`strings.HasPrefix(token, "xaat-")`" · [axiom-go `token.go`](https://github.com/axiomhq/axiom-go/blob/ae983c9447003f74f00e55a2ca64ea119b558fb8/internal/config/token.go#L7-L12) · 2023-09-19 · provider code (R6); docs response example + SDK fixture in UUID layout (R5) | T1 / T1 / T1 → **T1** (R5) | none; the UUID body keeps it apart from `jwt`/`bearer` | **distinct family** · [handoff](axiom.md) READY |
| 11 | 37 | `xata:api-key` | `xau_` / `xao_` + base62 of 20 random bytes + CRC32; fixtures 33, validator cap 40 total | "`lengthBytes = 20`", "`MaxLength = 40`", "`crc32.ChecksumIEEE`" · [xata `key.go`](https://github.com/xataio/xata/blob/fc4ac97f62a3830c4e4202b08a3ca51855970113/internal/api/key/key.go#L19-L57) · 2026-04-15 · provider code | T1 / T1 (bounded) / T1 → **T1** | `xau_` is short: the body window must come from the encoder | distinct family; the body range must be derived from the non-standard `jxskiss/base62` encoder before a handoff |
| 12 | 08 | `azure:storage-account-key` | 88 std-Base64: 76 + `+ASt` + 5 + `[AQgw]` + `==` (Marvin32 checksum) | "`[Base64]{76}{signature}[Base64]{5}[AQgw]==`" · [microsoft/security-utilities](https://github.com/microsoft/security-utilities/blob/638ad20eb4d446319a31e9c0ed293d087b4ffa55/src/Microsoft.Security.Utilities.Core/PreciselyClassifiedSecurityKeys/Azure64ByteIdentifiableKey.cs) · 2025-04-01 · provider-authored scanner (R2); "A combination of 88 characters … Checksum: Yes" · [Purview SIT](https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-access-key) · 2026-06-15 · provider docs | T1 / T1 / T1 → **T1** (needs Q2) | overlaps `connection-string` (`azure`) inside `AccountKey=`; legacy 86 + `==` has no signature | distinct family for the identifiable form; ruling Q2 on Microsoft-authored scanner code |
| 13 | 36 | `datastax:astra-db-application-token` | `AstraCS:` + 24 letters + `:` + 64 (97 total) | "`if (t.length() != 97)`" … "`split[1].length() != 24`" · [astra-cli `AstraToken.java`](https://github.com/datastax/astra-cli/blob/3d746a51c08c07696c8198ea65fb667625677564/src/main/java/com/dtsx/astra/cli/core/models/AstraToken.java#L27-L41) · 2026-08-14 · provider code | T1 / T1 / middle T1, tail **open** → T1 with policy fill (Q3) | none | distinct family if Q3 allows a policy tail alphabet; else ISSUANCE-GATED on the tail alphabet |
| 14 | 16 | `sourcegraph:access-token` | `sgp_` + optional (16 hex + `_` \| `local_`) + 40 hex | "Personal access tokens have the form: sgp_<instance-identifier>_<token>" · [public snapshot](https://github.com/sourcegraph/sourcegraph-public-snapshot/blob/c864f15af264f0f456a6d8a83290b5c940715349/internal/accesstoken/personal_access_token.go#L13-L48) · 2024-08-22 · provider code (R9) | T1 / T1 / T1 → **T1 as of 2024-08** | scanners' bare 40-hex alternative collides with git SHAs and must not be copied | distinct family; R9 applies because the repo went private |
| 15 | 24 | `unkey:root-key` | `unkey_` + Base58 21–24 (Go service 21–22; dashboard 24) | "`newKey({ prefix: "unkey", byteLength: 16 })`" · [unkey `createRootKey.ts`](https://github.com/unkeyed/unkey/blob/6c9bc65125dd2c8b5038ac80a11e173767dc9e52/web/apps/dashboard/lib/trpc/routers/key/createRootKey.ts#L56-L59) · 2026-09-02 · provider code | T1 / T1 (derived range) / T1 → **T1** | `unkey_`-prefixed identifiers in the length window; env name `UNKEY_ROOT_KEY` is a generic miss today | distinct family; confirm the length range from both generators |
| 16 | 13 | `buildkite:user-access-token` | `bkua_` and 13 sibling prefixes + `[A-Za-z0-9_.-]{38,}` | "The shortest tokens Buildkite issues have bodies of 38 bytes or more" · [buildkite/agent `redact.go`](https://github.com/buildkite/agent/blob/4b52e509c730797c2a97487972fdf99477fd07e6/internal/redact/redact.go#L30-L69) · 2026-09-29 · provider-authored redaction (R2) | T1 / T1 floor / T1 → **T1** (open-ended) | `bkaj_`/`bkjat_` bodies may be JWTs; the prefix must win over `jwt` | distinct family (prefix list + floor 38, cap by policy) |
| 17 | 01 | `pydantic:logfire-write-token` | `pylf_v<n>_<region>_` + optional org UUID + `[A-Za-z0-9]+`; fixtures 44 | "`pylf_v(?P<version>[0-9]+)_(?P<region>[a-z]+)_`" · [logfire `auth.py`](https://github.com/pydantic/logfire/blob/a413dc789002d35cbc3b1a281e0d936c0930762e/logfire-sdk/logfire/_internal/auth.py#L36-L41) · 2026-09-15 · provider code; `pylf_v\d+_` in the provider scrubber (R2) | T1 / open (fixtures 44) / T1 → **T1** (open-ended) | none; write/read/API tokens share the prefix | distinct family `pydantic:logfire-token`; floor by policy |
| 18 | 02 | `pydantic:ai-gateway-api-key` | same `pylf_v<n>_<region>_` namespace, body `[A-Za-z0-9_-]+` | "`^pylf_v(?P<version>[0-9]+)_(?P<region>[a-z]+)_[a-zA-Z0-9-_]+$`" · [pydantic-ai `gateway.py`](https://github.com/pydantic/pydantic-ai/blob/b2e37b94a275084716c820065e8c912809daed7c/pydantic_ai_slim/pydantic_ai/providers/gateway.py#L407-L418) · 2026-08-27 · provider code | T1 / open / T1 → T1 **as a role of #01**, T3 alone | byte-identical prefix to #01 | merge into #01; not a separate detector |
| 19 | 09 | `mapbox:secret-access-token` | `sk.` + base64url JSON (`eyJ` lead) + `.` + 22 base64url | "A literal value of either pk (public token), sk (secret token), or tk (temporary token)" · [Mapbox docs](https://docs.mapbox.com/api/accounts/tokens/) · observed 2026-09-29 · provider docs; `parseToken` · [parse-mapbox-token](https://github.com/mapbox/parse-mapbox-token/blob/015a6b470fdb489a2635a4889c9f5b1d545a512c/index.js) · 2026-06-29 · provider code | T1 / structure T1, signature 22 by example (R5) / T1 → **T1** | not a JWT (header is `sk`); `pk.` is public by design | distinct family; `pk.` unclaimed; decide on `tk.` |
| 20 | 18 | `fly:access-token` | optional `FlyV1 ` + comma-joined `fm1r_`/`fm1a_`/`fm2_` + std-Base64 (variable) | "`v2TokenLabel = "fm2"`" … "`base64.StdEncoding.DecodeString`" · [superfly/macaroon `format.go`](https://github.com/superfly/macaroon/blob/a0202e10fd947786884323dcbce46efbe8652171/format.go#L11-L60) · 2024-07-18 · provider code | T1 / variable (floor by policy) / T1 → **T1** (open-ended) | unquoted `FlyV1 ` env value is a generic miss today; `fo1_` is T2 | distinct family; floor by policy; claim the whole comma bundle |
| 21 | 07 | `azure:ai-services-key` | 84 base62: 52 + `JQQJ99` + 1 + `[A-L]` + 12 + `AAA<svc>` + `ACOG` + 4 | "`[Base62]{52}JQQJ99[Base62][A-L]{PlatformData}{ProviderData}{ProviderSignature}[Base62]{4}`" · [security-utilities](https://github.com/microsoft/security-utilities/blob/638ad20eb4d446319a31e9c0ed293d087b4ffa55/src/Microsoft.Security.Utilities.Core/PreciselyClassifiedSecurityKeys/LegacyCommonAnnotatedSecurityAccessKey.cs#L13-L21) · 2025-05-14 · provider-authored scanner (R2) | T1 / T1 / T1 → **T1** (needs Q2) | same CASK layout as `azure-devops-personal-access-token` (`AZDO` signature) | **extend existing** CASK scanner with `ACOG`; legacy 32-hex stays generic |
| 22 | 11 | `tailscale:api-key` | `tskey-(api\|auth\|client\|scim\|webhook)-` + key id + `-` + secret | "The prefix starts with `tskey-` and is followed by the key type" · [Tailscale KB 1277](https://tailscale.com/kb/1277/key-prefixes) · 2025-08-01 · provider docs; `HasPrefix(keyStr, "tskey-auth-")` · [tailscale CLI](https://github.com/tailscale/tailscale/blob/a00fd3273b3865ec587d0c4b36ab5debf358545e/cmd/tailscale/cli/tailnet-lock.go#L773-L779) · provider code | T1 / T2 (placeholder only) / T1 segments → **T2 for a fixed length** | `tskey-auth-xxxx` placeholders and test strings | distinct family if a floor-only grammar is accepted; else ISSUANCE-GATED on secret length |
| 23 | 12 | `circleci:personal-access-token` | `CCIPAT_` + 22 + `_` + 40 (70); project `CCIPRJ_` | "the CCIPAT_ placeholder (which also sets the input's width and char limit)" · [circleci-cli `token.go`](https://github.com/CircleCI-Public/circleci-cli/blob/acf7852dad47f1e9af5310f6b11a8e05588d3550/internal/ui/token.go#L35-L51) · 2026-08-12 · provider code | T1 / T1 / T2 (hex only in trufflehog) → **T2** (T1 with `[A-Za-z0-9]` by policy) | none; legacy unprefixed 40-hex stays generic | distinct family; ruling on policy alphabet; `CCIPRJ_` layout unconfirmed |
| 24 | 41 | `square:access-token` | traditional `EAAA` + 60 `[A-Za-z0-9_-]`; secret `sq0csp-` + 43/44 | "Traditional access token example: EAAA…" and "don't use token length for validation" · [Square docs](https://developer.squareup.com/docs/oauth-api/receive-and-manage-tokens) · observed 2026-09-29 · provider docs; SDK wire fixtures · [square-nodejs-sdk](https://github.com/square/square-nodejs-sdk/blob/5e484507548ce8ffdc55752395a290ecc2d26771/tests/wire/oAuth.test.ts) · provider code | T1 / T1 by example, provider disclaims length / T1 by example → **T1 (R5)**, shrinking | Meta/Facebook `EAA…` tokens; JWT-format Square tokens go to `jwt` (R7); `sq0idp-` ids are public | distinct family, with a note that Square is moving to JWTs |
| 25 | 40 | `onesignal:rich-auth-token` | `os_v2_(app\|org)_` + `[a-z0-9]{20,}` | "`\bos_v2_(?:app\|org)_[a-z0-9]{20,}`" · [OneSignal `scan_secrets.py`](https://github.com/OneSignal/onesignal-agent-plugin/blob/75c08e9ee30e055765c0a475c3dd39769cbde543/scripts/scan_secrets.py#L29) · 2026-08-13 · provider-org scanner (R2, author affiliation to verify) | T1 / floor 20 / T1 → **T1 if R2 authorship holds** | legacy UUID REST keys stay generic | distinct family after an R2 authorship check |
| 26 | 39 | `ory:network-api-key` | admin `ory_pat_`/`ory_apikey_`/`ory_wak_` (body unknown); siblings `ory_st_` + 32 alnum, `ory_(at\|rt\|ac)_` + b64url `.` b64url | "`x.OrySessionToken + randx.MustString(32, randx.AlphaNum)`" · [kratos `session.go`](https://github.com/ory/kratos/blob/b86338da04a040247a07f46100a86dcfb3875909/session/session.go#L279-L280) · 2026-05-29 · provider code; prefix table · [Ory token formats](https://www.ory.com/docs/security-compliance/token-formats) · provider docs | admin: T1 / not found / not found → **T2**; siblings **T1** | `ory_kratos_session` cookie names | split: session/OAuth siblings could be a T1 family; admin keys pending |
| 27 | 38 | `stytch:project-secret` | `secret-(live\|test)-` + 36 base64url-like ending `=` (48) | "`secret: "secret-live-…"`" repeated in three SDK READMEs · [stytch-node README](https://github.com/stytchauth/stytch-node/blob/a59868d7e970b44fb96e61bf38d3ddd884d4238a/README.md#L67) · 2024-07-22 · provider docs (R4/R5 by example) | T1 / by example / by example → **T1 or T2** (Q6) | `secret-test-` in generic test strings; `public-token-*` and `project-*` are not secret | distinct family if Q6 accepts SDK-README examples |
| 28 | 47 | `mercury:api-token` | `secret-token:mercury_(production\|sandbox)_<type>_` + ~45 base62 + `_yrucrem` | "`req.basic_auth 'secret-token:mercury_production_wma_…_yrucrem', ''`" · [Mercury docs](https://docs.mercury.com/docs/getting-started) · observed 2026-09-29 · provider docs (single example) | T1 (prefix and suffix) / single example / single example → **T1/T2** | `bearer-token` already claims the RFC 8959 `secret-token:` form | extend existing coverage for bare `mercury_…_yrucrem` only |
| 29 | 25 | `zuplo:consumer-api-key` | `zpka_` + 32 `[a-z0-9]` + `_` + 8 hex (CRC32) | "`zpka_<random>_<checksum>`" · [Zuplo docs](https://zuplo.com/docs/concepts/api-keys) · observed 2026-09-29 · provider docs (structure) | T1 / T2 / T2 → **T2** | none | distinct family (T2) or pending a T1 length |
| 30 | 43 | `flutterwave:secret-key` | `FLWSECK-` / `FLWSECK_TEST-` + 32 + `-X` | "`seckey.replace('FLWSECK-', '')`" · [Flutterwave Node-v3](https://github.com/Flutterwave/Node-v3/blob/537f9f4455f922a879e4f088cf0f596621c3517c/lib/security.js#L11) · 2026-06-17 · provider code; `X`-placeholders in docs · [Flutterwave docs](https://developer.flutterwave.com/docs/authentication) | T1 / T1 by placeholder / T2 → **T2** | `FLWPUBK` public key | distinct family if a policy alphabet is accepted |
| 31 | 46 | `shippo:api-token` | `shippo_(live\|test)_` + 40 hex | "Live keys begin with shippo_live_" · [Shippo docs](https://docs.goshippo.com/docs/guides_general/authentication/) · observed 2026-09-29 · provider docs; SDK `startsWith("shippo_")` (R6) | T1 / T2 / T2 → **T2** | none | distinct family (T2) |
| 32 | 45 | `duffel:access-token` | `duffel_(test\|live)_` + 43 `[A-Za-z0-9_-]` | "Testing tokens are easy to recognize: they start with duffel_test_." · [Duffel docs](https://duffel.com/docs/api/overview/test-mode) · observed 2026-09-29 · provider docs | T1 (test) / T2 / T2 → **T2** | none | distinct family (T2) |
| 33 | 49 | `brevo:api-key` | `xkeysib-` + 64 hex + `-` + 16 alnum; SMTP `xsmtpsib-` | docs response `"key": "xkeysib-…"` (masked placeholder) · [Brevo API reference](https://developers.brevo.com/reference/create-an-api-key-for-a-sub-account) · observed 2026-09-29 · provider docs (R4) | T1 / T2 / T2 → **T2** | none | distinct family (T2) |
| 34 | 50 | `mailersend:api-token` | `mlsn.` + alnum (length unknown); `mssp.` sibling | "`git secrets --add 'mlsn\.[A-Za-z0-9._-]+'`" · [mailersend-nodejs `lefthook.yml`](https://github.com/mailersend/mailersend-nodejs/blob/410d24d084cf0e07fdfcf4eb152c98cb01bbf663/lefthook.yml#L11-L12) · 2026-09-17 · provider-authored rule (R2) | T1 / not found / T1 loose → **T2** | `mssp.` collides with "MSSP" prose | distinct family with a floor, or pending a length |
| 35 | 26 | `airtable:personal-access-token` | `pat` + 14 alnum + `.` + 64 hex | "personal access tokens are prefixed with their ID, they should be otherwise treated as opaque, variable-length strings" · [Airtable docs](https://airtable.com/developers/web/guides/personal-access-tokens) · observed 2026-09-29 · provider docs | T1 (id half) / T2 / T2 → **T2** | the bare `pat` + 14 id is non-secret | distinct family (T2), secret half required |
| 36 | 28 | `contentful:personal-access-token` | `CFPAT-` + 43 `[A-Za-z0-9_-]` (2017 fixture: 46) | "Token type prefixes such as cfpat- and cfw- are removed before redaction." · [Contentful docs](https://www.contentful.com/developers/docs/tutorials/general/audit-logs/) · observed 2026-09-29 · provider docs | T1 / T2 (conflicting eras) / T2 → **T2** | none | distinct family (T2) |
| 37 | 29 | `hubspot:private-app-access-token` | `pat-(na1\|eu1\|…)-` + UUID | "legacy private app token format (pat-xxx) is being replaced by Service Keys" · [HubSpot Community (staff)](https://community.hubspot.com/t/private-app-access-token-format-change/151661) · observed 2026-09-29 · staff statement (R3, prefix) | T1 / T2 / T2 → **T2** | inside `glpat-` without a boundary; format is being replaced | pending (format migration) |
| 38 | 10 | `elastic:cloud-api-key` | `essu_` + Base64 (92 per Veles; 60–200 per betterleaks) | "`const UIAM_CREDENTIALS_PREFIX = 'essu_';`" · [Kibana `uiam/utils.ts`](https://github.com/elastic/kibana/blob/f65836545184f238efa7827b37c57dc3c80a6412/src/core/packages/security/server/src/uiam/utils.ts#L12-L20) · 2026-09-17 · provider code (R6) | T1 / T2 (disagree) / T2 → **T2** | stack API keys are unprefixed Base64 | pending a T1 length |
| 39 | 03 | `llamaindex:llama-cloud-api-key` | `llx-` + ~48 alnum | "`export LLAMA_CLOUD_API_KEY='llx-...'`" · [llama_cloud_services README](https://github.com/run-llama/llama_cloud_services/blob/f385e96ab82ddb88330277c34394546398c8bed0/py/llama_parse/README.md#L54) · 2026-03-24 · provider docs (R4) | T1 / T2 / T2 → **T2** | short 4-byte prefix | pending a T1 length |
| 40 | 14 | `figma:personal-access-token` | `figd_` + ~40 `[A-Za-z0-9_-]`; `figp_` plan token | "`'figd_…', // Access token`" (placeholder) · [figma/code-connect test](https://github.com/figma/code-connect/blob/204e84ada6500dbcfbf637f60c4d86d9e3928eee/cli/src/connect/__test__/e2e/test_wizard_e2e.ts#L44) · 2025-09-04 · provider code (R4) | T1 / T2 / T2 → **T2** | legacy UUID-like PAT collides with UUIDs | pending a T1 length |
| 41 | 17 | `harness:personal-access-token` | `pat.`/`sat.` + 3 dot-joined `[A-Za-z0-9_-]+` (scanners: 22.24.20) | "`ValidatePATFormat` … `pat.<accountId>.<tokenId>.<secret>`" · [harness/cli `auth.go`](https://github.com/harness/cli/blob/cfb36aa58bc9010a6396f909aca142f2b4f8ba03/pkg/auth/auth.go#L288-L327) · 2026-09-04 · provider code | T1 / T2 / T1 loose → **T2** | `pat.`/`sat.` property paths in code | pending segment lengths |
| 42 | 05 | `jina:api-key` | `jina_` + 60 alnum | "a hardcoded real API key jina_xxx" · [jina-ai/MCP README](https://github.com/jina-ai/MCP/blob/5d6eb191a75d8e67b6e01ce427f0cc5c05c800aa/README.md#L8) · observed 2026-09-29 · provider docs (R4) | T1 / T2 / T2 → **T2** | `jina_client`-style identifiers | pending a T1 length |
| 43 | 04 | `kaggle:api-token` | `KGAT_` + hex (length unknown) | "`"apiToken": "KGAT_<hex>"`" · [Kaggle/kaggle-skills](https://github.com/Kaggle/kaggle-skills/blob/fd71736386a6000af54e4b925f7458e80f9bc412/kaggle-standardized-agent-exam/SKILL.md#L71) · 2026-04-27 · provider docs (placeholder) | T1 / not found / T2 → **T2** | legacy 32-hex key is indistinct | pending (issuance) |
| 44 | 34 | `launchdarkly:access-token` | `api-`/`sdk-` + UUID; `mob-` public | "SDK keys always start with the prefix sdk-" · [LaunchDarkly docs](https://launchdarkly.com/docs/sdk/concepts/client-side-server-side) · observed 2026-09-29 · provider docs | T1 / T2 / T2 → **T2** | high: `api-`/`sdk-` + UUID resource ids | pending (collision-heavy) |
| 45 | 35 | `devcycle:server-sdk-key` | `dvc_server_` + unknown body; `dvc_client_`/`dvc_mobile_` client-side | "`sdkKey?.startsWith('dvc_server')`" · [DevCycle js-sdks](https://github.com/DevCycleHQ/js-sdks/blob/ffc52abae48312daf80dd5d462571e8704f0e27a/sdk/js-cloud-server/src/utils/paramUtils.ts#L42-L44) · 2023-10-18 · provider code (R6) | T1 / not found / not found → **T2** (partner list only) | `DEVCYCLE_SERVER_SDK_KEY=` is a generic miss today | pending (issuance) |
| 46 | 20 | `octopus-deploy:api-key` | `API-` + uppercase alnum (26 vs 29–34) | "`s.StartsWith("API-")`" · [OctopusTentacle wizard](https://github.com/OctopusDeploy/OctopusTentacle/blob/d9b3b3402c6bf7f796e8afd711366a0ab815cbcc/source/Octopus.Manager.Tentacle/TentacleConfiguration/SetupWizard/SetupTentacleWizardModel.cs#L845) · 2026-05-26 · provider code (R6) | T1 / T2 (contested) / T2 → **T2** | high: `API-GATEWAY`, ticket keys | pending; context-gated at best |
| 47 | 27 | `asana:personal-access-token` | `2/` + digits + `/` + digits + `:` + 32 hex (eras `0/`, `1/`) | "Asana API tokens should be treated as opaque. Token formats may change without notice" · [Asana docs](https://developers.asana.com/docs/personal-access-token) · 2026-01-22 · provider docs (anti-grammar) | T2 / T2 / T2 → **T2** (Q4) | digit/slash text | pending ruling Q4 |
| 48 | 44 | `gocardless:access-token` | `live_`/`sandbox_` + 40 `[A-Za-z0-9_=-]` | "for sandbox this begins with sandbox_" · [GoCardless staff, gocardless-pro-php#54](https://github.com/gocardless/gocardless-pro-php/issues/54#issuecomment-454874930) · 2019-01-16 · staff statement (R3) | T1 (sandbox) / T2 / T2 → **T2** | high: `live_`/`sandbox_` are generic words | generic coverage sufficient |
| 49 | 06 | `mixedbread:api-key` | `mxb_` + unknown | "`z.string().startsWith("mxb_", …)`" · [openbread CLI `config.ts`](https://github.com/mixedbread-ai/openbread/blob/c7925f2cff0da9662bca8dac09d5b8ae8d75dcf2/packages/cli/src/utils/config.ts#L58) · 2026-02-19 · provider code (R6) | T1 / not found / not found → **T3** | `mxb_client`-style identifiers | pending (issuance) |
| 50 | 19 | `dbt-cloud:service-token` | `dbtc_` / `dbtu_` + unknown | "`token.starts_with("dbtu_")`" · [dbt-labs/dbt `credential.rs`](https://github.com/dbt-labs/dbt/blob/d07f4e28e0c31e3661c8e74e3bdab63bea5292ad/crates/dbt-platform-auth/src/credential.rs#L58-L61) · 2026-06-01 · provider code (R6) | T1 / not found / not found → **T3** | none | pending (issuance) |

**Counts by likely tier.** T1 with a full grammar and a handoff: 10 (ranks
1–10). T1 but needing a derivation, a ruling or a policy floor first: 17 (ranks
11–27, with #02 merged into #01). T1/T2 split: 1 (rank 28). T2: 20 (ranks
29–48). T3: 2 (ranks 49–50).

## Step-3 handoffs

Same format, readiness definitions and shared contract rules as the
[#860 handoffs](../860/README.md#shared-contract-rules): provider-specific
finding types, `Specificity::Provider`, `Confidence::High`, listed in
`ALWAYS_REDACT_TYPES`, identifier-continuation boundaries, no
`generic-token` deferral, JWT siblings stay with `jwt` (R7), and test values
built at run time. The issuance-check protocol is the
[#860 protocol](../860/README.md#issuance-check-protocol-structure-only).

| Rank | Family | Handoff | Readiness | Route |
| ---: | --- | --- | --- | --- |
| 1 | `bitwarden:secrets-manager-access-token` | [bitwarden.md](bitwarden.md) | **READY** | new detector |
| 2 | `polar:organization-access-token` | [polar.md](polar.md) | **READY** | new detector |
| 3 | `sonarqube:token` | [sonarqube.md](sonarqube.md) | **READY** | new detector |
| 4 | `rubygems:api-key` | [rubygems.md](rubygems.md) | **READY** | new detector |
| 5 | `clojars:deploy-token` | [clojars.md](clojars.md) | **READY** | new detector |
| 6 | `crates-io:api-token` | [crates-io.md](crates-io.md) | **READY** | new detector |
| 7 | `dynatrace:api-token` | [dynatrace.md](dynatrace.md) | **READY** | new detector |
| 8 | `paddle:api-key` | [paddle.md](paddle.md) | **READY** | new detector |
| 9 | `honeycomb:api-key` | [honeycomb.md](honeycomb.md) | **READY** (ingest key); management key **ISSUANCE-GATED** | new detector |
| 10 | `axiom:api-token` | [axiom.md](axiom.md) | **READY** (R5; issuance check recommended) | new detector |

None of the ten prefixes is claimed by a current detector, and none shares a
prefix with an existing provider contract (checked against the detector
sources at `main` `b9e9091`). Polar's webhook secret is the one measured
overlap, and its handoff excludes it.

## Ruling questions for the maintainer

- **Q1, checksum post-checks.** Polar (CRC32 base62), Xata (CRC32), crates.io
  `cio_tp_` (one check character), Zuplo (CRC32, T2) and the Azure identifiable
  keys (Marvin32) carry offline-verifiable checksums. Proposal: the lexical
  grammar stays the contract, and a checksum is an optional post-check that
  only turns a match into a non-match (it never widens the grammar). Is that
  acceptable, and should a failed checksum be an intentional false negative?
- **Q2, Microsoft security-utilities as R2.** The Azure grammars rest on
  detection code in `microsoft/security-utilities`, written by Microsoft
  staff in a Microsoft repository. Does that satisfy R2 as provider-authored
  scanner code (T1), given that Learn documents only the storage key's length
  and checksum?
- **Q3, policy fill for DataStax.** The Astra CLI validator fixes the total
  (97), the middle segment (24) and the prefix, but no provider source fixes
  the 64-byte tail's alphabet. Does R10 extend to Astra, with a policy
  alphabet `[A-Za-z0-9]` at least as wide as the widely reported hex?
- **Q4, providers that disclaim a grammar.** Asana documents that tokens are
  opaque and may change without notice. Should such a family be refused, or
  allowed at T2 with a context keyword?
- **Q5, public siblings.** Confirm that documented-public siblings stay
  unclaimed: SonarQube `sqb_`, Polar `polar_ci_`, Mapbox `pk.`, LaunchDarkly
  `mob-` and client-side ids, DevCycle `dvc_client_`/`dvc_mobile_`, Stytch
  `public-token-*`, Flutterwave `FLWPUBK`, Dynatrace two-part token
  identifiers, Paddle `apikey_` ids.
- **Q6, SDK README examples as R5.** Stytch's only length and alphabet source
  is one example repeated in three provider SDK READMEs, not a docs response
  example plus fixtures. Does that meet R5?

## Step-3 handoffs, second batch (2026-09-30)

The ten candidates that step 1 called T1 but that needed a derivation, a
policy decision or no ruling id. Each was researched broad first (open web,
forums, public repositories, scanner rule sets and provider code), source
classes were labelled afterwards, and every grammar rests on at least two
independent sources where two exist. Shapes are schematic: no complete
key-shaped value appears, because a synthetic value in the exact shape can
still trip push protection. Test values are built at run time. No key was
issued and no provider API was called.

| Rank | Family | Record | Readiness | Route |
| ---: | --- | --- | --- | --- |
| 11 | `xata:api-key` | [xata.md](xata.md) | **READY** (body range derived from the bit-packed base62 encoder: `[0-9A-Za-z]{32,36}` after `xau_`/`xao_`) | new detector `xata-api-key` |
| 14 | `sourcegraph:access-token` | [sourcegraph.md](sourcegraph.md) | **READY** (T1 as of 2025-11-18, R1 and R9) | new detector `sourcegraph-token` |
| 15 | `unkey:root-key` | [unkey.md](unkey.md) | **READY** for the version 1 root key (`unkey_` + 8 + `unkeyv1` + 42 base58) and the dashboard form (`unkey_3Z` + 22); customer-prefixed keys need **Q10** | new detector `unkey-root-key` |
| 16 | `buildkite:user-access-token` | [buildkite.md](buildkite.md) | **READY** (15 prefixes, R2; floor 24 from the provider's own redactor) | new detector `buildkite-token` |
| 17, 18 | `pydantic:logfire-token` (AI Gateway key is a role of it) | [pydantic-logfire.md](pydantic-logfire.md) | **READY** (lexical grammar T1; the body floor is narrowing policy, **Q7**, non-blocking) | new detector `pydantic-logfire-token` |
| 19 | `mapbox:secret-access-token` | [mapbox.md](mapbox.md) | **READY, conditional on Q7** | new detector `mapbox-token` |
| 20 | `fly:access-token` | [fly.md](fly.md) | **READY, conditional on Q7** (whole comma bundle; the `FlyV1 ` scheme stays outside the span) | new detector `fly-token` |
| 24 | `square:access-token` | [square.md](square.md) | **READY under R5**, **Q8** (the provider disclaims length validation and its examples disagree); issuance check recommended | new detector `square-token` |
| 26 | `ory:network-api-key` | [ory.md](ory.md) | siblings (`ory_st_`, `ory_at_`/`ory_rt_`/`ory_ac_`) **READY**; admin keys (`ory_pat_`, `ory_apikey_`, `ory_wak_`) **BLOCKED** on issuance | new detector `ory-token` (siblings only) |
| 28 | `mercury:api-token` | [mercury.md](mercury.md) | **BLOCKED**: one provider example, no bound on the body width (**Q6** extended, or a structure-only issuance check) | none until unblocked; `bearer-token` already redacts the `secret-token:` form |

Nine of the ten are READY in whole or in part. None of their prefixes is
claimed by a current detector at `main`
[`cfa8736`](https://github.com/redact-secret/redact-secret/commit/cfa87360)
(checked against the detector sources and `benchmarks/support-matrix.json`).
The one overlap is Mercury, where `bearer-token` already claims the `secret-token:`
form, and Mapbox, where `jwt` does not claim the `sk.` header.

## New ruling questions (2026-09-30)

Q1–Q6 above stay open. Q6 is extended: Mercury has the same shape of problem
as Stytch (one provider example, no fixtures).

- **Q7, floors for open-ended segments.** Logfire, Mapbox, Fly and Buildkite
  have segments with no provider-stated length. Mapbox (payload floor 20) and
  Fly (body floor 64) derive a floor from provider code or wire format;
  Logfire (floor 20, region cap 16) uses a policy floor below every observed
  value; Buildkite uses the provider redactor's own 24. May a derived or
  narrowing policy floor serve as the T1 floor when no alphabet is narrowed
  (R8 intact)? **Recommendation: yes.** If no: Fly needs a provider-stated
  floor or an issuance check, Mapbox falls back to a lead-pinned payload,
  Logfire to `{1,}`.
- **Q8, R5 when the provider disclaims length.** Square says not to validate
  token length, and its own examples differ (`EAAA` + 60 vs a 63-character
  `EAAl` form; 43 vs 44). May R5 still support an exact-width grammar?
  **Recommendation: yes**, claim `EAAA` + 60 and `sq0csp-` + 43 or 44, leave
  the conflicting shapes unclaimed, and run the issuance check.
- **Q9, short-lived or weakly sourced siblings.** Confirm that Mapbox `tk.`
  (expires within one hour) and a standalone Fly `fo1_` stay unclaimed.
  **Recommendation: yes**, until a provider source states their length.
- **Q10, Unkey customer-prefixed keys.** Version 1 customer keys
  (`<1–16 byte prefix>_` + 8 + `unkeyv1` + 42) are credentials for the
  customer's own product, anchored on the `unkeyv1` marker; Unkey's own
  scanning covers root keys only. Claim them as a separate finding type
  `unkey_api_key`? **Recommendation: yes.**
- Q1 extends to Xata and Unkey version 1 (both checksum-bearing).
  **Recommendation:** keep them lexical, as Polar and crates.io shipped.

Newly recorded as policy choices, not rulings: the Buildkite floor (24 vs the
provider's "38 or more" remark), Sourcegraph `sgd_`/`sgph_` as a later
extension, and Ory enterprise custom OAuth2 prefixes as an accepted false
negative.

## Step 4: disposition of all 50 candidates

Written 2026-09-30. One row per candidate, at `main`
[`cfa8736`](https://github.com/redact-secret/redact-secret/commit/cfa87360).
The Disposition column uses these terms:

- **SHIPPED**: detector merged to `main`, unreleased (product issue and PR
  from the [#1014 status](https://github.com/redact-secret/redact-secret/issues/1014)).
- **HANDOFF READY**: a record above, implementation issue drafted in step 5.
- **BLOCKED**: a named gate (ruling, issuance, evidence, policy).
- **T2 FAMILY**: eligible for a distinct T2 family under the
  [Together/Tavily precedent](../../../specs/detector-families.md); no handoff
  written yet. A T2 handoff is the next action, no ruling needed.
- **GENERIC**: no dedicated family; generic coverage stays.
- **DEFERRED**: not pursued now, with the reason.

| Rank | # | Candidate | Disposition | Gate or next action |
| ---: | ---: | --- | --- | --- |
| 1 | 30 | `bitwarden:secrets-manager-access-token` | SHIPPED (#1019, PR #1039) | none |
| 2 | 48 | `polar:organization-access-token` | SHIPPED (#1020, PR #1039) | Q1 for the CRC32 |
| 3 | 15 | `sonarqube:token` | SHIPPED (#1021, PR #1039) | none |
| 4 | 21 | `rubygems:api-key` | SHIPPED (#1023, PR #1039) | none |
| 5 | 23 | `clojars:deploy-token` | SHIPPED (#1025, PR #1039) | none |
| 6 | 22 | `crates-io:api-token` | SHIPPED (#1031, PR #1039) | Q1 for the check character |
| 7 | 31 | `dynatrace:api-token` | SHIPPED (#1032, PR #1039) | none |
| 8 | 42 | `paddle:api-key` | SHIPPED (#1033, PR #1039) | none |
| 9 | 32 | `honeycomb:api-key` | SHIPPED for the ingest key (#1034, PR #1039) | management key BLOCKED on issuance |
| 10 | 33 | `axiom:api-token` | SHIPPED (#1035, PR #1039) | none |
| 11 | 37 | `xata:api-key` | HANDOFF READY ([xata.md](xata.md)) | Q1 for the CRC32; classic keys stay generic |
| 12 | 08 | `azure:storage-account-key` | BLOCKED on **Q2** | after Q2, a handoff; legacy 86-character form stays generic |
| 13 | 36 | `datastax:astra-db-application-token` | BLOCKED on **Q3** | if Q3 is refused, issuance of the 64-byte tail |
| 14 | 16 | `sourcegraph:access-token` | HANDOFF READY ([sourcegraph.md](sourcegraph.md)) | optional issuance check (server repo is private) |
| 15 | 24 | `unkey:root-key` | HANDOFF READY ([unkey.md](unkey.md)) | **Q10** for customer-prefixed keys; Q1 for the CRC-32C |
| 16 | 13 | `buildkite:user-access-token` | HANDOFF READY ([buildkite.md](buildkite.md)) | none |
| 17 | 01 | `pydantic:logfire-write-token` | HANDOFF READY ([pydantic-logfire.md](pydantic-logfire.md)) | **Q7** (non-blocking) |
| 18 | 02 | `pydantic:ai-gateway-api-key` | MERGED into rank 17 (same namespace, one detector) | none |
| 19 | 09 | `mapbox:secret-access-token` | HANDOFF READY, conditional ([mapbox.md](mapbox.md)) | **Q7**; **Q9** for `tk.` |
| 20 | 18 | `fly:access-token` | HANDOFF READY, conditional ([fly.md](fly.md)) | **Q7**; **Q9** for `fo1_` |
| 21 | 07 | `azure:ai-services-key` | BLOCKED on **Q2** | route is extending the CASK scanner with `ACOG`, not a new family |
| 22 | 11 | `tailscale:api-key` | BLOCKED (policy: floor-only grammar) | else issuance of the secret length |
| 23 | 12 | `circleci:personal-access-token` | BLOCKED (policy: alphabet `[A-Za-z0-9]` for the 40-byte segment) | then a T2 handoff; `CCIPRJ_` layout unconfirmed |
| 24 | 41 | `square:access-token` | HANDOFF READY ([square.md](square.md)) | **Q8**; issuance check recommended |
| 25 | 40 | `onesignal:rich-auth-token` | BLOCKED (R2 authorship check of the scanning rule) | then a handoff |
| 26 | 39 | `ory:network-api-key` | HANDOFF READY for siblings ([ory.md](ory.md)); admin keys BLOCKED on issuance | one project key and one workspace key, structure only |
| 27 | 38 | `stytch:project-secret` | BLOCKED on **Q6** | then a handoff |
| 28 | 47 | `mercury:api-token` | BLOCKED ([mercury.md](mercury.md)) | **Q6** (extended) or issuance of a Read Only and a Read and Write token |
| 29 | 25 | `zuplo:consumer-api-key` | T2 FAMILY | Q1 for the CRC32 |
| 30 | 43 | `flutterwave:secret-key` | T2 FAMILY | policy alphabet for the 32-byte segment |
| 31 | 46 | `shippo:api-token` | T2 FAMILY | none |
| 32 | 45 | `duffel:access-token` | T2 FAMILY | none |
| 33 | 49 | `brevo:api-key` | T2 FAMILY | none |
| 34 | 50 | `mailersend:api-token` | T2 FAMILY | floor by policy; `mssp.` prose collision |
| 35 | 26 | `airtable:personal-access-token` | T2 FAMILY | secret half required |
| 36 | 28 | `contentful:personal-access-token` | T2 FAMILY | 43 vs 46 eras to settle |
| 37 | 29 | `hubspot:private-app-access-token` | DEFERRED | format is being replaced by Service Keys; revisit after the migration |
| 38 | 10 | `elastic:cloud-api-key` | BLOCKED (evidence: a T1 length for `essu_`) | provider source or issuance |
| 39 | 03 | `llamaindex:llama-cloud-api-key` | BLOCKED (evidence: a T1 length) | provider source or issuance |
| 40 | 14 | `figma:personal-access-token` | BLOCKED (evidence: a T1 length) | provider source or issuance |
| 41 | 17 | `harness:personal-access-token` | BLOCKED (evidence: segment lengths) | provider source or issuance |
| 42 | 05 | `jina:api-key` | BLOCKED (evidence: a T1 length) | provider source or issuance |
| 43 | 04 | `kaggle:api-token` | BLOCKED (issuance) | one issued token, structure only |
| 44 | 34 | `launchdarkly:access-token` | DEFERRED | `api-`/`sdk-` + UUID collides with resource ids; context-gated coverage only, not a family |
| 45 | 35 | `devcycle:server-sdk-key` | BLOCKED (issuance) | one issued key, structure only; `DEVCYCLE_SERVER_SDK_KEY=` is also a generic-name miss |
| 46 | 20 | `octopus-deploy:api-key` | DEFERRED | `API-` collides with ticket keys and gateway names; context-gated at best |
| 47 | 27 | `asana:personal-access-token` | BLOCKED on **Q4** | the provider documents the format as opaque |
| 48 | 44 | `gocardless:access-token` | GENERIC | `live_`/`sandbox_` are generic words; no family |
| 49 | 06 | `mixedbread:api-key` | BLOCKED (issuance) | one issued key, structure only |
| 50 | 19 | `dbt-cloud:service-token` | BLOCKED (issuance) | one issued token per prefix (`dbtc_`, `dbtu_`), structure only |

Counts (50): 10 SHIPPED; 9 HANDOFF READY (two conditional on Q7, Ory
siblings only); 1 merged into another (rank 18); 8 T2 FAMILY; 3 DEFERRED;
1 GENERIC; 18 BLOCKED (6 on rulings Q2, Q3, Q4 and Q6; 3 on policy or
authorship; 5 on evidence; 4 on issuance). Honeycomb management keys and Ory
admin keys are BLOCKED parts of rows counted as SHIPPED or HANDOFF READY.

## Step 5: implementation issues to open

Not opened by this record. The drafts are in the maintainer's hands: one
product issue per READY family, per-family commits inside one PR for the
batch, and one benchmarks issue modelled on
[benchmarks#528](https://github.com/redact-secret/redact-secret-benchmarks/issues/528),
which covered ranks 1 to 10 and is closed. The titles:

| Repository | Title | Covers | Gate |
| --- | --- | --- | --- |
| product | Beta.12: `xata:api-key` detector | xata.md | none |
| product | Beta.12: `sourcegraph:access-token` detector | sourcegraph.md | none |
| product | Beta.12: `unkey:root-key` detector | unkey.md | Q10 for the customer-prefixed type only |
| product | Beta.12: `buildkite:user-access-token` detector | buildkite.md | none |
| product | Beta.12: `pydantic:logfire-token` detector | pydantic-logfire.md | Q7 (non-blocking) |
| product | Beta.12: `square:access-token` detector | square.md | Q8 |
| product | Beta.12: `ory:session-and-oauth-tokens` detector | ory.md (siblings) | none |
| product | Beta.12: `mapbox:secret-access-token` detector | mapbox.md | Q7 |
| product | Beta.12: `fly:access-token` detector | fly.md | Q7 |
| benchmarks | Beta.12: contracts and corpus for the #1014 second-wave families | the nine above | product issues above; fixtures need the Xata bit-packed base62 and CRC32, the Unkey CRC-32C, the Buildkite JWT-body case, the Fly bundle-span case, the Mapbox no-double-report case |
| benchmarks | Measure one issued key per issuance-gated #1014 candidate (structure only) | Honeycomb management, Ory admin, Mercury, Kaggle, DevCycle, Mixedbread, dbt Cloud, Tailscale | issuance by the maintainer; model: benchmarks#526 |

The full bodies are drafted in the task report for #1014, not in the
repository.

## Research inputs

- The per-candidate research tables (step 1) are issue comments on #1014:
  [#01–#10 AI and cloud](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900446812),
  [#11–#20 developer platforms and CI/CD](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447016),
  [#21–#30 registries and SaaS](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282),
  [#31–#40 observability, databases and auth](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540),
  [#41–#50 payments and messaging](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447820).
- The ranked table above is also posted on #1014.

## Acceptance for this step

- [x] All 50 have a role, best evidence with permalink, date and source class,
  per-fact tiers, a likely tier, scanner coverage and collision risks.
- [x] Current generic coverage is measured on `main`, not assumed.
- [x] The ten candidates with a full T1 grammar have handoffs with supported
  and excluded shapes, provenance, tier rationale, test axes, overlap and
  output policy, FP/FN boundary, issuance checklist and route.
- [x] Open grammar questions are raised as rulings (Q1–Q6), not averaged into
  a wider grammar.
- [x] No credential value or real-derived material appears in this record.
- [x] (2026-09-30) The ten candidates without a handoff have step-3 records
  (seven READY, two conditional on Q7 or Q8, Mercury BLOCKED with the exact
  gate, Ory admin keys BLOCKED).
- [x] (2026-09-30) Every one of the 50 candidates has an explicit disposition.
- [ ] Step 5: the product and benchmarks issues above are opened after
  maintainer review.

## Authority

This record freezes the proposed ranking and handoffs for review only. It
does not authorize implementation, support-status promotion, a version
change, a tag, publication or release.
