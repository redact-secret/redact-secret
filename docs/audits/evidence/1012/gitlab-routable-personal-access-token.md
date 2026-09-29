# #1012 research: `gitlab:routable-personal-access-token`

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 shared contract rules](../860/README.md#shared-contract-rules)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: READY-T1.** GitLab's own generator, its decoder, the model that
binds the generator to personal access tokens, and GitLab's design document
state every part of the grammar: prefix, payload alphabet and length range,
separators, version field, length field and checksum. GitLab-authored
secret-detection rules agree.

**Route:** extend the existing `gitlab-token` detector with a routable
`glpat-` branch, finding type `gitlab_token` (unchanged), reusing the
CRC-checked routable parser the product already has for `glrt-`.

## Current product behaviour

`gitlab-token` (`crates/secret-scan-core/src/detectors/gitlab.rs`) matches
`glpat-` + at least 20 `[A-Za-z0-9_-]`. A routable token contains `.`, so the
run stops at the first `.`. On a synthetic routable value the finding covers
`glpat-` and the payload only; the `.<version>.<length><crc>` tail stays in
plaintext after redaction. The #860 shared rule says a value is never
truncated into a match, so this is a defect, not only a missing contract.
The support-matrix reason: "routable tokens are not covered by the
20-character-body pattern".

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [gitlab-org/gitlab `lib/authn/token_field/generator/routable_token.rb` L7-L86 @ fa2faf33](https://gitlab.com/gitlab-org/gitlab/-/blob/fa2faf332129a1fd9130b052f42b85f0fa346b65/lib/authn/token_field/generator/routable_token.rb#L7-L86) | version field added 2025-04-22 (8343330f); payload order 2025-04-15; CRC helper refactored 2026-01-15 | provider generator | R1, R9 = T1 | `TOKEN_VERSION = 1`, `TOKEN_VERSION_LENGTH = 2`, `RANDOM_BYTES_LENGTH = 16`, `CRC_BYTES = 7`, `MAXIMUM_SIZE_OF_ROUTING_PAYLOAD = 159`; `Base64.urlsafe_encode64(encodable_payload, padding: false)`; `"#{prefix}#{base64_payload}.#{token_version}.#{base64_payload_length}"`; `Zlib.crc32(encoded).to_s(36).rjust(CRC_BYTES, '0')` appended over that whole string |
| 2 | [gitlab-org/gitlab `lib/authn/token_field/decoders/v1/routable_payload.rb` L24-L71 @ fa2faf33](https://gitlab.com/gitlab-org/gitlab/-/blob/fa2faf332129a1fd9130b052f42b85f0fa346b65/lib/authn/token_field/decoders/v1/routable_payload.rb#L24-L71) | at the pinned commit | provider validator | R1 = T1 | a token is valid when the CRC of everything before the last 7 characters equals those 7 characters; the payload length is read from the third `.`-separated field |
| 3 | [gitlab-org/gitlab `app/models/personal_access_token.rb` L22-L36 @ fa2faf33](https://gitlab.com/gitlab-org/gitlab/-/blob/fa2faf332129a1fd9130b052f42b85f0fa346b65/app/models/personal_access_token.rb#L22-L36) | routable since 2024-11-22 (3bd08ef6), behind the default-off `routable_pat` flag; flag removed 2025-07-24 (36573efc) | provider code | R1 = T1 | `PERSONAL_TOKEN_PREFIX = 'glpat-'`; `routable_token: { payload: { o: …, u: … } }`. Every new PAT has been routable since the flag was removed |
| 4 | [GitLab handbook, routable tokens design document](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/cells/routable_tokens/) (source `gitlab-com/content-sites/handbook` @ 55ccf193) | created 2024-10-15, edited 2026-03-03 | provider design document | T1 | "`<prefix><base64-payload>.<token-version>.<base64-payload-length><crc32>`"; "Minimum size of `<base64-payload>` is 27 bytes"; "Maximum size of `<base64-payload>` is 300 bytes"; the version and CRC fields are base36; "Maximum size of prefix is 20 bytes" |
| 5 | [gitlab-org/security-products/secret-detection/secret-detection-rules `rules/mit/gitlab/gitlab.toml` L27-L57 @ cae5670b](https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules/-/blob/cae5670b0d83aaea0ff37c085119e82ff394f283/rules/mit/gitlab/gitlab.toml#L27-L57) | versioned rule added 2025-04-24 | provider-authored scanner rule | R2 = T1 | `gitlab_personal_access_token_routable_versioned`: `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}\.[0-9a-z]{2}[0-9a-z]{7}\b`; an older unversioned rule is kept beside it |
| 6 | [gitlab-org/gitlab `app/assets/javascripts/lib/utils/secret_detection_patterns.js` L5-L24 @ fa2faf33](https://gitlab.com/gitlab-org/gitlab/-/blob/fa2faf332129a1fd9130b052f42b85f0fa346b65/app/assets/javascripts/lib/utils/secret_detection_patterns.js#L5-L24) | 2024-11-22, updated 2026-04-23 | provider client-side detection regex | R2 = T1 | payload `[0-9a-zA-Z_-]{27,300}`, then `\.[0-9a-z]{2}\.`, a 2-character length and a 7-character CRC; the prefix may also be an instance prefix `<inst>-glpat-` or an admin-custom prefix |
| 7 | [gitleaks `cmd/generate/config/rules/gitlab.go` L116-L131 @ b58d3f1](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/gitlab.go#L116-L131) | 2024-12-06 | peer scanner rule | T2 | unversioned form only; it cannot match a versioned token |
| 8 | [trufflehog `pkg/detectors/gitlab/v3/gitlab_v3.go` L34 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/gitlab/v3/gitlab_v3.go#L34) | 2025-12-04 | peer scanner rule | T2 | versioned form, with unescaped `.` |
| 9 | [trufflehog issue #4551](https://github.com/trufflesecurity/trufflehog/issues/4551) | 2025-11-13 | third-party report | summary | newly generated PATs on SaaS and self-managed have the versioned shape |

Searched, nothing further: the docs.gitlab.com token page (prefix table only;
no "routable", CRC or version text); the `analyzers/secrets` project (it
consumes the rules project); betterleaks (no routable rule); CredSweeper (a
loose `gl…-` rule with up to two dot segments and a 64-byte cap).

## Role and blast radius

A GitLab personal access token authenticates as its user to the REST and
GraphQL APIs, Git over HTTPS and the registry, within its scopes (up to
`api` and `sudo` for admins). Routable tokens carry an organization and user
routing payload for Cells; the secret part is the 16 random bytes inside the
payload.

## Supported shape

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `glpat-` | model constant (#3), docs, rules | T1 |
| Payload P | unpadded base64url `[A-Za-z0-9_-]`, 27 to 300 characters | generator (#1), design doc (#4), provider rules (#5, #6) | T1 |
| Separator | `.` | generator (#1) | T1 |
| Version V | exactly 2 `[0-9a-z]` (base36, zero-padded; `01` today) | generator (#1) | T1 |
| Separator | `.` | generator (#1) | T1 |
| Length L | exactly 2 `[0-9a-z]`, equal to base36 of the length of P | generator (#1), decoder (#2) | T1 |
| Checksum C | exactly 7 `[0-9a-z]`: base36 CRC32 (zlib) of every byte from `g` of `glpat-` through L, zero-padded | generator (#1), decoder (#2) | T1 |

Total 46 to 319 bytes. The current generator caps the payload at 235
characters (16 random bytes, at most 159 routing bytes and one length byte);
300 is the design cap and is used here. An unpadded base64 length is never
1 modulo 4, which is a free extra check.

**Proposed type:** `gitlab_token` (unchanged), new signals
`gitlab-routable-grammar` and `gitlab-routable-crc`.

## Excluded shapes (unclaimed siblings)

| Shape | Why excluded |
| --- | --- |
| Legacy `glpat-` + 20 `[A-Za-z0-9_-]` | already claimed by the existing branch; unchanged |
| Unversioned routable form `glpat-P.LC` (no version field) | emitted only between 2024-11-22 and 2025-04-22 behind a default-off flag. It is CRC-checkable the same way and may be added, but GitLab.com issuance of it is not evidenced. Until then it keeps today's truncated legacy match |
| Instance or admin-custom prefixes (`<inst>-glpat-`, custom prefixes) | the CRC covers the full custom prefix, so a CRC computed from `glpat-` fails. Accepted false negative; the legacy branch still covers the payload |
| A value whose CRC or length field does not verify | rejected whole; never truncated into a match |
| Other routable GitLab prefixes (`glrt-` is already routable in the product) | out of scope here |

## Overlap and output policy

- **Existing detectors.** `gitlab-token` claims the payload today (truncated).
  The routable branch must run first and, when the CRC verifies, report the
  whole value; the legacy branch must not also report the payload prefix of
  the same span. `generic-token` and `bearer-token` lose to the provider
  finding as usual.
- **Output.** `Specificity::Provider`, `Confidence::High`, in
  `ALWAYS_REDACT_TYPES` (unchanged for `gitlab_token`).
- **`generic-token` deferral.** No change.

## Test axes

**Positives:** synthetic routable values built at run time with a correct
base36 CRC, payload widths 27, a typical width and 300, in every #860 probe
context (bare, env, `export`, Bearer, `PRIVATE-TOKEN:` header, JSON `token`
and `api_key`, SDK keyword argument, chat sentence), and in a Git remote URL
(`https://oauth2:<token>@gitlab.com/…`).

**Near-miss twins:** CRC off by one character; length field not equal to the
payload length; version of one or three characters; a missing `.`; an
uppercase letter in the version, length or CRC field; payload of 26; a
leading or trailing glue byte.

**Benign:** a legacy 20-byte `glpat-` value (must keep today's finding),
`glrt-` routable values (runner detector only), a `glpat-` prefix in prose.

**Regression:** the span must end at the last CRC byte; no plaintext tail.

## False-positive / false-negative boundary

- **Accepted false negatives:** custom and instance prefixes; the unversioned
  2024-11 to 2025-04 form; a future version whose layout changes.
- **Accepted false positives:** none known. The CRC makes a chance match
  about one in 78 billion.

## Issuance checklist (optional confirmation; structure only)

1. Create one PAT on GitLab.com (free account).
2. Record: total length, payload length, the two `.` positions, version field
   value, whether the length field equals base36 of the payload length,
   whether the CRC verifies, `rawValueRetained: false`, revoked.
