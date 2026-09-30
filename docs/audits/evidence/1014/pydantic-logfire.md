# #1014 handoff: `pydantic:logfire-token` (Logfire write, read and API keys; AI Gateway key)

[#1014 index](README.md) · ranks 17 and 18 (merged) ·
[Research tables #01 and #02](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900446812)

**Readiness: READY** (lexical grammar is T1; the body floor is a narrowing
policy, see ruling Q7, non-blocking). **Route:** new detector
`pydantic-logfire-token`, one finding type `pydantic_logfire_token`.

The AI Gateway key (#02) is not a separate family. It is the same
`pylf_v<n>_<region>_` namespace, parsed by a second provider regex, and no
text feature tells it from a Logfire token. The same holds for write tokens,
read tokens and organization or project API keys.

## Role and blast radius

A Logfire write token (`LOGFIRE_TOKEN`) lets the holder send telemetry into a
project (pollution, spoofing, quota burn). A read token or API key
(`LOGFIRE_READ_TOKEN`, `LOGFIRE_API_KEY`, `Authorization: Bearer`) reads
traces that may contain sensitive data and, with scopes, manages projects,
tokens and variables. An AI Gateway key
(`PYDANTIC_AI_GATEWAY_API_KEY`) proxies paid LLM inference under the
organization's spend limits. All four sit in `.env` files, OpenTelemetry
configs and agent tool environments.

## Supported shape

Discovery started from open-web and code search (the `pylf_v` literal across
public repositories, scanner rule sets, forum and docs hits), and the source
class is labelled afterwards. Checked 2026-09-30.

- **Provider code (SDK parser).** `pydantic/logfire` `auth.py` at
  [`a413dc7`](https://github.com/pydantic/logfire/blob/a413dc789002d35cbc3b1a281e0d936c0930762e/logfire-sdk/logfire/_internal/auth.py#L36-L41)
  (commit 2026-09-29): `^pylf_v<digits>_<[a-z]+ region>_` then an optional
  lowercase-hex 8-4-4-4-12 UUID followed by `_` (the organization id), then
  `[a-zA-Z0-9]+`. The UUID segment is new since the step-1 table. The same
  file lists the regions `us` and `eu`; `config.py` maps `stagingus` and
  `stagingeu` to the staging domain and falls back to `us` for a token with
  no prefix (legacy tokens without `pylf_` exist and stay out of scope).
- **Provider code (second SDK parser).** `pydantic-ai` `gateway.py` at
  [`b2e37b9`](https://github.com/pydantic/pydantic-ai/blob/b2e37b94a275084716c820065e8c912809daed7c/pydantic_ai_slim/pydantic_ai/providers/gateway.py#L407-L418):
  `^pylf_v<digits>_<[a-z]+>_[a-zA-Z0-9-_]+$`. A v2 key with the UUID
  segment fits this body class (the UUID contributes the `-` and `_`).
  `test_gateway.py` uses the regions `ap` and `stagingus` as parser cases.
- **Provider code (redaction rule, R2).** `scrubbing.py` default patterns
  include `pylf_v\d+_`: the provider's own scrubber treats any text with
  this prefix as sensitive. `CHANGELOG` records the addition (PR #1993).
- **Provider fixtures (length).** `tests/conftest.py`, `test_auth.py`,
  `test_query_client.py` (write and read fixtures, v1) and `test_configure.py`
  / `test_variables.py` (v2 with UUID) all use a body of exactly 44
  `[A-Za-z0-9]` bytes. The fixtures are synthetic placeholders in a public
  test suite; only the shape is used here.
- **Provider repositories, Terraform/Pulumi/Crossplane.** Docs and
  READMEs use placeholder `pylf_v1_...` for the write token and
  `pylf_v2_...` for API keys (`terraform-provider-logfire`,
  `pulumi-logfire`, `provider-upjet-logfire`). This is the version split:
  v1 = project write and read tokens, v2 = API keys with an organization
  UUID. Provider docs (API keys page) say keys are shown once, carry scopes
  (`project:write_otlp`, `project:read_otlp`, `project:gateway_proxy`,
  organization scopes) and are sent as `Authorization: Bearer`. No page
  states a length.
- **Third-party scanner rules (T2, corroboration).** `ghostsecurity/poltergeist`
  `pkg/rules/logfire.yaml`: `pylf_v<digit>_<[a-z]{2}>_<uuid>_[a-z0-9]{44}`
  (case-insensitive, so the body is 44 alphanumerics). Its positives also
  include two shapes (`pylf_v3_` and `pylf_v4_` with an 80-byte body and no
  UUID) that no provider source confirms; they are ignored. A dotfile
  secret filter (`ipruning/dotfiles`) uses `pylf_v1_[a-z]+_[A-Za-z0-9]{20,}`.
  GitHub's partner list carries `logfire_token` and
  `pydantic_ai_gateway_api_key` (private repositories only).

Two independent sources (provider test fixtures and a third-party scanner
rule) agree on a 44-byte body. The provider's own regex has no bound, so
the length is T2 as a fixed number and T1 as a floor-and-open shape.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `pylf_v` + digits + `_` + `[a-z]+` region + `_` | SDK parser (R1), scrubber (R2) | T1 |
| Organization id | optional lowercase or uppercase hex 8-4-4-4-12 + `_` | SDK parser (R1); v2 fixtures | T1 |
| Body | `[A-Za-z0-9]{20,}` (fixtures and scanner: 44) | SDK regex `+` (R1); 44 by fixtures and scanner rule | T1 open-ended; 44 is T2 |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy tokens with no `pylf_` prefix | no distinctive shape |
| `pylf_v<n>_<region>_` with a body under 20 | placeholders and test stubs in provider tests and docs (`..._xxx`, `..._token1`, `..._fake`); the provider scrubber still redacts the bare prefix, which is a stronger posture than this detector takes (see Q7) |
| Gateway-regex bodies containing `-` or `_` that are not a UUID segment | no provider source issues them; accepted false negative |
| v3, v4 shapes with an 80-byte body (scanner fixtures only) | no provider source |
| `pylf_v<n>_<region>_` token ids shown in the UI | not found; the dashboard masks tokens (`pylf_v1_us_0kYhc****` in the CLI) |

## Tier rationale

T1 under R1 (two provider SDK parsers) and R2 (provider-authored scrubber
rule on the prefix). The alphabet is stated by the provider regexes. The
length is stated only by fixtures and a third-party rule, so no exact
width is claimed; the floor of 20 is a narrowing policy below every
observed token (44) that removes the documented placeholders. It does not
widen the provider grammar, so R10's restriction to named families does not
apply. The UI masking shows only the first 5 body bytes, below the floor.

## Overlap and output policy

- **Existing detectors.** None claims `pylf_`. The synthetic probe in the
  index shows `LOGFIRE_TOKEN=` is caught as `contextual_secret`; bare, chat
  and JSON `"token"` occurrences are missed.
- **Roles.** Write, read, API key and gateway key share one finding type.
  Claiming one more type per role would invent a distinction the text does
  not carry.
- **Checksum.** None known.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` anchored on `pylf_v`: 1 to 3 digits, `_`,
`[a-z]{2,16}` (policy cap on the region), `_`, optional UUID + `_`, then
`[A-Za-z0-9]{20,}` with the usual `[A-Za-z0-9_-]` boundary consumed after
the body. Signals: `pydantic-logfire-documented-prefix`,
`pydantic-logfire-org-id`. The hex in the UUID is case-insensitive
(staging fixtures use uppercase).

## Test axes

**Positives:** every #860 index context; `LOGFIRE_TOKEN=`,
`LOGFIRE_READ_TOKEN=`, `LOGFIRE_API_KEY=`, `PYDANTIC_AI_GATEWAY_API_KEY=`;
`logfire.configure(token=...)`; `Authorization: Bearer`; a v1 body of 44;
a v2 key with an organization UUID (lower and upper case); regions `us`,
`eu`, `stagingus`, `ap`.

**Near-miss twins:** body of 19; `pylf_v_us_` (no digits); `pylf_v1__`
(no region); `pylf_v1_US_` (uppercase region); an uppercase `PYLF_`; a UUID
segment with a wrong group width; a leading glue byte and a trailing glue
byte.

**Benign:** `pylf_v1_us_...`; `pylf_v1_us_xxx`; `pylf_v1_us_token1`;
the masked `pylf_v1_us_0kYhc****`; the scrubber pattern `pylf_v\d+_` in
config text; `LOGFIRE_TOKEN=${LOGFIRE_TOKEN}`.

Build test values at run time from this grammar. The public test suites of
the provider and of third parties hold bodies that may be live: do not copy
any.

## False-positive / false-negative boundary

- **Accepted false negatives:** a body under 20; non-UUID dash or
  underscore bodies; legacy unprefixed tokens; the Logfire `logfire-us`
  API hostnames are not credentials.
- **Accepted false positives:** a placeholder longer than 19 alphanumerics
  after the prefix (for example a docs string written by hand). None is
  known.

## Issuance checklist (optional confirmation; structure only)

For one write token, one v2 API key and one AI Gateway key:

- prefix, version digit, region letters;
- whether an organization UUID segment is present, and its hex case;
- body length (expect 44) and alphabet classes;
- `rawValueRetained: false` and revoked.
