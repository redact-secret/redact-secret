# #1014 handoff: `buildkite:user-access-token`

[#1014 index](README.md) · rank 16 ·
[Research table #13](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447016)

**Readiness: READY.** **Route:** new detector `buildkite-token`, finding types
per role (see the table): `buildkite_api_access_token` (`bkua_`),
`buildkite_oauth_token`, `buildkite_agent_token`, `buildkite_job_token`,
`buildkite_packages_token`, `buildkite_pipeline_token`,
`buildkite_portal_token`. The maintainer may collapse the roles into fewer
types; the grammar does not change.

## Role and blast radius

Buildkite is a hosted CI/CD platform. The 15 token prefixes below cover every
credential the platform issues. An API access token (`bkua_`, sent as
`Authorization: Bearer`, or `BUILDKITE_API_TOKEN` / `BUILDKITE_API_ACCESS_TOKEN`
in the MCP server and CLI) reads and controls pipelines and builds within its
scopes. Agent, cluster and registration tokens let a machine join a cluster and
pull jobs, and with them the secrets and source of every pipeline the queue
serves. A job acquisition token (`bkjat_`) and a job token (`bkaj_`) are JWTs
that let a process acquire or act as one job. Package registry tokens read or
write a private registry. Portal tokens and secrets call a portal and mint
ephemeral portal tokens. These tokens appear in CI logs, `ps` output and agent
command lines, which is where an agent transcript will see them.

## Supported shape

Discovery started broad and labelled classes afterwards. Sources, re-checked
2026-09-30:

- **Provider-authored redaction rule (R2).** `buildkite/agent`
  `internal/redact/redact.go` at
  [`4b52e50`](https://github.com/buildkite/agent/blob/4b52e509c730797c2a97487972fdf99477fd07e6/internal/redact/redact.go#L30-L69)
  (merged 2026-09-29, PR
  [#4425](https://github.com/buildkite/agent/pull/4425), "Redact Buildkite
  tokens by prefix in job logs"): `tokenPrefixes` is a list of 15 prefixes
  ("Keep in sync with app/models/token_prefixes.rb in the Buildkite codebase");
  the body alphabet is "the base64url alphabet, plus '.', which separates the
  parts of tokens that embed an organization ID or are JWTs"; "The shortest
  tokens Buildkite issues have bodies of 38 bytes or more"; the redaction floor
  is `TokenBodyLengthMin = 24` (chosen below 38 "to also catch tokens that have
  been truncated (e.g. by `ps` …) while leaving short placeholders like
  `bkjat_encoded-token` alone"); the cap is `TokenBodyLengthMax = 2048`, because
  "Job acquisition tokens are JWTs and the longest tokens Buildkite issues, at
  several hundred bytes".
- **Provider docs.** `buildkite/docs` `pages/platform/security/tokens.md` at
  [`0d99082`](https://github.com/buildkite/docs/blob/0d9908248f21aa3beec6e417de99c6164360e25f/pages/platform/security/tokens.md#L18-L21)
  (2026-08-27) and <https://buildkite.com/docs/platform/security/tokens>:
  per-type prefixes `bkua_` (API access, created after 2023-03), `bkaa_` (agent
  session, after 2025-01), `bkaj_` (agent job, "notably longer"), `bkar_`
  (unclustered agent, after 2025-04), `bkct_` (cluster agent, after 2025-04),
  `bkpt_` (registry and packages temporary, extended length), `bkpat_` and
  `bkps_` (portal token and secret), `bkjat_` (job acquisition; "expire 15
  minutes after issuance" by default).
- **Provider test fixtures (R5).** `redact_test.go`
  ([L128–L190](https://github.com/buildkite/agent/blob/4b52e509c730797c2a97487972fdf99477fd07e6/internal/redact/redact_test.go#L128-L190)),
  described as "made-up values in the shape of real tokens": `bkaa_`/`bkct_` =
  a short org-ID segment, `.`, then a base58 body of about 60 bytes; `bkpat_`
  and the like use an org-ID segment, `_`, then 40 lowercase hex; `bkjat_` is a
  three-part dot-joined JWT (`eyJ` header); `bkua_` and `bkur_` use 40 lowercase
  hex. Bodies of 23 bytes are not redacted; 24 are.
- **Scanner rules (T2, corroboration only).** trufflehog `buildkite/v2`
  `bkua_[a-z0-9]{40}` at
  [`48b58d3`](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/buildkite/v2/buildkite.go#L27);
  the third-party `plenoai/pleno-dlp` detector uses the same `bkua_` + 40 hex.
  GitGuardian's "Buildkite Agent Token" detector page states the agent token is
  "Not prefixed", which describes its legacy form. The GitHub secret-scanning
  partner list carries ten Buildkite types (agent access, agent job, agent
  registration, cluster queue, cluster, packages registry, packages temporary,
  portal secret, portal token, user access) with push protection, which
  confirms the prefix families are secret by provider intent.

| Prefix | Role | Body | Tier |
| --- | --- | --- | --- |
| `bkua_` | API access token | `[A-Za-z0-9_.-]{24,2048}` | T1 (R2) |
| `bkur_`, `bktx_` | OAuth refresh token, token exchange | same | T1 (R2; role from code comments) |
| `bkaa_`, `bkar_`, `bkct_`, `bkcqt_` | agent access, agent registration, cluster, cluster queue | same (fixtures: org id, `.`, base58) | T1 (R2) |
| `bkaj_`, `bkjat_` | agent job, job acquisition (JWT) | same; `eyJ` header, two `.` | T1 (R2); the whole JWT is the match |
| `bkpt_`, `bkrt_` | packages temporary (also deprecated portal), packages registry | same | T1 (R2) |
| `bktr_`, `bkat_` | pipeline trigger, pipeline access | same | T1 (R2) |
| `bkpat_`, `bkps_` | portal token, portal secret | same | T1 (R2) |

Every prefix, the shared alphabet and the 2048 cap are from one
provider-authored rule; the 38-byte real-token floor is the provider's own
statement in a code comment inside that rule. Exact per-type lengths are not
stated anywhere: the docs describe some as "extended length", the fixtures are
made up, and the docs masked `bkua_` example of 53 characters is a mask, not a
count.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Bare 40-hex API token (legacy, no prefix) | no distinctive shape; collides with git SHAs; generic context |
| Legacy unprefixed agent token | no distinctive shape (GitGuardian: "Not prefixed"); generic context |
| `bka_` + 40 alphanumerics (plenoai only) | one third-party rule, no provider source; T2 |
| `bkzz_`-style unknown `bk?_` prefixes | the provider list is closed; the redactor test treats an unlisted prefix as benign |
| Placeholders such as `bkjat_encoded-token`, `bkua_xxx` | shorter than the floor; the provider's own test keeps them unredacted |
| A body of 23 bytes or fewer | below the provider redaction floor (truncated and placeholder values) |

## Tier rationale

T1 under R2: prefix list, alphabet, floor and cap are a provider-authored
redaction rule, dated 2026-09-29 (R9), with the prefix list cross-checked
against provider docs (R1 docs). No per-type exact length is claimed. The
detector claims the provider's own grammar and no tighter one, which is also the
only grammar that stays correct across the org-ID, base58, hex and JWT layouts.
R8 is respected: nothing is narrowed from a third-party library. The one
narrower third-party shape (`bkua_` + 40 hex) is not a limit on the contract.

## Overlap and output policy

- **Existing detectors.** No prefix `bk*_` is claimed on `main`
  (`cfa87360`, checked against detector sources and the support matrix).
  `jwt` would otherwise match the `eyJ…` body of `bkjat_`/`bkaj_`. The prefixed
  form must win and report one span from the prefix to the last JWT byte, as
  R7 already settles for JWT siblings of a provider prefix. `generic-token`
  defers to the provider type; `bearer-token` and `contextual_secret` may
  still report the same span.
- **Prior coverage (#1014 probe on `b9e9091`).** `BUILDKITE_*=value` gives
  `contextual_secret`; bare, chat and JSON `"token"` were missed.
- **New output.** Provider types, `Specificity::Provider`, high confidence,
  always redact.

## Implementation notes

`KnownFormatProviderDetector` with one `PrefixShape` per prefix: a variable
body `{24,2048}` over `[A-Za-z0-9_.-]`, leading boundary `[A-Za-z0-9_-]`, and
the body stops at the first non-body byte. A trailing `.` is a body byte in the
provider rule; the detector may trim one trailing run of `.` so sentence
punctuation is not swallowed, and the redaction of that byte either way is
harmless. Put the longer prefixes (`bkjat_`, `bkpat_`, `bkcqt_`) before any
shorter overlapping one; `bkpt_` and `bkpat_` do not overlap. Signals:
`buildkite-documented-prefix`, `buildkite-provider-redaction-grammar`.

**Floor choice (policy, not a ruling).** The provider's redactor uses 24 to
catch truncated values and notes real tokens are at least 38. The security-first
default is to adopt the provider's 24. A floor of 38 would drop truncated `ps`
fragments and still keep every placeholder out. The handoff recommends 24; it is
a one-constant change either way.

## Test axes

**Positives:** every #860 index context for `bkua_`; `Authorization: Bearer
bkua_…`; `BUILDKITE_API_ACCESS_TOKEN=` and `BUILDKITE_AGENT_TOKEN=` in `.env`;
a `buildkite-agent start --token …` command line; a `ps` line with
`--acquire-job bkjat_…`; one per prefix; a base58 body with an org-ID segment
and a `.`; a three-part JWT body for `bkjat_` and `bkaj_`; a 2048-byte body; a
24-byte body.

**Near-miss twins:** body of 23 (no finding); a `bkzz_` prefix; `BKUA_`
uppercase; `bkua-` or `bkua.` separator; a body containing `=` or `/`;
`bkat_` versus `bkaa_`; a leading glue byte (`xbkua_…`); a body of 2049 bytes
(match stops at the cap; the tail is not part of the finding).

**Benign:** `bkjat_encoded-token`; `bkua_xxx`; `bkua_` + 53 `*` (the docs mask);
`BUILDKITE_AGENT_TOKEN=${BUILDKITE_AGENT_TOKEN}`; identifiers such as
`bkct_cluster_name_for_builds` are the known risk (see below).

## False-positive / false-negative boundary

- **Accepted false negatives:** the unprefixed legacy agent and API tokens
  outside named contexts; a prefix Buildkite adds after 2026-09-29; truncated
  values below 24 bytes.
- **Accepted false positives:** an unrelated `bk??_`-prefixed identifier of
  24 or more body bytes from the listed prefixes, for example a snake_case
  variable name that begins `bkct_` or `bkat_`. The 24-byte floor, the body
  alphabet and the prefix boundary limit this; no real-world collision is known.
  This is the main trade-off of adopting the provider's floor instead of a
  tighter length.

## Issuance checklist (optional confirmation; structure only)

Not required for READY. For one API access token and one agent token (revoked
after the check):

- total length and body length for each (expect `bkua_` body of about 40
  lowercase hex, agent token body of about 60 to 80 with one `.`);
- alphabet classes per `.`-separated segment;
- `rawValueRetained: false` and revoked.
