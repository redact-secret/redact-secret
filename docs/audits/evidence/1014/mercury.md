# #1014 handoff: `mercury:api-token`

[#1014 index](README.md) · rank 28 ·
[Research table #47](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447820)

**Readiness: BLOCKED** (the body width has one provider example and no
provider bound; see [What is missing](#what-is-missing)). **Route:** if
unblocked, a small distinct detector `mercury-api-token` for the **bare**
form; the `secret-token:` form stays with `bearer-token`.

## Role and blast radius

A Mercury API token grants account, statement, recipient and card data, and
(read-write or custom scope) money movement. Mercury offers Read Only,
Read and Write (IP allow-list required) and Custom tokens. Tokens are
passed as HTTP Basic (token as username) or `Authorization: Bearer`, and
the documented value includes the scheme `secret-token:`.

## Supported shape

Discovery started from open-web and code search for the suffix
`_yrucrem`; source classes are labelled afterwards. Checked 2026-09-30.

- **Provider docs.** `docs.mercury.com/docs/getting-started` and
  `/reference/getting-started-with-your-api` show one production example
  `secret-token:mercury_production_wma_<body>_yrucrem`; the body counts 45
  characters, `[A-Za-z0-9]` only. "Custom", "Read Only" and "Read and
  Write" are described in prose; the `api-token-security-policies` page
  states no format. No provider page shows a sandbox token or states a
  length.
- **Provider OpenAPI description.** The security-scheme text of Mercury's
  API description (mirrored, for example, in `amannm/docs` `specs/mercury`)
  repeats the same production example for the Basic and the Bearer schemes,
  with the `secret-token:` scheme inside the Bearer value. It is the same
  example, not an independent one.
- **Third-party scanner rules (T2).** betterleaks
  [`mercury.go`](https://github.com/betterleaks/betterleaks/blob/fa62e6aaad9de6da71de49e7114234700c84006e/cmd/generate/config/rules/mercury.go),
  Kingfisher `mercury.yml` (production and non-production) and other
  derived catalogs:
  `mercury_(production|sandbox)_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem`.
  These look derived from one source; a Kingfisher `references` entry
  cites the docs plus a third-party research note. The `{40,50}` window is
  a guess around the docs example. A fixture uses the tag `rma`; a public
  GitHub-staff test repository holds `rma` and `pentest` forms. The tag
  pairing `wma` (Read and Write) and `rma` (Read Only) is inferred, not
  documented; the tag for Custom tokens is unknown.
- **Third-party code.** `plenoai/pleno-dlp` `mercurybank.go` anchors on
  the prefix and suffix with no length window, stating "anchoring is the
  gate". A `.env.example` in a public repository shows a 46-byte body, so
  body widths of 45 and 46 are both seen (third-party, unverified).
- GitHub partner list: Mercury Production and Non-Production API Tokens
  (private repositories, partner list).

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Environment prefix | `mercury_production_` | provider docs example (R4) | T1 |
| Environment prefix | `mercury_sandbox_` | scanner rules only; no provider example | T2 |
| Type tag | `[a-z]{3,6}`, seen `wma`, `rma` | docs (`wma`), scanners | `wma` T1; rest T2 |
| Body | `[A-Za-z0-9]` × 40 to 50 (docs: 45; third-party: 46) | one docs example; scanner window | T2 (R5 wants docs example plus fixtures) |
| Suffix | literal `_yrucrem` | docs example | T1 |

## What is missing

1. **A provider bound on the body.** The only provider artifact is one
   45-byte example, repeated in the docs and the OpenAPI text. R5 asks for a
   docs example plus fixtures (Mercury publishes no SDK fixtures), and
   third-party sightings of 46 contradict an exact 45. Either a ruling
   (Q6, the same as Stytch: may a single provider example, repeated in the
   provider's own machine-readable API description, meet R5, and may policy
   set a window such as 40 to 50 around it?) or a structure-only issuance
   check of one Read Only and one Read and Write token (length, alphabet,
   tag) resolves it.
2. **Sandbox and tag set.** `mercury_sandbox_` and the tags for Read Only
   and Custom tokens have no provider source.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `secret-token:` + any token | already redacted by `bearer-token` (RFC 8959 scheme, body of 8 or more); this detector would only add attribution, and must not double-report |
| `mercury_<env>_<tag>_` with no `_yrucrem` suffix | the suffix is the anchor |
| `mercury_pentest_*` and other environments | no provider source |
| Mercury account, recipient and transaction ids (UUIDs) | identifiers |

## Tier rationale

Prefix and suffix are provider-documented by example (R4); the structure is
distinctive enough that a false positive needs the literal reversed brand.
The width is T2 today. A window from scanner rules would be a third-party
alphabet or length (R8 forbids narrowing from third-party libraries and
this would do the same for scanner rules), so it cannot be frozen without
a ruling or an issuance check.

## Overlap and output policy

- **`bearer-token`.** `secret-token:mercury_…_yrucrem` is already reported
  by `bearer_token.rs` (`SECRET_TOKEN_SCHEME`, body 8 or more, `is_secret_token_body_byte`
  allows `_`). Coverage of the documented form exists today; the new
  detector would cover the bare form (`MERCURY_API_TOKEN=mercury_…`, JSON
  `"token"`, chat) and attribute it. An overlap with `bearer-token` on the
  `secret-token:` form must resolve to the provider type when both match
  the same span, or the new detector must start after the scheme.
- **Env names.** `MERCURY_API_KEY=` gets `contextual_secret` today.
- **New output (if unblocked).** Provider type `mercury_api_token`, high
  confidence, always redact.

## Implementation notes (if unblocked)

`KnownFormatProviderDetector` on `mercury_` then `production`/`sandbox`,
`_`, `[a-z]{3,6}`, `_`, `[A-Za-z0-9]{40,50}`, `_yrucrem`; optional leading
`secret-token:` consumed into the span; boundary `[A-Za-z0-9_-]`. Signals:
`mercury-documented-prefix`, `mercury-reversed-suffix`.

## Test axes

**Positives:** bare in prose, `MERCURY_API_KEY=`, JSON `"token"`, chat, a
basic-auth username, `Authorization: Bearer secret-token:…` (expect one
finding, provider type); tags `wma`, `rma`; bodies of 44, 45 and 46.

**Near-miss twins:** body of 39 and 51; `_yrucrem` missing or misspelt;
`_mercury` (unreversed); an uppercase environment; a tag of 2 or 7
letters; a `-` in the body; glue bytes either side.

**Benign:** `mercury_production_wma_` placeholders with short bodies;
the reversed word on its own; Mercury account ids.

## False-positive / false-negative boundary

- **Accepted false negatives:** sandbox tokens until sourced; bodies
  outside the window; tokens in a form other than the documented one.
- **Accepted false positives:** none known (prefix and suffix are both
  needed).

## Issuance checklist (structure only)

For one Read Only, one Read and Write and, if possible, one Custom token
(production) and one sandbox token:

- the environment word and the type tag letters;
- body length and alphabet classes (expect 45, alphanumeric);
- whether the `secret-token:` scheme is part of the value the dashboard
  shows;
- `rawValueRetained: false` and revoked.
