# #1014 handoff: `square:access-token`

[#1014 index](README.md) · rank 24 ·
[Research table #41](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447820)

**Readiness: READY under R5 (issuance check recommended; one new ruling, Q8,
on the provider's length disclaimer).** **Route:** new detector
`square-token`, finding types `square_access_token` (`EAAA`) and
`square_oauth_application_secret` (`sq0csp-`, `sandbox-sq0csb-`).

## Role and blast radius

A Square access token (`SQUARE_ACCESS_TOKEN`, sent as `Authorization:
Bearer`) acts for a merchant or the developer's own account: payments,
refunds, orders, customers, inventory and locations, within its OAuth
scopes. A personal access token from the Developer Console is the same
shape. The OAuth application secret (`client_secret`) lets an integration
exchange authorization codes and renew or revoke seller tokens, so a leak
compromises every seller that authorized the application. Both are pasted
into `.env` files, SDK calls (`new Client({ accessToken })`) and MCP server
configs, which is where agents see them.

## Discovery (broad first, source classes labelled afterwards)

Searched, 2026-09-30: web search on the prefixes, lengths and false
positives; Square developer forums; scanner rule sets (gitleaks `b58d3f1`,
trufflehog `48b58d3`, noseyparker `2e6e7f3`, betterleaks, GitGuardian docs,
Veles, the GitHub partner list); GitHub issues on those scanners; Square docs
and SDK fixtures. Every example width below was counted from the fetched page
on 2026-09-30; no example is reproduced.

| Source | Class | What it gives |
| --- | --- | --- |
| [Receive and manage seller OAuth tokens](https://developer.squareup.com/docs/oauth-api/receive-and-manage-tokens), observed 2026-09-30 | provider docs | "transitioning to JWT (JSON Web Token) access tokens ... don't use token length for validation"; the traditional access token example is 64 characters, `EAAA` + 60, alphabet letters, digits and `_`; authorization code example `sq0cgb-` + 22 |
| [ObtainToken reference](https://developer.squareup.com/reference/square/o-auth-api/obtain-token), observed 2026-09-30 | provider docs | `access_token` example `EAAl` + 59 (63 total); `refresh_token` `EQAA` + 60 (64); `client_secret` `sq0csp-` + 44; `client_id` `sq0idp-` + 22 |
| [OAuth walkthrough](https://developer.squareup.com/docs/oauth-api/walkthrough), observed 2026-09-30 | provider docs | `sq0csp-` + 43; `sandbox-sq0csb-` + 43; `sq0idb-` and `sandbox-sq0idb-` + 22 (application ids) |
| [square-nodejs-sdk wire test](https://github.com/square/square-nodejs-sdk/blob/5e484507548ce8ffdc55752395a290ecc2d26771/tests/wire/oAuth.test.ts) (HEAD 2026-09-30) | provider code (generated fixtures) | the same values as the ObtainToken reference: `EAAl` + 59, `EQAA` + 60, `sq0csp-` + 44 |
| [trufflehog `square.go`](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/square/square.go#L33): `EAAA[a-zA-Z0-9\-_+=]{60}` with the keyword `square`; [`squareapp.go`](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/squareapp/squareapp.go#L32): `(?:sandbox-)?sq0c[a-z]{2}-[0-9A-Za-z_-]{40,50}` | third-party scanner rules | independent 60-character `EAAA` body; wide secret window |
| [gitleaks `square.go`](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/square.go#L14): `(?:EAAA|sq0atp-)[\w-]{22,60}` and `sq0csp-[\w-]{43}` | third-party scanner rules | `sq0csp-` + 43; a loose `EAAA` window; `sq0atp-` exists only here and in noseyparker |
| [noseyparker `square.yml`](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/square.yml) | third-party scanner rules | `sq0atp-[a-z0-9_-]{22}`, `sq0csp-[a-z0-9_-]{43}` |
| [Veles request osv-scalibr#1656](https://github.com/google/osv-scalibr/issues/1656), 2026-01-12 (closed, PR #1669) | issue (community) | `EAAA` 64 total with `[\w\-\+\=]{60}`, `sq0csp-` 50 total; no validation evidence given |
| [gitleaks#1468](https://github.com/gitleaks/gitleaks/issues/1468), 2024-08-16 | issue (community) | false positives: lowercase `eaaa…` Docker image digests matched the loose rule |

GitHub's partner list names Square Access Token and the Production and
Sandbox Application Secret. The scanners agree on `EAAA` + 60 and on
`sq0csp-` + 43; Square's own pages disagree with themselves on 63 vs 64 and
43 vs 44 (hand-written examples).

## Supported shape

| Role | Shape | Provenance | Tier |
| --- | --- | --- | --- |
| Access token, traditional (production personal and OAuth) | `EAAA` + exactly 60 `[A-Za-z0-9_-]` (64 total) | prefix, length and alphabet from the docs example (R4, R5); corroborated by trufflehog, Veles, gitleaks (T2) | T1 (R5), with the conflict and the disclaimer below |
| OAuth application secret, production | `sq0csp-` + 43 or 44 `[A-Za-z0-9_-]` | 43: walkthrough docs; 44: ObtainToken reference and SDK fixture (R5); the union is claimed | T1 (R5) |
| OAuth application secret, sandbox | `sandbox-sq0csb-` + 43 `[A-Za-z0-9_-]` | walkthrough docs example | T1 (R5, one docs page) |

The 43 or 44 union follows the Polar era-union precedent: both widths appear
in provider-authored material, so neither is dropped.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| JWT-format access tokens (`eyJ…`) | R7: they stay with `jwt` |
| `EAAl` + 59 access token (63 total) and `EQAA` + 60 refresh token | one provider example each (docs reference plus its generated SDK fixture): the same value, so not independent, and it disagrees with the 64-character example; needs an issuance check before a claim |
| `sq0atp-` + 22 legacy personal access token | scanner rules only (T2); Square's pages show no such token |
| `sq0cgb-` + 22 authorization code | short-lived and single use; docs example only |
| `sq0idp-`, `sq0ids-`, `sq0idb-`, `sandbox-sq0idb-` application ids | public identifiers by design (Q5) |
| Any non-`EAAA` token of another length | no source |

## Tier rationale

- The prefix `EAAA` is T1 by the docs example (R4). Length 64 and the
  alphabet are T1 by example under R5 (docs example plus, for `sq0csp-`, the
  SDK fixture). The exception is the access token's length: Square's page
  says "don't use token length for validation", and the provider's other
  example (63) disagrees. The 64-character example is the page that defines
  the token, and all four independent scanner or request sources use 60
  after `EAAA`, but those are T2. This is the reason Q8 is asked.
- `sq0csp-` has two provider widths; the union is the contract.
- The family shrinks over time as Square moves to JWTs, and the `jwt`
  detector keeps the migrated tokens.

## Overlap and output policy

- **Existing detectors.** None claims `EAAA` or `sq0`. A `grep` of the
  detector sources at `main` `cfa87360` finds no Square contract (the only hit
  is an unrelated base64 PNG header in a `generic-token` test).
  `SQUARE_ACCESS_TOKEN=` is expected to be a generic `contextual_secret`; the
  bare, chat and JSON `"token"` occurrences are missed (step-1 probe).
- **`jwt`.** A JWT-format Square token is reported by `jwt`, never by this
  family.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector`. `PrefixShape::exact("EAAA", 60, <[A-Za-z0-9_-]
predicate>, …)`, `PrefixShape` for `sq0csp-` (43 and 44) and
`sandbox-sq0csb-` (43). Boundary `[A-Za-z0-9_-]` on both sides, so a longer
run (a Meta `EAAA…` Graph token is far longer, a Docker digest is lowercase
and 64 hex) cannot match. Match case-sensitively. Signals:
`square-docs-prefix`, `square-docs-shape`.

## Test axes

**Positives:** every #860 index context; `SQUARE_ACCESS_TOKEN=`;
`Authorization: Bearer EAAA…`; `new Client({ accessToken })`; an MCP `env`
block; a body containing `-` and `_`; `sq0csp-` at 43 and at 44;
`sandbox-sq0csb-`.

**Near-miss twins:** `EAAA` + 59 and + 61; `EAAB`, `EAAl` and `EAAA` inside a
longer alphanumeric run (Meta-style); lowercase `eaaa` + 60 hex-like; a `+`,
`=` or `/` in the body; `sq0csp-` + 42 and + 45; `sq0idp-` + 22;
`sandbox-sq0csb-` + 42; a leading glue byte and a trailing glue byte.

**Benign:** a `sha256:eaaa…` Docker digest; a Base64 image or binary blob
containing `EAAAAAAA…` runs of `A` (padding); `sq0idp-` application ids;
`EAAA` + 60 inside a longer alphanumeric run; placeholders
(`EAAA-your-access-token`, `sq0csp-xxxxxxxx`);
`SQUARE_ACCESS_TOKEN=${SQUARE_ACCESS_TOKEN}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** JWT-format tokens (`jwt` keeps them), `EAAl`
  (63) and `EQAA` tokens, `sq0atp-`, tokens with `+` or `=` (trufflehog's
  class allows them; Square's own example does not), any future
  traditional-token width change, and `sq0csp-` of another width.
- **Accepted false positives:** an unrelated run of `EAAA` + 60 URL-safe
  bytes at identifier boundaries, which includes a binary-derived Base64 line
  made almost entirely of `A` bytes. The boundary makes this very rare; a
  post-check that rejects an almost-constant body is an option for the
  implementation issue, not part of this contract.

## Issuance checklist (structure only; recommended, not a precondition)

For one production access token, one sandbox access token, one refresh token
and one OAuth application secret (production and sandbox):

- total length and alphabet classes (does `+`, `=`, `_` or `-` occur; expect
  64 for the access token);
- whether the sandbox access token also starts with `EAAA`, and whether `EAAl`
  and `EQAA` are real prefixes or placeholder edits;
- `sq0csp-` body length (43 or 44);
- `rawValueRetained: false` and revoked.

Follow the [#860 issuance-check protocol](../860/README.md#issuance-check-protocol-structure-only).
No key was requested or issued for this record.
