# #1012 research: `google:oauth2-credential`

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#487 evidence](../487/README.md) ·
[#519 evidence](../519/README.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict, per part:**

| Part | Verdict |
| --- | --- |
| OAuth client secret `GOCSPX-` | **READY-T2** (READY-T1 if the maintainer applies R2 to Google's own osv-scalibr rule) |
| Access token `ya29.` | **BLOCKED**: Google's own example contains a `.` after `ya29.c`, which every rule excludes; no length floor |
| Refresh token `1//` | **BLOCKED**: Google's example contradicts the only peer rule on lead byte and length |

## What is new compared with #487 and #519

- #487 (2026-09-20) found no rule for `GOCSPX-` in its three pinned tools.
  Three rules exist elsewhere: Google's own osv-scalibr veles rule (2025),
  noseyparker (2023) and CredSweeper (2023). All give exactly 28 after the
  prefix.
- Google's osv-scalibr was set to exactly 28 by a Google engineer on
  2025-12-03, replacing a 10–40 range.
- Two Google-owned repositories commit installed-app client secrets of the
  same width. They are issued values, so they are **withheld and not
  counted** here; the maintainer may choose to rule on them.
- Google's service-account access-token example (`ya29.c.` then more) has an
  interior `.`.
- Google's refresh-token example is `1//` + 43, which contradicts
  CredSweeper's `1//0` + at least 80.

## Current product behaviour

No detector claims `GOCSPX-`, `ya29.` or `1//`. `client_secret=GOCSPX-…` is
caught only by `generic-token`'s `client_secret` name (#519). The synthetic
probe on `main` confirms a bare `GOCSPX-` value gives no finding.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| G1 | [google/osv-scalibr `veles/secrets/gcpoauth2client/detector.go` L51-L58 @ 5ab8022](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/gcpoauth2client/detector.go#L51-L58) | added 2025-09-22 (b30af46, `{10,40}`); exactly 28 since 2025-12-03 (0583d09, "Update gcpoauth2client regexp to match for blobs that are exactly 28 bytes long"); both by `@google.com` authors | provider-authored scanner rule | R2 = T1 candidate | `\bGOCSPX-[a-zA-Z0-9_-]{28}`. Comment: "There is no clear documentation on the exact format of GCP OAuth2 client secrets. But most online references suggest they start with "GOCSPX-" prefix." |
| G2 | [noseyparker `rules/google.yml` L17-L29 @ 2e6e7f3](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/google.yml#L17-L29) | 2023-02-06 | peer scanner rule | T2 | `\b(GOCSPX-[a-zA-Z0-9_-]{28})(?:[^a-zA-Z0-9_-]\|$)` |
| G3 | [CredSweeper `config.yaml` L463-L475 @ f21ab2f](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/rules/config.yaml#L463-L475) | rule 2023-12-27 | peer scanner rule | T2 | `GOCSPX-[0-9A-Za-z_-]{28}(?![0-9A-Za-z_-])` |
| G4 | [googleworkspace/cli `oauth_config.rs` @ a3768d0](https://github.com/googleworkspace/cli/blob/a3768d0e82ad83cca2da97724e46bea4ff0e6dbd/crates/google-workspace-cli/src/oauth_config.rs#L26) | HEAD 2026-09-29 | provider code placeholder | R4 (prefix only) | `"client_secret": "GOCSPX-..."` |
| G5 | [Google Identity, OAuth 2.0 "Token size"](https://developers.google.com/identity/protocols/oauth2) | updated 2026-05-26 | provider docs | T1 (ceilings) | "Access tokens 2048 bytes", "Refresh tokens 512 bytes", "your application must support variable token sizes" |
| G6 | [Google Identity, web-server flow token response](https://developers.google.com/identity/protocols/oauth2/web-server) | read 2026-09-29 | provider docs example | R5 | refresh token `1//` + 43 `[A-Za-z0-9-]`, first body byte a letter |
| G7 | [Cloud IAM, create short-lived credentials](https://docs.cloud.google.com/iam/docs/create-short-lived-credentials-direct) | read 2026-09-29 | provider docs example | R5 | `accessToken` begins `ya29.c.` followed by a Base64url-like run with a further `.`; elided with `...` |
| G8 | [Cloud authentication, token types](https://docs.cloud.google.com/docs/authentication/token-types) | updated 2026-09-24 | provider docs | none | access tokens are "opaque" |
| G9 | [google/osv-scalibr `veles/secrets/gcpoauth2access/detector.go` L28-L42 @ 5ab8022](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/gcpoauth2access/detector.go#L28-L42) | 2025-09-22, `@google.com` author | provider-authored scanner rule | R2 candidate | `\bya29\.[a-zA-Z0-9_-]{10,500}`; comment: "There are not documented lower and upper bounds on the length of the token"; the 500 cap is an "assumption" |
| G10 | [trufflehog `googleoauth2_access_token.go` L34 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/googleoauth2/googleoauth2_access_token.go#L34) | 2024-01-26 | peer scanner rule | T2 | `ya29\.` + at least 10 `[a-z0-9_-]` (case-insensitive) |
| G11 | [noseyparker `rules/google.yml` L48-L57 @ 2e6e7f3](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/google.yml#L48-L57) | HEAD 2026-02-21 | peer scanner rule | T2 | `ya29\.[0-9A-Za-z_-]{20,1024}` |
| G12 | [CredSweeper `config.yaml` L477-L503 @ f21ab2f](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/rules/config.yaml#L477-L503) | HEAD | peer scanner rule | T2 | `ya29\.[0-9A-Za-z_-]{22,8000}`; refresh `1//0[0-9A-Za-z_-]{80,8000}` (weak confidence) |
| G13 | [Google Cloud console help, client secrets](https://support.google.com/cloud/answer/15549257) | read 2026-09-29 | provider docs | none | client secrets are hashed from June 2025 (existing clients from November 2025); the console shows only the last four characters. No format |

Searched, nothing further: gitleaks and betterleaks (no rule for any of the
three); Kingfisher (no native rule); GitHub code search in `googleapis` and
`firebase` (no hits), `GoogleCloudPlatform` (quota); GitGuardian's page
("Prefixed: True", no shape).

## `GOCSPX-` client secret: handoff contract

**Corroboration count:** G1 (Google, provider-authored code), G2
(Praetorian), G3 (Samsung): three dated references, three owners, two
classes (provider code and peer scanner rule).

**Role and blast radius.** The client secret of a Google OAuth client. With
the public client ID it lets an attacker complete authorization-code
exchanges and refresh tokens as that client. Installed-app secrets are
treated by Google as non-confidential; web-app secrets are confidential and
share the prefix. The redaction default is unchanged by that split.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `GOCSPX-` | G1, G2, G3; G4 placeholder (R4) | T2 (T1 under R2 for G1) |
| Body | exactly 28 `[A-Za-z0-9_-]` (35 in total) | G1, G2, G3 | T2 |
| Boundary | not `[A-Za-z0-9_-]` on either side | G2, G3 | T2 |

**Proposed type:** `google_oauth_client_secret`, new detector
`google-oauth-client-secret`, provider, high, always-redact.

**Excluded shapes:** client secrets issued before the prefix (no
prefix; context only); the client ID (`<digits>-<id>.apps.googleusercontent.com`,
public); `GOCSPX-` below or above 28.

**Overlap:** `generic-token` covers `client_secret=` today; the provider type
wins on the same span. No deferral change.

**Test axes.** Positives: bare, `client_secret.json` (`"client_secret":`),
env `GOOGLE_CLIENT_SECRET=`, chat. Twins: 27 and 29; `gocspx-`; `GOCSPX_`; a
`.` inside; glue bytes. Benign: a client ID, `GOCSPX-...` placeholders.

**FP/FN boundary.** False negatives: unprefixed legacy secrets outside
named contexts; any future width change. False positives: none known.

**Issuance checklist (optional).** Create one OAuth client in a test project,
read the secret once at creation: total length (35?), classes present
(`_`, `-`?), `rawValueRetained: false`; delete the client.

## `ya29.` access token: exact missing evidence

- **Alphabet:** Google's example (G7) has an interior `.`; every rule found
  (G9–G12, including Google's own) excludes it. Nothing settles which bytes
  occur.
- **Length:** floors 10, 20 and 22 across rules; caps 500, 1024, 8000 or
  none. Google states only "at most 2048 bytes" and variable (G5).
- **Structure-only check:** one user token (`gcloud auth
  print-access-token`) and one service-account token (`generateAccessToken`):
  total length, whether a `.` follows the `ya29.` prefix, whether `_` or `-`
  occur. Tokens expire in an hour. Value is low: short-lived, and Bearer
  contexts are already redacted by `bearer-token`.

## `1//` refresh token: exact missing evidence

- **Lead and length:** Google's example (G6) is 43 after `1//` and starts
  with a letter; CredSweeper (G12) requires `1//0` and at least 80. No
  Google-authored rule exists. Floor unknown; ceiling 512 bytes (G5).
- **False-positive risk:** a three-byte prefix plus an open run matches code
  such as integer floor division; a floor is needed before any rule.
- **Structure-only check:** one refresh token from an installed-app flow:
  total length, whether it starts `1//0`, classes present; revoke the grant.
