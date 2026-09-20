# Issue #487 — Google OAuth credential coverage evidence (`GOCSPX-`, `1//`, `ya29.`)

[Audit archive](../../README.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Precision contracts: `google-api-key` family](../367/precision-contracts.json) ·
[Issue #487](https://github.com/redact-secret/redact-secret/issues/487) ·
[Issue #481 (Cloudflare `cfat_`, adopted)](https://github.com/redact-secret/redact-secret/issues/481) ·
[Issue #486 (Cloudflare `cfk_`, not adopted precedent)](https://github.com/redact-secret/redact-secret/issues/486)

Reviewed 2026-09-20 against this repository's `main`. This is an evidence-tier
review, not a detector change: it adds no `PrefixShape`, no new finding type,
and no fixture. It changes no runtime code.

## Summary

Issue #487 asked whether three Google OAuth credential formats —
`GOCSPX-` (client secret), `1//` (refresh token) and `ya29.` (access token) —
should be adopted as dedicated `google-api-key`-detector shapes, since today
all three are found only incidentally, when `generic-token`'s contextual rule
happens to fire. The issue's own text rates the evidence weaker than sibling
coverage issues #481 and #485, and explicitly asks that each format's tier be
settled "including the case where a format stays unadopted."

**None of the three formats is adopted.** Verified directly against each
pinned tool's source (not taken on the issue body's own summary of what those
tools cover), no consulted source — Google's own documentation, gitleaks
8.30.1, trufflehog 3.97.4, or flare-redact 1.6.1 — corroborates a body grammar
for `GOCSPX-` at all. `1//` and `ya29.` each have exactly one single-tool rule,
and each is the same broad "prefix plus a minimum-length run" shape issue #367
already found flags near-miss twins across seven other families. All three are
recorded pending (T0) in `docs/audits/evidence/367/precision-contracts.json`'s
new `google-api-key` family, alongside the family's one already-adopted
variant (`AIza`, unchanged). `crates/secret-scan-core/src/detectors/additional_providers.rs`
is not modified by this issue.

| Format | Issue #487's own ranking | Tool corroboration found | Disposition |
| --- | --- | --- | --- |
| `GOCSPX-` (client secret) | "the strongest candidate" | **none** — no pinned tool has any rule for it | not adopted, T0 |
| `1//` (refresh token) | "highest-impact... but risky on prefix alone" | flare-redact only, `1//[A-Za-z0-9_-]{20,160}` | not adopted, T0 |
| `ya29.` (access token) | "prefix risk similar to `1//`, lower value" | trufflehog only, `ya29\.[a-z0-9_-]{10,}` (open-ended) | not adopted, T0 |

The reversal on `GOCSPX-` is the material finding: the issue's own text names
"TruffleHog registers `googleoauth2`" and "flare-redact ships a default
`gcp_refresh_token` detector" as the available tool corroboration, and ranks
`GOCSPX-` as the strongest of the three candidates. Read directly, neither
cited tool's rule covers `GOCSPX-` — `googleoauth2` matches only `ya29.`, and
`gcp_refresh_token` matches only `1//`. `GOCSPX-` ends up with *less* tool
corroboration than either of the other two, not more.

## Evidence, per format

### `GOCSPX-` (OAuth client secret)

- **Google's own documentation.** `developers.google.com/identity/protocols/oauth2`
  (reobserved 2026-09-20) shows no example value and no format detail for the
  client secret, or for any of the three credentials. It states byte-length
  ceilings for two of the other two credentials (below) but nothing about the
  client secret at all.
- **gitleaks 8.30.1** (`config/gitleaks.toml`, tag `v8.30.1`). The only Google
  rule is `gcp-api-key`: `\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)`. Searched
  the full 3209-line file directly for `gocspx`, `1//`, `ya29`, and `google`;
  no other Google rule of any kind exists.
- **trufflehog 3.97.4** (`pkg/detectors`, tag `v3.97.4`). Four Google/GCP
  detector packages exist: `gcp` (service-account key JSON, keyed on
  `auth_provider_x509_cert_url`), `gcpapplicationdefaultcredentials`,
  `googlegemini` (the `AIzaSy` shape), and `googleoauth2` (`ya29.` only, see
  below). `gcpapplicationdefaultcredentials`'s `keyPat` is
  `\{[^{]+client_secret[^}]+\}` — it extracts whatever value already sits in a
  `client_secret` JSON field once `.apps.googleusercontent.com` triggers its
  keyword prefilter. That is contextual JSON extraction, not a lexical grammar
  for the value itself, and it cannot help the bare, dotenv, or log-line
  surfaces issue #487 reports as undetected — those are exactly the surfaces
  with no surrounding `{...client_secret...}` structure for this detector to
  key on.
- **flare-redact 1.6.1** (`spec/detectors.json`, tag `v1.6.1`, commit
  `c652ea7946028b70527069d7c282752b8a0ccee3`). Ships `google_api_key`
  (`AIza[0-9A-Za-z_-]{35}`) and `gcp_refresh_token`
  (`1//[A-Za-z0-9_-]{20,160}`). No `GOCSPX-` rule of any kind.
- **GitHub secret-scanning partner patterns**
  (reobserved 2026-09-20). Lists a "Google OAuth Client ID" type that also
  names `google_oauth_client_secret`, with push protection enabled. This is
  existence corroboration only — the page publishes no prefix, length, or
  alphabet for any partner pattern, the identical reading this repository
  already gives the same page for Cloudflare's `cfk_`
  (`docs/audits/evidence/367/precision-contracts.json`,
  `families.cloudflare-token.pending`, closed via issue #486).

No consulted source states or implies a body length or alphabet for
`GOCSPX-`. Freezing one now would be a guess, not a reviewed contract — the
same conclusion issue #486 reached for Cloudflare's `cfk_`, and the same
honest-alternative disposition this repository already applies to
DigitalOcean's `dop_v2_` and Slack's legacy prefixes.

### `1//` (OAuth refresh token)

flare-redact 1.6.1's `gcp_refresh_token` is the only rule any consulted
source ships: `1//[A-Za-z0-9_-]{20,160}` — a bare 3-byte prefix followed by a
20-to-160-byte range over a common alphabet. Single-tool, and not
independently corroborated: gitleaks has no rule, and none of trufflehog's
four Google/GCP packages matches `1//`. Google's OAuth 2.0 protocol page
states one relevant fact — refresh tokens are ≤512 bytes total — an upper
bound only, with no example value, so it corroborates neither the 160-byte
ceiling nor any narrower one. A bare prefix plus an open minimum-to-maximum
run is exactly the shape issue #367's decision record names as the beta.4
defect across seven other families ("that shape cannot express a marker, an
exact width, a per-segment alphabet... flags every near-miss twin"); adopting
`1//[A-Za-z0-9_-]{20,160}` on a single uncorroborated source would
reintroduce that same class deliberately, which issue #487's own text warns
against. GitHub's partner-pattern page lists a "Google OAuth Refresh Token"
type (push protection enabled) — existence only. Not adopted.

### `ya29.` (OAuth access token)

trufflehog 3.97.4's `googleoauth2` package registers exactly one rule:
`\b(ya29\.(?i:[a-z0-9_-]{10,}))(?:[^a-z0-9_-]|\z)` — an open-ended minimum
length (10-byte floor, no ceiling at all) over a common alphabet. This is a
weaker shape than even `1//`'s bounded range: no consulted source gives
`ya29.` an upper bound. gitleaks has no rule; flare-redact 1.6.1 has no
`ya29.` rule (only `google_api_key` and `gcp_refresh_token`). Google's OAuth
2.0 protocol page states access tokens are ≤2048 bytes total — again an upper
bound only, with no example value. GitHub's partner-pattern page lists a
"Google OAuth Access Token" type (push protection enabled) — existence only.
`ya29.` tokens are also short-lived by design (issue #487's own text), which
lowers the value of detecting them even where a grammar existed. Not adopted.

### `AIza` (OAuth API key — unaffected, recorded for completeness)

`google-api-key` was never one of issue #367's seven frozen families, so no
precision-contracts.json entry existed for it before this issue. Since this
issue creates the family's first entry, the already-implemented `AIza`
variant is recorded alongside the three pending OAuth formats rather than
left undocumented. Three independent sources agree on the same 39-byte total
length: gitleaks 8.30.1's `gcp-api-key` (`AIza[\w-]{35}`, prefix + 35),
flare-redact 1.6.1's `google_api_key` (`AIza[0-9A-Za-z_-]{35}`, identical),
and trufflehog 3.97.4's `googlegemini` (`AIzaSy[A-Za-z0-9_-]{33}`, a
narrower 6-byte `AIzaSy` split of the same 39 bytes). Google's own
authentication docs page shows one example value,
`AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe` (39 characters), consistent with
all three. Tier T2, matching the tier this repository's other
tool-corroborated-only families already carry.
`crates/secret-scan-core/src/detectors/additional_providers.rs`'s `GOOGLE`
constant is not changed by this issue.

## Corpus impact

Adding the `google-api-key` family to
`docs/audits/evidence/367/precision-contracts.json` makes
`scripts/audit-precision-contracts.py` audit the family's one adopted
variant (`AIza`) against every existing fixture that already references the
`google-api-key` detector. Re-run after this issue's edit:

```
python3 -B scripts/audit-precision-contracts.py --write
python3 -B scripts/audit-precision-contracts.py --check
# Precision contract audit complete: 0 error(s)
```

`docs/audits/evidence/367/corpus-audit.json` gains 19 `google-api-key` rows,
all `retained` (9) or `silent` (10); zero `broad-shape` and zero `review`.
`docs/audits/evidence/367/beta4-twin-baseline.json` is unchanged: Google was
never part of the beta.4 twin baseline, and this issue adds no new baseline
pair. `npm run precision-contracts:check` and `npm run coverage:check` both
pass unchanged.

## What this document does not claim

- It does not assert that `GOCSPX-`, `1//`, or `ya29.` can never be adopted —
  only that no consulted source today corroborates a body grammar for any of
  them. If gitleaks or trufflehog ships a `GOCSPX-`-specific rule, or Google's
  own documentation states a body length or alphabet for any of the three,
  the corresponding `pending` entry in
  `docs/audits/evidence/367/precision-contracts.json` should be revisited,
  the same reopening path issue #486 left for Cloudflare's `cfk_`.
- It does not change how any of the three formats is currently found:
  `generic-token`'s contextual rule still fires when one of these values
  follows a credential-like assignment name, unaffected by this issue. The
  gaps issue #487 reported — bare values, vendor-prefixed environment
  variables (`GOOGLE_CLIENT_SECRET`), and log lines — remain gaps.
  `generic-token`'s whole-name `HIGH_SIGNAL_NAMES` matching is out of scope
  here, as issue #487's own text says: "a general contextual-detector
  question, not a Google one."

## Verification

```
cargo test -p redact-secret --lib detectors::
# 630 passed; 0 failed

npm run precision-contracts:check
npm run coverage:check
```

CLI reproduction of issue #487's synthetic fixtures against `main`, confirming
the reported gaps are unchanged and the reported negatives stay silent:

| Input | Result |
| --- | --- |
| `GOCSPX-SYNTHETICREVOKEDOAUTH0` (bare) | 0 findings (unchanged, undetected) |
| `GOOGLE_CLIENT_SECRET=GOCSPX-SYNTHETICREVOKEDOAUTH0` (dotenv) | 0 findings (unchanged, undetected) |
| `1//0eSYNTHETICREVOKEDGCLOUDREFRESHTOKEN0000000000000000000` (bare) | 0 findings (unchanged, undetected) |
| `000000000000-abc123def456ghi789.apps.googleusercontent.com` (client id) | 0 findings (stays silent) |
| `synthetic@proj.iam.gserviceaccount.com` (service-account email) | 0 findings (stays silent) |
| `AIzaSy` + 33-byte synthetic body (existing `AIza` positive) | 1 finding, `google-api-key`, high/redact (unchanged) |

Service-account key JSON continues to be caught by `private-key` at `block`
through the existing `detectors::private_key` test suite (part of the 630
passing tests above); this issue touches neither that detector nor its
fixtures.

## Recommendation

Close issue #487 with this evidence. Acceptance criterion 1 ("each format's
evidence tier is settled and recorded... including the case where a format
stays unadopted") is met by the `google-api-key` family's `pending` entries.
The remaining acceptance criteria are conditioned on adoption ("if adopted:
...") and are vacuously satisfied: nothing is adopted, so there is no new
range to report at each context, no new negative twin to keep silent, and no
new fixture to commit. `AIza` behavior, the negative client-id/service-account
surfaces, and service-account key JSON coverage are all confirmed unchanged
above.

## Authority

This document records an evidence-tier review. It does not change detector
behavior beyond documenting the existing `AIza` contract, select a version,
create a tag, publish a package, or authorize any release operation. A
release still requires the explicit approval `AGENTS.md` mandates.
