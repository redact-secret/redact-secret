# Issue #519 — Google credential-family audit beyond `google-api-key`

[Audit archive](../../README.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Precision contracts: `google-api-key` family](../367/precision-contracts.json) ·
[Issue #519](https://github.com/redact-secret/redact-secret/issues/519) ·
[Issue #501 (epic)](https://github.com/redact-secret/redact-secret/issues/501) ·
[Issue #487 (Google OAuth credential coverage evidence, adopted here by reference)](../487/README.md) ·
[Issue #163 (service-account JSON export, PEM structural match)](https://github.com/redact-secret/redact-secret/issues/163)

Reviewed 2026-09-20 against this repository's `main`. This is a family-by-family
audit and evidence-tier review, not a new detector: it adds no `PrefixShape`,
changes no runtime grammar, and adds no new finding type. It adds five
corpus fixtures (four regression pins for a currently-undetected format, one
new benign-control pin) and no other behavior change.

## Summary

Issue #519 (B2, under Epic #501) scopes four Google credential families for a
support decision, each with its evidence tier: OAuth client secret,
service-account private key / JSON credential context, Gemini API
credentials, and OAuth refresh/access credentials "only where structurally
meaningful."

| Family | Disposition | Tier | Basis |
| --- | --- | --- | --- |
| OAuth client secret (`GOCSPX-`) | pending, not adopted | T0 | Issue #487 (unchanged) |
| Service-account private key / JSON credential context | **supported** | structural (T1-equivalent; no external corroboration needed) | Issue #163 — `private-key` detector's PEM delimiter match |
| Gemini API credentials | **supported** | T2 | Subsumed by the existing `google-api-key` `AIza` variant — no separate grammar or finding type |
| OAuth refresh token (`1//`) | pending, not adopted | T0 | Issue #487 (unchanged) |
| OAuth access token (`ya29.`) | pending, not adopted | T0 | Issue #487 (unchanged) |

Nothing here is silently absent: the two pending families keep the
`docs/audits/evidence/367/precision-contracts.json` `pending` entries issue
#487 already recorded, each with an unblocking condition; the two supported
families are backed by existing, already-shipped detector behavior and
fixtures, formalized here as an explicit family-level decision for the first
time. `crates/secret-scan-core/src/detectors/{additional_providers,
private_key}.rs` are not modified by this issue.

## Family 1 — OAuth client secret (`GOCSPX-`)

No re-review was needed: issue #487, reviewed the same day against the same
`main`, already settled this exhaustively. Restated for this audit's
completeness rather than re-derived: no consulted source (Google's OAuth 2.0
protocol page, gitleaks 8.30.1, trufflehog 3.97.4, flare-redact 1.6.1)
corroborates a body length or alphabet for `GOCSPX-` at all — it has *less*
tool corroboration than either OAuth token format below, the reverse of
issue #487's own tentative ranking of it as "the strongest candidate." See
[issue #487's evidence](../487/README.md#gocspx--oauth-client-secret) and
`precision-contracts.json`'s `families.google-api-key.pending[0]`
(`oauth-client-secret`) for the full source-by-source breakdown. Disposition
unchanged: pending, T0.

This audit adds one corpus fixture pinning the current, deliberate silence:
`google-negative-oauth-client-secret` (`conformance/fixtures/synchronous-
corpus.json`), a bare `GOCSPX-` value that resolves to zero findings. Issue
#487 verified this by CLI reproduction only; committing it as a fixture means
a future grammar addition here is a reviewed decision, not a silent
regression the next full corpus run would miss.

## Family 2 — Service-account private key / JSON credential context

**Supported.** A GCP/Firebase service-account key export is a JSON document
whose `private_key` field carries a standard PEM block
(`-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----`), surrounded by
non-secret identifying context (`type`, `project_id`, `private_key_id`,
`client_email`, `client_id`, `auth_uri`, `token_uri`). This is a **structural**
match, not a provider-prefixed one — `crates/secret-scan-core/src/detectors/
private_key.rs`'s delimiter-stack PEM parser finds the key by its own
universal PEM shape, with no Google-specific code path and no dependency on
the surrounding JSON structure at all. Per `docs/coverage/evidence-
requirements.md` §1, a structural detector's grammar does not need external
tool corroboration to earn a tier the way a provider-prefixed one does — the
delimiter shape is the evidence.

This is not new work: issue #163 already added the representative fixture,
`private-key-positive-json-service-account-export`
(`conformance/fixtures/synchronous-corpus.json`), a synthetic full
service-account export where the PEM body carries JSON-escaped `\n` line
breaks (the shape a real export produces before any JSON-string unescaping).
Its own note states the deliberate design point issue #519's acceptance
criteria ask for explicitly: "the structural PEM match alone finds the key;
the service-account shape is not consulted... it is optional corroborating
evidence only, never a substitute for the structural match." What issue #519
adds is the formal family-level disposition itself — until now, `private-key`
covering Google's service-account key shape had only been exercised as one
fixture under issue #163's PEM-parser feature work, never stated as a Google
credential-family decision in its own right.

### Benign controls: the surrounding JSON fields are not secrets

The acceptance criteria call for confirming the non-secret fields around a
service-account key stay silent, not just the key itself. Two new negative
fixtures cover the two identifiers that appear both inside a service-account
JSON export and independently in logs, IAM policy files, and OAuth
redirect-URI configuration:

- `google-negative-service-account-email` — a bare `client_email` value
  (`synthetic-sa@synthetic-project.iam.gserviceaccount.com`) with no
  accompanying key. This identifies the account; it is not the credential.
- `google-negative-oauth-client-id` — a bare OAuth 2.0 client ID
  (`000000000000-abc123def456ghi789jkl0mnopqrstu.apps.googleusercontent.com`).
  Google's OAuth documentation and the `apps.googleusercontent.com` issuance
  convention both treat this as a public application identifier embedded in
  client-side code and redirect URIs — the paired client secret (Family 1,
  above) is the actual secret, not the ID.

Neither carries an `AIza`/`GOCSPX-`/`1//`/`ya29.` shape, and CLI reproduction
against `main` confirms both resolve to zero findings today, matching issue
#487's own CLI table for the service-account email. Both dispositions are
now backed by a committed fixture rather than only a CLI reproduction table.

## Family 3 — Gemini API credentials

**Supported — subsumed by the existing `google-api-key` `AIza` variant. No
separate grammar or finding type.** Google's Gemini Developer API (issued via
Google AI Studio or the Cloud Console, restricted to the Generative Language
API) uses the identical `AIza`-prefixed, 39-byte-total key format as every
other Google Cloud API key; it is not a distinct credential family at the
lexical level, only a distinct *usage* of the same key shape.

This is not a new observation invented for this issue — the evidence already
lived inside `precision-contracts.json`'s `google-api-key` family, just not
stated as its own family decision. `trufflehog-3.97.4`'s `googlegemini`
detector package (`\b(AIzaSy[A-Za-z0-9_-]{33})`) is one of the three
independent tool sources the existing `api-key` variant (`AIza` +
exact-35-byte suffix, T2) already cites — trufflehog names its own rule after
Gemini specifically, and its narrower 6-byte `AIzaSy` prefix split of the
same 39-byte total length corroborates, rather than conflicts with,
gitleaks' and flare-redact's 4-byte `AIza` + 35-byte-suffix rule. The corpus
already carries direct evidence this shape is reached through Gemini-specific
naming: `google-positive-dotenv` (`conformance/fixtures/synchronous-
corpus.json`) uses `GEMINI_API_KEY=AIzaSy...` as its `.env`-context positive,
unchanged by this issue.

No separate finding type is warranted: unlike GitHub's six credential
families (issue #517), which have materially different issuance paths and
blast radii that a support matrix needs to distinguish, a Gemini API key and
a Google Maps or Firebase API key are the *same* credential type issued
through the *same* mechanism (a Cloud Console or AI Studio API key,
optionally restricted to specific APIs by scope configuration) — the
restriction is a runtime authorization property, invisible in the key's own
bytes, not a structural difference this repository's shape-only detector
could observe. Splitting `google_api_key` by intended-API-restriction would
require information no lexical detector has access to.

No corpus or detector change accompanies this disposition: `google-positive-
dotenv`, `google-positive-qualified`, and the rest of the `google-api-key`
family's existing positive/boundary/negative/overlap/adversarial fixtures
already fully evidence this family. This section exists to make the decision
explicit and citable, closing the gap issue #519 names.

## Family 4 — OAuth refresh / access credentials, "only where structurally meaningful"

Issue #519 asks that "opaque access tokens with no lexical evidence... be
recorded `unsupported`, not forced into a low-confidence detector." Applied
to Google's two OAuth token formats:

- **`1//` (refresh token)** carries a literal, documented 3-byte prefix —
  structurally meaningful in principle — but the only rule any consulted
  source ships is flare-redact's single-tool, uncorroborated 20-160 byte
  open range (`1//[A-Za-z0-9_-]{20,160}`). Google's own OAuth 2.0 protocol
  page states only an upper bound (≤512 bytes total) with no example value.
  This is exactly the broad prefix-plus-minimum-length shape issue #367's
  decision record already names as the beta.4 defect pattern across seven
  other families. Not structurally meaningful enough to adopt: pending, T0
  (unchanged from issue #487).
- **`ya29.` (access token)** has exactly one single-tool rule (trufflehog's
  `googleoauth2`, an open-ended minimum length with *no* ceiling at all,
  weaker than `1//`'s bounded range) and is short-lived by design, lowering
  detection value even where a grammar existed. Pending, T0 (unchanged from
  issue #487).

Both formats *do* carry a literal prefix, which is why they are recorded
`pending` rather than `unsupported` — a `pending` entry names a real
candidate grammar an issue can revisit once a length/alphabet source exists,
while `unsupported` is reserved (per `docs/decisions/2026-09-20-inventory-
gitlab-token-families.md`'s identical distinction, drawn there for GitLab's
legacy runner-registration token) for values with no prefix or shape at all
to build a future grammar on. Neither Google OAuth format matches that
description, so neither was reclassified to `unsupported`; `pending` was
already the correct disposition and issue #487 already recorded it that way.

Two new regression-pin fixtures make this dimension's negative twin explicit
in the corpus rather than only in a CLI reproduction table:
`google-negative-oauth-refresh-token` and `google-negative-oauth-access-token`
(`conformance/fixtures/synchronous-corpus.json`), each a bare, synthetic
instance of its prefix resolving to zero findings today.

## What "structurally meaningful" excludes here

Per the issue's own framing, an opaque bearer value with zero lexical
evidence is not a candidate for this family's prefix/structure-anchored
detectors at all, and is correctly left uncovered by `google-api-key` and
`private-key` alike — it is picked up only incidentally by `generic-token`'s
contextual rule when a high-signal key name (`client_secret`, `private_key`,
etc.) sits next to it, the same general contextual-detector mechanism issue
#487 already scoped out of Google-specific review ("a general
contextual-detector question, not a Google one"). Verified unchanged by this
issue: `client_secret=GOCSPX-...` (exact high-signal key name) still
produces one `generic-token` `contextual_secret` finding; `GOOGLE_CLIENT_
SECRET=GOCSPX-...` (a vendor-prefixed key name outside `generic-token`'s
`HIGH_SIGNAL_NAMES` exact-match set) still produces zero findings, matching
issue #487's own CLI table exactly. `generic-token`'s own contextual
evidence is unaffected by, and out of scope for, this issue.

## Corpus impact

Five new fixtures in `conformance/fixtures/synchronous-corpus.json`
(`fixtureCount` 1354 → 1359), all `detector: "google-api-key"`, `kind:
"negative"`:

| Fixture | Purpose |
| --- | --- |
| `google-negative-oauth-client-secret` | Regression pin: `GOCSPX-` stays silent (pending, T0) |
| `google-negative-oauth-refresh-token` | Regression pin: `1//` stays silent (pending, T0) |
| `google-negative-oauth-access-token` | Regression pin: `ya29.` stays silent (pending, T0) |
| `google-negative-oauth-client-id` | Benign control: OAuth client ID is a public identifier, not a secret |
| `google-negative-service-account-email` | Benign control: bare `client_email` is not a secret |

All input values are synthetic (`SYNTHETIC`/`REVOKED` markers or clearly-fake
identifiers under a `synthetic-*`/`0000...` construction); no real credential
appears anywhere in this document or these fixtures.
`conformance/fixtures/common-profile-expectations.json` was regenerated
(`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1 cargo test -p redact-secret
--test common_profile_corpus`): all five new fixtures resolve empty under the
`common` profile, the same as every other `google-api-key` fixture (`Pack::
Provider`-only). `docs/coverage/coverage-declarations.json` and
`docs/coverage/inventory-report.json` were regenerated
(`scripts/generate-coverage-{declarations,inventory}.py`) rather than
hand-edited; `google-api-key`'s `near-miss-negative` dimension evidence
gained the two new benign-control fixture ids and still resolves
`supported`. `docs/audits/evidence/367/precision-contracts.json` is
unchanged: no variant, pending entry, or source list was edited, since no
disposition in this document changes what that file already records.

## What this document does not claim

- It does not assert `GOCSPX-`, `1//`, or `ya29.` can never be adopted —
  only that, as of this review, no consulted source corroborates a body
  grammar for any of them, the same qualification issue #487 already stated
  and this issue does not need to restate differently.
- It does not change how any of the five families is currently detected.
  `google-api-key`'s `AIza` contract, `private-key`'s PEM match, and
  `generic-token`'s contextual coverage are all unaffected; only the corpus
  gains explicit, committed evidence for dispositions that were previously
  correct but undocumented as family-level decisions (service-account
  private key, Gemini) or evidenced only by a CLI reproduction table rather
  than a corpus fixture (the two pending OAuth token formats, the OAuth
  client ID, the bare service-account email).

## Verification

```
cargo test -p redact-secret --lib detectors::
cargo test -p redact-secret --test canonical_corpus
npm run coverage:check
npm run precision-contracts:check
```

CLI reproduction, confirming the five new fixtures' expectations against
`main`:

| Input | Result |
| --- | --- |
| `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ECRET0` (bare) | 0 findings (unchanged, pending) |
| `1//0eSYNTHETICREVOKEDGCLOUDREFRESHTOKEN0000000000000000000` (bare) | 0 findings (unchanged, pending) |
| `ya29.SYNTHETICREVOKEDACCESSTOKEN00000000000000000000000000` (bare) | 0 findings (unchanged, pending) |
| `000000000000-abc123def456ghi789jkl0mnopqrstu.apps.googleusercontent.com` (client ID) | 0 findings (benign, stays silent) |
| `synthetic-sa@synthetic-project.iam.gserviceaccount.com` (bare service-account email) | 0 findings (benign, stays silent) |
| `client_secret=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ECRET0` | 1 finding, `generic-token`/`contextual_secret` (unaffected, out of scope) |
| `GOOGLE_CLIENT_SECRET=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ECRET0` | 0 findings (unaffected, matches issue #487) |
| `GEMINI_API_KEY=AIzaSy` + 33-byte synthetic body (existing `google-positive-dotenv`) | 1 finding, `google-api-key`, high/redact (unchanged) |

## Recommendation

Close issue #519 with this evidence. Every acceptance criterion is met:
each of the four scoped families has an explicit support decision and
evidence tier (Families 1-4 above); nothing is silently absent (both pending
formats keep their `precision-contracts.json` entries and now also carry a
committed regression-pin fixture); service-account private-key material is
handled by the existing structural `private-key` match with only synthetic
fixture material; the requested benign controls (OAuth client ID, bare
service-account email; Firebase/sample-app config values already covered by
`google-positive-javascript-firebase-config`) are asserted as corpus
fixtures; negative twins exist for every asserted dimension and no existing
positive fixture changed, so T1/T2 leaked-span counts are unchanged; and
every check above ran deterministically offline with no credential
validation of any kind.

## Authority

This document records a family-by-family evidence review. It does not
change detector behavior beyond adding the five fixtures above, select a
version, create a tag, publish a package, or authorize any release
operation. A release still requires the explicit approval `AGENTS.md`
mandates.
