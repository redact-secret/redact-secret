# Issue #649 — T1 provider evidence for `firebase:server-key`

[Audit archive](../../README.md) ·
[Issue #649](https://github.com/redact-secret/redact-secret/issues/649) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Second-pass research](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5784943010) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5785369001) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5786066937) ·
[Firebase contract decision](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Prior evidence: #520](../520/README.md)

Written 2026-09-23 on branch `chore/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

No provider-domain source states the identifying element of the contract, the
literal `AAAA` prefix, or any grammar for the `AAAA…:…` key. Every source
class in the issue's "Done when" was checked. Google did publish two shape
statements, but neither establishes the prefix, and both contradict the
contract (see Contradictions).

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `AAAA` | no | no provider page states it; tools only, all traced to one 2020 write-up |
| head length 11 (`AAAA` + 7) | no | tools and observed keys only |
| `:` delimiter | no (signal only) | Firebase blog 2017 screenshot shows a colon-delimited value, but it is a mock with a 10-char head and no `AAAA` |
| body length 140 | no | tools only; the provider's only length statement is 175 total (163-char body), which the contract rejects |
| alphabet `[A-Za-z0-9_-]` | no | tools and observed keys only |
| marker / checksum (`APA91b` body prefix) | no | observed in every real key, never provider-stated; not in the contract |

The legacy-generation server key (the "Legacy server key" of 2016–2020) is
provider-documented as `AIza`-shaped. That shape belongs to `google-api-key`,
not this family.

## The source

No source meets the bar. The provider-domain statements that bear on the shape,
all re-fetched 2026-09-23:

- `https://firebase.googleblog.com/2017/01/debugging-firebase-cloud-messaging-on.html`
  (Firebase blog on a Google domain, 2017-01-31): "Your server key should be
  listed there as a giant 175-character string." It also calls the 153-char
  registration token a string "that looks a lot like your server key". The
  screenshot shows a mocked colon-delimited value that does not start with
  `AAAA`. `observedAt`: 2026-09-23.
- `https://firebase.google.com/support/releases` (March 2020 entry): "From
  March 2020, FCM has stopped creating legacy server keys. Existing legacy
  server keys will continue to work, but we recommend that you instead use the
  newer version of key labeled Server key". This names two generations. It
  gives no shape for either. `observedAt`: 2026-09-23.
- `https://web.archive.org/web/20240604012527/https://firebase.google.com/docs/cloud-messaging/auth-server`
  (archived provider docs; the same sentence as the release note, plus the only
  published `Authorization:key=` example). The example is a truncated
  `AIza`-prefixed placeholder. The same `AIza` example is already present in the
  2016-07-06 snapshot of `/docs/cloud-messaging/server` (UNT web archive).
  0 `AAAA` in both. `observedAt`: 2026-09-23.

Provider-authored code that contains a real `AAAA…:APA91b…` key
(`firebase/firebase-js-sdk` `integration/messaging/test/utils/sendMessage.js`,
added 2020-06-12, 11 + `:` + 140) is an embedded credential, not
documentation of a format. It counts as corroboration only, following the #647
treatment of provider-repo artefacts.

## Proposed `covers` sentence

None. The family stays T2. If a `review` note is updated, a factual version is:

> Google documents no lexical shape for the FCM server key: its only published
> key example is `AIza`-shaped (the older generation), and its only length
> statement (Firebase blog, 2017) gives 175 characters, which this 152-byte
> contract does not match; the `AAAA` prefix, 11-byte head, `:` separator and
> 140-byte body are tool-corroborated only.

## Contradictions with the current contract

Contract (`redact-secret-benchmarks` `benchmarks/lib/assessment.ts` line 112,
last changed at `0e879a4f`): `^AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}$`, T2.
The product detector
`crates/secret-scan-core/src/detectors/firebase.rs` implements the same exact
shape.

- **Length.** The provider's only length statement (175 total, Jan 2017)
  describes the late-2016 generation. The web-search pass measured bodies of
  162, 167 and 183 for that generation, 8 of 66 unique real keys. The exact
  `{140}` misses all of them. 140 holds for about 88% of observed keys
  (2017 onward). No source documents the change.
- **"Documented" labels in the product.** The detector emits the signal
  `firebase-documented-prefix`, and its doc comments describe the segments as
  "exactly documented length". No provider documents either. The benchmarks
  `review` text is accurate: it says Google publishes no rule for the shape.
  Recorded, not changed here.
- **`AAAA` is not a designed marker.** The 11-char head base64url-decodes to
  the 64-bit Firebase project number (Sender ID). 5 of 5 repos checked in the
  web-search pass confirm this. `AAAA` follows from project numbers below 2^40.
  It is analysis, not a provider source. No new key can now be issued, so it
  does not create a live false-negative class.
- **`APA91b` not required.** Every real key has it right after `:`. The
  contract and the synthetic fixtures do not require it. Pinning it would
  lower the false-positive rate but make existing synthetic fixtures miss.
  Undecided here.
- **Re-scope input (record only).** Legacy HTTP/XMPP FCM, the only API both
  key generations authenticated, was shut down from June–July 2024
  (troubleshooter page: "Shutdown begins in July 2024"). Live docs redirect
  every legacy page to v1 content, and `migrate-v1` is 404. No provider page
  will ever document this key again, so the family can reach `stable` only
  through a policy change, not through new evidence. Retiring it versus
  keeping it T2 as a historical-leak detector is for #575 to decide.

## Sources checked

Every class required by the issue was checked on 2026-09-22 and the
load-bearing pages re-fetched on 2026-09-23. The full URL-level tables are in the
[second-pass](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5784943010),
[broad-discovery](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5785369001)
and [web-search](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5786066937)
comments.

| source class | result |
| --- | --- |
| product docs and API reference (incl. JSON schemas) | live `auth-server`/`server`/`http-server-ref`/`xmpp-server-ref` redirect to v1 pages, 0 `AAAA`; `migrate-v1` 404 (re-checked 2026-09-23); archived legacy pages 2016–2024: only an `AIza` example; `fcm.googleapis.com` v1 discovery document has no server-key field; the legacy API had none |
| troubleshooter (first-pass caveat) | `firebase.google.com/support/troubleshooter/fcm/legacy`, rendered in a browser 2026-09-23: a migration notice and a support-case form; no key shape, 0 "server key". The caveat is closed |
| changelog / release notes | `firebase.google.com/support/releases`, March 2020: two generations named, no shape; Admin Node SDK release notes: nothing |
| FAQ | `firebase.google.com/support/faq` (live, 2026-09-23): "server keys" only in an OAuth-vs-server-key comparison, no shape |
| engineering / security blog | firebase.googleblog.com 2017-01 post: 175-character length, mock screenshot (above); firebase.blog FCM category and 8 posts, Google Developers / Android Developers / Cloud blogs: no shape |
| secret-scanning partner pages / token-format announcements | GitHub list: `firebase_cloud_messaging_server_key` is a GitHub-authored pattern, not a Google partner registration, no shape; no Google token-format announcement exists |
| provider-run secret detection | Google Cloud Sensitive Data Protection infoTypes reference (`docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference`, 2026-09-23): no FCM or Firebase server-key infoType; Google's `osv-scalibr` veles secrets: no FCM detector |
| SDK / CLI docs | `firebase.google.com/docs/admin/setup`, `/docs/cli`; `firebase-ios-sdk`/`firebase-android-sdk` required-options docs: they say the FCM server key differs from the API key, but give no shape |

Tools and community sources (nuclei-templates, BChecks, SecretFinder, titus,
pleno-dlp, Stack Overflow, the Abss 2020 write-up) are corroboration only.
Most tool regexes trace back to that one 2020 write-up, so they are not
independent.

Not read: Reddit (blocked in every pass), Firebase Google Group and Community
Discourse. None of these is a provider-documentation class, so the verdict
does not depend on them.

## Open items

- Empirical check on one surviving legacy key (head/Sender-ID match, body
  prefix, body length, issuance date), as specified in the
  [web-search comment](https://github.com/redact-secret/redact-secret/issues/649#issuecomment-5786066937).
  It settles the length question for #575's re-scope decision. It cannot
  produce T1 evidence. Record counts only.
- Re-scope of the family (retire vs. keep T2), for #575.
- Product labels `firebase-documented-prefix` / "documented length" in
  `firebase.rs`: this is a wording fix for a separate issue, not decided here.

## What this document does not do

It changes no detector, contract, fixture or tier.
`docs/contracts/precision/precision-contracts.json` has no entry for this
family and is untouched. The benchmarks contract is unchanged. It contains
no credential and no full example token value. Key lengths are measured
counts only.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
