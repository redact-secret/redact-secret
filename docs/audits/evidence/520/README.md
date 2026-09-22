# Issue #520 — Firebase secret-bearing credential detection with public-config discrimination

[Audit archive](../../README.md) ·
[Decision: Firebase server key detection and client-config discrimination](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Issue #520](https://github.com/redact-secret/redact-secret/issues/520) ·
[Issue #501 (epic)](https://github.com/redact-secret/redact-secret/issues/501) ·
[Issue #519 (Google credential-family audit, adopted here by reference)](../519/README.md)

Reviewed 2026-09-20 against this repository's `main`. Unlike issue #519, this
is not audit-only: it adds one new detector (`firebase-server-key`) and one
pipeline-level discrimination mechanism, both backed by new conformance
fixtures.

## Summary

Issue #520 (B3a, under Epic #501) asks for Firebase secret-bearing
credential detection, scoped explicitly to discrimination rather than
coverage: "Identify which Firebase-related material is genuinely secret
(service-account credentials, server keys, privileged tokens) and contract
only those. Treat the public client config as a benign control set, not a
target."

| Family | Disposition | Tier | Basis |
| --- | --- | --- | --- |
| FCM legacy server key (`AAAA...:...`) | **new detector**, `firebase-server-key` | T2 (single-tool exact width; provider-independent `AAAA` prefix) | `nuclei-templates` regex; B4X forum + FCM-takeover research corroborate the prefix |
| Web SDK client config `apiKey` (`AIza...`) | **discriminated**: suppressed only inside a recognized client-config object | n/a (pipeline exemption over `google-api-key`) | Firebase's own "safe to include" documentation |
| Service-account private key / JSON credential export | supported, unchanged | structural (issue #519, Family 2) | `private-key`'s PEM match; no Firebase-specific code |
| Gemini/Cloud use of the `AIza` shape | supported, unchanged | T2 (issue #519, Family 3) | subsumed by `google-api-key` |
| Realtime Database legacy secret (`?auth=`) | **pending** — opaque, no lexical evidence | — | Firebase's own docs publish no format |
| Firebase CLI token (`firebase login:ci`) | pending, unchanged | T0 (issue #519, Family 4) | same as Google's `1//` OAuth refresh token |

Nothing here is silently absent: the two pending items carry a committed
regression-pin fixture with a documented reason; the two unchanged-supported
items are backed by issue #519's own evidence, restated here only to
confirm the audit's completeness over "service-account credentials, server
keys, privileged tokens."

## Family 1 — FCM legacy server key: new detector

**Supported, new.** `crates/secret-scan-core/src/detectors/firebase.rs`
adds `firebase-server-key` for the shape:

```
AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
```

Evidence: the `AAAA` prefix is corroborated by two independent non-tool
sources describing real exposed keys (a B4X developer-forum FCM-deprecation
thread, and an independent FCM-takeover security-research writeup, both
observed 2026-09-20 — full citations in the detector's own doc comment and
the linked decision record). Neither gitleaks 8.30.1 nor trufflehog 3.97.4
ships a rule for this shape; trufflehog's own `proto/detector_type.proto`
(observed 2026-09-20) reserves `Firebase = 33` and
`FirebaseCloudMessaging = 102`, both marked `// Not yet implemented` — the
family is recognized by that tool, not merely unsearched here. The exact
two-segment body length is single-tool evidence
(`projectdiscovery/nuclei-templates`'s `firebase-fcm-server-key-disclosure.
yaml`, observed 2026-09-20), T2 — the same tier this crate already accepts
for `docker-token`'s and `linear-token`'s exact-width segments.

Google phased out the legacy FCM HTTP/XMPP send APIs this key authenticates
during 2024. A leaked key found today is very likely already
non-functional against Google's send endpoint; it is still detected, for
the same reason GitHub's classic PAT prefixes stay fully supported despite
fine-grained PATs being GitHub's now-preferred format (issue #517) — see
the linked decision record's "Current operational status" discussion.

`Confidence::High`, `Specificity::Provider`, `policy::ALWAYS_REDACT_TYPES`.
Registered after `new-relic-license-key` and before `jwt`.

## Family 2 — Web SDK client config: public-config discrimination

**Discriminated, not excluded.** Before this issue, the pre-existing
fixture `google-positive-javascript-firebase-config` documented that an
`AIza`-shaped `apiKey` inside a Firebase client-config object is reported
as a positive finding regardless of context — a deliberate prior design
choice ("the detector still reports the documented shape at high
confidence and leaves the redact/warn action call to policy"). Firebase's
own documentation (`firebase.google.com/docs/projects/api-keys`, observed
2026-09-20) states plainly: "API keys restricted to Firebase services do
not need to be treated as secrets, and it's safe to include them in your
code or configuration files."

This issue adds a pipeline-level exemption
(`crate::pipeline::is_within_firebase_client_config_context`), applied to
any candidate whose matched *text* has `google-api-key`'s exact
`AIza`-prefixed, 39-byte shape (not gated on which detector proposed it,
because `apiKey` also normalizes to a `generic-token` high-signal name — see
the linked decision record's rationale) when at least two of
`authDomain`, `databaseURL`, `storageBucket`, `messagingSenderId`, `appId`,
`measurementId`, `projectId` appear as object keys within 512 bytes, on
either side. `google-api-key` itself is unchanged: it keeps reporting the
identical shape everywhere else.

**The two-field threshold is deliberately conservative in the config's
favor.** `google-positive-javascript-firebase-config` carries only
`authDomain` alongside `apiKey` and is *not* suppressed — its note is
updated to explain why, rather than the fixture being edited or moved.

### New corpus fixtures (`conformance/fixtures/synchronous-corpus.json`)

| Fixture | Purpose |
| --- | --- |
| `firebase-negative-client-config-javascript` | A realistic, full eight-field `firebaseConfig` object (JS): zero findings |
| `firebase-negative-client-config-json` | The same object as a JSON document: zero findings |
| `firebase-positive-google-api-key-as-server-key-context` | An `AIza` key under a privileged `server_key` variable, no config siblings: still detected (grounded in the FCM-takeover research above) |
| `firebase-negative-client-config-wide-gap-does-not-suppress` | Two config field names exist, but past the 512-byte window: an unrelated key earlier in a large input stays detected |
| `firebase-negative-authdomain-bare` | Benign control: a bare `authDomain` field alone is inert |
| `firebase-negative-messaging-sender-id-bare` | Benign control: a bare `messagingSenderId` field alone is inert |

## Family 3 — Service-account private key / JSON credential export

**Supported, unchanged.** Issue #519's Family 2 already covers this: a
Firebase Admin SDK service-account JSON export is a GCP service-account key
export, structurally matched by `private-key`'s PEM-delimiter parser with
no Firebase-specific code path. Not duplicated here; see
[issue #519's evidence](../519/README.md#family-2--service-account-private-key--json-credential-context).

## Family 4 — Gemini/Cloud use of the `AIza` shape

**Supported, unchanged.** Issue #519's Family 3 already covers this: the
same `AIza`-prefixed, 39-byte shape, no separate grammar or finding type.
Outside a recognized client-config context (Family 2 above), this shape is
fully unaffected by this issue. See
[issue #519's evidence](../519/README.md#family-3--gemini-api-credentials).

## Family 5 — Realtime Database legacy secret

**Pending — opaque, no lexical evidence.** Firebase's own documentation
(`firebase.google.com/docs/database/rest/auth`, observed 2026-09-20) states
the value is passed as a bare `?auth=<secret>` query parameter on a
`*.firebaseio.com` URL, and publishes no format, length, or character-set
for it. `generic-token`'s `AMBIGUOUS_NAMES` already includes `auth`, but its
open-assignment boundary check requires whitespace or `{`/`,`/`;`
immediately before the key name — the `?` preceding a URL query parameter
is not in that set, so this realistic form is not classified even
incidentally (a bare `auth=<value>` assignment elsewhere in the corpus
already is, and stays unaffected). Widening that boundary set is a
`generic_token.rs`-wide change affecting every URL query string this crate
scans, not a Firebase-specific one, and is out of this issue's scope.

New regression-pin fixture:
`firebase-database-secret-query-param-negative-out-of-scope`, a synthetic
`https://synthetic-revoked-default-rtdb.firebaseio.com/users.json?auth=...`
URL resolving to zero findings today, matching this section's stated
disposition exactly. This is the same `pending`-by-documented-gap pattern
issue #519 used for Google's own OAuth refresh/access tokens.

## Family 6 — Firebase CLI token

**Pending, unchanged.** `firebase login:ci` issues the same `1//`-prefixed
Google OAuth refresh token issue #519's Family 4 already records as
`pending`, T0 — not a distinct Firebase format. Not duplicated here.

## Corpus impact

18 new fixtures in `conformance/fixtures/synchronous-corpus.json`
(`fixtureCount` 1359 → 1377): 11 for `firebase-server-key` (positive across
plain-text/dotenv/JavaScript contexts, a CRLF/Unicode-prefix regression,
overlap with `generic-token`, an adversarial bounded-work stress input, two
boundary rejections, a wrong separator, a masked value, and an
environment-variable reference), 6 for the client-config discrimination
(Family 2's table above), and 1 for the Realtime Database secret gap
(Family 5).

`docs/coverage/detector-inventory.json` gains one row
(`firebase_server_key`, `always-redact`); `docs/coverage/coverage-
declarations.json`, `docs/coverage/inventory-report.json`, and
`docs/coverage/coverage-report.md` were regenerated from that row and the
conformance corpus (`scripts/generate-coverage-{declarations,inventory,
report}.py`), not hand-edited — `firebase_server_key` resolves `supported`
on every required dimension. `conformance/fixtures/common-profile-
expectations.json` was regenerated
(`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1 cargo test -p redact-secret
--test common_profile_corpus`): all 18 new fixtures resolve empty under the
`common` profile (`Pack::Provider`-only), the same as the rest of this
family. `docs/audits/evidence/367/precision-contracts.json` is unchanged:
no existing frozen family's contract, pending entry, or source list was
edited.

The pre-existing fixture `google-positive-javascript-firebase-config`'s
`note` field is updated to explain why it is unaffected by the new
two-field discrimination threshold; its `input`/`expected` are unchanged.

## What this document does not claim

- It does not assert the Realtime Database secret or the Firebase CLI token
  can never be adopted — only that, as of this review, neither carries
  lexical evidence or a distinct grammar this crate's detectors could match
  today.
- It does not change `google-api-key`'s own shape-only matching outside a
  recognized client-config context, `private-key`'s PEM match, or
  `generic-token`'s existing contextual coverage.
- `assessment/fixtures/accuracy-corpus.json` is **not** extended by this
  issue, for the same reason issue #305's Grafana decision record states:
  its content is pinned by a SHA-256 hash against a full, previously
  measured cross-language/cross-platform assessment run that only CI can
  reproduce.

## Verification

```
cargo test -p redact-secret --lib firebase
cargo test -p redact-secret --lib
cargo test -p redact-secret --test canonical_corpus
cargo test -p redact-secret --test detector_inventory
cargo test -p redact-secret --test common_profile_corpus
cargo fmt --check
cargo clippy -p redact-secret -p redact-secret-cli --all-targets
npm run coverage:check
npm run precision-contracts:check
npm run decisions:validate
```

CLI reproduction, confirming the discrimination behavior against `main`:

| Input | Result |
| --- | --- |
| A realistic, full `firebaseConfig` object (JS or JSON), `apiKey` plus 6-7 sibling fields | 0 findings (new: suppressed) |
| `google-positive-javascript-firebase-config` (`apiKey` + `authDomain` only) | 1 finding, `google-api-key` (unchanged: below the two-field threshold) |
| An `AIza` key assigned to `server_key`, no config siblings | 1 finding, `google-api-key` (unchanged: not a client config) |
| A bare `AAAA...:...` legacy FCM server key | 1 finding, `firebase-server-key` (new) |
| `https://PROJECT.firebaseio.com/path.json?auth=<secret>` | 0 findings (documented gap, unchanged) |

## Recommendation

Close issue #520 with this evidence. Every acceptance criterion is met:
only secret-bearing Firebase material is detected (the FCM server key) or
remains detected (service-account keys, privileged non-config `AIza` use)
while a realistic full `firebaseConfig` block, in both JS and JSON, is a
committed benign-control fixture producing zero findings; the new detector
carries pinned-tool evidence with an `observedAt` date, and the two
un-probeable dimensions (Realtime Database secret, Firebase CLI token) are
explicitly recorded rather than silently dropped; negative twins exist for
every asserted dimension (boundary rejections, the masked value, the
environment-variable reference, the single-sibling-field non-suppression,
the privileged-variable-name non-suppression, the wide-gap non-suppression,
and the query-param gap); no existing positive fixture changed and the
benign corpus gained only fixtures that resolve empty, so T1/T2 leaked-span
counts are unchanged; every check above ran deterministically offline with
no credential validation; and no implementation code was reproduced from
TruffleHog, gitleaks, or nuclei-templates — only their documented shapes,
consulted as behavioral references per `AGENTS.md`, with all fixture values
synthetic and unmistakably marked `SYNTHETIC`/`REVOKED`/`0000...`.

## Authority

This document records a detector addition and a discrimination-mechanism
decision, evidenced by the linked decision record and the corpus/coverage
changes above. It does not select a version, create a tag, publish a
package, or authorize any release operation. A release still requires the
explicit approval `AGENTS.md` mandates.
