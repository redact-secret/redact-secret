---
decision_id: decision-add-firebase-server-key-detection-and-client-config-discrimination
status: accepted
scope: workspace
title: Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key
decided_at: 2026-09-20
spec: detector-families
---

# Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from `google-api-key`

## Decision

For issue #520 (B3a, under Epic #501), two independent additions:

**1. A new `firebase-server-key` detector**
(`crates/secret-scan-core/src/detectors/firebase.rs`) for the legacy
Firebase Cloud Messaging (FCM) HTTP/XMPP "server key":

```
AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
```

The literal `AAAA`, then exactly 7 bytes of `[A-Za-z0-9_-]`, then a literal
`:`, then exactly 140 bytes of `[A-Za-z0-9_-]`, for 152 bytes total.
`Confidence::High` unconditionally, `Specificity::Provider`, listed in
`policy::ALWAYS_REDACT_TYPES`, registered after `new-relic-license-key` and
before `jwt`.

**2. A pipeline-level exemption** so a `google-api-key` `AIza`-shaped match
is not reported when it sits inside a recognized Firebase Web SDK
client-config object
(`crate::pipeline::is_within_firebase_client_config_context`,
`has_google_api_key_shape`): at least two of `authDomain`, `databaseURL`,
`storageBucket`, `messagingSenderId`, `appId`, `measurementId`, `projectId`
appear as object keys (JS or JSON) within 512 bytes of the match, on either
side. `google-api-key` itself is unchanged — it keeps reporting the
identical shape everywhere else, the same as before this issue.

## Rationale

### Server key grammar

The `AAAA` prefix is corroborated by two independent non-tool sources
describing real exposed keys: a Firebase Cloud Messaging deprecation
discussion thread on the B4X developer forum
(`www.b4x.com/android/forum/threads/firebase-cloud-messaging-disable-
server-keys-and-legacy-http-protocol-on-june-20-2024.148656/`, observed
2026-09-20, quoting an example beginning `AAAAHMbG..`) and an independent
FCM-takeover security-research writeup
(`abss0x7tbh.github.io/posts/fcm-takeover/`, observed 2026-09-20). Neither
gitleaks 8.30.1 nor trufflehog 3.97.4 ships a rule for this shape;
trufflehog's own `proto/detector_type.proto` (observed 2026-09-20) reserves
`Firebase = 33` and `FirebaseCloudMessaging = 102`, both explicitly marked
`// Not yet implemented` — the family is recognized, not merely unsearched.

The exact two-segment body length comes from one tool source:
`projectdiscovery/nuclei-templates`'s `http/exposures/tokens/
firebase-fcm-server-key-disclosure.yaml` (observed 2026-09-20), whose
detection regex is `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`. This is T2,
single-tool evidence for the exact widths — the same tier this crate
already accepts for `docker-token`'s and `linear-token`'s exact-width
segments (`docs/decisions/2026-09-17-freeze-precision-contracts-for-
seven-provider-families.md`).

Google phased out the legacy FCM HTTP/XMPP send APIs this key authenticates
during 2024; a leaked key found today is very likely already
non-functional. It is still detected: this crate does not special-case a
format's detection on its issuer's current operational status, the same
posture GitHub's fully-supported classic prefix scheme takes despite
fine-grained PATs being GitHub's now-preferred format (issue #517). The key
also still frequently appears embedded in old client bundles,
`firebase-messaging-sw.js` service worker files, and `manifest.json` files
— the exact three locations `nuclei-templates`' own scan template checks.

### Client-config discrimination

Issue #520's scope is explicit: "Identify which Firebase-related material
is genuinely secret ... Treat the public client config as a benign control
set, not a target." Firebase's own documentation
(`firebase.google.com/docs/projects/api-keys`, observed 2026-09-20) states
plainly: "API keys restricted to Firebase services do not need to be
treated as secrets, and it's safe to include them in your code or
configuration files." The Web SDK `apiKey` field shares `google-api-key`'s
exact `AIza`-prefixed, 39-byte shape
(`crates/secret-scan-core/src/detectors/additional_providers.rs`'s `GOOGLE`
entry) — before this issue, the pre-existing corpus fixture
`google-positive-javascript-firebase-config` documented that this shape is
reported as a positive finding regardless of context, "leaves the
redact/warn action call to policy, not to this shape-only detector."

That per-detector, shape-only design is kept: `google-api-key` still never
suppresses a match itself. The discrimination is applied once, at the
pipeline level, the same mechanism `KNOWN_VENDOR_PLACEHOLDER_LITERALS`
already uses for AWS's documented example credentials — a cross-cutting
exemption over candidates, gated on the matched *text*'s shape rather than
on `type_name() == "google_api_key"`, because `apiKey` also normalizes to
one of `generic-token`'s `HIGH_SIGNAL_NAMES`: without checking text shape
directly, a suppressed config's `apiKey` value would still surface as a
`contextual_secret` finding for the identical span from a second detector.

**Two-field threshold.** A single sibling field name is not required to be
distinctive enough: `google-positive-javascript-firebase-config` (the
pre-existing fixture) carries only `authDomain` alongside `apiKey` and is
deliberately *not* suppressed by the new exemption — it stays a positive
finding, matching what its own note now explains. `FIREBASE_CONTEXT_MIN_FIELDS
= 2` was chosen so a realistic, complete client-config object (Firebase's
console always emits at least `apiKey`, `authDomain`, and five to six more
fields) is recognized, while a minimal two-field snippet or a single decoy
field name near an unrelated key is not.

**512-byte window.** Comfortably larger than every realistic pretty-printed
`firebaseConfig` object (under 400 bytes for all eight documented fields;
see the `firebase-negative-client-config-*` fixtures), while far short of a
whole source file — an unrelated Google API key documented elsewhere in a
large file cannot be suppressed by coincidence
(`firebase-negative-client-config-wide-gap-does-not-suppress` pins this).

**What stays detected.** An `AIza`-shaped key assigned to a privileged
variable name outside a recognized client config — for example `server_key`
— is unaffected: `firebase-positive-google-api-key-as-server-key-context`
pins this, grounded in a documented real-world FCM-takeover pattern
(decompiled Android apps storing an `AIza` key under `server_key` /
`notification_server_key`, the same `abss0x7tbh` writeup cited above).

### What this issue does not change

- **Service-account credentials** (Firebase Admin SDK JSON export): already
  covered by `private-key`'s structural PEM match, with no Firebase-specific
  code path — the identical conclusion issue #519's audit reached for
  Google's own service-account exports (`docs/audits/evidence/519/README.md`,
  Family 2). Not duplicated here.
- **Gemini/Cloud use of the `AIza` shape**: already covered by
  `google-api-key` (issue #519's audit, Family 3). Unaffected outside a
  recognized client-config context.
- **Firebase Realtime Database legacy secret**: Firebase's own
  documentation (`firebase.google.com/docs/database/rest/auth`, observed
  2026-09-20) states the value is passed as a bare `?auth=<secret>` query
  parameter and publishes no format, length, or character-set for it — an
  opaque value with zero lexical evidence, the same category issue #519
  records as correctly left uncovered for Google's OAuth tokens.
  `generic-token`'s `AMBIGUOUS_NAMES` already includes `auth`, but its
  open-assignment boundary check requires whitespace or `{`/`,`/`;`
  immediately before the key name; the `?` preceding a URL query parameter
  is not in that set, so this realistic form is not classified even
  incidentally. Widening that boundary set is a `generic_token.rs`-wide
  change affecting every URL query string this crate scans, not a
  Firebase-specific one, and is out of this issue's scope.
  `firebase-database-secret-query-param-negative-out-of-scope` pins the
  current, deliberate silence.
- **Firebase CLI token** (`firebase login:ci`): the same `1//`-prefixed
  Google OAuth refresh token issue #519 already records as `pending`, T0.
  Not a distinct Firebase format.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers
  `firebase-server-key` after `new-relic-license-key` and before `jwt`.
- `docs/coverage/detector-inventory.json` gains a `firebase_server_key` row
  with `always-redact` policy class; coverage declarations, the inventory
  report, and the coverage report are regenerated from that row and the
  conformance corpus.
- New conformance fixtures cover `firebase-server-key` across
  bare/dotenv/JavaScript contexts, a CRLF/Unicode-prefix regression, exact
  and one-byte-short boundaries for both segments, a wrong separator, a
  masked value, an environment-variable reference, overlap with
  `generic-token`, and an adversarial bounded-work stress input; plus the
  client-config discrimination fixtures listed above and two Firebase-field
  benign controls (`firebase-negative-authdomain-bare`,
  `firebase-negative-messaging-sender-id-bare`).
- `conformance/fixtures/common-profile-expectations.json` is regenerated:
  every new fixture resolves empty under the `common` profile (`Pack::
  Provider`-only), the same as the rest of this family.
- A `firebase-server-key` value whose tail segment is shorter than 140
  bytes, longer than 140 bytes, or separated by anything other than a
  literal `:` is a documented, known false negative — the same tradeoff
  every other fixed-shape provider grammar in this crate makes.
- The client-config exemption is scoped to `google-api-key`'s exact
  `AIza`-prefixed, 39-byte shape and a recognized Firebase field
  vocabulary; it has no effect on any other detector or provider.
