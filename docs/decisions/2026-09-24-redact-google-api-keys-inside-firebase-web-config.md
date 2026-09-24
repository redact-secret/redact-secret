---
decision_id: decision-redact-google-api-keys-inside-firebase-web-config
status: accepted
scope: workspace
title: Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption
decided_at: 2026-09-24
spec: detector-families
---

# Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption

## Decision

An `AIza`-shaped value (`google-api-key`'s exact 39-byte shape) is reported
wherever it appears, including as the `apiKey` of a Firebase Web SDK client
config. The pipeline no longer drops a candidate because Firebase config
field names sit near it. Issue
[#749](https://github.com/redact-secret/redact-secret/issues/749) reverses
the client-config half of
`decision-add-firebase-server-key-detection-and-client-config-discrimination`
(#520, B3a, folded into
[the precision-contracts record](2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)).
The Firebase FCM legacy server key detection that record added is
unchanged.

The config's other fields (`authDomain`, `databaseURL`, `projectId`,
`storageBucket`, `messagingSenderId`, `appId`, `measurementId`, and their
`.env` and `google-services.json` equivalents) are identifiers. No detector
claims them, and they stay unflagged.

## Rationale

#520 relied on Firebase's statement that "API keys restricted to Firebase
services do not need to be treated as secrets". That holds only for a
restricted key, and the text around a key cannot show whether it is
restricted:

- **The shape carries no API scope.** Firebase, Maps and standard Gemini
  (Generative Language) keys share the same `AIza` format. A
  `firebaseConfig` object says where a key is used, not what it can call.
- **Gemini changed what an unrestricted key can reach.** Truffle Security
  showed in February 2026 that enabling the Generative Language API on a
  project gives every unrestricted key on it Gemini access. They found 2,863
  live exposed keys, Firebase and Maps keys among them. The impact is billing
  abuse and access to uploaded files and cached content
  ([report](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules)).
  Google began rejecting unrestricted standard keys for Gemini on 2026-06-19.
  The full migration to auth keys starts only in September 2026, so legacy
  unrestricted keys stay exposed for other APIs
  ([follow-up](https://trufflesecurity.com/blog/google-fixes-the-gemini-api-key-privilege-escalation-issue)).
- **Firebase still tells developers to restrict keys**
  ([firebase.google.com/docs/projects/api-keys](https://firebase.google.com/docs/projects/api-keys)),
  so this product cannot assume restriction.
- **Peers report it.** gitleaks `gcp-api-key` flags `AIza` everywhere and
  allowlists only the Firebase SDK's own sample values (gitleaks#1635).
  GitHub secret scanning reports Firebase web keys as Google API keys.
  TruffleHog detects and verifies them. The exemption made redact-secret the
  outlier.
- **The costs are asymmetric here.** redact-secret redacts before text
  reaches a log or an AI context. Redacting a public identifier costs little.
  Letting a live key through to a prompt or a log costs a lot.

The benchmark measured the gap independently of scanner output:
redact-secret-benchmarks `beta8-209--google-api-key-firebase-web-config`
expects the key's span, and it was the only finding holding
`google-api-key` below stable (benchmark record `product-520`).

## What this costs

A deliberately public, properly restricted Firebase web key is now redacted.
In a redacted log or prompt, the reader sees a placeholder where the key
was. The config still works, because redaction changes only the scanned
copy. A consumer that wants the key visible can set its own policy for
`google_api_key`. No neighbouring identifier is lost: only the key's span is
reported.

## Consequences

- `crates/secret-scan-core/src/pipeline.rs` loses
  `is_within_firebase_client_config_context` and its window/threshold
  constants. `run_detector_pipeline` keeps only the vendor-placeholder
  literal exemption.
- `conformance/fixtures/synchronous-corpus.json`: the two
  `firebase-negative-client-config-*` fixtures become
  `firebase-positive-client-config-{javascript,json}`. Three new regression
  positives are added:
  `firebase-positive-client-config-minimal-javascript`,
  `firebase-positive-client-config-dotenv` and
  `firebase-positive-google-services-json`. Each expects only the key's span.
  `firebase-negative-client-config-wide-gap-does-not-suppress` tested the
  removed window and is dropped.
- The `benchmark-gap-749` record in `conformance/benchmark-regressions.json`
  waits until the `beta8-209` corpus reaches redact-secret-benchmarks `main`.
  Until then, the vendored pin manifest cannot resolve its fixture id or
  corpus hash.
