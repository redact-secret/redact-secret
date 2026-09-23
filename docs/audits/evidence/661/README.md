# Issue #661 — T1 provider evidence for `twilio:api-key-secret`

[Audit archive](../../README.md) ·
[Issue #661](https://github.com/redact-secret/redact-secret/issues/661) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Exhaustive provider pass](https://github.com/redact-secret/redact-secret/issues/661#issuecomment-5784958637) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/661#issuecomment-5785620973) ·
[Twilio grammar freeze (#303)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Sibling evidence: #662 (Auth Token)](../662/README.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

Every source class the issue's "Done when" lists was checked (2026-09-22) and
the load-bearing provider pages were re-read on 2026-09-23. No provider-domain
or RFC source states any lexical property of the API key **secret**. Twilio
documents it only by role (basic-auth password paired with the API key SID;
HMAC key for Access Tokens) and lifecycle (returned once, at creation).

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix / fixed header | no | none documented; no tool or example shows one either |
| length (32) | no | provider schema has no `minLength`/`maxLength`; 32 comes from trufflehog's regex and 32 × `x` placeholders in provider repos (a placeholder is not a spec) |
| alphabet `[0-9A-Za-z]` | no | provider schema has no `pattern`; only trufflehog asserts a class |
| delimiter / marker / checksum | no | none documented anywhere |

Provider-documented, but for the **paired identifier**, not the secret: the
API key SID is `SK` + 32 hex, 34 characters. That documents the pairing
structure. Whether a pairing structure can satisfy the T1 bar is a question
about the bar, which this issue does not change.

## The source (none meets the bar)

The nearest provider-domain statements, re-fetched 2026-09-23:

- `https://www.twilio.com/docs/iam/api-keys/key-resource-v1.md`: every `Sid`
  schema is `"minLength":34,"maxLength":34,"pattern":"^SK[0-9a-fA-F]{32}$"`;
  the create response example gives `secret` as a 6-letter placeholder word,
  and the page says "Twilio returns the `secret` field only when the API key
  is first created". No pattern or length for `secret`.
- `https://github.com/twilio/twilio-oai` `spec/yaml/twilio_iam_v1.yaml`
  @ `5aa7f31977ce5812f7b7bc1f46a38555ebaa2888` (still `main` HEAD on
  2026-09-23): `new_key.secret` is `type: string`, `nullable: true`,
  description "The secret your application uses to sign Access Tokens and to
  authenticate to the REST API (you will use this as the basic-auth
  `password`)". No `pattern`, `minLength` or `maxLength`.
- `https://www.twilio.com/docs/glossary/what-is-a-sid.md`: "This SID consists
  of a two-letter prefix followed by 32 hexadecimal digits." Applies to SIDs.

`observedAt`: 2026-09-23 (first observed 2026-09-22).

## Proposed `covers` sentence

None. The family stays T2. If a later bar change admits pairing structure,
the only provider-stated element is the `SK` + 32-hex SID, not the secret.

## Contradictions with the current contract

`docs/contracts/precision/precision-contracts.json` has no Twilio entry; the
benchmarks record the contract as T2 with no pattern. The frozen grammar lives
in `crates/secret-scan-core/src/detectors/twilio.rs` and the ADR
`decision-freeze-twilio-auth-token-api-key-secret-grammar`
(`docs/specs/detector-families.md`, `confidence-gated`).

- **Secret grammar: no contradiction.** Detector: exactly 32 bare
  `[0-9A-Za-z]`, no prefix. Every source that states a shape agrees; none
  contradicts it and none claims hex.
- **Paired SID alphabet.** The detector's High-confidence pairing marker is
  `SK` + 32 `[0-9A-Za-z]` (trufflehog's class). The provider schema and
  glossary give `SK` + 32 `[0-9a-fA-F]`. The detector accepts a superset.
  This affects the confidence tier, not what counts as a secret match.
- **Module comment.** The `twilio.rs` header says Twilio publishes "no
  character-class grammar for any of these four values". That holds for the
  Auth Token and API key secret, but not for the two SIDs, which have
  provider `pattern`s.

## Sources checked

Required classes were checked on 2026-09-22; full URL-level tables are in the
[exhaustive provider pass](https://github.com/redact-secret/redact-secret/issues/661#issuecomment-5784958637)
and the [broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/661#issuecomment-5785620973).

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | key-resource v1/v2010, API-keys overview, console, restricted keys, requests-to-twilio, access tokens, SID/API-key glossary, security pages, `llms.txt`; `twilio-oai` IAM and 2010 specs: secret is a bare `string`, SID is `^SK[0-9a-fA-F]{32}$` |
| changelog / release notes | twilio.com changelog (Git Guard 2019, RAK entries 2024–2026), `twilio-oai` `CHANGES.md`: no secret format |
| engineering / security blog | Git Guard post (Account SID + Auth Token only), phishing/fraud posts, C# API-key post: no format |
| help center | support.twilio.com Zendesk API (articles 9318455807771, 36881264279067, keyword searches): no format |
| secret-scanning partner pages | GitHub supported-patterns list: `twilio_api_key` type, no regex, SID-vs-secret ambiguous; not provider domain. No Twilio token-format announcement exists |
| SDK / CLI docs on provider domain | twilio.com CLI profiles, install, libraries pages; provider-authored `twilio-cli`, `twilio-cli-core`, `twilio-python`, `twilio-node`: secret passed through, only required non-empty |

Broad discovery added on 2026-09-23 (WebSearch, six phrasings incl.
`site:reddit.com`, "32 characters", regex, leak write-ups). New sources found,
all non-provider and none stating a secret shape: GitLab DAST check 798.117
(tool doc, no regex), GitGuardian Twilio remediation page and Invicti
vulnerability page (third-party, no format), `streaak/keyhacks` (Account SID +
Auth Token only). Search-engine summaries repeatedly attribute
`^SK[0-9a-fA-F]{32}$` to the *secret*; the underlying Twilio pages attach it
to `sid`. Do not cite those summaries.

Not read: Reddit directly (WebFetch refused `reddit.com`; the 2026-09-22
pass got HTTP 403/429) and the Xygeni catalog (403). `site:reddit.com`
search returned no Reddit threads. Neither can meet the T1 bar, so they do
not change the verdict.

## Open items

- Empirical measurement of freshly issued secrets (length, character classes,
  fixed header across two keys, Standard/Restricted/Main, one non-US1 region,
  SID case), as specified in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/661#issuecomment-5785620973).
  It is the only independent check on 32 and on the alphabet. Record counts
  only; delete each key.
- Whether to narrow the pairing marker to the provider's hex SID, and correct
  the `twilio.rs` header, is a separate detector decision; not taken here.

## What this document does not do

It changes no detector, contract, fixture, or tier, and proposes no change to
the T1 bar in `benchmarks/lib/assessment.ts`. It contains no credential and no
full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
