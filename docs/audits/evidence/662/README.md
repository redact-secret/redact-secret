# Issue #662 — T1 provider evidence for `twilio:auth-token`

[Audit archive](../../README.md) ·
[Issue #662](https://github.com/redact-secret/redact-secret/issues/662) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 1](https://github.com/redact-secret/redact-secret/issues/662#issuecomment-5784950050) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/662#issuecomment-5785593335) ·
[Prior evidence: #647](../647/README.md)

Written 2026-09-23 on branch `workbench/662-twilio-auth-token-t1`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND for length only, with caveats the maintainer must accept or reject

A provider-authored source states the Auth Token length. No provider source
states the alphabet, a prefix, or any marker. If the caveats below are not
acceptable, the verdict is NOT FOUND (exhaustive): every source class the
issue names was checked and nothing on twilio.com or support.twilio.com states
a length, alphabet or structure.

| property | provable at T1 | basis |
| --- | --- | --- |
| length exactly 32 | yes, with caveats | `twilio/twilio-cli` validator message; four more Twilio-owned repos agree |
| alphabet (lowercase hex) | no | tool-corroborated only; provider code shows `[a-z0-9]` / "letters and numbers" |
| prefix / delimiter / marker | no | none exists in any source (GitGuardian: "Prefixed: False") |
| secondary, regional, test, subaccount tokens | no | no source states their shape |

Caveats:

- The source is CLI code in a Twilio-owned repository, not twilio.com prose.
- The check is client-side and skipped by a hidden flag, so it shows what
  Twilio's tooling assumes, not a published format guarantee.

## The source

`https://github.com/twilio/twilio-cli/blob/48957956fecbd279a2cb8249f20a432fa646484a/src/commands/profiles/create.js#L107-L119`
(`twilio/twilio-cli`, not archived; the commit is the default-branch tip as of
re-fetch 2026-09-23). `validAuthToken()`, the prompt validator for
`twilio profiles:create`, re-read 2026-09-23:

> `if (input.length !== 32) { return 'Auth Token must be 32 characters in length'; }`

guarded by `if (!this.flags[SKIP_VALIDATION])`. Added by twilio-cli PR #153
(merged 2020-02-24, released in CLI 1.10.0). `observedAt`: 2026-09-23 (first
observed 2026-09-22).

Corroborating provider-owned code, all length-only unless noted:
`twilio-labs/serverless-toolkit` (two copies of `check-auth-token.ts`: "32
characters long and made of letters and numbers"),
`twilio/twilio-voice-notification-app` (`^[a-z0-9]{32}$`),
`twilio-labs/plugin-queued-callbacks-and-voicemail`, `twilio-labs/plugin-webhook`.
URLs and dates are in the broad-discovery comment.

Precedent fit: same class as `sendgrid:api-key`, where the provider documents
the fixed total length and the remaining structure stays tool-corroborated.
This is weaker than that precedent on the two caveats above. The T1 bar in
`benchmarks/lib/assessment.ts` is unchanged.

## Proposed `covers` sentence

> Twilio's own CLI (`twilio/twilio-cli`, `profiles:create`) validates the Auth
> Token as exactly 32 characters; the lowercase-hex alphabet, and the same-line
> Account SID / keyword context the detector requires, are tool-corroborated,
> not this citation. The check is client-side and can be skipped with a hidden
> flag.

## Contradictions with the current contract

Contract: a bare run of exactly 32 bytes `[0-9a-f]`, no prefix, gated on
same-line context (an `AC` SID for high confidence, `twilio` for medium);
detector `crates/secret-scan-core/src/detectors/twilio.rs`.

- **Length.** No contradiction. The one outlier is the `twilio/twilio-oai`
  placeholder examples for `auth_token` and `secondary_auth_token`, 33
  characters of one repeated letter. They are placeholders, not a format
  statement, and a twin generator should not copy them.
- **Alphabet.** Not contradicted, not proven. Two provider-owned sources accept
  wider than hex. Twilio's sample code also calls `[a-z0-9]` "hexadecimal" for
  the Account SID, which its docs state as `^AC[0-9a-fA-F]{32}$`, so the wider
  wording is most likely loose. If a real token contained `g`-`z`, the contract
  would miss it; no source shows that.
- **Excluded label.** detect-secrets calls its `SK` + 32 pattern an "Auth
  token". That is a Twilio API Key SID (#661), so it is not counted here.

## Twin properties this makes provable

Length (32) only. Prefix, alphabet, delimiter and marker are not provable from
a provider source.

## Sources checked

Every class required by the issue was checked on 2026-09-22. Full URL-level
table: see the [research pass 1 comment](https://github.com/redact-secret/redact-secret/issues/662#issuecomment-5784950050).

| source class | result |
| --- | --- |
| product docs and API reference (incl. `twilio-oai` OpenAPI) | `authToken`, `secondaryAuthToken` are untyped-length strings; no pattern, `minLength` or `maxLength`; only the Account SID has a pattern |
| changelog / release notes | `twilio-oai` and `twilio-cli` `CHANGES.md`, Git Guard entry: no format. The twilio.com changelog listing is client-rendered and its search results were not read |
| engineering / security blog | Git Guard, phishing, quarterly fraud, Codecov and secure-account posts: no format; one post reproduces trufflehog output (tool, corroboration only) |
| secret-scanning partner pages | GitHub partner list has `twilio_access_token`, `twilio_account_sid`, `twilio_api_key`; no Auth Token type and no pattern shown |
| SDK / CLI docs | twilio.com CLI and library docs show `[hidden]`, no format; `twilio-python`, `twilio-node`, `twilio-cli-core` have no validation; `twilio-cli` is the source above |

Not read: general web search engines and Reddit outside r/twilio were blocked
in the broad pass, and Xygeni docs returned 404. Recorded as unchecked. Community
sources cannot meet the T1 bar, so they do not change the verdict.

## Open item

Empirical check of the live token shape (length, alphabet over several tokens,
fixed leading part, secondary, test, subaccount and regional tokens), as
specified in the broad-discovery comment. It needs Console access and is the
only thing that can settle the alphabet. Record counts and character classes
only.

## What this document does not do

It changes no detector, contract, fixture, or tier. The re-tier, the twin
work, and any `covers` edit happen in the T1 re-tier batch of #575, after the
maintainer accepts or rejects the caveats. It contains no credential and no
full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
