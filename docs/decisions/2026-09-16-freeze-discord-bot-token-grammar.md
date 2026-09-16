---
decision_id: decision-freeze-discord-bot-token-grammar
status: accepted
scope: workspace
title: Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token
decided_at: 2026-09-16
---

# Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token

## Decision

Add a dedicated `discord-bot-token` detector
(`crates/secret-scan-core/src/detectors/discord.rs`) for issue #301,
matching a Discord bot token by the shape:

```
<exactly 24 bytes from [A-Za-z0-9_-]>.<exactly 6 bytes from [A-Za-z0-9_-]>.<exactly 27 bytes from [A-Za-z0-9_-]>
```

bounded on both sides by a byte outside `[A-Za-z0-9_-]` or the edge of
input, **with the additional requirement that the first segment, decoded as
unpadded base64url, consists entirely of ASCII digit bytes** (a Discord
snowflake ID rendered as its decimal string). Confidence is `High` and
specificity is `Provider`; the default policy always redacts a match
(`discord_bot_token` in `ALWAYS_REDACT_TYPES`,
`crates/secret-scan-core/src/policy.rs`), the same class every other
dedicated provider detector in this registry gets.

Three variants are intentionally out of scope, not fuzzy-matched:

- A **webhook URL token** (the opaque path segment in
  `https://discord.com/api/webhooks/{id}/{token}`) is a single segment, not
  three dot-joined segments with a digit-decoding first segment; it is a
  distinct credential family per issue #301's own scope note ("Webhook URL
  tokens ... require explicit scope decisions, not implicit support") and is
  left undetected by this dedicated detector.
- An **OAuth2 client secret** is an opaque value with no documented,
  independently-verifiable shape; issue #301 requires an explicit scope
  decision for it rather than implicit coverage, and none is made here.
- A **user/self-bot token** (historically `mfa.`-prefixed for
  MFA-enabled accounts) is a separate, non-bot credential family outside
  issue #301's "Bot authorization contexts" scope; it is not fuzzy-matched
  into this detector.

## Rationale

Discord's own developer reference
(`https://docs.discord.com/developers/reference`) publishes no formal
character-class grammar for a bot token. It shows exactly one example, in
the Authentication section:

```
Authorization: Bot MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs
```

Issue #301's acceptance criteria require freezing "the supported grammar,
confidence, action, and known unsupported variants ... before
implementation" and note that "ambiguous unprefixed values require reliable
context" -- since Discord documents no prefix and no length, that freeze is
an explicit judgment call over the one documented example, not a
transcription of a spec, matching the precedent set by
`decision-freeze-atlassian-api-token-grammar` and
`decision-freeze-microsoft-entra-client-secret-grammar` for the same reason.

**Segment lengths.** The documented example's three dot-separated segments
are exactly 24, 6, and 27 bytes. Consulted only as an external behavioral
reference per `AGENTS.md` (no code copied from either project), gitleaks's
and trufflehog's independent Discord bot-token rules both encode the same
three exact lengths (24/6/27) from real-world samples, corroborating the
single documented example rather than contradicting it. Unlike Atlassian's
API token -- whose own documentation explicitly disclaims a fixed length --
Discord's documentation makes no such disclaimer, so `RunLength::Exact` is
used for all three segments rather than a minimum.

**The digit-decoding requirement.** A bare "three dot-separated base64url
segments of fixed lengths" shape is structurally identical to a JWT (see
`super::jwt`), which would either force this detector to fight the JWT
detector over the same input or force a much wider net that also matches
incidental dotted base64url-looking text. Decoding the documented example's
first segment (`MTk4NjIyNDgzNDcxOTI1MjQ4`) as unpadded base64url yields the
18-byte ASCII string `198622483471925248` -- an all-digit decimal number,
which is exactly the shape of a Discord snowflake ID (Discord IDs are
generated per
`https://discord.com/developers/docs/reference#snowflakes` as 64-bit
integers, conventionally rendered and transmitted as decimal strings). A
JWT's first segment decodes to `{"..."` (JSON), never to an all-digit
string, so requiring the decode-to-all-ASCII-digits property is a
verified-by-construction way to anchor this detector to Discord's specific
token shape without overlapping the JWT detector's grammar, and without
requiring a `Bot `/`Authorization:` keyword nearby the way a purely
contextual heuristic would. No base64 crate is added: the workspace
disallows core-crate dependencies
(`[workspace.metadata.redact-secret] allowed-dependencies = []`), so the
decode is a small hand-rolled base64url-to-6-bit-value table, matching how
`crates/secret-scan-core/src/detectors/pattern.rs` already hand-rolls its
own matching primitives for the same reason. 24 bytes is a multiple of 4,
so the first segment decodes cleanly to 18 bytes with no padding-character
edge case to handle.

**No context requirement.** The digit-decoding check makes a spurious match
astronomically unlikely on unrelated text (each of the 18 decoded bytes
would independently need to land in the 10/256 sub-range that decodes to an
ASCII digit), so, like every other `Specificity::Provider` detector in this
registry, no surrounding keyword or `Authorization: Bot` context is
required to classify a match.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `atlassian-api-token` and before `jwt`; overlap resolution's
  registration-order tie-break is unaffected in practice since this
  detector's digit-decoding first segment cannot also satisfy the JWT
  detector's `eyJ`-prefixed JSON-header requirement.
- `docs/coverage/detector-inventory.json` gains a `discord_bot_token` row
  (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures: `discord-bot-token-positive-bare`,
  `-positive-dotenv`, `-positive-json`, `-positive-yaml`, `-positive-log`,
  `-positive-crlf-unicode-prefix`, `-overlap-generic-context`,
  `-overlap-jwt-shape`, `-adversarial-long-padding`,
  `-boundary-segment-one-short`, `-boundary-segment-two-short`,
  `-boundary-segment-three-short`, `-boundary-segment-one-non-digit`,
  `-negative-webhook-url`, `-negative-placeholder`, `-negative-masked`,
  `-negative-reference`, `-negative-public-application-id`.
- A webhook URL token, an OAuth2 client secret, and a `mfa.`-prefixed
  user/self-bot token all go undetected by this dedicated detector; a
  qualified `name=value` assignment of any of them still gets a
  lower-confidence, lower-specificity contextual finding through the
  existing generic-token path regardless of format.
- A benign three-segment dotted string whose first segment happens to
  base64url-decode entirely to ASCII digits at exactly 24/6/27 byte lengths
  would false positive; this is accepted as the same class of risk every
  other structurally-anchored detector in this registry already carries
  (see `super::jwt`'s own equivalent tradeoff), bounded here by a
  probability of incidental collision low enough that no real-world corpus
  fixture in this repository exercises it.
- A future change to Discord's token shape (e.g. a wider snowflake once
  existing IDs exceed the current 18-decimal-digit range, which would shift
  the first segment's byte length) is out of scope for this decision and
  would require a follow-up freeze, the same tradeoff
  `decision-freeze-atlassian-api-token-grammar` accepts for Atlassian's
  documented token-length variability.
