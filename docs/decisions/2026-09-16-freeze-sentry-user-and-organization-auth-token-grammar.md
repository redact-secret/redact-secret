---
decision_id: decision-freeze-sentry-user-and-organization-auth-token-grammar
status: accepted
scope: workspace
title: Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes
decided_at: 2026-09-16
spec: detector-families
---

# Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes

## Decision

Add dedicated `sentry-user-auth-token` and `sentry-org-auth-token` detectors
(`crates/secret-scan-core/src/detectors/sentry.rs`) for issue #306.

The user auth token detector matches the literal `sntryu_` followed by an
exact 64-byte run of lowercase hex:

```
sntryu_[0-9a-f]{64}
```

The organization auth token detector matches the literal `sntrys_`, then a
base64 (`[A-Za-z0-9+/]`) run that must begin with the literal `eyJ` and is
matched maximally, at least 26 bytes total (`eyJ` plus at least 23 more),
then up to two trailing `=` padding bytes, a literal `_`, and an exact
43-byte base64 run:

```
sntrys_eyJ[A-Za-z0-9+/]{23,}={0,2}_[A-Za-z0-9+/]{43}
```

(the leading `eyJ` is a literal continuation of the `sntrys_` prefix, not a
separate segment; see the Rationale section for where the 26-byte minimum
comes from.)

Both prefixes (`sntryu_`, `sntrys_`) are unambiguous provider markers, so
unlike Twilio's Auth Token and API Key Secret
(`decision-freeze-twilio-auth-token-api-key-secret-grammar`), neither
detector requires surrounding context to classify a match: the shape alone
is `Specificity::Provider` and `Confidence::High`, matching every other
prefixed detector in this registry. Both types are `always-redact`
(`crates/secret-scan-core/src/policy.rs`).

Sentry's legacy, pre-2024 unprefixed 64-byte lowercase-hex token (gitleaks's
`sentry-access-token`, trufflehog's `sentrytoken/v1`) is intentionally out of
scope: no dedicated detector is added for it. A public Sentry DSN
(`https://<public_key>@<host>/<project_id>`) shares no shape with either
grammar and is not classified by either detector.

## Rationale

Sentry's own authentication documentation
(`https://docs.sentry.io/api/auth/`,
`https://docs.sentry.io/account/auth-tokens/`) describes how personal
("user") and organization auth tokens are created and scoped, but -- unlike
Telegram's or Discord's docs -- publishes no worked example, prefix, or
character-class grammar for either value at all. Issue #306's acceptance
criteria require freezing "the supported grammar, confidence, action, and
known unsupported variants... before implementation" and warn that "ambiguous
unprefixed values require reliable context," matching
`decision-freeze-twilio-auth-token-api-key-secret-grammar`'s situation. Here,
though, both in-scope formats do carry a distinguishing prefix, so neither
needs the context-gating that grammar required.

**Prefixes and shapes.** Consulted only as external behavioral references per
`AGENTS.md`, gitleaks 8.30.1's independent `sentry-user-token` and
`sentry-org-token` rules and trufflehog 3.97.4's independent
`sentrytoken/v2` and `sentryorgtoken` detectors converge on the same two
shapes: `sntryu_` followed by 64 lowercase-hex bytes for a user token, and
`sntrys_eyJ...` for an organization token. No code from either project is
reproduced here; this module's matching logic (a hand-rolled linear scan
over precomputed maximal alphabet runs, the same technique every other
detector in this registry uses) is authored independently.

**The organization token's `eyJ` marker and separator.** `eyJ` is the
well-known base64 encoding of a JSON object's opening `{"` (the same
structural fact a JWT's own header segment relies on); independent reporting
on the org-token format and both reference scanners agree the payload,
base64-decoded, is a JSON object carrying at least an `iat` (issued-at) claim
and a `region_url` claim. This detector does not decode or parse the
payload -- requiring the literal `eyJ` marker plus a minimum length is
already highly specific once combined with the 7-byte `sntrys_` prefix, the
literal `_` separator, and the exact 43-byte trailing signature, without the
added complexity of a hand-rolled base64 decoder. The `_` separator is
unambiguous because standard base64's alphabet (`[A-Za-z0-9+/=]`) never
contains `_`, so it cannot appear inside the payload or signature runs
themselves.

**Payload length.** Sentry documents no length for the payload, and it is not
fixed in practice: the embedded `region_url` claim's length varies with the
account's region host name. Cross-referencing trufflehog's fixed-length
`sentryorgtoken` pattern (10-byte prefix `sntrys_eyJ` + 197 more bytes = 207
bytes total, of which 43 bytes are the trailing signature and 1 byte is the
separator, leaving roughly 153 bytes of payload after the `eyJ` marker, 156
including it) gives one real-world sample's length. Rather than freeze that
observed length as a minimum -- which would reject a shorter self-hosted
region URL or a future payload shape -- `ORG_MIN_PAYLOAD_LEN = 26` is set to
the base64 length of the smallest plausible payload: an `iat` claim alone,
`{"iat":1700000000}` (19 bytes), which unpadded base64 encodes to 26 bytes.
There is no documented upper bound, so the payload run is matched maximally
(a longer, real-world-shaped payload is matched unconditionally by
construction).

**The signature is an exact length, not a minimum.** Both reference patterns
agree on exactly 43 base64 bytes trailing the final `_`, the unpadded base64
encoding of a 32-byte (256-bit) HMAC-SHA256-shaped signature -- a fixed
digest size, unlike the payload, so `ORG_SIGNATURE_LEN` is matched exactly:
a run one byte short or one byte long is rejected outright rather than
truncated or greedily over-matched.

**Legacy format: out of scope.** Sentry's legacy, pre-2024 API token (bare
64-byte lowercase hex, gitleaks's `sentry-access-token`, trufflehog's
`sentrytoken/v1`) carries no distinguishing prefix at all -- indistinguishable
by shape alone from an ordinary SHA-256 digest or any other opaque hex blob,
exactly the "ambiguous unprefixed value" the issue's acceptance criteria
warn about. Issue #306 titles this work "Sentry user and organization auth
tokens detection" specifically (both of which do carry a prefix); a
context-gated third detector for the legacy format, matching
`decision-freeze-twilio-auth-token-api-key-secret-grammar`'s approach, was
considered and rejected as outside this issue's scope. A qualified
`name=value` assignment of it still gets a lower-confidence,
lower-specificity contextual finding through
`crates/secret-scan-core/src/detectors/generic_token.rs` regardless of
format, the same overlap `decision-freeze-atlassian-api-token-grammar`
accepts for Atlassian's own pre-2022 unprefixed token.

**Public DSN: out of scope.** A Sentry DSN (`https://<public_key>@<host>/<project_id>`)
is a public identifier Sentry itself displays and ships in client SDK
configuration, not a private auth token, and shares no shape with either
grammar above; per the issue's explicit false-positive boundary ("Public
DSNs... must not be blanket-classified as private auth tokens"), it is not
classified by either detector and is not fuzzy-matched.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers both detectors
  after `discord-bot-token` and before `jwt`.
- `docs/coverage/detector-inventory.json` gains `sentry_user_auth_token` and
  `sentry_org_auth_token` rows (`always-redact`); coverage declarations,
  the inventory report, and the coverage report are regenerated from that
  inventory and the conformance corpus.
- New conformance fixtures cover bare/env/JSON/YAML/log contexts, CRLF and
  Unicode prefixes, base64 padding before the organization token's
  separator, a longer-than-minimum payload, overlap with the generic
  contextual detector, bounded adversarial near-miss runs, below-minimum and
  above-exact-length boundaries for every segment, a missing separator, a
  missing `eyJ` marker, masked values, environment-variable references, a
  wrong prefix, the out-of-scope legacy unprefixed token, and a public DSN.
- A self-hosted Sentry instance whose organization token payload happens to
  be shorter than 26 bytes -- which would require a payload with no `iat`
  claim at all, not currently observed -- goes undetected; there is no
  documented case this excludes today.
- The legacy unprefixed 64-byte hex token and a bare organization/project
  identifier both go undetected by these two dedicated detectors, by design;
  the legacy token still gets contextual coverage through
  `generic_token`.
