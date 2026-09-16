---
decision_id: decision-freeze-twilio-auth-token-api-key-secret-grammar
status: accepted
scope: workspace
title: Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values
decided_at: 2026-09-16
---

# Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values

## Decision

Add dedicated `twilio-auth-token` and `twilio-api-key-secret` detectors
(`crates/secret-scan-core/src/detectors/twilio.rs`) for issue #303.

The Auth Token detector matches a 32-byte lowercase-hex run:

```
[0-9a-f]{32}
```

The API Key Secret detector matches a 32-byte alphanumeric run:

```
[A-Za-z0-9]{32}
```

Neither value has a provider-owned prefix or suffix, so both detectors require
reliable Twilio context on the same line as the candidate. A paired Twilio
identifier gives `High` confidence: an Account SID (`AC` plus 32 lowercase
hex bytes) for an Auth Token, or an API Key SID (`SK` plus 32 alphanumeric
bytes) for an API Key Secret. Without that paired identifier, a
case-insensitive `twilio` substring on the same line gives `Medium`
confidence. Specificity is `Provider`; the default policy redacts high
confidence findings and warns on medium confidence findings through the
existing confidence-gated provider policy.

Account SIDs and API Key SIDs are intentionally not findings. They identify
an account or key and are not secret values by themselves.

## Rationale

Twilio's request-authentication documentation and API-key documentation
describe Account SIDs, Auth Tokens, API Key SIDs, and API Key Secrets, but do
not publish a distinguishing prefix or full lexical grammar for the secret
values themselves. The public identifier shapes are documented and
provider-specific; the secret values are opaque. Issue #303 therefore requires
freezing "the supported grammar, confidence, action, and known unsupported
variants" and warns that ambiguous unprefixed values need reliable context.

The 32-byte Auth Token and API Key Secret shapes are community-observed in
gitleaks and trufflehog, consulted only as external behavioral references.
No implementation code is copied from either project. The Auth Token's
lowercase-hex shape is especially ambiguous because it is indistinguishable
from an MD5 digest or a hyphen-stripped UUID without Twilio context. The API
Key Secret's mixed-alphanumeric shape is similarly indistinguishable from many
opaque application tokens.

Context is scoped to one line so whole-input scanning and incremental
line-at-a-time scanning agree. This creates a known false negative for inputs
that put an Account SID or API Key SID on one line and the secret value on a
later line. That false negative is accepted to avoid broad cross-line
coincidence matches over ordinary hashes, IDs, and opaque text.

Medium-confidence keyword-only matches are retained because real
configuration commonly appears as `TWILIO_AUTH_TOKEN=...` or
`twilio_api_key_secret: ...`, where the key name is the only available
provider context. Those findings warn rather than redact under the default
policy because the value itself still has no Twilio-owned marker.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers both detectors
  after `atlassian-api-token` and before `jwt`.
- `docs/coverage/detector-inventory.json` gains `twilio_auth_token` and
  `twilio_api_key_secret` rows with `confidence-gated` policy classes;
  coverage declarations and reports are regenerated from that inventory and
  the conformance corpus.
- New conformance fixtures cover paired identifiers, keyword-only env/JSON/YAML
  context, CRLF and Unicode prefixes, wrong lengths, public IDs alone,
  placeholder-style masks, environment-variable references, bearer overlap,
  dense adversarial candidate lines, and incremental same-line versus
  different-line behavior.
- `assessment/fixtures/accuracy-corpus.json` records a paired-ID positive and
  a separate-line false negative so benchmark runs preserve the documented
  tradeoff.
- A secret value split from its paired identifier onto another line is a known
  false negative. A benign 32-byte value on a line with a Twilio keyword is a
  possible false positive and remains medium confidence.
