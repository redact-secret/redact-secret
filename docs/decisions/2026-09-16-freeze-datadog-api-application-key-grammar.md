---
decision_id: decision-freeze-datadog-api-application-key-grammar
status: accepted
scope: workspace
title: Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values
decided_at: 2026-09-16
---

# Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values

## Decision

Add dedicated `datadog-api-key` and `datadog-application-key` detectors
(`crates/secret-scan-core/src/detectors/datadog.rs`) for issue #304.

The API Key detector matches a 32-byte lowercase-hex run:

```
[0-9a-f]{32}
```

The Application Key detector matches a 40-byte lowercase-hex run:

```
[0-9a-f]{40}
```

Neither value has a provider-owned prefix or suffix, and neither carries a
paired public identifier the way a Twilio Account SID or API Key SID does, so
both detectors require reliable Datadog context on the same line as the
candidate:

- a same-line, case-insensitive literal marker that names the specific key
  type together with the vendor (covering the documented `DD-API-KEY` /
  `DD-APPLICATION-KEY` HTTP headers, the documented `DD_API_KEY` /
  `DD_APPLICATION_KEY` environment variables, the shorter `DD_APP_KEY` alias
  some client libraries accept, and their common `-`/`_`-joined config-key
  spellings) gives `Confidence::High`; or, absent that,
- a bare case-insensitive `datadog` substring anywhere on the line gives
  `Confidence::Medium`.

The bare two-letter `dd` short form is never checked as an unanchored
substring (it collides with `address`, `middleware`, `redirect`, and similar
ordinary words); it is only reachable as part of the longer literal markers
above. Specificity is `Provider`; the default policy redacts high-confidence
findings and warns on medium-confidence findings through the existing
confidence-gated provider policy.

## Rationale

Datadog's account-management documentation and authentication documentation
describe an API Key (write access) and an Application Key (broader read
access), and publish the header names `DD-API-KEY` / `DD-APPLICATION-KEY` and
the environment variable names `DD_API_KEY` / `DD_APPLICATION_KEY`, but do not
publish a character-class grammar for either key's body. Issue #304 therefore
requires freezing "the supported grammar, confidence, action, and known
unsupported variants" and warns that ambiguous unprefixed values need
reliable context.

The 32-byte and 40-byte lengths are community-observed in gitleaks 8.30.1's
`datadog-access-token` rule and trufflehog 3.97.4's independent
`datadogapikey` and `datadogtoken` detectors, consulted only as external
behavioral references per `AGENTS.md`; no code from either project is
reproduced here. Both tools match a broader `[A-Za-z0-9-]` alphabet as a
looser catch-all heuristic gated only by a regex-anchored `datadog`/`dd`
prefix. This module instead freezes the tighter lowercase-hex shape actually
issued by the platform, per the issue's own scope note to cover "API and
application key values, with context for opaque hex formats" -- narrowing the
alphabet meaningfully reduces false positives against the broader catch-all,
at the cost of a known, intentionally unsupported variant if Datadog ever
issues a key body outside `[0-9a-f]`.

Neither key carries a paired public identifier of its own the way Twilio's
Account SID / API Key SID pairing does (see
`2026-09-16-freeze-twilio-auth-token-api-key-secret-grammar.md`), so context
gating here uses literal same-line markers instead. The markers are split
into two tiers rather than one flat `datadog` keyword check: a marker that
names the specific key type (`dd_api_key`, `dd-application-key`, ...) is
strong enough evidence to redact by default, while a bare `datadog` mention
is not. This also records, in the two distinct finding types
(`datadog_api_key` vs `datadog_application_key`) and their metadata rows in
`docs/coverage/detector-inventory.json`, the issue's requested distinction
between an ingestion credential (API Key) and application-API authority
(Application Key) -- even though `DefaultPolicy` applies the same
confidence-gated class to both.

The bare `dd` short form is deliberately excluded from the generic keyword
check: unlike `datadog` or `twilio`, two letters collide with ordinary English
inside common identifiers (`address`, `middleware`, `redirect`, `odd`), so
admitting it as a standalone substring keyword would trade a small
false-negative reduction for a much larger false-positive increase. It
remains reachable, safely, as part of the longer literal markers (`dd_api_key`,
`dd-application-key`, ...), which is how the documented `DD_API_KEY` /
`DD_APPLICATION_KEY` environment variables are actually covered at `High`
confidence without an unanchored two-letter substring check.

Context is scoped to one line so whole-input scanning and incremental
line-at-a-time scanning agree, the same tradeoff every other line-scoped
heuristic in this crate already makes. This creates a known false negative
for inputs that put a marker and the secret value on separate lines, for
example a YAML document with a `datadog:` parent key and an indented `api_key:`
child on the next line.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers both detectors
  after `discord-bot-token` and before `jwt`.
- `docs/coverage/detector-inventory.json` gains `datadog_api_key` and
  `datadog_application_key` rows with `confidence-gated` policy classes;
  coverage declarations and reports are regenerated from that inventory and
  the conformance corpus.
- New conformance fixtures cover specific-marker and vendor-keyword-only
  context at both confidence tiers, env/JSON/YAML/shell contexts, CRLF and
  Unicode prefixes, wrong lengths (including a Datadog key record ID and an
  application-key-length value on an api-key-marked line and vice versa),
  masked/placeholder values outside the frozen alphabet, an environment-
  variable interpolation reference, bearer overlap, dense adversarial
  candidate lines, and incremental same-line versus different-line behavior.
- A marker split from its secret value onto another line is a known false
  negative. A benign 32- or 40-byte hex value on a line that happens to
  mention `datadog` is a possible false positive and remains medium
  confidence.
