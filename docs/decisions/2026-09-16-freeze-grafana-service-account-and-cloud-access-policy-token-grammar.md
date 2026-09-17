---
decision_id: decision-freeze-grafana-service-account-and-cloud-access-policy-token-grammar
status: accepted
scope: workspace
title: Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key
decided_at: 2026-09-16
---

# Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key

## Decision

Add dedicated `grafana-service-account-token` and
`grafana-cloud-access-policy-token` detectors
(`crates/secret-scan-core/src/detectors/grafana.rs` and the `GRAFANA_CLOUD`
entry in `crates/secret-scan-core/src/detectors/additional_providers.rs`)
for issue #305.

**Grafana service account token** (`glsa_`): the literal `glsa_`, then
exactly 32 bytes of `[A-Za-z0-9]`, then a literal `_`, then exactly 8 bytes
of `[A-Fa-f0-9]` (a checksum), for 46 bytes total:

```
glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}
```

**Grafana Cloud access policy token** (`glc_`, formerly documented as a
"Cloud API token"): the literal `glc_`, then a minimum 32 bytes of the
standard base64 body alphabet `[A-Za-z0-9+/]` (no `=` padding in the match --
padding carries no secret entropy and is simply left outside the matched
range):

```
glc_[A-Za-z0-9+/]{32,}
```

Both are `Confidence::High` unconditionally, `Specificity::Provider`, and
listed in `policy::ALWAYS_REDACT_TYPES`: the fixed, provider-owned prefix
makes each shape specific enough on its own, with no context gating needed,
the same tradeoff every other fixed-prefix provider grammar in this crate
already makes (Discord, SendGrid, npm, Google, etc.).

**Grafana's legacy API key is explicitly excluded from this issue's scope.**
See "Legacy API key" below.

## Rationale

Grafana's own documentation (`administration/service-accounts/` and Grafana
Cloud's `access-policies/` page) describes both token kinds only
functionally -- "a generated random string" -- and publishes no
character-class grammar. The service-accounts page's own example request
does show every token beginning with the literal `glsa_`; neither page
documents the `glc_` body's encoding.

Two independent external tools, consulted only as behavioral references per
`AGENTS.md` (no code reproduced from either):

- gitleaks 8.30.1's `grafana-service-account-token` rule:
  `` glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8} ``
- gitleaks 8.30.1's `grafana-cloud-api-token` rule:
  `` glc_[A-Za-z0-9+/]{32,400}={0,3} ``
- gitleaks 8.30.1's `grafana-api-key` rule (legacy):
  `` eyJrIjoi[A-Za-z0-9]{70,400}={0,3} ``
- trufflehog's `grafana` detector, independently: the same `glsa_`-based
  shape for service account tokens, and a narrower `glc_eyJ[A-Za-z0-9+/=]
  {60,160}` for Cloud tokens -- observing that the Cloud token's body itself
  decodes as base64-encoded JSON (`eyJ` is the base64 encoding of `{"`).

Both tools converge on the same `glsa_`-prefixed shape for the service
account token, so that grammar is frozen exactly as both describe it.

For the Cloud token, the two tools disagree on how tightly to bound the
body: gitleaks accepts any base64-shaped run of at least 32 bytes; trufflehog
additionally requires the body to begin with `eyJ` (i.e. to decode to JSON
starting `{"`) and bounds it to 60-160 bytes. This decision adopts gitleaks's
looser, better-documented floor (32 bytes, no upper bound enforced -- this
crate's `RunLength::AtLeast` semantics do not support an upper bound) rather
than trufflehog's `eyJ` anchor: requiring a specific decoded-JSON prefix
would encode one tool's implementation detail, observed from unpublished
reverse engineering, rather than an independently confirmed provider fact.
The `glc_` prefix itself is exceedingly unlikely to occur by coincidence, so
the false-positive cost of the looser bound is low.

## Legacy API key

Issue #305 explicitly instructs: "explicitly decide legacy API-key support."
This decision is to **not** implement it in this issue:

- Grafana's own service-accounts documentation states that service accounts
  "replace API keys as the primary way to authenticate applications that
  interact with Grafana" -- the format is deprecated by the provider itself.
- The legacy key is a bare base64-encoded JSON blob (`{"k":...}`, giving it
  the literal prefix `eyJrIjoi` once encoded -- confirmed by direct
  base64-encoding `{"k":"` in this decision's own preparation, not merely
  asserted from gitleaks's rule). Beyond that generic base64/JSON encoding
  convention, it carries no Grafana-owned structural marker.
- This crate's `jwt` and `generic_token` detectors already carry the same
  false-positive/false-negative tradeoff surface for opaque base64/JSON-
  shaped values; adding a third, narrower detector for one more base64-JSON
  variant without a documented grammar to bound false positives would not
  clearly improve on that existing coverage.

This is a deliberate scope exclusion, not an oversight, and is covered by a
conformance fixture (`grafana-legacy-api-key-negative-out-of-scope`)
documenting the known false negative. It can be revisited in a future issue
if a documented grammar or a stronger structural marker becomes available.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers
  `grafana-service-account-token` and `grafana-cloud-access-policy-token`
  after `discord-bot-token` and before `jwt`.
- `docs/coverage/detector-inventory.json` gains `grafana_service_account_token`
  and `grafana_cloud_access_policy_token` rows with `always-redact` policy
  classes; coverage declarations and reports are regenerated from that
  inventory and the conformance corpus.
- New conformance fixtures cover both types across bare/dotenv/JSON/YAML/log
  contexts, CRLF and Unicode prefixes, exact and minimum-length boundaries,
  wrong separators, non-hex checksums, invalid-alphabet breaks, masks,
  environment-variable references, placeholders, overlap with the generic
  contextual detector, and adversarial bounded-work stress inputs, plus the
  legacy-key exclusion fixture above.
- `assessment/fixtures/accuracy-corpus.json` (the cross-language accuracy
  benchmark) is **not** extended by this issue: its content is pinned by a
  SHA-256 hash in `assessment/acceptance-criteria.json` and
  `assessment/acceptance-criteria-linux-x64.json` against a full,
  previously-measured cross-language/cross-platform assessment run,
  including a Linux-x64 baseline `assessment/acceptance.test.ts` confirms can
  only be produced by CI (`runs-on: ubuntu-latest`), not a local session.
  Editing the corpus without re-running that whole pipeline and updating the
  pinned hash and accuracy counts from real measured results would either
  break that gate or require fabricating evidence; neither is acceptable.
  This is a known, pre-existing gap this crate's provider-detector additions
  have not closed (issues #301-#303 did not extend it either); closing it is
  out of scope for a single detector-addition issue and is better tracked as
  its own assessment-refresh work.
- A Grafana Cloud token whose body happens to be shorter than 32 bytes, or a
  legacy API key, are documented, known false negatives.
