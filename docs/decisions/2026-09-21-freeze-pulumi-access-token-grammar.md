---
decision_id: decision-freeze-pulumi-access-token-grammar
status: accepted
scope: workspace
title: Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape
decided_at: 2026-09-21
spec: detector-families
---

# Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape

## Decision

Add a `pulumi-access-token` detector
(`crates/secret-scan-core/src/detectors/additional_providers.rs`, `PULUMI`)
for issue #522 (B3c, under Epic #501), matching Pulumi Cloud personal,
organization, and team access tokens by one shape:

```
pul-<exactly 40 bytes from [a-f0-9]>
```

matched maximally (never a fuzzy or truncated match), bounded on both sides
by a byte outside `[A-Za-z0-9_-]` or the edge of input, the same
`KnownFormatProviderDetector`/`PrefixShape` table-driven mechanism this
registry already uses for `GRAFANA_CLOUD`, `NPM`, `DIGITALOCEAN`, and the
other single- or few-shape providers in the same module. Confidence is
`High` and specificity is `Provider`; the default policy always redacts a
match (`pulumi_access_token` added to `ALWAYS_REDACT_TYPES`,
`crates/secret-scan-core/src/policy.rs`), the same class every other
dedicated provider detector in this registry gets. All three token kinds
(personal, organization, team) share this one literal prefix and body
shape — Pulumi's own REST API reference documents no kind-specific prefix —
so one `PrefixShape` covers all three, rather than one per kind.

## Rationale

Issue #522's acceptance criteria require freezing "the grammar... before
implementation" and recording "what the citation establishes... verbatim
(prefix vs. length vs. alphabet)," with undocumented dimensions marked
"tool-corroborated" rather than asserted.

**Prefix: provider-documented.** Pulumi's own Cloud REST API reference
(`pulumi.com/docs/reference/cloud-rest-api/access-tokens/`, observed
2026-09-21) states, of the token-creation response: "The response includes
the token ID and the tokenValue (prefixed with 'pul-')." Its
`personal-access-tokens` sibling page carries the identical sentence,
observed the same day. Neither page states a length or alphabet for the
value that follows -- only the literal prefix itself is a direct citation
from Pulumi's own documentation.

**Body length and alphabet: tool-corroborated, not provider-documented.**
Two independently maintained tools, consulted only as external behavioral
references per `AGENTS.md`, converge on the same shape:

- gitleaks 8.30.1's `pulumi-api-token` rule:
  `` \b(pul-[a-f0-9]{40})(?:[`'"\s;]|\\[nr]|$) ``
- `github.com/plenoai/pleno-dlp`'s Pulumi detector: "the `pul-` prefix plus
  40-hex"

Both independently pin exactly 40 lowercase hexadecimal bytes after the
prefix; neither registers any other length or alphabet. A worked,
explicitly non-working example (Nelson Figueroa, "How to Tell What Kind of
Pulumi Access Token You Have," dev.to, observed 2026-09-21, itself citing
gitleaks/trufflehog) shows one 40-lowercase-hex-byte example each for the
personal, organization, and team token kinds, consistent with that tool
agreement; it is treated as corroborating, not as an independent third
source. No consulted source registers any other length, alphabet, or
kind-specific prefix, so this crate does not assert one.

**Exact length, not a minimum.** Both corroborating tools pin the body to
exactly 40 bytes rather than a floor, so a 39- or 41-byte body is an
intentional false negative -- the same exact-length precedent
`decision-freeze-docker-pat-oat-exact-length-grammar` and `DIGITALOCEAN`'s
64-byte hex contract already set in this module, rather than the looser
minimum-length shape this registry's earlier, less-evidenced families use.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `firebase-server-key` and before `jwt`; overlap resolution's
  registration-order tie-break is unaffected in practice since this
  grammar cannot overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains a `pulumi_access_token` row
  (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`
  (`scripts/generate-coverage-{declarations,inventory,report}.py`), not
  hand-edited.
- New corpus fixtures (`conformance/fixtures/synchronous-corpus.json`,
  1377 → 1400 fixtures): nine positives (bare, dotenv, the Pulumi CLI's
  `~/.pulumi/credentials.json` shape, a hardcoded GitHub Actions value, a
  log line, a quoted shell export, punctuation-adjacent, a CRLF/Unicode-prefix
  regression, and a repeated value reported independently per occurrence),
  five grammar boundary near-misses (one byte short, one byte long, an
  uppercase hex byte, a wrong separator, a percent-encoded prefix
  lookalike), five benign controls (the prefix embedded in a wider
  identifier, a masked value, a doc-style `x`-filled placeholder, a
  qualified Pulumi stack reference, `pulumi up`/`pulumi version`-style CLI
  output, and a GitHub Actions `secrets:` reference), one overlap case
  (qualified provider evidence outranks a bare contextual assignment), and
  one adversarial long-suffix case (a long hex run stays a single rejected
  wider identifier, never a carved-out match, bounded scan time).
  `conformance/fixtures/common-profile-expectations.json` was regenerated
  (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1 cargo test -p redact-secret
  --test common_profile_corpus`): every new fixture resolves the same under
  the `common` profile as it does under `full` minus the `pulumi-access-token`
  detector itself, since `pulumi-access-token` is `Pack::Provider`.
- `scripts/measure-detector-cost.mjs`'s `CANONICAL_IDS` and the `cloud`
  measurement group gain `pulumi-access-token` in the same change, rather
  than as a follow-up fix.
- A body shorter or longer than 40 bytes, in uppercase hex, or using any
  other undocumented character goes undetected by this dedicated detector;
  a qualified `name=value` assignment of any of them still gets a
  lower-confidence, lower-specificity contextual finding through the
  existing generic-token path regardless of format.
- A benign string that happens to contain `pul-` followed immediately by
  40 lowercase hex bytes, with no boundary break, would false positive;
  this is accepted as the same class of risk every other exact-length
  structural detector in this registry already carries.

## Authority

This document records a detector-addition decision, evidenced by the
corpus and coverage changes above. It does not select a version, create a
tag, publish a package, or authorize any release operation. A release
still requires the explicit approval `AGENTS.md` mandates.
