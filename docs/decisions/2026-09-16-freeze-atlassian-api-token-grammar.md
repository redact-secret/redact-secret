---
decision_id: decision-freeze-atlassian-api-token-grammar
status: accepted
scope: workspace
title: Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body
decided_at: 2026-09-16
---

# Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body

## Decision

Add a dedicated `atlassian-api-token` detector
(`crates/secret-scan-core/src/detectors/atlassian.rs`) for issue #299,
matching an Atlassian Cloud (Jira / Confluence) API token by the shape:

```
ATAT<at least 100 bytes from [A-Za-z0-9_-]>
```

bounded on both sides by a byte outside `[A-Za-z0-9_-]` or the edge of
input. Confidence is `High` and specificity is `Provider`; the default
policy always redacts a match (`atlassian_api_token` in
`ALWAYS_REDACT_TYPES`, `crates/secret-scan-core/src/policy.rs`), the same
class every other dedicated provider detector in this registry gets.

Two variants are intentionally out of scope, not fuzzy-matched:

- The legacy, pre-2022 unprefixed 24-character token (20 lowercase
  alphanumeric bytes followed by 4 lowercase-hex bytes) carries no
  distinguishing marker at all. It is indistinguishable from ordinary opaque
  text without reliable surrounding context, and is left entirely to
  `generic_token.rs`'s existing `name=value` contextual heuristic, which
  already produces a lower-specificity `contextual_secret` finding for a
  qualified assignment today.
- `ATCT`-prefixed access tokens (workspace/project/repo) and
  `ATBB`-prefixed app passwords are separate Atlassian credential families,
  not variants of the API token this detector targets; the latter is also
  explicitly out of scope per issue #299 ("Data Center and Bitbucket
  credentials are explicitly separate formats").

## Rationale

Atlassian's own token-management documentation
(`https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/`)
publishes no character-class grammar for a token's value and explicitly
disclaims a fixed length: "We use a varied API token length ... rather than
fixed length ... If your script relies on fixed API token length, check
that it can handle a variable instead." It does not document a literal
prefix either. Issue #299's acceptance criteria require freezing "the
supported grammar, confidence, action, and known unsupported variants...
before implementation" and note that "ambiguous unprefixed values require
reliable context" -- since neither a prefix nor a length is formally
documented, that freeze is an explicit judgment call rather than a
transcription of a spec, matching the precedent set by
`decision-freeze-microsoft-entra-client-secret-grammar` for the same reason.

**Prefix.** An Atlassian Team member's reply in the product's own community
forum (not the formal docs, but an authoritative first-party source),
confirmed three stable prefixes distinguishing credential families going
forward: `ATAT` for API tokens, `ATCT` for access tokens, and `ATBB` for app
passwords -- explicitly more durable than the fuller, community-observed
literal samples (`ATATT3xFfGF0...`, `ATCTT3xFfGN0...`) that gitleaks's
`atlassian-api-token` rule and trufflehog's `atlassian/v2` detector encode,
consulted here only as external behavioral references per `AGENTS.md` (no
code copied from either project). This detector follows the Atlassian-staff
guidance and matches only the 4-byte `ATAT` marker, the same precision this
registry already extends to Google's 4-byte `AIza` prefix
(`additional_providers.rs`).

**Length.** Both reference scanners independently observe real-world API
tokens of 192 bytes total (188 bytes after the fuller `ATATT3xFfGF0` prefix,
186 after gitleaks's shorter `ATATT3`). Using `RunLength::Exact` at that
length would contradict Atlassian's own explicit "don't assume fixed
length" guidance, so this detector uses `RunLength::AtLeast(100)` instead: a
minimum comfortably below every currently observed sample (188 bytes),
tolerating a shorter token Atlassian may issue in the future, while still
long enough that `ATAT` followed by 100 uninterrupted bytes from
`[A-Za-z0-9_-]` is not something ordinary text produces by chance.

**Alphabet excludes `=`.** Both reference patterns allow `=` appearing
anywhere in the body (real samples carry it once, near the end, as base64
padding ahead of a checksum suffix). Including `=` in the *boundary*
alphabet was considered and rejected: it would make the ubiquitous
`KEY=<token>` assignment delimiter immediately preceding a real token look
like a truncated slice of a longer run and reject the whole match --
verified concretely (a version of this detector with `=` included failed
to match `ATLASSIAN_API_TOKEN=ATAT...`, the single most common real-world
usage shape). A match that instead stops just short of an embedded `=`,
still comfortably past the 100-byte minimum on every observed sample and
still redacting the overwhelming majority of the secret, is the accepted
tradeoff.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `microsoft-entra-client-secret` and before `jwt`; overlap
  resolution's registration-order tie-break is unaffected in practice since
  this grammar cannot overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains an `atlassian_api_token` row
  (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures: `atlassian-api-token-positive-bare`,
  `-positive-dotenv`, `-positive-json`, `-positive-log`,
  `-positive-crlf-unicode-prefix`, `-overlap-generic-context`,
  `-adversarial-long-padding`, `-boundary-below-min`,
  `-boundary-invalid-alphabet`, `-boundary-wrong-prefix-access-token`,
  `-boundary-wrong-prefix-app-password`, `-negative-legacy-unprefixed`,
  `-negative-placeholder`, `-negative-masked`, `-negative-reference`,
  `-negative-public-cloud-id`.
- The legacy unprefixed 24-byte token, an `ATCT`-prefixed access token, and
  an `ATBB`-prefixed app password all go undetected by this dedicated
  detector; a qualified `name=value` assignment of any of them still gets a
  lower-confidence, lower-specificity contextual finding through the
  existing generic-token path regardless of format.
- A token shorter than 100 bytes past `ATAT` -- were Atlassian to ever issue
  one, which its own documentation reserves the right to do -- goes
  undetected; a token containing an embedded `=` is matched only up to that
  byte, not past it.
- A benign string that happens to contain `ATAT` immediately followed by
  100+ bytes from `[A-Za-z0-9_-]` with no boundary break would false
  positive; this is accepted as the same class of risk every other
  provider-prefixed detector in this registry already carries, bounded here
  by a 100-byte minimum run that is not something ordinary text produces by
  chance.
