---
decision_id: decision-freeze-azure-devops-pat-grammar
status: accepted
scope: workspace
title: Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape
decided_at: 2026-09-16
---

# Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape

## Decision

Add a dedicated `azure-devops-personal-access-token` detector
(`crates/secret-scan-core/src/detectors/azure_devops.rs`) for issue #298,
matching the *current* Azure DevOps personal access token (PAT) shape:

```
<76 bytes from [A-Za-z0-9]>AZDO<4 bytes from [A-Za-z0-9]>
```

(84 bytes total, exactly), bounded on both sides by a byte outside
`[A-Za-z0-9]` or the edge of input. Confidence is `High` and specificity is
`Provider`; the default policy always redacts a match
(`azure_devops_personal_access_token` in `ALWAYS_REDACT_TYPES`,
`crates/secret-scan-core/src/policy.rs`), the same class every other
dedicated provider detector in this registry gets.

No surrounding context (`PAT=`, `azure devops`, ...) is required to classify
a match: the vendor documents the `AZDO` marker itself as a `Checksum: Yes`
signal, meaning it is specific enough on its own, matching how every other
`Specificity::Provider` detector in this module works.

Known unsupported variant: the legacy/pre-signature PAT shape (52 bytes,
lowercase-alphanumeric-leaning, no embedded marker) carries no distinguishing
structure of its own and is not detected by this rule, with or without
surrounding context. That gap is a scope boundary of this detector, not
something a future contextual heuristic in `generic_token.rs` is expected to
close.

## Rationale

Unlike most providers in this registry, Microsoft publishes the exact
grammar for the current PAT shape rather than leaving it to be
reverse-engineered:

- Azure DevOps's own docs
  (`https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate#pat-format`),
  updated 2026-09-04: "Tokens are *84* characters long, with 52 characters
  being randomized data... Tokens issued by Azure DevOps include a fixed
  `AZDO` signature at positions 76-80."
- Microsoft Purview's sensitive-information-type definition for this
  credential (`sit-defn-azure-devops-personal-access-token`, updated
  2026-06-15) is the more precise of the two: "Any combination of 84
  characters consisting of: a-z or A-Z (case-sensitive), or 0-9, with a fixed
  signature `AZDO` at position 76-80", and declares `Checksum: Yes` ("the
  service can make a positive detection based on the sensitive data alone").
  Its worked example --
  `abcdefghijklmnopqrstuvwxyz012345679ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnoAZDOabcd`
  -- is 84 bytes with exactly 76 alphanumeric bytes before the marker and
  exactly 4 after it. That example, not the "positions 76-80" prose (a
  4-byte span written as an inclusive-looking range), is what this detector's
  constants (`PREFIX_LEN = 76`, `SUFFIX_LEN = 4`) are frozen against.

Issue #298's acceptance criteria require freezing "the supported grammar,
confidence, action, and known unsupported variants... before implementation"
and note that "ambiguous unprefixed values require reliable context." Because
Purview declares this grammar `Checksum: Yes`, the vendor itself is asserting
the marker is reliable context on its own -- the same trust every other
provider-prefixed grammar in this registry gets -- so no dedicated keyword
gate (`PAT=`, `azure devops`, ...) is added on top of it.

Current evidence cited in the issue also points at trufflehog's
`azuredevopspersonalaccesstoken` detector, consulted here only as an external
behavioral reference per `AGENTS.md` (no code reproduced). Its key pattern is
a provider-name-prefixed `[0-9a-z]{52}` run -- the *legacy* shape, with no
embedded marker, gated on a nearby `azure` keyword because the bare value has
no distinguishing structure. That is exactly the ambiguous-unprefixed case
issue #298 warns about, and exactly the class of value this decision declares
a known, intentional false negative: a bare 52-byte alphanumeric run is
indistinguishable from an ordinary build hash, commit SHA, or opaque
identifier -- the issue's own named false-positive boundary
("do not flag arbitrary build hashes, organization URLs, or pipeline IDs").
Adding a contextual heuristic for it is left to `generic_token.rs`'s existing
general-purpose contextual-assignment coverage, not this detector.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `microsoft-entra-client-secret` and before `jwt`; overlap
  resolution's registration order tie-break is unaffected in practice since
  this grammar cannot overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains an
  `azure_devops_personal_access_token` row (`always-redact`);
  `docs/coverage/coverage-declarations.json`, `inventory-report.json`, and
  `coverage-report.md` are regenerated from it and
  `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures (`azdo-pat-*`): `positive-bare`,
  `overlap-generic-context`, `adversarial-long-padding`,
  `boundary-short-prefix`, `boundary-prefix-below-required`,
  `boundary-prefix-above-required`, `boundary-suffix-below-required`,
  `boundary-suffix-above-required`, `boundary-broken-prefix`,
  `negative-legacy-unmarked`, `negative-legacy-unmarked-in-context`,
  `negative-placeholder`, `negative-lookalike`.
- A value at the legacy, unmarked 52-byte format goes undetected by this
  dedicated detector regardless of surrounding context; a
  `PAT=`/`token=`-style assignment around it may still surface through the
  existing generic-token contextual path if it happens to match that
  heuristic's own shape, independent of this decision.
- A benign 84-byte alphanumeric run that happens to carry `AZDO` at exactly
  byte offset 76 would false-positive; this is accepted as the same class of
  risk every other provider-marker detector in this registry already
  carries (e.g. `microsoft-entra-client-secret`'s digit-`Q~` marker), and is
  bounded by requiring an exact 84-byte span with boundary characters on
  both sides, not an open-ended run.
- The detector's `scan` short-circuits on `!input.contains("AZDO")` before
  computing the whole-input alphabet-run table
  (`crates/secret-scan-core/src/detectors/pattern.rs`'s `run_ends`), so
  adding this 22nd built-in detector does not measurably change the runtime
  of adversarial fixtures that never contain the literal marker.
