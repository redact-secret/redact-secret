---
decision_id: decision-govern-cross-language-conformance
status: accepted
scope: workspace
title: Govern cross-language conformance
decided_at: 2026-09-09
spec: engine
---

# Govern cross-language conformance

## Decision

Move detector and sanitizer conformance evidence to a language-neutral,
top-level `conformance` corpus that is the single behavioral contract for the
Rust core and every binding. All supported implementations run that corpus in
the same repository CI.

Fixtures contain only unmistakably synthetic or revoked inputs. Expected
public metadata never copies a matched value. Canonical fixture ranges use
UTF-8 byte offsets; each binding runner deterministically converts those ranges
to its documented native offset unit and verifies that the converted span has
the same meaning.

The corpus covers detector results, exclusions, overlap precedence, policy,
redaction, incremental partition equivalence, Unicode boundaries, adversarial
limits, and input-free diagnostics. Generated grammar mutations remain
deterministic and record their provenance.

The existing TypeScript core remains a temporary behavioral oracle while the
corpus is extracted and the Rust implementation reaches parity. Once the Rust
core passes the complete corpus and the JavaScript API, stream, lifecycle, and
package tests, remove the TypeScript detector core before the first public
release. Preserve its history in Git rather than maintaining a permanent
`ts-legacy` implementation.

## Rationale

A shared repository alone does not prevent drift. A single executable contract
ensures that a detector change cannot merge while a supported binding disagrees
about findings, redaction, or failure behavior. Canonical UTF-8 coordinates are
stable in JSON files and natural for the Rust core while binding runners retain
idiomatic host APIs.

## Alternatives considered

- Copying fixtures into each binding was rejected because copies can diverge.
- Keeping UTF-16 as the permanent corpus coordinate was rejected because it
  privileges the temporary TypeScript oracle over the canonical Rust core.
- Permanently retaining the TypeScript implementation as a second oracle was
  rejected because it recreates the duplicate maintenance this migration is
  intended to remove.

## Consequences

- The current TypeScript corpus must first prove that its exported data captures
  existing behavior, then be converted to the canonical schema.
- Unicode cases with astral characters before, within, and after findings are
  mandatory evidence for every binding runner.
- A corpus schema change is reviewed as a cross-language contract change.
