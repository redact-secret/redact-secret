---
decision_id: decision-define-the-bounded-built-in-structured-validator-registry
status: accepted
scope: workspace
title: Define the bounded built-in structured-validator registry
decided_at: 2026-09-26
spec: engine
---

# Define the bounded built-in structured-validator registry

## Context

Issue [#792](https://github.com/redact-secret/redact-secret/issues/792) needs
reusable validation for structured PII candidates. Checksums and bounded
semantic parsers answer whether a candidate has the shape of an identifier;
they do not answer whether that occurrence is sensitive. Several future PII
families need the same primitive algorithms, while country-specific formats
may need to compose those primitives with their own lexical and contextual
rules.

The existing declarative ruleset is intentionally a bounded matching format,
not a general-purpose programming language. Adding expressions, scripts, or
caller-provided checksum functions to fit PII would create an unbounded
execution surface and could produce different behavior in Node, WebAssembly,
and Python. Implementing validators separately in each binding would create
the same cross-runtime drift. Neither option preserves the one-Rust-core
architecture.

The PII evidence model also needs reproducible provenance. Recording only
"checksum passed" is insufficient: evaluation must identify the exact
algorithm contract so a semantic change cannot silently reuse evidence from an
older implementation.

## Decision

The Rust core owns one crate-private, compile-time registry of built-in
structured validators. Detectors request a validator by an exact stable
`identity` and positive integer `version`. A successful result returns that
same pair as provenance; changing accepted syntax, arithmetic, or failure
semantics requires a new version.

The registry is closed code, not an extension surface:

- callers cannot register a validator, callback, expression, or script;
- declarative ruleset v1 is unchanged and cannot select these validators;
- bindings expose no validator API and contain no validator implementation;
- future country-specific validators may compose reviewed core primitives but
  remain built in until a separate public extension decision is justified.

Every registration declares a maximum candidate byte length. Registry lookup
and the length check occur before algorithm execution. A known, in-bound
candidate is processed in one bounded, allocation-free integer pass. The
initial registry contains `luhn` version 1 with a 19-byte maximum and
`iban-mod97` version 1 with a 34-byte maximum. Both use the same registry
contract; their different lexical grammars remain inside their registrations.

Validation is total and returns either provenance-bearing type evidence or one
fixed, input-free failure:

- `UnknownValidator` for an unregistered identity/version pair;
- `CandidateTooLong` before the algorithm runs;
- `Malformed` when the lexical shape is outside the versioned contract; or
- `ChecksumMismatch` when the shape is valid but the check value fails.

No failure contains candidate bytes, a substring, a checksum, or another
candidate-derived value. A failure returns no partial evidence. Success is
type/identity evidence only: it never chooses an action, changes overlap
priority, or proves that the occurrence is sensitive. PII context and policy
remain later, independent stages.

Because every binding links the same core, native, Node, WebAssembly, Python,
and CLI consumers will execute this implementation when built-in PII detectors
start using it. Cross-runtime qualification therefore runs the core contract on
native and Wasm targets rather than copying validator vectors into each host.
Validator correctness is evaluated separately from detector sensitivity and
precision.

## Rejected alternatives

- **Widen declarative ruleset v1 with checksum code or expressions.** This
  turns a bounded data grammar into a programming surface, increases resource
  and review risk, and lets untrusted configuration define identity evidence.
- **Expose a public validator registry or callback.** This is premature before
  more PII families establish a stable extension contract, and it would permit
  host code to inspect candidates and diverge by runtime.
- **Implement validators in each binding.** This forks authoritative behavior
  and requires per-host conformance rather than exercising one core.
- **Treat a checksum match as sensitive.** Valid check digits occur in test
  data and unrelated numbers; this would collapse type evidence into policy
  and raise false positives.
- **Use an unversioned validator name.** Evaluation evidence could then compare
  incompatible semantics under one provenance identity.

## Consequences

Adding or changing a validator requires a reviewed core change and a product
release; users cannot immediately supply a new national algorithm. That cost is
accepted to keep execution bounded, deterministic, and reviewable. Versioned
identity may retain multiple implementations during a migration, but prevents
silent evidence drift.

The first implementation lands before its consuming PII detectors and is
therefore crate-private dead code outside tests for a short interval. A scoped
lint expectation documents that state and must be removed when a detector
starts using the registry. This foundation alone adds no finding type, detector
inventory row, public API, support claim, or policy behavior.

The v1 lexical contracts deliberately reject lower-case, separator-bearing,
malformed, and overlong candidates. A future detector may normalize a candidate
only under its own reviewed contract before calling the validator. This favors
bounded precision and can miss display-form identifiers until such
normalization is specified.
