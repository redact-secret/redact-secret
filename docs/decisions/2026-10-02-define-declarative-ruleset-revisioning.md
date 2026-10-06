---
decision_id: decision-define-declarative-ruleset-revisioning
status: accepted
scope: workspace
title: Define declarative ruleset revisioning and the revision 1 freeze
decided_at: 2026-10-02
spec: engine
---

# Define declarative ruleset revisioning and the revision 1 freeze

## Context

[`decision-define-declarative-detector-ruleset-contract`](2026-09-19-define-declarative-detector-ruleset-contract.md)
fixed the ruleset grammar as `ruleset-revision: 1`, fail-closed and under the
built-ins' control. It did not say what may change inside a revision, what
starts a new one, or how long an old one is supported. The 0.1.x stable
contract ([`decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes`](2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md))
needs those answers before a ruleset file becomes a stable input format.

The audit in [`docs/audits/evidence/1072`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1072/README.md)
([#1072](https://github.com/redact-secret/redact-secret/issues/1072)) found the
design sound and three leniencies (a repeated field, an invisible-character
prefix, non-canonical run counts) that a stable file would have pinned. They
were rejected in
[#1182](https://github.com/redact-secret/redact-secret/issues/1182) before the
freeze.

## Decision

The owner accepted the disposition and the revisioning policy on 2026-10-02,
as recommended in the audit.

1. **Revision 1 is frozen byte for byte.** `ruleset-revision: 1` means exactly
   the grammar published in `docs/guides/rulesets.md#grammar` at 0.1.0: the
   same bytes are accepted or rejected with the same class and produce the same
   candidates, for as long as revision 1 is supported.
2. **A new alphabet, validator, specificity, field, block kind or cost bound is
   `ruleset-revision: 2`.** Growing the vocabulary inside revision 1 would make
   a file load on a new binding and fail on an older one, so the revision would
   stop naming one thing. Tightening or loosening a bound is likewise a
   revision change.
3. **Unknown input always fails closed**, in every revision: an unknown
   revision (`UNKNOWN_REVISION`), field, block kind or vocabulary entry rejects
   the whole document. It is never skipped, partially loaded or guessed.
4. **Revisions coexist.** The first line selects the parse function; every
   revision produces the same internal specification, so matching, ordering and
   containment under the built-ins are shared. Revision 2 may be a strict
   superset of revision 1, so migration is editing one line.
5. **Additive growth within revision 1** is limited to: new `RulesetErrorClass`
   variants that relabel a rejection already made (the enum is
   `#[non_exhaustive]`), performance work, diagnostics, and new surfaces that
   accept the same bytes.
6. **Breaking growth** is any change to which bytes are accepted or what an
   accepted file detects: a different match, boundary rule, validator, tie-break
   or confidence; a changed `type` or `detector` string; a changed default
   action; a removed field. It is new revision work, and a change to revision 1
   itself is a breaking change under the stable contract.
7. **Support period.** Revision 1 is supported for the whole major-version
   series in which revision 2 first ships and the next one. Removal happens only
   in a major release, with a decision record and a migration note. No 0.x
   release may drop it.
8. **Default action stays `warn` in 0.1.x.** A ruleset detection is
   `confidence: medium` and therefore `warn` under the default policy, so
   `scanAndRedact` and `redact-secret --redact` leave its text unchanged; only a
   caller policy can redact it. `--redact --ruleset` keeps running. A settable
   `action` is a revision 2 candidate that needs its own containment argument.
9. **JavaScript errors** carry no rejection class in 0.1.x, as decided in the
   stable-contract record; Rust, Python and the CLI report it.

## Trade-offs

A one-line vocabulary addition costs a revision bump. That is intended:
bindings ship in lockstep, so adoption is free, and the revision number stays a
real portability guarantee. Leaving rulesets `warn` means an organization that
wants redaction from a ruleset needs a caller policy until revision 2.

Rejected alternatives:

- Freeze revision 1 unchanged, with the three leniencies documented. It pins
  "last duplicate wins" and a never-matching prefix into a stable format.
- Let `DefaultPolicy` redact ruleset detections. It lifts a ruleset candidate
  over built-in `warn` candidates and breaks the rule that a ruleset can never
  silently outrank a built-in's resolved finding.
- Skip unknown keys, as comparable tools do. A file written for a newer library
  would be silently weakened on an older one.

## Consequences

The ruleset guide and `conformance/fixtures/ruleset-reference.json` are the
frozen revision 1 definition; the reference fixture runs on every surface that
loads a ruleset. A pull request that changes either needs a revision decision
instead. This decision changes no code.
