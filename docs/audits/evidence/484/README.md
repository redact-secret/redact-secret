# Issue #484 — declarative ruleset names section: false-positive and containment evidence

[Audit archive](../README.md) · [Issue #484](https://github.com/redact-secret/redact-secret/issues/484) ·
[decision-define-declarative-detector-ruleset-contract](../../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md)

Measured at commit `75f758d945c19a2b370cf6c90aca5c55b667e499` on
`milocosmopolitan/add-the-declarative-ruleset-names-section-on-top`, the
working tree with #484's implementation applied on top of `main` (which
already carries #483 and #495).

## What #484 actually changes

The issue's own hazard analysis is about `assignment_confidence`
(`crates/secret-scan-core/src/detectors/generic_token.rs`): a caller-supplied
**high-signal** name would select the lower entropy bar and could reach
`Confidence::High` on a `Contextual` candidate from a *built-in* detector,
where the value section's `Confidence::Medium` containment argument does not
apply. This implementation closes that hazard structurally rather than
arguing it away after the fact:

- **The names section never mutates `generic-token`.** The built-in
  detector's code path (`NameSource::BuiltIn` in `assignment_confidence`) is
  byte-for-byte the pre-#484 code — same branches, same constants, same
  order of checks. A caller-supplied name is matched by a **second,
  separately registered detector** (`generic-token-ruleset-names`), built by
  `generic_token_ruleset_names_detector` and only emitted by `load_ruleset`
  when a ruleset's names section adds at least one name.
- **Only the ambiguous bucket, ever.** That second detector's
  `NameSource::Ruleset(names)` branch never consults `HIGH_SIGNAL_NAMES` or
  `HIGH_ENTROPY_THRESHOLD`. It checks only the caller-supplied list, always
  at `AMBIGUOUS_ENTROPY_THRESHOLD` (3.5), and always resolves to
  `Confidence::Medium` — never `Confidence::High`, regardless of the
  matched value's length or entropy. This is asserted directly in
  `crates/secret-scan-core/src/detectors/generic_token.rs`'s
  `a_ruleset_supplied_name_never_reaches_high_confidence_regardless_of_entropy`
  test, using the exact value shape that reaches `High` through the built-in
  high-signal path.
- **A built-in name is a no-op, not an override.** `crate::ruleset::flush_names`
  normalizes every caller-supplied name with `normalize_name` — the same
  function a scanned input's captured assignment name is normalized with —
  and silently drops it if the result already equals a
  `HIGH_SIGNAL_NAMES`/`AMBIGUOUS_NAMES` entry
  (`is_reserved_name`). `ruleset.rs`'s
  `a_name_that_normalizes_to_a_built_in_name_is_a_silent_no_op` test exercises
  `api_key`, `ApiKey`, `API-KEY`, `auth`, and `Auth`. There is no code path
  that removes, re-buckets, or raises the confidence of a built-in name.
- **Containment is structural, not re-derived.** `generic-token-ruleset-names`
  claims only `Specificity::Contextual` and `Confidence::Medium`, and
  `load_ruleset` appends it to the same custom-detector list a value-section
  `RulesetDetector` is appended to — registered after every built-in
  (`decision-define-detector-profile-and-pack-contract`'s registration-order
  rule). It therefore inherits, without new pipeline reasoning, the same
  `RankedCandidate::priority` containment #495 already established for a
  value-section ruleset detector: it can never outrank a built-in `Structural`/
  `Provider`/`PrivateKey` candidate, and at an equal-specificity tie it loses
  to a built-in on registration order.

## Corpus regression evidence: the no-ruleset and value-only paths are unchanged

Because the built-in `generic-token` code path is untouched, every existing
fixture that does not load a names section is a **zero-behavior-change**
claim, not merely a low-risk one. This was verified by running the full
existing Rust and Python suites — including
`crates/secret-scan-core/tests/canonical_corpus.rs`,
`crates/secret-scan-core/tests/common_profile_corpus.rs`,
`crates/secret-scan-core/tests/detectors_conformance.rs`,
`crates/secret-scan-core/tests/adversarial_bounds.rs`, and the existing
`crates/secret-scan-core/tests/ruleset_conformance.rs`/
`bindings/python/tests/test_ruleset_conformance.py` value-section cases —
against the changed tree, with no fixture, expectation, or corpus edit:

| Suite | Result |
| --- | --- |
| `cargo test` (whole workspace: core, CLI, all integration suites) | 1230 passed, 0 failed |
| `cargo clippy --all-targets` | 0 warnings |
| `cargo fmt --check` | clean |
| `pytest` (Python bindings, all suites, built via `maturin develop --release`) | 3702 passed, 0 failed |

No fixture's expected `kind`/`confidence`/`start`/`end` changed. This is the
"false-positive evidence against the conformance corpus" the issue's
Evidence-required section asks for, in its strongest form: not "no material
change observed," but "no code path that produces a canonical-corpus finding
was touched," confirmed by the full corpus passing unmodified.

## New-path evidence: the names-section detector's own behavior

The names-section detector is new, so its own precision is characterized
directly rather than inferred:

- `conformance/fixtures/ruleset-reference.json`'s `names` fixture (run by
  `crates/secret-scan-core/tests/ruleset_conformance.rs` and
  `bindings/python/tests/test_ruleset_conformance.py`) exercises: a
  names-only ruleset (no `detector:` blocks) resolving a caller-declared
  ambiguous name at the entropy threshold; an unrelated name producing no
  finding; and declaring an already-built-in name (`api_key`, `Auth`) being
  a no-op, with `api_key`'s own assignment still resolved by `generic-token`
  itself, unchanged.
- `generic_token.rs`'s new unit tests cover: the ambiguous threshold and
  `Confidence::Medium` ceiling (never `High`), a value below the entropy
  threshold being ignored, an unlisted name producing no candidate, the
  detector never consulting `HIGH_SIGNAL_NAMES`, and the detector not
  duplicating `Basic`/`Token` authorization-scheme candidates (which have
  nothing to do with names and are left to the built-in detector only).
- `ruleset.rs`'s new unit tests cover every new rejection class
  (`NAME_BUCKET_NOT_CLAIMABLE`, `NAME_TOO_LONG`, `TOO_MANY_NAMES`), the
  reserved-id collision with the fixed `generic-token-ruleset-names` id,
  name deduplication, and interleaving a `names:` block with `detector:`
  blocks in either order.

## Worst case, stated with magnitude

The issue asks for "an existing detector fires more often," with the
measured magnitude, not just the reasoning. Given the structural containment
above, the precise worst case is:

**A ruleset with a names section adds, at most, one new detector
(`generic-token-ruleset-names`) that can emit a `Confidence::Medium`,
`Specificity::Contextual` finding for an assignment whose normalized name is
one the caller explicitly declared, and whose value is at least 16 bytes
long with Shannon entropy ≥ 3.5** — the identical bar the built-in
`AMBIGUOUS_NAMES` bucket (`auth`, `credential`, `credentials`,
`signing_key`, `auth_token`) already applies today. No existing detector's
own candidate set changes (per-detector invariance, unaffected by this
change), and no existing finding's confidence, specificity, or resolved
action changes, because the code path that produces every existing finding
is untouched. The added detector cannot resolve a span a built-in already
resolves as `redact` at equal or lower registration priority; it can only
resolve a previously-unflagged span, or lose an overlap tie to a competing
built-in.

## What this evidence does not cover

The issue also asks for "a measured before/after against
`redact-secret-benchmarks` at a pinned commit." That external,
precision/recall-style measurement was **not** run as part of this
implementation pass — it requires the separate `benchmark-candidate`
workflow against an external corpus repository and is left as an explicit
merge-gate follow-up, not silently satisfied by the corpus-regression
evidence above. The corpus-regression and unit/conformance evidence in this
document establish that the change is structurally contained and that no
existing behavior regresses; they do not substitute for a measured
precision/recall delta on real-world-shaped inputs against a ruleset that
actually adds ambiguous names, which is what a `redact-secret-benchmarks`
run would add.
