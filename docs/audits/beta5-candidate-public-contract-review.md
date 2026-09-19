# Beta.5 candidate public-contract review

Reviewed on 2026-09-19 for release tracking issue
[#421](https://github.com/redact-secret/redact-secret/issues/421). The candidate
is `0.1.0-beta.5` (`0.1.0b5` on PyPI) on `rc/0.1.0-beta.5`, based on reviewed
`main` revision `341cd81335ce53e6a3d8cd5228014792266749e6`. The exact frozen
candidate revision is recorded by the qualification inventory and release
manifest so that this document does not claim evidence for a later source
change. The readiness review that preceded it, and the fixes it required, are
in [beta.5 release readiness review](beta5-release-readiness-review.md).

## Public API and compatibility

Unlike beta.4, this candidate has a public API diff from its predecessor. The
changes, with their migrations, are recorded under the dated `0.1.0-beta.5`
changelog heading. In summary:

Breaking or compatibility-affecting:

- Whole-input `scan`, `redact`, and `scan_and_redact` on every binding apply
  default limits of 64 MiB and 50,000 findings and fail closed with
  `INPUT_LIMIT_EXCEEDED` or the new `FINDING_LIMIT_EXCEEDED`. Callers raise
  them explicitly through `WholeInputLimits` and the `*_with_limits`
  functions, the JavaScript `limits` option, or the Python `limits` keyword.
  The CLI's 64 MiB read bound is unchanged in value; its file scans newly
  inherit the finding bound.
- Every finding carries `obfuscation`. The Node addon's `redact()` rejects a
  finding without it, and the TypeScript types require it. Findings returned
  by `scan()` for the same input — the documented contract — are unaffected;
  a hand-built finding or one serialized from beta.4 is not.
- `SecretScanErrorCode` gains `FindingLimitExceeded` on an enum that is not
  `#[non_exhaustive]`, so an exhaustive Rust `match` needs a new arm.
- The CLI text report emits `obfuscation=` before `id=`.
- `@redact-secret/wasm` declares an `exports` map for the first time, so deep
  imports of its files other than the two `.wasm` binaries no longer resolve.
  It remains an implementation dependency of `@redact-secret/core`.

Additive: the opt-in `common` detector profile in Rust, the Node addon,
WebAssembly, and `@redact-secret/core` (not Python or the CLI), with
`./common`, `./common/node-stream`, and `./common/web-stream` subpaths and a
`PROFILE` constant; the `Obfuscation` signal and `SecretObfuscation` type; the
Node WebAssembly fallback with the `artifact()` export and `ArtifactKind`; the
two musl Node platform packages; and the `workerd` import condition with two
`.wasm` subpath exports on `@redact-secret/wasm`.

Range units, callback contracts, initialization, incremental session
behavior, placeholder formatting, and the remaining error codes are unchanged.

## Default policy and detection

Overlap resolution now ranks candidates by resolved action before
specificity, and selects the disjoint subset with the greatest total evidence
instead of accepting the first disjoint candidate in priority order. The
first change alters the winner only where a medium-confidence candidate
overlaps a stricter-resolving one; the second changes no canonical fixture.

Invisible code points are removed into a scan copy before detection and every
range is translated back, so a credential obfuscated with zero-width
characters is now detected and redacted. Custom Rust detectors receive that
same scan copy.

Seven provider grammars are narrowed to their frozen contracts. Their
intentional false negatives are recorded per family in the dated decision
records, and the measured effect — fixed-corpus twin discrimination from
32/56 to 56/56 with every required positive preserved and no new collateral
redaction — is in `docs/audits/evidence/376/` under
`decision-gate-beta5-on-precision-gains-and-positive-preservation`. Detector
ids, finding types, confidence, and specificity are unchanged.

## Artifact set

Beta.5 publishes thirteen artifacts, two more than beta.4: ten npm package
identities (the facade, `@redact-secret/wasm` including its `common` subpath
files, and eight `@redact-secret/node-<platform>` packages, now including
`linux-x64-musl` and `linux-arm64-musl`), two crates, and the Python
distribution's eight wheels plus sdist. The CLI still ships no musl binary and
no GitHub Release. Publication verifies all eight native platforms by clean
registry install — the two musl lanes in `node:22-alpine` containers — plus
Chromium, and requires the installed Node consumer to report `artifact() ===
"addon"` so a silent WebAssembly fallback cannot satisfy an addon lane.

## Changelog and blocker disposition

The former `Unreleased` content is condensed under the dated `0.1.0-beta.5`
heading, with grammar provenance left in the decision records and
`docs/audits/evidence/367/`. Every blocker recorded on #421 (#414–#420, the
pre-release fixes in PR #422, and the release, recovery, record, and
qualification gaps found on 2026-09-19 and fixed in PR #465) is closed. The
non-blocking items and their dispositions are listed in the readiness review.

Publication still depends on exact-revision Artifact qualification, Package
Release Rehearsal, and SAST at the frozen candidate SHA, and on explicit
release approval after that evidence is reviewed. Those runs, the artifact
inventory, registry observations, installed-consumer evidence, tag target,
and final manifest belong to the versioned durable release record.
