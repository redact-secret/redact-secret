# Issue #731: exact beta.8 candidate qualification

[Audit archive](../../README.md) ·
[Issue #731](https://github.com/redact-secret/redact-secret/issues/731) ·
[Benchmarks counterpart #214](https://github.com/redact-secret/redact-secret-benchmarks/issues/214)

Written 2026-09-25. This record fixes the identity of the candidate that was
measured and states, gate by gate, what that measurement shows. It does not
authorize a version, tag, publication or deploy, and it closes no issue. The
run's raw evidence stays in `redact-secret-benchmarks`; nothing here copies it.
It holds synthetic values only.

## Candidate identity

| Field | Value |
| --- | --- |
| Product source commit | `9d9ca8e00cfbf7fee1bcf4cc24c0e1b0f456769a` (clean) |
| Benchmarks source commit | `cfaeac4d83a4c98cffd77328d3416eb920a7d25b` (clean) |
| Benchmarks lockfile sha256 | `cbbb00a192cf384857e286d9e81a8851bb43797d47410a0618e21690ff050363` |
| Package (`@redact-secret/core`) sha256 | `8b6e759b98201ebfed797a5389eca57a3aa52fef1bc96783d522c60418662520` |
| Node addon (darwin-arm64) sha256 | `67261fb0dd29edcb0b8ca3f3691656e0239c78473db4878351978593cbc117a4` |
| WASM sha256 | `3ecbb5839af26333a09b0ac4987b80af3068043f0bf880f892ee9903b8a03080` |
| Scanner adapter configuration hash | `c1af1eee97cce08f227e7a07ef3338f8de48b9e37dd771f014c8f6cf1b79d783` |
| Declared version | `0.1.0-beta.7` (not yet advanced; no version was chosen) |
| Peer scanner | trufflehog 3.97.4, binary sha256 `8c7af13e84f217bffd10aec09780fb7bbe59892187c99006291cef9c6f001beb` |
| Measurement mode | candidate |
| Run ID | `4b748f4f-3344-4d21-be10-0a5a1d6e1600`, scope `full-suite`, status `complete` |
| Fixtures | 2990 selected, 2990 scanned, 2990 written, 0 failures |
| Runtime | Node v22.16.0, darwin arm64 |

The trufflehog on `PATH` was 3.97.6 and a nominally pinned copy had
self-updated to 3.97.8, so the pinned 3.97.4 binary was placed first on `PATH`
for every measurement below. The benchmarks validator accepted the evidence
file at the benchmarks commit above.

## Stable portfolio gates

Compared at taxonomy-family level, beta.7 tag matrix against the candidate
matrix:

- **Regression:** none. All 51 families stable in the beta.7 matrix are stable.
- **Newly stable, existing families:** 19. 16 moved provisional to stable, all
  `empirical` with the evidence tier unchanged (T2). 2 moved unsupported to
  stable and 1 moved pending to stable, all three `documented` T1. Excluding those
  3 reclassifications leaves 16, above the floor of 15 by one.
- **Open discrepancy:** the issue and epic #576 state a baseline of 34 stable at
  beta.7; the beta.7 tag's matrix records 51. The comparison above uses the tag.
  Which is the frozen baseline needs a maintainer answer before the first two
  boxes are checked.
- Detector-family view (74 families): 66 stable (40 documented, 26 empirical),
  7 provisional, 1 pending.

## New-family gates

- 15 taxonomy rows are new against the beta.7 matrix. 13 are stable; each has
  zero unresolved mutation, metamorphic and differential items and a filled
  fixture profile (32 to 48 fixtures, 5 to 13 twin pairs, 6 control axes).
- `openrouter:management-api-key` and `pinecone:legacy-api-key` are
  `unsupported`, so by the gate's own wording ("provisional or better") they do
  not satisfy it. No record replacing them was found. This gate is not met as
  written until they are replaced or the count is settled.
- No family in the matrix carries an unresolved critical item.

## Global gates

- **T1/T2 leaked spans:** 0. Every T1 and T2 `must-not-flag` fixture is clean in
  the candidate run, and every non-T0 `must-redact` fixture is `EXACT`.
- **T0 note:** two T0 `observed:0` results (openai `svcacct` twins) differ from
  a `clean` baseline label. They are observation-tier and not findings.
- **Consumer paths**, all against this commit: Node and browser/WASM clean-install
  lanes passed on the candidate tarballs, byte-for-byte checked; the Python lane
  passed on a wheel built locally from this commit (not a CI-qualified artifact);
  the release CLI binary passed `qualify-cli-binary` (sha256
  `d5137e63195087713ebcdaec826ebbb583cfb30abfbaa3d5913a0939c4eb4751`);
  `cargo test --workspace --release` passed with 0 failures.
- **Not verified:** matrix, README, release notes and package metadata
  agreement, since the declared version is still beta.7 and no beta.8 release
  notes exist; and the absence of raw credentials across all evidence output.

## Measurements for #523 and #524

Candidate results for the families the two issues introduced, from the run above:

| Family | Positives | Negatives |
| --- | --- | --- |
| `travis-ci:api-token` | 19 `EXACT` | 29 clean |
| `neon:api-key` | 18 `EXACT` | 24 clean |
| `postman:collection-access-key` | 32 `EXACT` | 52 clean |

Leaked spans: 0 for all three.

#523's status-badge control had no fixture. It was measured directly against the
candidate package rather than by adding a fixture, because a fixture change
would alter the product commit and void this identity. Four synthetic
badge URLs (Markdown, HTML, reStructuredText, and an API badge URL) each
produced 0 findings, and a `TRAVIS_TOKEN=` positive control produced 1. A badge
URL carrying a `?token=` parameter produced 1 finding; that is the expected
behavior for a value that is a credential. The badge control should be added
as a committed fixture in a separate change.

## What is not decided here

Tagging and publication remain separate explicit actions. #576 and #577 stay
open until #731 passes.
