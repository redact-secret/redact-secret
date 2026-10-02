# #1169 - adaptive SSN / payment-card digit discovery

Product judgement. Final record for
[#1169](https://github.com/redact-secret/redact-secret/issues/1169) (parent
#1068, epic #1065). Baseline: `main` at `a2b2aa6c` (after #1148/#1149).
All inputs are synthetic; no value is printed.

## Verdict

**Rejected. No code change.** Six adaptive designs for skipping non-digit
bytes in `pii_us_ssn.rs` and `pii_payment_card.rs` were built and measured
against the real shipped detector. Every one of them gives a very large gain
on sparse input (SSN -95% to -97%, PAN -90% to -94%, isolated-digit input
-27% to -80%) and every one of them still regresses the digit-dense or
digit-noise workloads the issue says must not regress (SSN dense +10.7% to
+31%, SSN sparse-head/dense-tail +15% to +21%, PAN digit noise +6.5% to
+16%), against a control that moves by at most +-1% on the same
runs. The issue's adopt gate (no regression beyond the A/A band on dense and
noisy workloads) is not met, so the repository keeps the one-byte-at-a-time
loops. The decision is a measured rejection, not a deferral: a future
attempt would need a different structure, not another threshold.

The sparse gain is real and large (a 74 KB prose input with one SSN is
36 us now and 1.3 us with skipping), which is why this is worth revisiting
only together with a change that does not touch the dense loop's code
generation. See "Why the dense path regresses" below.

## What was built

All variants keep the original loop as the dense path and add a skipping
path, with the skipped bytes proven non-digits (the original loops step over
exactly those bytes one at a time), so spans, types, confidence, order and
IDs could not change. `next_ascii_digit(bytes, from)` is the exact "first
ASCII digit at or after `from`" search (16-byte block test, then a byte walk
in the block that holds the digit). For V5 the differential tests against a
verbatim copy of the old loop passed at the detector level: boundaries,
malformed shapes, Unicode, a 1,000-byte digit run, every window of a sparse
input, and the skipping loop forced on and off over sparse, dense and mixed
corpora (5 of the module's 7 tests). The two whole-scan / incremental family
tests did not complete: the longer filler inputs added to reach the 256-byte
dispatch threshold exceeded the incremental test's token limit, a test setup
limit, so equivalence is shown at detector level only. The rejection is about
time, not correctness.

| variant | structure | raw data |
|---|---|---|
| V1 | `next_ascii_digit` (8-byte probe, then blocks) asked once per non-digit at the loop head | `raw-prodab-pii3.txt` |
| V2 | as V1, but a single separator is peeked inline; only a second non-digit asks | `raw-pii3way.txt` |
| V3 | head-density dispatch: sparse head (< 8 digits in the first 128 bytes of an input of at least 256 bytes) runs a loop with the jump, otherwise the original loop; one const-generic function | `raw-pii3way2.txt` |
| V4 | as V3 with `#[inline(never)]` on the scan functions | `raw-pii3way3.txt` |
| V5 | head-density dispatch; the original loop runs unchanged over a 32-byte window after each jump (one instantiation of the loop) | `raw-pii3way5.txt` |

`rejected-variant-window-dispatch.patch.txt` is the V5 diff (production code
and its tests), kept so the rejected design is reproducible. The issue's
first naive pilot (4-byte nearby test, then skip a 16-byte block) was also
measured in-process and is +327% on digits every 17 bytes
(`raw-in-process-variants.txt`).

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile. **The host was
shared and loaded** (load average 3 to 40 across the session); runs that
carried a control spread above +-3% are not used for any claim. Timing was
serialized behind a lock directory, every run alternated the binaries in
A B B A order over several rounds, and each run is the median of 41 timed
batches of 20 ms or more.

Three kinds of control, because the first two comparisons turned out to be
misleading:

1. **In-process A/B** (`raw-in-process-variants.txt`): the detector run with
   the discovery passed as a function. The baseline here is a generic
   instantiation of the new code, not the shipped function. It reported
   production-equivalent results within +-6% on dense input, which the
   cross-binary runs below contradict. It is kept as raw data and not used
   for any claim.
2. **Cross-binary A/B on the shipped function** (`timing-harness-production-only.rs.txt`):
   two release test binaries, one built from `origin/main` and one from the
   candidate, each timing only `detect_us_ssns` / `detect_payment_cards`.
   This is the comparison the verdict rests on.
3. **Layout control** (`oldp`): a third binary built from `origin/main` plus
   the candidate's helper functions left unused. It moves code addresses
   exactly as the candidate does without changing the detectors. Its
   deltas against the first binary are the noise band for a cross-binary
   comparison: -0.9% to +0.4% on minimum time in the V5 run, up to +7% on
   one long-digit-run row in earlier runs.

V5, cleanest run (`raw-pii3way5.txt`, 3 rounds, A/A band +-1% on the
minimum), change of the candidate against the shipped detector, minimum
time (p25 in parentheses where it differs):

| workload | SSN | PAN |
|---|---|---|
| sparse ASCII, 74 KB, one value | **-96.6%** | **-93.1%** |
| sparse Unicode, 78 KB | -96.6% | -93.2% |
| all non-digit, 60 KB | -96.7% | -93.6% |
| isolated digit every 24 bytes | -53.7% | -32.8% |
| isolated digit every 17 bytes | -37.4% | +2.3% |
| dense, repeated values | **+10.7%** (+16.3%) | +0.1% |
| digit noise, 48 KB | -18.8% | **+15.8%** |
| 60 KB digit run | -20.0% | +0.3% |
| sparse head, dense tail | **+14.7%** | -0.8% |
| dense head, sparse tail | -45.1% | **+5.1%** |

Earlier variants, same method, same control, minimum time:

| workload | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| SSN dense | +14.2% | +31.1% | +16.2% | +25.2% |
| SSN sparse head, dense tail | n/a | n/a | +20.9% | +17.1% |
| PAN digit noise | +11.8% | +12.2% | +6.5% | +14.6% |
| PAN isolated digit every 17 bytes | +4.0% | +10.6% | -58.2% | -58.1% |
| SSN sparse ASCII | -95.1% | -94.8% | -96.6% | -96.6% |
| PAN sparse ASCII | -90.2% | -89.5% | -93.1% | -93.1% |

(V1 ran as a two-binary A/B without the layout control; its control-free
numbers agree with the later runs in sign and size.)

## Why the dense path regresses

V3 and V4 route a dense input to the original loop, instantiated through a
const-generic function whose skip branch is compiled out; the dense path is
source-identical to the shipped loop. It is still +16% to +25% slower on
dense SSN input. V5 keeps one copy of the loop and still regresses. The cost
is therefore not the skip logic. Changing the function that holds the loop
(a second caller or instantiation, an out-parameter, a wrapper) changes
which of `parse_candidate`, the boundary checks and the validator the
compiler inlines into it, and on a loop that does about 14 ns of work per
value a lost inline is a double-digit percentage. The layout control shows
this is not address alignment. A design that keeps the dense detectors'
function bodies byte-identical and does the skipping somewhere the compiler
does not fold into them was not found within these six attempts.

The PEM discovery in #1163 does not have this problem because its dense path
was already a single scalar search whose replacement is cheaper in every
shape except zero-length bodies; see `docs/audits/evidence/1163/README.md`.

## Not measured

No whole-scan, native/WASM, allocation or released-size claim. The change
adds no allocation. The WASM binding runs the same Rust and was not timed.

## Temporary in-repo measurement

No measurement file remains in the repository tree outside this directory.
The harnesses use `std::time::Instant` and `println!`, which `rust:check`
forbids under `crates/secret-scan-core/src`, so they were appended
temporarily to `crates/secret-scan-core/src/pii.rs` (a test-only module that
calls `pii_us_ssn` and `pii_payment_card`, which needed the two detect
functions made `pub(super)` for the duration) and removed before the
commit. The same text was appended to a copy of `origin/main` for the
baseline binary. Nothing was added to `alloc_attribution.rs`.

- `timing-harness-production-only.rs.txt`: the cross-binary harness (ignored
  test `measure_1169_production`).
- `timing-harness.rs.txt`: the earlier in-process variant harness (ignored
  test `measure_1169`); it needs the intermediate build that still had
  `detect_us_ssns_with` / `detect_payment_cards_with`, so it does not apply
  to current `main`.
- `rejected-variant-window-dispatch.patch.txt`: the V5 candidate (not
  applied).
- `raw-*.txt`: raw runs; `raw-in-process-variants.txt` is the in-process
  run described above. `summary-*.txt` reduce the same runs to median, 25th
  percentile and minimum against the shipped binary.

Neither harness is part of the build. Per #1152 any measurement code that
stays in the repository moves to the measurement engine before the beta.13
release; cross-repository references to the benchmarks repository are
written `redact-secret-benchmarks#NNN`, for example
`redact-secret-benchmarks#608`.
