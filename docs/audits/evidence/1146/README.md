# #1146 - exact `otpauth://` scheme discovery

Product judgement. Final record for
[#1146](https://github.com/redact-secret/redact-secret/issues/1146) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline: the
#1145 commit on this branch (re-baselined after #1145, as both change
`detectors/otpauth.rs`). All inputs are synthetic; no value is printed.

## Finding

`OtpauthDetector::detect` advanced one character at a time and, at every
position, compared both full 15-byte prefixes (`otpauth://totp/`,
`otpauth://hotp/`) and called `char_at` to step over multi-byte characters.

## Change (`crates/secret-scan-core/src/detectors/otpauth.rs`)

- Discovery now calls the existing `pattern::find_literal` for the exact
  lowercase ASCII scheme `otpauth://`, then checks the two supported prefixes
  at that offset. Everything after discovery (left boundary, label bound of
  2,048 bytes, query bound of 8,192 bytes, first-`secret=` rule, base32
  validation, candidate shape and the shared signal packs) is the old code,
  unchanged.
- A scheme not followed by a supported type resumes the search one byte after
  its first byte, exactly where the per-character walk would next have tried
  a prefix; after a match the cursor still moves to the end of the prefix
  only, never to the end of the query, so nested eligible URIs and the
  invalid-first-secret behavior are preserved. Case, `totp`/`hotp` spelling
  and the `REQUIRED_LITERALS` prefilter are unchanged.
- UTF-8: the match starts with an ASCII `o`, so it is always on a character
  boundary, and `find_literal` compares bytes only; no character decoding or
  new Unicode acceptance is involved. No dependency, no `unsafe`, no public
  API change, and the anchor is private to this detector (no other detector is
  gated by it).

## Equivalence

`detect_per_character_walk` in the unit tests is the pre-change `detect`
body verbatim (only renamed, with `with_signals` kept so candidate equality
also checks the signal values). Every comparison is full `Candidate` vector
equality (type, confidence, specificity, range, signals, order):

- over 400 named shapes (35 hand-written plus 128 ASCII left-boundary bytes, each in three framings): nested URIs after malformed or unsupported prefixes,
  repeated and invalid first `secret=`, unsupported types (`push`, `totpx`,
  truncated `tot`/`totp`/bare scheme, wrong-case scheme and type), percent and
  Unicode labels, Unicode before and after the URI (2-, 3- and 4-byte
  characters, a combining mark), the label at 2,046 to 2,049 bytes and the
  query at 8,190 to 8,193 bytes (with assertions that 2,048 and 8,192 are
  accepted and 2,049 and 8,193 are not), every ASCII byte as the left-boundary
  character and as the separator between two URIs, and back-to-back URIs;
- 4,000 generated inputs of up to 14 pieces (prefixes, near-prefixes, Unicode,
  separators, secrets);
- every `[start, end)` character-aligned window of 60 more generated inputs and
  of one fixed multi-URI input, which covers every prefix, suffix and chunk
  partition that an incremental session can present to the detector;
- sparse inputs with the URI at offsets 0, 1, 7, 8, 31, 32, 63, 64, 4,095,
  4,096 and 20,000 (ASCII and with trailing Unicode), 400-URI dense inputs
  (ASCII and Unicode-prefixed), prefix-noise and repeated bare-scheme inputs.

The public test `tests/otpauth_discovery_1146.rs` pins the whole-input
`otpauth-uri` finding ranges and checks that every UTF-8 byte partition, the
single-byte partition and several fixed chunk sizes of the incremental surface
reproduce the whole-input result. It passes unchanged on the pre-change code
(`origin/main`) as well as on this change. A mutation check (resuming 15 bytes
after an unsupported scheme instead of 1) fails the differential test; resuming
10 bytes is an equivalent mutant because the scheme has no self-overlap.

## Measurement

Complete `OtpauthDetector::detect`, median of 21 batches per run, five
alternating rounds of baseline, candidate and an A/A control (a second run of
the baseline binary), lock-serialized, on a **heavily loaded shared macOS
host** (load average 17 to 30; the A/A control spans up to -43%/+50% on a
single pair, so only medians and paired medians mean anything). Raw data:
`ab-raw-vs-1145.txt` (baseline = #1145 commit) and `ab-raw-vs-main.txt`
(baseline = `origin/main`, i.e. #1145 and #1146 together, plus the extra
`otp-lead-noise` workload). Harness (not compiled):
`otp-detect-timing-harness.rs.txt`.

Against the #1145 commit:

| workload | baseline | candidate | paired change (median [range]) | A/A control |
|---|---|---|---|---|
| otp-sparse-ascii (74 KB + 1 URI) | 161.4 us | 36.3 us | -77.5% [-80.8, -74.7] | +0.0% |
| otp-sparse-unicode | 161.4 us | 36.7 us | -77.5% [-81.0, -74.4] | -3.7% |
| otp-dense (1,000 URIs) | 242.0 us | 217.5 us | -13.0% [-23.8, +2.3] | -4.0% |
| otp-dense-unicode | 263.2 us | 254.8 us | -18.5% [-25.6, +1.2] | -8.7% |
| otp-prefix-noise (unsupported types) | 186.2 us | 55.6 us | -71.6% [-72.7, -65.4] | -11.2% |

Against `origin/main` (includes #1145), same session:

| workload | baseline | candidate | paired change (median [range]) |
|---|---|---|---|
| otp-lead-noise (`ooo otpaut otpauth: otpauth:/ ...`, many lead bytes, no scheme) | 109.0 us | 64.1 us | -43.5% [-46.3, -35.5] |
| otp-sparse-ascii | 97.4 us | 23.0 us | -77.6% [-81.1, -75.4] |
| otp-sparse-unicode | 99.7 us | 23.0 us | -78.4% [-81.3, -75.4] |
| otp-dense | 213.9 us | 132.7 us | -40.9% [-52.5, -30.4] |
| otp-dense-unicode | 219.0 us | 145.1 us | -38.2% [-50.9, -27.0] |
| otp-prefix-noise | 96.8 us | 35.6 us | -67.6% [-76.1, -61.0] |

No measured workload regressed in its median. The dense gain on its own is
modest (-13% to -19%) and its range reaches +2%, inside the control's noise on
this host; dense inputs are dominated by parsing and candidate construction,
not discovery. The sparse and noisy cases are the target of the change.
Allocation requests are identical before and after (`alloc_attribution`
reports 1,060 / 772,289 bytes dense and 21 / 70,878 sparse for both, with the
same finding digest). These are detector-stage numbers, not whole-scan or
WASM measurements; no WASM run was made.

## Residual risk

None identified beyond the usual one: equivalence is established by the
differential tests above, not by proof. The `find_literal` helper is shared
with other detectors and is not modified.

## Temporary in-repo measurement

Per #1152 these move to the measurement engine before the beta.13 release.

- `crates/secret-scan-core/examples/alloc_attribution.rs` with the `otp-dense`
  and `otp-sparse` workloads added by #1145 (no further change here); it was
  used to confirm identical allocation counts and finding digests.
- `docs/audits/evidence/1146/otp-detect-timing-harness.rs.txt` (uncompiled
  detector timing harness; it uses clock names, so it cannot live under
  `src`) and the two raw outputs.
