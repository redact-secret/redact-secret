# #1145 - shared finite built-in diagnostic signal packs

Product judgement. Final record for
[#1145](https://github.com/redact-secret/redact-secret/issues/1145) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving; the public
`Candidate::signals() -> &[String]` slice API, `with_signals` ownership, `Eq`,
`Hash`, `Debug` and `Clone` values are unchanged. Baseline: `main` at
`ad877c03`. All inputs are synthetic; no value is printed.

## Finding

`Candidate` stored `Vec<String>`. `with_signals` turned every literal into an
owned `String` and `Clone` copied the vector and each string again, although
every built-in detector passes the same fixed diagnostic constants.

## Change

- `Candidate.signals` is now `Cow<'static, [String]>`. `signals()` still
  returns `&[String]`; `with_signals` still builds an owned list, so custom
  and runtime-derived signals (`format!`, iterators over `&str` tables) stay
  owned and are untouched. `Candidate::new`/`built_in` borrow an empty slice.
- `SignalPack` (crate-private) holds a `&'static [&'static str]` and a
  `OnceLock<Box<[String]>>`; `signal_pack!("a", "b")` expands to one
  `static` per definition site. A new crate-private
  `Candidate::with_signal_pack(&'static SignalPack)` borrows the pack's one
  slice. A pack only ever contains the literals written at its definition
  site: no registry, no unbounded growth, no interning of source input or any
  runtime-derived name.
- Converted the 22 built-in call sites whose argument is a literal array
  (`anthropic`, `atlassian`, `aws`, `azure_devops`, `bearer_token` x2,
  `discord`, `firebase`, `generic_token` x3, `grafana`, `jwt`,
  `microsoft_entra`, `openai`, `sendgrid`, `sentry` x2, `shopify`,
  `telegram`, `terraform`, `vault`) and `otpauth` (two packs, one per form).
  Sites that take a runtime signal (`[signal, "..."]`), a `signals.iter()`
  table, a constant shared by reference, or a `format!` result are
  deliberately left owned: they are not a single finite literal set, and the
  issue asks to keep dynamic paths owned. Converting more tables is a
  mechanical follow-up if a representative budget justifies it.
- No dependency, no `unsafe`, no public API or hook.

## Equivalence and tests

- `a_signal_pack_equals_with_signals_for_the_same_labels` (types.rs): a packed
  and an owned candidate with the same labels are `==`, hash identically
  (`DefaultHasher`), print identical `Debug`, and `signals()` still has type
  `&[String]`.
- `candidates_from_one_pack_share_a_single_slice_and_clone_keeps_it`: two
  separate constructions through the same site, and a `Clone`, return the same
  slice (`std::ptr::eq`); a different pack and an owned list do not alias.
  This is the structural proof that no per-candidate signal strings are
  allocated: the borrowed slice is the very static one.
- `with_signals_and_with_signal_pack_each_replace_the_previous_list`: both
  orders of replacement, plus a `format!`-built dynamic signal.
- `otpauth_candidates_share_one_signal_slice_per_form`: signal values and
  order (`["otpauth-scheme", "totp"|"hotp"]`) and per-form sharing.
- All 1,798 library tests and the public-API/integration suites pass
  unchanged; every `signals()` consumer (evidence context, gitlab, private
  key, connection string) is covered by its existing tests.

## Measurement

Whole `scan` allocation requests, existing `alloc_attribution` example
(counts `alloc`/`realloc` requests and cumulative requested bytes; synthetic
`otpauth://` lines; the digest of the full finding list is identical on both
builds). Release build:

| workload | baseline requests / bytes | candidate requests / bytes |
|---|---|---|
| otp-dense (1,000 URIs, 1,000 findings) | 4,060 / 838,289 | 1,060 / 772,289 |
| otp-sparse (one URI in 74 KB) | 24 / 70,944 | 21 / 70,878 |

Exactly three requests per candidate disappear (two signal strings and the
vector buffer), with the bytes of those requests; 66,000 bytes less on the
dense input. No allocator was used to measure static retention: the one-time
pack setup is one boxed slice plus its short strings per definition site,
known from the code, paid once per process.

Wall clock, complete `OtpauthDetector::detect` (the stage most affected),
median of 21 batches per run, five alternating rounds of baseline, candidate
and an A/A control (a second run of the baseline binary), lock-serialized, on
a **heavily loaded shared macOS host** (load average above 30; the A/A control
ranged from -41% to +83% on a single pair, so only the medians and the paired
medians mean anything). Raw data: `ab-raw.txt`; harness (not compiled):
`otp-detect-timing-harness.rs.txt`.

| workload | baseline | candidate | paired change (median [range]) | A/A control |
|---|---|---|---|---|
| otp-sparse-ascii | 84.2 us | 84.2 us | +0.1% [-1.8, +1.7] | +0.2% |
| otp-sparse-unicode | 84.2 us | 84.1 us | -0.2% [-10.1, +0.2] | -0.1% |
| otp-dense | 176.8 us | 124.8 us | -29.5% [-46.0, -28.1] | -0.1% |
| otp-dense-unicode | 190.5 us | 137.0 us | -27.7% [-51.4, -18.4] | -0.3% |
| otp-prefix-noise (no candidate built) | 83.6 us | 84.1 us | +0.5% | -0.0% |

Sparse and no-match inputs build at most one candidate, so they are
unchanged (within noise); the gain is proportional to candidates built.
This is a detector-stage result, not a whole-scan or release speedup: the
finding conversion still allocates its own metadata. Isolated construction
timings from the issue (about -96% for 1,000 two-signal candidates) were not
re-measured; this record relies on the allocation counts and the whole
detector.

## Residual risk

- The first use of each pack allocates its strings once and retains them for
  the process lifetime (a few dozen short constants in total).
- `Cow` adds a discriminant check on `signals()`. `Candidate` size was not
  measured here and no size assertion exists in the crate.
- A site that passes a dynamic signal must keep using `with_signals`; the pack
  macro only accepts string literals, so a runtime value cannot reach it.

## Temporary in-repo measurement

Per #1152 these move to the measurement engine before the beta.13 release.

- `crates/secret-scan-core/examples/alloc_attribution.rs` (the only file that
  may hold `unsafe`): two added workloads, `otp-dense` and `otp-sparse`
  (functions `otp_dense`, `otp_sparse` and two entries in `main`'s workload
  list), so whole-scan allocation requests of OTP input can be counted.
  Added after the lines the `sast/baseline.json` entries point at, so those
  entries are unchanged.
- `docs/audits/evidence/1145/otp-detect-timing-harness.rs.txt` is the
  uncompiled detector timing harness (it uses clock names, so it cannot live
  under `src`); `ab-raw.txt` is its raw output.
