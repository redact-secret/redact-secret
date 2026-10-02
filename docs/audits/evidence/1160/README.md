# #1160 - IPv4/IPv6 host validation without temporary Vec storage

Product judgement. Final record for
[#1160](https://github.com/redact-secret/redact-secret/issues/1160) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline:
`origin/main` at a2b2aa6c (the issue's pinned baseline `9c66a706` was
requalified; `connection_string.rs` has no later semantic change to these
helpers). All inputs are synthetic.

## Change (`crates/secret-scan-core/src/detectors/connection_string.rs`)

- `is_valid_ipv4`: `value.split('.')` is walked with a counter instead of
  `collect::<Vec<_>>()`. It fails on the fifth part or any invalid octet and
  requires exactly four. `is_valid_ipv4_octet` (leading zero, range, 1 to 3
  digits) is untouched.
- `is_valid_ipv6`: the two sides are a fixed `[head, tail]` array (the tail is
  empty without a `::`), empty sides are skipped, and a `peekable` group walk
  replaces the `sides` and `groups` Vecs. `peek()` identifies the last group, the
  only position an IPv4 tail may occupy. The single-`::` check, the
  empty-group rejection, hex group (1 to 4 digits) rule, unit counts (8 without
  compression, fewer than 8 with) and the "IPv4 tail counts 2 units" rule are
  unchanged. No broader IP grammar.

No unsafe, no dependency, no public API change, no input-retaining cache. Spans,
types, confidence, actions, order and IDs cannot change: both functions return
the same `bool` for every `&str`.

## Equivalence

The pre-change functions are kept in the test module as `oracle_is_valid_ipv4`
and `oracle_is_valid_ipv6`. Tests compare them with the shipped functions on:

- 56 named shapes (valid, single and double compression, bare/leading/trailing
  colons, 7/8/9 groups, IPv4 tails in and out of last position, short/long
  tails, leading zeros, 256, empty octets, Unicode digits and a fullwidth
  digit, NUL, spaces);
- every string over three alphabets: `{0,2,5,:,.,f}` up to 7 characters,
  `{:,.,1,g}` up to 10 characters, and `{:,.,1,e-acute,fullwidth 1}` up to 7
  characters (about 1.8 million inputs);
- 40,000 xorshift-generated concatenations of boundary atoms (octets 0, 9, 25,
  255, 256, hex groups of 2/4/5 digits, `::`, dotted quads, Unicode);
- long inputs: 5,000 to 10,000 groups, 4,000 dotted parts, 8 groups plus a long
  tail, 0..=12 groups with and without compression.

A mutation check (dropping the `peek()` last-group condition) makes three of the
four tests fail. Both helpers are pure functions of one host string, so
whole-input and incremental/streaming partitioning cannot change their result:
the detector hands them the same authority text either way, and the existing
incremental suites in `crates/secret-scan-core/tests/` still pass.

## Measurement

Host: Apple M4 (arm64), rustc 1.98.1, release profile (`lto = "fat"`,
`codegen-units = 1`), **a shared host under load (load average 6 to 17)**.
Different ISA from the issue's x86_64 run. Stage run
(`timing-harness.rs.txt`): 41 rounds alternating old/new/old (A/A) order,
medians, benchmark lock held.

| Workload (ns per call) | old | new | change | A/A |
|---|---|---|---|---|
| ipv4 valid | 68.97 | 38.11 | -44.7% | -0.5% |
| ipv4 invalid | 84.63 | 34.98 | -58.7% | -0.8% |
| ipv6 full | 289.30 | 200.35 | -30.7% | -1.5% |
| ipv6 compressed | 111.74 | 55.38 | -50.4% | +0.1% |
| ipv6 with IPv4 tail | 176.59 | 107.73 | -39.0% | +0.1% |
| ipv6 malformed | 80.58 | 49.76 | -38.3% | +0.1% |
| not an IP (no colon, early exit, no Vec in either) | 8.04 | 8.38 | +4.2% | +0.7% |

The last row runs the same code on both sides (one `contains(':')`) and is
placement noise of an 8 ns call; no row regresses outside that.

Whole scan (`whole-scan-harness.rs.txt`, public `scan` with the built-in
registry, two release test binaries built from baseline and candidate source,
5 rounds of base/candidate/base A/A): sparse (8 URLs in 32 kB of prose), dense
IPv6 URLs, dense reg-name hosts, dense placeholders, dense malformed IPv6 and
prose noise. Findings counts are identical in every case. The host was too
noisy to resolve the effect: A/A control medians moved between -19% and +15%
and individual rounds between -60% and +140% (raw: `raw-whole-scan.txt`, summary
by `aggregate.py.txt`). **No whole-scan gain is claimed.** The stage saving is
about 30 to 50 ns per validated host, so 2,000 dense URLs save at most
0.1 ms of a 10 to 16 ms scan (about 1%), and sparse inputs validate a handful
of hosts.

Allocation requests were not counted. Structurally, each IPv4 validation no
longer allocates one Vec and each IPv6 validation no longer allocates two
(`sides` and `groups`), plus one more for an IPv4 tail. Native/WASM budget
qualification belongs to #1068 and the benchmarks repository.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No in-repo measurement file was added or changed for this issue (tracked in
#1152; it moves to the measurement engine before the beta.13 release, see
`redact-secret-benchmarks#608`). Kept as inert `.txt` text under this
directory, never built by Cargo and never under `src/`:
`timing-harness.rs.txt` (a module appended temporarily to
`detectors/connection_string.rs`; it re-declares the pre-change functions),
`whole-scan-harness.rs.txt` (temporarily copied to
`crates/secret-scan-core/tests/zz_whole.rs`, removed before commit),
`aggregate.py.txt` and `raw-whole-scan.txt` (summary script and raw output).
`examples/alloc_attribution.rs` was not used.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
