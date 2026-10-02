# #1151 - where the counting allocator's `unsafe` lives

Product judgement. Final record for
[#1151](https://github.com/redact-secret/redact-secret/issues/1151) (parent
[#1068](https://github.com/redact-secret/redact-secret/issues/1068), under #1065).
It changes no detector, no public API and no shipped behavior. The execution of
this decision is [#1152](../1152/README.md).

## Decision

**The counting allocator lives outside this repository.** Allocation-request
counting needs a `#[global_allocator]`, and Rust requires `unsafe impl
GlobalAlloc` for one, so there is no safe implementation; the only choice is
where the `unsafe` lives and who reviews it. The decision is option 2 of the
card, retargeted: the harness lives in the separate measurement engine, and it
uses a pinned third-party counting-allocator crate, `stats_alloc` (option 3),
so the engine carries no `unsafe` of its own for this either. This repository
adds no crate, no dependency and no workspace member for measurement.

| Option | Verdict | Reason |
|---|---|---|
| 1. Isolated internal measurement crate in this workspace | rejected | would keep a reviewed `unsafe` and a SAST entry in this tree for tooling that no published artifact uses |
| 2. Harness in the measurement engine | **adopted** | evidence and benchmark-run artifacts already belong outside this repository; the engine runs against an exact, immutable core commit through the public API |
| 3. Reviewed third-party counting allocator | **adopted inside the engine** | `stats_alloc` is pinned there; it never enters this repository's dependency graph or any published artifact |
| 4. Platform tools (`leaks`, heaptrack, valgrind) | not pursued | not comparable to the existing request counts, and not reproducible on both macOS arm64 and Linux CI |
| 5. Safe structural proxies (count constructor/clone calls) | rejected | too weak: they miss `realloc` growth and hidden allocations, which the #1121 attribution depended on |

The decision was validated by reproduction rather than argued: the engine
reproduces the #1121 baseline exactly with the third-party allocator (ordinary
18,451 -> 5,451, diverse 18,459 -> 4,274, references 12,155 -> 1,054 requests
per 1,000 assignments, findings identical) and gates it with a release test in
its own CI. Details and the loss accounting are in
[`../1152/README.md`](../1152/README.md).

## Standing rule

`crates/secret-scan-core` and `crates/secret-scan-cli` contain no `unsafe` in
any form, tooling and examples included. `grep -rn unsafe crates/` finds only
the `forbid(unsafe_code)` declarations and prose. This tooling is not an
exception. The rule text is in
[`docs/rust-workspace.md`](../../../rust-workspace.md#unsafe-code), which also
keeps the narrower allowance for a binding crate: an item-scoped
`#[allow(unsafe_code)]` only at a real FFI boundary, with a `// SAFETY:` comment
and a recorded review. That allowance never applied to core or CLI, and the
file-level `#![allow(unsafe_code, ...)]` the merged example carried did not match
it; the example is gone, so the rule and the code agree again.

## What the check enforces

`python3 -B scripts/check-rust-workspace.py` (`npm run rust:check`), in its
unsafe-code check:

- `[workspace.lints.rust] unsafe_code` is `deny` or `forbid`, and every member
  inherits workspace lints (unchanged).
- The core and CLI crate roots carry `#![forbid(unsafe_code)]` (unchanged).
- **New:** no `.rs` file anywhere under either crate directory (`src`,
  `examples`, `tests`, `benches`, `build.rs`) names the `unsafe` keyword as a
  whole word outside a `//` or `/* */` comment. `unsafe_code` inside
  `forbid(unsafe_code)` is not the keyword. Comments and doc comments may say
  the word. A string literal containing the word would also be flagged; none
  exists, and if one is ever needed it should be reworded.

The check is covered by unit tests in
`scripts/tests/test_check_rust_workspace.py` (keyword in a core example is
rejected with its line number, keyword in a CLI test is rejected, comments and
the forbid attribute are accepted). It does not cover binding crates, which may
have a recorded FFI allowance, and it is a text check, not a semantic one: the
compiler lint (`unsafe_code = "deny"` plus the crate-root `forbid`) remains the
authority.

## Consequences

- `crates/secret-scan-core/examples/alloc_attribution.rs` and its five
  `sast/baseline.json` dispositions are removed (#1152).
- Counters record request counts and sizes only: no plaintext, no pointer
  values. Synthetic fixtures only.
- Measurement-run artifacts (`redact-secret-allocation-counts.json`) live in the
  separate measurement engine, not here.

Not claimed: any timing direction. See #1152.
