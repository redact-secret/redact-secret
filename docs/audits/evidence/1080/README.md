# Evidence: #1080, an optional zeroization design for core-owned plaintext buffers

**Result:** a narrow design is feasible and measured. With a core Cargo feature
(proposed name `memory-hygiene`, off by default) that enables `zeroize`
(`=1.9.0`, `default-features = false`, `features = ["alloc"]`), the core
overwrites the **current allocation** of four kinds of core-owned plaintext
buffer when their life ends: the incremental `retained` and `scanned` buffers,
the owned text of a `NormalizedInput`, and (proposed, not prototyped) the
private-key tracker's `lookbehind`. It also wipes the allocation a buffer
leaves behind when it grows or is rebuilt at a flush, so those two buffers
leave no earlier copy. It wipes nothing the caller owns, nothing a detector
copies transiently, and nothing a host makes. The prototype added no
dependency to `redact-secret` beyond `zeroize`, kept `#![forbid(unsafe_code)]`,
built for `wasm32-unknown-unknown` and `wasm32-wasip1`, and cost about 5 % of
the incremental path natively (20 to 26 extra instructions per input byte),
8 to 11 % of a WebAssembly incremental run, and 1.3 KB (0.21 %) of WebAssembly
size. Adopting it conflicts with one accepted rule: **the core declares no
Cargo features and no optional dependency**, enforced by check 8 of
`scripts/check-rust-workspace.py`. So adoption needs an ADR that amends that
rule, which this record drafts in [Policy conflict](#policy-conflict-and-the-adr-it-needs)
and does not decide. No build of the core zeroizes anything today, and this
record changes no code.

Issue [#1080](https://github.com/redact-secret/redact-secret/issues/1080).
It decides inside the vocabulary of
[`decision-define-the-plaintext-memory-lifetime-contract`](../../../decisions/2026-09-30-define-the-plaintext-memory-lifetime-contract.md)
and reads the inventory in [#1079 evidence](../1079/README.md) (IDs `I2`, `I3`,
`W2` and so on are that inventory's). The contract as users read it is
[plaintext lifetime](../../../reference/plaintext-lifetime.md).

Measured at `defaf187` (the #1079 record on `origin/main` `f4618965`) on
`aarch64-apple-darwin`, rustc 1.98.1, `zeroize` 1.9.0. The prototype is a
local branch, `workbench/1080-zeroize-design-proto`, never pushed and never
to be merged; its shape is reproduced under
[Prototype shape](#prototype-shape) so this record stands without it.

## Method and limits

- **Prototype, not product.** One scratch commit on the local branch above
  implements the design and ten lifecycle tests. The deliverable branch for
  this record carries no dependency and no code.
- **Native cost** is read from `time -l` instructions retired and cycles,
  because the machine was heavily loaded (load average 35 to 40 during the
  runs, 72 to 81 logged-in users). Three interleaved repetitions of each of
  three binaries (base `defaf187`, prototype with the feature off, prototype
  with it on) per workload, `scan_cost --runs 5 --no-detectors`. Wall-clock
  minima over 21 runs were also taken and are **not** used: the whole-input
  path, which the feature barely touches, drifted by up to 40 % between
  identical binaries. The harness is the repository's own
  `crates/secret-scan-core/benches/scan_cost.rs`, unmodified (the #1076 bench
  patch has already merged).
- **Instruction counts cover the whole process** (input generation, both
  scan paths, all runs), so the percentage on the incremental path alone is
  larger than the total's. The per-byte figure below divides the added
  instructions by the incremental bytes processed.
- **The canary allocator** is a scratch `GlobalAlloc` wrapper that needs
  `unsafe`, so it lives in an example of the prototype branch, never in
  `src`. It inspects a block when it is freed or reallocated away and counts
  blocks that still hold a synthetic marker, byte for byte. It cannot see a
  case-changed or normalized copy of the marker, the caller's own buffers, the
  allocator's free lists, the stack, or any other process. It is
  implementation evidence for one allocator on one target, nothing more.
- **Not measured:** Node and Python binding builds with the feature, the
  Windows and Linux native targets, a Rust 1.88 toolchain (only 1.98.1 is
  installed; `zeroize` declares 1.85), and WebAssembly throughput beyond the
  one incremental stream below.

## What `zeroize` 1.9.0 guarantees and does not

Read from the crate's own source and documentation in the local registry
(`zeroize-1.9.0`), not from memory. Line numbers are in `src/lib.rs` unless
noted.

| Statement | Source |
| --- | --- |
| `Zeroize for Vec<Z>` zeroes every initialized element, calls `clear`, then zeroes the **entire spare capacity**. The doc calls it "best effort" and says it "cannot ensure that previous reallocations did not leave values on the heap". | `:520-534` |
| `Zeroize for String` delegates to its `Vec<u8>`. Result: length 0, the whole current allocation zeroed, the allocation **kept**. | `:566-569` |
| The crate's guidance: the `Vec`, `String` and `CString` impls "cannot guarantee copies of the data were not previously made by buffer reallocation. It's therefore important ... to initialize them to the correct capacity, and take care to prevent subsequent reallocation." | `:172-175` |
| The write is a byte-by-byte loop of `ptr::write_volatile` followed by `optimization_barrier`. There is no `memset`. | `:748-763`, `:472-473` |
| `optimization_barrier` is `core::arch::asm!` on aarch64, arm, arm64ec, loongarch64, riscv32, riscv64, s390x, x86 and x86_64, and `black_box` plus a `read_volatile` fallback everywhere else, which includes `wasm32`. | `src/barrier.rs` |
| The guarantee is that the compiler cannot optimize the zeroing away, through LLVM volatile semantics. Microarchitectural leakage (Spectre-class) is expressly not covered. | `:144-158` |
| Register clearing, `mlock`, `mprotect` and similar protection are "explicitly out-of-scope". Stack spills of heap data may leave temporary copies. | `:162-166`, `:187-201` |
| `Zeroizing<Z>` zeroes only in its `Drop`. A `Clone` of it is a second buffer. | `:696-703`, `Clone` impl |
| With `default-features = false, features = ["alloc"]` the crate has **no dependencies**. `zeroize_derive` and `serde` are separate optional features. | `Cargo.toml` of the crate; `cargo tree` below |
| License `Apache-2.0 OR MIT`. MSRV 1.85, edition 2024, below the workspace's 1.88. | `Cargo.toml` of the crate |

Two corrections to the research note on the issue, because the design
depends on them:

1. The note, and the crate's own README, say the crate uses "memory fences"
   and "no FFI or inline assembly". For 1.9.0 that is out of date.
   `CHANGELOG.md` for 1.9.0 lists "Replace `atomic_fence` with
   `optimization_barrier`", and the barrier is inline assembly on the
   architectures above. Nothing changes for `redact-secret`, whose
   `forbid(unsafe_code)` applies to its own source, not to a dependency. The
   supply-chain consequence is real: the core would link a dependency that
   contains `unsafe` and, on most targets, inline assembly. `cargo deny`
   does not see either.
2. The note says `zeroize` zeroes `String` capacity and the design can rely on
   it. That is true of the current allocation only. The same sentence in the
   crate's docs is the reason the design below grows buffers itself.

## The decision

Stated inside the #1079 vocabulary. "Zeroized" here always means "overwritten
by `zeroize`'s volatile write followed by its optimization barrier".

**What is wiped.** The current allocation, length and spare capacity, of:

| ID | Buffer | Wiped | Not wiped |
| --- | --- | --- | --- |
| I2 | `IncrementalSanitizer::retained`, which holds the lead (I5) in front | at a flush, at `finalize`, `abort`, every failure, at drop, and when it grows | the caller's chunk, and the released output |
| I3 | `IncrementalSanitizer::scanned` | at unit end, at every terminal transition, at drop, and when it grows | |
| W2, I4, I9, I13 | the owned text of a `NormalizedInput` | when the view is dropped. Borrowed text holds no allocation, so the ASCII and no-invisible-code-point common path pays nothing | |
| I7 | `PrivateKeyRetentionTracker.lookbehind` (proposed, at most `MAX_DELIMITER_LEN - 1` bytes) | at reset and at drop | |
| I10 | the `split_off` copy of the last line | when it drops | |

**What stays outside, even with the feature on.**

1. Caller-owned input and the returned output (`W1`, `W9`, `I1`, `I11`). Under
   `warn` and `allow` the output still holds the value.
2. Detector temporaries `D1` to `D11`. They are stack-scoped owned copies of a
   value, a line or a context window, and the feature does not touch them.
   The 1079 finding `R2` removes most of them by not copying; that is the
   right fix and it is independent of this one. The canary run below cannot
   see them because they are case-changed or normalized.
3. Every earlier allocation of any buffer **not** in the table, including
   `Released.text` (`I11`, grown by `push_str`) and the placeholder strings.
4. Bindings, CLI, V8, CPython, and WebAssembly linear memory. A wiped block in
   linear memory is zeros, but the copy `wasm-bindgen` encoded the argument
   into, and the JS string it came from, are untouched and the host can read
   all of memory at any time. After a WebAssembly trap (`panic = abort`), no
   `Drop` runs.
5. Stack frames, spilled registers, allocator free lists, swap, dumps, and
   microarchitectural state. Prior to the wipe, the plaintext existed in all of
   them as it does today.
6. Timing. A wipe happens at a flush or terminal call, not at a deadline. A
   session nobody finishes keeps its plaintext until it is dropped.
7. Panics that do not unwind, and a session kept alive by a caller that never
   calls `abort`.

**When.** At the moments in the [transition table](#terminal-transitions-under-the-feature).
Drop is a backstop, not the contract: terminal paths wipe explicitly, because
the life of a buffer should end at the documented transition and not at the
caller's next garbage collection.

**Under which mode.** The Cargo feature `memory-hygiene` of the `redact-secret`
crate, off by default. With it off the crate has no `zeroize` in its build
graph and the code is the code today (instructions within 0.5 % of base,
binary 89 bytes different in WebAssembly from a refactor that stays on in both
modes; see [Measurements](#measurements)). A build that enables it may say
"selected core-owned plaintext buffers are zeroized when their documented life
ends" and must keep the list above. It must not say secrets are erased.

**What it adds.** Table below; in one line, about 5 % of the incremental path,
no cost to the whole-input ASCII path, 1.3 KB of WebAssembly, one dependency
with none of its own.

## The seven questions

1. **Is a feature-gated `zeroize` the right primitive?** Yes, for this scope.
   It is the only option measured that both has a documented optimizer
   guarantee (volatile writes plus a barrier) and needs no `unsafe` in the
   core's own source. `secrecy` adds a wrapper model for long-lived secrets
   and does not cure reallocation; `mlock` and `mprotect` are outside the core
   boundary (see the issue's constraints). The no-dependency option is covered
   [below](#the-no-dependency-alternative). The primitive's price is that the
   core links a dependency with `unsafe` and inline assembly in it, and that
   its `volatile_set` is a byte loop.
2. **Which buffers, and on drop or on terminal transition?** The five in the
   table above, on both. Terminal transitions wipe explicitly; drop wipes the
   same field through its type, so `drop` of an accepting session, and an
   unwinding panic, are covered with no `Drop` on the session itself.
3. **Clear immediately on `finalize`, `abort` and failure?** Yes. The session
   already releases there (`discard_retained`, `incremental.rs:806-812`);
   under the feature that release becomes wipe-then-release, so the existing
   structural tests keep passing and a wipe hook is observable at the same
   places.
4. **Pre-size to avoid reallocations?** **No.** The design replaces
   pre-sizing with wipe-on-grow. Pre-sizing to the bound the limits permit
   means at least `max_buffered_bytes`, which the CLI sets to 1 MiB + 128
   bytes (`IncrementalLimits::minimum_buffered_bytes`, `LOOKAROUND_BYTES =
   128`), for every session, including ones that hold a few hundred bytes.
   `zeroize` zeroes the full capacity, so every wipe would then touch all of it
   (a 1 MiB write per flush, not per byte retained), and WebAssembly linear
   memory never shrinks. Wipe-on-grow gives the same result for the same two
   buffers: the growth path allocates the larger buffer itself, copies, wipes
   the old one, and only then lets it go, so no earlier copy exists. The one
   flush that rebuilds `retained` (`incremental.rs:1185-1189`) wipes the old
   allocation the same way. A fixed pre-size only reduces the number of wipes,
   and it does so at a cost paid by every session.
5. **Does `Zeroizing<String>` help?** Partly. It gives wipe-on-drop and, on
   assignment, wipe-on-replace, and it derefs to `String` so `push_str` needs
   no change. It does **not** wipe the allocation `push_str` frees when it
   grows, which is the gap this design exists to close. So the prototype wraps
   `String` in a small `pub(crate)` newtype (`PlainBuf`, about 150 lines
   including the test counter) that owns growth, derefs to `str`, prints only
   its length in `Debug`, and is a plain `String` with no `Drop` when the
   feature is off. Mutation is four methods (`push_str`, `truncate`,
   `split_off`, `release`); every other use reads through `Deref`.
6. **Artifact size and runtime?** See [Measurements](#measurements).
7. **Implementation detail or public feature?** An implementation detail with
   one visible seam: the Cargo feature itself is part of the crate's manifest,
   so it is visible to dependents and to `cargo metadata`. No Rust item, no
   JavaScript, Python or CLI API, and no output changes. Feature unification
   is benign here: enabling the feature anywhere in a build graph only adds
   wiping and cannot change a finding or an output byte (the 1,746 existing
   tests pass with it on, and the WebAssembly incremental stream gives
   identical output). That is the opposite of the detector-profile case, where
   unification adds detection; see the ADR below.

## Terminal transitions under the feature

Columns map to the #1079 table of terminal transitions. "Wipe" is
`zeroize` on the current allocation of the field, then release.

| Transition | `retained` (I2, includes lead I5) | `scanned` (I3) | `NormalizedInput` | Test in the prototype |
| --- | --- | --- | --- | --- |
| `append` succeeds, lines closed (flush) | old allocation wiped, replaced by a copy of the open tail | kept or reset with the unit | per-piece view wiped when it drops | `a_flush_wipes_the_buffer_that_held_the_released_units` |
| `append`, buffer grows | old allocation wiped after the copy | same | | `growth_wipes_each_allocation_it_leaves_behind` |
| Limit failure | wiped by `fail_with` through `discard_retained` | wiped | | `a_limit_failure_wipes_the_retained_allocation` |
| Policy, formatter or placeholder failure | wiped | wiped | | `a_policy_failure_wipes_the_retained_allocation` |
| `finalize` succeeds | wiped (the last flush, then `discard_retained`) | wiped | | `finalize_wipes_the_retained_allocation` |
| `abort` | wiped | wiped | | `abort_wipes_the_retained_allocation`, `a_terminal_transition_wipes_the_normalized_scan_copy` |
| Drop while `accepting` | wiped by the field's `Drop` | wiped | | `dropping_an_accepting_session_wipes_it` |
| Whole-input scan, invisible code point present | | | wiped when `detect_units` returns, on success and on `?` | `an_owned_normalized_view_wipes_on_drop_and_a_borrowed_one_does_not` |
| Wrong state (`InvalidState`) | nothing to wipe: buffers are already empty | | | existing `a_state_failure_leaves_nothing_retained_to_discard` |
| Panic in a host callback that unwinds and drops the session | wiped by the field's `Drop` on native unwinding; nothing on `panic = abort` targets | | | not testable structurally |

The wipe-observing tests use a `cfg(test)` thread-local counter that the wipe
helper increments with the capacity it overwrote. They prove the hook ran at
that transition over at least the bytes the buffer held. They do not read freed
memory. A mutation check confirmed they are sensitive: replacing the terminal
release with a forget made four of the ten fail.

The existing structural assertions (`assert_nothing_retained`, zero
capacity after release) still hold unchanged, because `release` leaves an empty
`String` with no allocation.

## Measurements

### Dependency, policy and `unsafe`

| Check | Result |
| --- | --- |
| Transitive dependencies added to the core graph | none: `zeroize v1.9.0` only. `cargo tree -p redact-secret --features memory-hygiene -e normal` lists `tinyvec` and `unicode-normalization` as before plus `zeroize`. Feature off: no `zeroize` in the graph |
| `Cargo.lock` | one new package, `zeroize 1.9.0`, which the lock lists **even with the feature off** (a lockfile scanner sees it; a feature-aware SBOM does not) |
| License | `Apache-2.0 OR MIT`, within the `deny.toml` allow list |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok`, with the dependency and feature in place |
| `npm run rust:check`, allowed-dependencies procedure of `docs/rust-workspace.md` | adding `zeroize` to `allowed-dependencies` satisfies check 1. **Check 8 fails by design**: `the core declares no Cargo features; found ['memory-hygiene']` and `[dependencies] zeroize is optional, which would feature-gate the core`. Those are the only two errors. The 54 checker unit tests and the invisible-table check pass |
| `#![forbid(unsafe_code)]` in `redact-secret` | compiles with the feature on and off. The prototype has no `unsafe` in `crates/secret-scan-core/src` |
| `cargo clippy -p redact-secret` (lib), feature on and off | no warnings |
| `cargo test -p redact-secret --lib` | feature off 1,746 passed; feature on 1,756 passed (the same plus 10 lifecycle tests) |
| `wasm32-unknown-unknown` and `wasm32-wasip1`, `cargo build -p redact-secret --release` | both build with the feature on, and with the scratch `fill-only` variant |

### Native runtime

Instructions retired for the whole `scan_cost` process, median of three
repetitions per binary. `off` is the prototype with the feature off, `on` with
it on, `base` is `defaf187`.

| Workload | Base instructions | off / base | on / base | on / off | Cycles, on / base | Added instr. per incremental byte |
| --- | --- | --- | --- | --- | --- | --- |
| scale-logs-256k (two incremental paths) | 2.177 G | 0.9996 | 1.0297 | 1.0301 | 1.031 | 20.8 |
| unicode-invisible-64k | 356.1 M | 1.0003 | 1.0544 | 1.0541 | 1.052 | 49.0 (also counts the whole-path view wipe) |
| minified-json-256k | 1.643 G | 1.0010 | 1.0263 | 1.0252 | 1.029 | 26.4 |
| open-assignment-whitespace-10k | 371.6 M | 1.0048 | 1.0405 | 1.0355 | 1.097 | 24.5 |
| hex-heavy-log-256k | 1.942 G | 0.9995 | 1.0173 | 1.0178 | 1.043 | 22.0 |
| mixed-10m | 51.40 G | 1.0001 | 1.0284 | 1.0283 | 1.050 | 23.1 |

Reading: the feature off is indistinguishable from base (within 0.5 %). The
feature on adds 1.7 % to 5.4 % of the whole process, which is roughly 20 to
26 instructions per byte the incremental path processes, or about 5 % of that
path's roughly 450 instructions per byte. The whole-input ASCII path is
unchanged. The cost is `zeroize`'s byte-at-a-time volatile loop, run roughly
four times per byte over a session's life (growth, flush, terminal), each time
over the full capacity.

Peak memory footprint (`time -l`, KB, median of three; identical binaries varied
by about 500 KB between repetitions, so read only the larger differences):

| Workload | base | off | on |
| --- | --- | --- | --- |
| scale-logs-256k | 2,880 | 2,992 | 3,168 |
| minified-json-256k | 3,776 | 4,176 | 4,640 |
| unicode-invisible-64k | 2,832 | 2,800 | 2,928 |
| mixed-10m | about 35,000 | about 35,000 | about 35,000 |

On a 256 KiB input the feature adds 0.1 to 0.6 MiB of peak footprint: the wipe
touches spare capacity that would otherwise stay untouched, and growth holds
the old and new buffer at once. At 10 MiB it is lost in the noise.

### WebAssembly

Raw and gzip -9 bytes of the `.wasm` from `scripts/build-browser-artifact.mjs`,
with `redact-secret-wasm` forwarding the feature to the core for the `on`
column (scratch edit, not proposed as is).

| Artifact | base | off | on | on - off, raw | on - off, gzip |
| --- | --- | --- | --- | --- | --- |
| full | 599,573 / 209,186 | 599,662 / 209,140 | 600,936 / 209,713 | +1,274 (0.21 %) | +573 (0.27 %) |
| common | 410,652 / 145,525 | 410,733 / 145,530 | 412,007 / 146,012 | +1,274 (0.31 %) | +482 (0.33 %) |
| full + pii | 898,764 / 330,678 | 898,837 / 330,664 | 900,065 / 331,276 | +1,228 (0.14 %) | +612 (0.19 %) |
| common + pii | 709,958 / 266,233 | 710,039 / 266,236 | 711,313 / 266,809 | +1,274 (0.18 %) | +573 (0.22 %) |

`off` differs from `base` by 73 to 89 bytes raw: the prototype removes
`NormalizedInput::into_text` in favour of holding the view, which a real
implementation would also do.

One incremental run in Node, `full` artifact: a 1 MiB synthetic log of
repeated lines with a revoked placeholder value, fed in 4 KiB chunks, nine runs
per build, two alternating pairs. Median 172 ms and 170 ms with the feature
off, 185 ms and 189 ms on, so **+8 % to +11 %**. The sanitized output was
byte-identical (854,194 bytes) and linear memory was the same 1.125 MiB. Under
WebAssembly the barrier is the `black_box` fallback, and the byte loop is not
vectorized.

### What the canary allocator saw

Blocks freed or reallocated away while still holding the exact marker
`SYNTHETIC_REVOKED_RETENTION_MARKER`, counting only what the scenario's own
code freed (the caller's input and the returned output are outside it):

| Scenario | Feature off | Feature on |
| --- | --- | --- |
| Incremental, 400 lines in 61-byte chunks, `finalize` | 795 blocks (83,103 bytes) | 0 |
| Incremental, `abort` mid-stream | 84 (8,546) | 0 |
| Incremental, drop while `accepting` | 84 (8,546) | 0 |
| Incremental, invisible code points, `finalize` | 236 (14,736) | 0 |
| Whole-input `scan_and_redact`, plain | 0 | 0 |
| Whole-input `scan_and_redact`, invisible code points | 1 (2,300) | 0 |

The feature-off counts are the copies the 1079 record described: growth by
doubling and the per-flush rebuild. They are zero with the feature on, which
shows the current allocations **and** the allocations left behind by growth and
flush of `retained`, `scanned` and the normalized view were overwritten before
the allocator saw them. This says nothing about detector temporaries (they hold
case-changed copies the canary cannot match), nothing about other allocators,
and nothing about freed memory the canary did not inspect.

## The no-dependency alternative

The alternatives are these, with what each can and cannot be called.

1. **Clear and pre-size only.** `String::clear` and an up-front capacity
   reduce copies and leave every byte in place. It is worth doing on its own
   terms, which is what the 1079 review rule already prefers. It overwrites
   nothing and cannot be described as zeroization.
2. **A manual overwrite loop with `write_volatile` or `ptr::write_bytes`.**
   Not allowed: both are `unsafe`, and the core forbids it. `compiler_fence`
   is safe but orders operations and does not keep a store that is never read
   again from being removed.
3. **A safe-Rust fill plus `std::hint::black_box`.** Possible with no
   dependency and no `unsafe`: take the `String`'s bytes with `into_bytes`,
   `clear`, `resize(capacity, 0)`, then `black_box` the vector before it drops.
   Measured as the scratch `fill-only` variant: the canary counts were **0** in
   every scenario above on this toolchain and target, and the native cost was
   within 0.3 % of the feature off (0.9974 to 1.0016 of off), because it
   compiles to a vectorized `memset`. But `black_box` is documented as a
   best-effort hint, not a guarantee, and a later compiler or another target
   may remove the store as a dead store before the free. Under the #1079
   vocabulary ("a write the optimizer cannot remove") it is not zeroization,
   and a build that uses it may not make the claim.

So the trade is concrete: `zeroize` pays about 5 % for a documented
guarantee and one more dependency with `unsafe` inside; the safe fill is free
and gives no guarantee. The prototype shows the wipe-on-grow and
wipe-at-terminal structure works with either, so the choice is reversible: a
follow-up can switch the body of one helper. It is a legitimate alternative if
a maintainer would rather ship a hygiene measure that cannot be claimed than a
dependency.

## Prototype shape

The entire mechanism is one helper and one type. Reproduced in part so the
record does not depend on an unpushed branch.

```rust
// plaintext.rs (crate-private). With the feature off, PlainBuf has no Drop.
pub(crate) fn wipe_string(text: &mut String) {
    #[cfg(test)] probe::note(text.capacity());      // counts, never reads memory
    text.zeroize();                                   // length 0, whole capacity
}

impl PlainBuf {
    pub(crate) fn push_str(&mut self, piece: &str) {
        #[cfg(feature = "memory-hygiene")]
        {
            let needed = self.0.len().saturating_add(piece.len());
            if needed > self.0.capacity() {
                let capacity = needed.max(self.0.capacity().saturating_mul(2)).max(8);
                let mut next = String::with_capacity(capacity);
                next.push_str(&self.0);
                wipe_string(&mut self.0);             // the old allocation, before it is freed
                self.0 = next;
            }
        }
        self.0.push_str(piece);
    }
    pub(crate) fn release(&mut self) { wipe_string(&mut self.0); self.0 = String::new(); }
}
#[cfg(feature = "memory-hygiene")]
impl Drop for PlainBuf { fn drop(&mut self) { wipe_string(&mut self.0); } }
```

In `incremental.rs`, `retained: PlainBuf`, `scanned: Option<PlainBuf>`;
`discard_retained` calls `retained.release()` and `reset_unit_state` releases
`scanned`; the flush builds the new tail with `PlainBuf::copy_of`, and
assigning it drops, and so wipes, the old buffer. In `normalize.rs`, a feature
gated `Drop for NormalizedInput` wipes an owned `Cow`, and `into_text`, which
would move the text out of a type with `Drop`, is replaced by holding the view
and reading `text()` and `is_owned()` at its five call sites. The diff is about
700 lines including the ten tests and the scratch canary example.

## Policy conflict and the ADR it needs

**A core Cargo feature contradicts accepted policy.**
`decision-define-detector-profile-and-pack-contract` says the core "keeps its
policy of **no Cargo features**" and rejects core features because Cargo
unifies them and they "only add". `docs/rust-workspace.md` ("No runtime I/O",
manifest shape) and check 8 of `scripts/check-rust-workspace.py` enforce it,
as shown by the two errors above. That rule exists so one dependent cannot
change what detection another dependent gets. It does not bite here, because
this feature cannot change detection or output, only add wiping; that is an
argument for an exception, not a reason the rule does not exist.

**Whether a new ADR is required:** yes if the feature is adopted, and not
before. The artifact-taxonomy decision reserves a new ADR for new policy, a new
trade-off, or a precedent that spans families. This is all three: it amends an
accepted workspace rule, it is the first optional dependency and the first
feature in the core, and it sets the precedent for any later hardening
feature. It is also not a spec-table row, because no current spec rule covers
it. This record does **not** add the ADR: adopting the feature is a maintainer
ruling (the same way T1 rulings are), and an `accepted` ADR written before that
ruling would misstate the state of the project. Its proposed text is for the #1080
thread, where the issue drafts of the 1079 record also live, and lists: the amended rule (the core
may declare exactly one named optional dependency and the feature that enables
it, `zeroize` and `memory-hygiene`, checked by name in check 8); the
unification argument above; the contract wording the feature permits; the
rejected alternatives (unconditional dependency, `Zeroizing` only, safe fill,
`secrecy`, protected memory); and the requirement that no published artifact
enable the feature until a release-shape ruling says so.

## Findings and follow-ups

| ID | Finding | Direction |
| --- | --- | --- |
| Z1 | Adoption needs an ADR amending the no-core-features rule and a change to `check_core_manifest` to allow one named feature and dependency | Maintainer ruling, then the ADR |
| Z2 | The implementation: `PlainBuf`, the `NormalizedInput` `Drop`, the tracker `lookbehind`, `memory-hygiene` feature, allowlist entry, docs, and one test per terminal state | New issue after Z1, tests as in the table above |
| Z3 | The feature does nothing for users unless a build enables it: forward it from `bindings/wasm`, the CLI, and optionally Node and Python as off-by-default features, and rule whether any release artifact ships it | Separate release-shape issue |
| Z4 | Detector temporaries `D1` to `D11` stay outside whatever the feature does | `R2` of the 1079 record: remove copies instead of wiping them |
| Z5 | The `Released.text` output buffer and the WebAssembly incremental result clones are caller-visible and stay outside | `R5` and `R6` of the 1079 record |
| Z6 | A maintainer-local canary allocator harness, outside `src` | The 1079 "proposed" item, now with a working sketch |

## What this record does not establish

- That any byte was erased in any process other than the canary runs, on any
  allocator other than the system allocator on `aarch64-apple-darwin`.
- Anything about Linux or Windows native builds, Node or Python builds with
  the feature, or a 1.88 toolchain.
- Statistically significant wall-clock cost. The machine was too loaded; the
  conclusions rest on instruction counts.
- That `zeroize`'s guarantee holds for a future release of the crate. The
  dependency is pinned with `=` and a bump is a reviewed change.
- That a Rust `String` capacity wipe covers memory an allocator returned with
  more room than requested (`capacity()` is what the crate zeroes).
