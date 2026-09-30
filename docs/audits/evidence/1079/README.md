# Evidence: #1079, where plaintext can exist in the core and its hosts

**Result:** every owned buffer that can hold input-derived text in
`crates/secret-scan-core` is inventoried below with its owner, its lifetime and
its release point on success, error, abort, finalize and drop. Two buffers
are required retention (the incremental `retained` and `scanned`). One is a
required normalized copy (the whole-input scan copy). The rest are
transients, and the audit found the avoidable or reducible copies listed
under [Findings](#findings). No current behavior contradicts the retention claims the
[plaintext lifetime note](../../../reference/plaintext-lifetime.md) makes.
Every current release is an ordinary deallocation: no buffer is overwritten
before it is freed anywhere in the core, the bindings or the CLI, and this
record makes no claim that it is.

Issue [#1079](https://github.com/redact-secret/redact-secret/issues/1079).
The contract this evidence supports is
[`decision-define-the-plaintext-memory-lifetime-contract`](../../../decisions/2026-09-30-define-the-plaintext-memory-lifetime-contract.md).
It feeds the zeroization design in
[#1080](https://github.com/redact-secret/redact-secret/issues/1080).

Read at `origin/main` `f4618965` (after #1076 and #1077 landed in #1081).
Line numbers below are at that revision. The only edit this change makes to a
cited file adds test code below the cited production lines (`incremental.rs`
test module), so every cited line is unchanged.

## Method and limits

Code read through `graft` and direct reads at the cited spans. Counts of
owned-copy sites in detectors come from a textual sweep of non-test code for
`to_ascii_lowercase`, `to_lowercase`, `to_owned`, `to_string`, `format!`,
`String::with_capacity`, `String::new`, `concat`, `collect::<String>`,
`into_owned` and `to_vec`, each hit then read in context. The sweep finds
copies written in source; it cannot see copies made inside `std`, the allocator,
`wasm-bindgen`, `napi`, `pyo3` or the host runtime beyond what their public
behavior documents. No allocator instrumentation or memory dump was used, so
every statement is about ownership and control flow, never about the
contents of freed memory.

Terms used below:

- **released** or **discarded**: the core no longer owns or references the
  buffer. The allocation went back to the allocator (or the value was dropped).
- **zeroized**: bytes were explicitly overwritten by a primitive the optimizer
  cannot remove. Nothing in the core does this today.

## Buffer classes

| Class | Meaning |
| --- | --- |
| **Borrowed** | caller memory the core reads through `&str`. The core cannot wipe it or shorten its life. |
| **Required owned** | an owned copy the detection contract cannot avoid. |
| **Normalized copy** | a derived copy with governed invisible code points removed. |
| **Avoidable** | an owned copy a borrowed view or an allocation-free comparison would replace. |
| **Output** | caller-visible sanitized text. Under `warn` and `allow` it can still hold the detected value. |
| **Derived summary** | offsets, bitsets or counts computed from plaintext that hold no text. |

## Whole-input path: `scan`, `redact`, `scan_and_redact`

Entry points: `scan_with_limits` (`pipeline.rs:693-714`),
`redact_with_limits` (`redact.rs:222-271`), `scan_and_redact_with_limits`
(`pipeline.rs:774-784`), which is a `scan` followed by a `redact`.

| ID | Buffer | Where | Class | Owner, lifetime and release |
| --- | --- | --- | --- | --- |
| W1 | `input: &str` | `pipeline.rs:693`, `redact.rs:222` | Borrowed | Caller. The core never copies it whole except as W2. Released by the caller, on the caller's schedule. |
| W2 | `NormalizedInput.text`, `Cow::Owned(String)` | `normalize.rs:51-56`, built at `normalize.rs:58-110`, used at `pipeline.rs:544-545` | Normalized copy | Created only for non-ASCII input that holds a governed invisible code point (`normalize.rs:67-74`); otherwise `Cow::Borrowed` and no allocation. One allocation of `input.len()` bytes up front (`normalize.rs:79`), so it never reallocates and leaves no earlier copy. Owned by the local `normalized` in `detect_units`, dropped when `detect_units` returns or returns early through `?` (`pipeline.rs:558`, `:599`, `:643`). Plain deallocation. |
| W3 | `seams: Vec<Seam>` | `normalize.rs:36-43`, `:55` | Derived summary | Offsets only. Same owner and release as W2. |
| W4 | Thread-local `ActiveScan`: address and length, a byte-pair bitset, long-run line ranges | `detectors/prefilter.rs:407-459`, entered at `pipeline.rs:191` | Derived summary | Holds an address as `usize`, a lossy presence bitset and ranges, never text. `ScanScope::drop` restores the previous value (`prefilter.rs:450-458`). Nothing persists across scans. |
| W5 | `per_detector: Vec<Vec<Candidate>>` | `pipeline.rs:187`, `types.rs:312-321` | Derived summary | A `Candidate` holds a type id, confidence, range and `signals: Vec<String>`. The pipeline rejects a candidate whose matched text equals its type or detector id (`pipeline.rs:106-115`). Built-in detectors set only fixed signal strings (sweep of `with_signals`, `types.rs:366`). A custom `Detector` can put any text in a signal, which is that author's decision. Dropped at the end of `detect_units`. |
| W6 | `ranked`, `accepted`, `DetectedFinding`, `Finding` | `pipeline.rs:560-645`, `types.rs:464-472`, `:579-583` | Derived summary | Ids, type names, ranges and actions. No matched text by construction. Returned to the caller. |
| W7 | `ForbiddenMatchedText.values: Vec<&str>` | `redact.rs:66-85`, built at `redact.rs:231` | Borrowed | Re-verified after #1076 (#1081): the values are borrowed slices of `input` (`redact.rs:75-80`), sorted and deduplicated. No matched text is copied. The `Vec` holds pointers and lengths and is dropped when `redact_with_limits` returns. |
| W8 | `placeholders: Vec<String>` | `redact.rs:236-254` | Output | Formatter output, at most 256 bytes each (`redact.rs:15`), checked not to reproduce any finding's matched text (`redact.rs:246-251`). Dropped on return. |
| W9 | `output: String` | `redact.rs:257-270` | Output | Allocated once at exactly the final size, so it never reallocates. Moved to the caller inside `ScanResult` (`types.rs:681-691`). Under `warn` and `allow` it keeps the detected value. The caller owns it from then on. |
| W10 | Shadow comparisons | `pipeline.rs:616-628`, `evidence/shadow.rs:139-145` | Borrowed | Computed only when a caller passes `Some`. Every public entry passes `None` (`pipeline.rs:497`); the session records them under `cfg(test)` (`incremental.rs:581-582`), and the maintainer-local `examples/shadow_evaluation.rs` compiles the core source as its own crate. The matched value is passed as `&str`. |
| W11 | Statics: registry prefilters, PII vocabulary, email forms | `registry.rs:187`, `:228`, `pii.rs:888`, `pii/pii_email.rs:142` | Derived summary | Constant tables built from detector definitions, not from input. |

The core keeps no cache, `static` or `thread_local` that retains input text
(sweep of `thread_local`, `OnceLock`, `LazyLock`, `Rc`, `RefCell`).

### Detector temporaries (whole-input and incremental)

Each is a stack-scoped owned copy made inside one detector call and dropped
when that function returns, on success and on every early return. None is
retained or returned. All are plain deallocation. D1 to D5 copy a candidate
value, a whole line or a call chain, D6 copies a credential name, and D7 to D11
are in the PII code.

| ID | Site | What is copied | Class |
| --- | --- | --- | --- |
| D1 | `detectors/generic_token.rs:232`, `:1521`, `:1664`, `:1884` | ASCII-lowercased candidate value (or a segment of it) for placeholder and masking checks | Avoidable: an allocation-free case-insensitive comparison gives the same result |
| D2 | `detectors/connection_string.rs:298-302` | ASCII-lowercased connection-string password value, plus a `Vec<&str>` of borrowed tokens | Avoidable |
| D3 | `detectors/keyword_gated_keys.rs:434`, `:452`, `:509` | ASCII-lowercased whole line (may contain the credential) | Avoidable |
| D4 | `detectors/keyword_gated_keys.rs:324`, `:475` | lowercased callee name, and a lowercased window of up to `HEADER_WINDOW` bytes before a value | Avoidable |
| D5 | `detectors/keyword_gated_keys.rs:405-422` | `pieces.concat()` of an SDK call chain | Reducible |
| D6 | `detectors/aws.rs:141`, `detectors/confluent.rs:291`, `detectors/generic_token.rs:392` | lowercased or normalized credential name, not the value | Avoidable, low sensitivity |
| D7 | `pii.rs:743-776`, called at `:1092-1161` | NFC, case-folded owned copy of the text windows around a PII candidate, which can include neighboring secrets | Normalized copy (required by the context contract) |
| D8 | `pii/pii_payment_card.rs:124-150` | digits of a payment card display in a `String` | Avoidable: a fixed-size array would do |
| D9 | `pii/pii_email.rs:331` | lowercased email domain | Avoidable, low |
| D10 | `detectors/private_key.rs:306` | `[lookbehind, piece].concat()`, which copies the whole piece, in the retention tracker | Avoidable: only the join needs scanning |
| D11 | `pii.rs:636` | a second `NormalizedInput` of the whole input | Normalized copy, maintainer-local only: `IdentityOutcome` is `pub(crate)` with no caller on a public path |

## Incremental path: `IncrementalSanitizer`

Fields at `incremental.rs:538-593`. Lifecycle: `append` (`:1337-1381`),
`finalize` (`:1392-1404`), `abort` (`:1412-1417`). The session has no `Drop`
implementation (sweep of `impl Drop` in non-test code: only `ScanScope`,
`detectors/prefilter.rs:450`), so dropping it drops its fields.

| ID | Buffer | Where | Class | Owner, lifetime and release |
| --- | --- | --- | --- | --- |
| I1 | `chunk: &str` | `append` argument | Borrowed | Caller. |
| I2 | `retained: String` | `incremental.rs:548`, pushed at `:1001` | Required owned | Session. Holds, in order, the optional lead (I5), the closed units waiting in the batch, and the current unit. Bounded: the current unit by `max_token_bytes` or `max_multiline_bytes` and `max_buffered_bytes` (`:1010-1031`), the batch by `max_buffered_bytes` (`:978-983`). Grows by `push_str`, so it reallocates by doubling and each earlier allocation is freed without being cleared. After each flush the buffer is replaced by a fresh copy of only the open tail (`:1185-1189`), so the allocation holding every released unit, matched values included, is freed un-wiped once per `append` that closes lines. Released by replacement at every terminal transition (`discard_retained`, `:806-812`). |
| I3 | `scanned: Option<String>` | `incremental.rs:563`, built at `:990-1000` | Normalized copy | Session. Exists only after a piece of the current unit lost an invisible code point. Sized `unit.len() + piece.len()` when created, then grown by `push_str`. Cleared with the unit at `close_unit` (`:1051`, via `reset_unit_state` `:816-823`) and at every terminal transition. |
| I4 | `piece` normalization | `incremental.rs:989` | Normalized copy, transient | `NormalizedInput::new(piece).into_text()` per piece: owned only when the piece loses a code point. Dropped at the end of `append_retained`. |
| I5 | Lead: a released line kept in front of `retained` | `incremental.rs:553`, `:1203-1209`, `:1185-1190` | Required owned, retained past release | Kept only while the session runs `aws-secret-access-key` and the line carries an AWS access key ID, because the next unit's detector reads it (#1028, #1040). The line is already in released output (redacted or not, per policy), and a copy stays in the session until the next flush drops it or a terminal transition discards it. Counts toward no limit (`:549-552`). |
| I6 | `unit_ends: Vec<usize>`, `unit_start`, `lead_len`, `aws_held_line`, `open_tail`, `multiline_*`, `finalized_bytes`, counts | `incremental.rs:553-573` | Derived summary | Offsets and flags. `unit_ends` keeps its capacity across a flush (`:1192-1193`), which holds offsets only. |
| I7 | `PrivateKeyRetentionTracker.lookbehind: String` | `detectors/private_key.rs:266-331`, `incremental.rs:574`, `:1006` | Required owned | Holds a suffix of at most `MAX_DELIMITER_LEN - 1` bytes starting at its first `-` (`private_key.rs:321-324`). The suffix is the last bytes of a piece, so it can hold the tail of a key body. Reused in place between pieces. `reset` replaces the whole tracker (`:329-331`), which frees it. |
| I8 | `last_lines` window | `LookbackTail`, `detectors/mod.rs:160-202`, used at `incremental.rs:867-872` | Borrowed | `[&str; MAX_LOOKBACK_LINES]` into `retained` or `scanned`. No copy. |
| I9 | Line-above normalization | `incremental.rs:902`, `:917`, `:1208` | Normalized copy, transient | `NormalizedInput::new(last line).into_text()`, owned only when that line has an invisible code point. Dropped at the end of the call. |
| I10 | `split_off` of the last line | `incremental.rs:915-922` | Avoidable | Copies the last line into a new `String`, then pushes it back. The new `String` is dropped at the end of `split_before_last_line`, on success and on error. Only when a unit is held for an AWS secret-shaped run (#1044). |
| I11 | `Released { text, findings }` | `incremental.rs:339-343`, `:1351`, `:1396` | Output | One per `append` or `finalize` call. `text` starts empty and grows by `push_str`, so it reallocates. Moved to the caller in `IncrementalResult` (`:1380`, `:1403`). On error it is dropped inside the failing call. |
| I12 | Per-unit `redact` result | `incremental.rs:1275-1285` | Output, avoidable duplicate | `redact` returns a fresh `String` copy of the unit, which is then copied again into `released.text`. A unit with no findings skips it (`:1251-1259`). |
| I13 | Detection scan copy for the batch | `detect_units` via `detect_batch` and `detect_after`, `incremental.rs:361-396`, `:1105`, `:1161` | Normalized copy | W2 applied to `retained[..batch_end]` or one unit. Dropped when the call returns. The lead and unit are contiguous, so neither is copied to be scanned (`:354-360`). |

### Terminal transitions and what each releases

`discard_retained` (`incremental.rs:806-812`) assigns `retained = String::new()`
and `unit_ends = Vec::new()`, zeroes `lead_len` and `unit_start`, and calls
`reset_unit_state` (`:816-823`: `scanned = None`, `aws_held_line = None`,
`open_tail` default, `private_key.reset()`, both multiline flags false). It is
called from `fail_with` (`:828-832`), `finalize` (`:1401`) and `abort`
(`:1414`). All of these are assignments that drop the old value: **released,
not overwritten**.

| Transition | What happens to plaintext the session holds | Where | Structural test |
| --- | --- | --- | --- |
| `append` succeeds, lines closed | Closed units are scanned, redacted and emitted, then `retained` is replaced with a copy of only the open tail. The old allocation is freed, un-wiped. | `:1086-1195` | `a_flush_keeps_only_the_open_tail_of_the_buffer` (added), `a_finalized_unit_is_discarded_once_its_offsets_are_recorded` |
| `append` succeeds, nothing closed | Nothing released. `retained` and `scanned` grow. | `:971-1037` | existing |
| Limit failure (input, buffer, token, multiline) | `fail_with` discards, state `Failed`. | `:1345`, `:1033-1034`, `:981-982` | `a_limit_failure_discards_the_construct_that_reached_it`, `an_input_limit_failure_discards_everything_retained_so_far` |
| Policy, formatter or placeholder failure while finalizing a unit | `fail_with` at the `append` or `finalize` call site. A `Released` built so far is dropped. | `:1378-1379`, `:1399-1400`, `:1366-1367`, `:1371` | `a_policy_failure_discards_the_unit_it_was_evaluating`, `a_formatter_failure_…`, `an_invalid_placeholder_…`, `a_failure_while_finalizing_discards_the_last_unit` (added) |
| Wrong state | Returns `InvalidState` without touching state or buffers (they are already empty in a terminal state). | `:793-799` | `a_state_failure_leaves_nothing_retained_to_discard` |
| `finalize` succeeds | Last unit emitted, then `discard_retained`, state `Finalized`. | `:1392-1404` | `finalize_discards_what_it_resolves_and_what_was_derived_from_it` (added) |
| `abort` | `discard_retained`, state `Aborted`, nothing emitted. | `:1412-1417` | `abort_discards_an_open_construct`, `abort_discards_an_open_private_key_block` |
| Terminal with a normalized `scanned` or a lead | Both cleared with the rest. | `:806-823` | `a_terminal_transition_discards_the_normalized_scan_copy`, `the_released_line_kept_as_a_lead_is_discarded_on_every_terminal_transition` (added) |
| Drop while `accepting` | No `Drop` body. Fields drop: `retained`, `scanned`, `unit_ends` and the tracker are deallocated. No buffer is overwritten. No terminal state is entered. | `:538-593` | not testable structurally |
| Panic in a callback or detector | The core has no `catch_unwind` and no guard. The session stays `Accepting` with its buffers until it is dropped or the host aborts it. `clippy::panic` is denied workspace-wide (`Cargo.toml:52`), so this concerns a panic in a host-supplied callback or a dependency. Whether each host catches it was not verified. | `:1337-1381` | not tested |

`Debug` for the session prints only `state` and `limits` (`:595-601`), so
formatting it never prints retained text (`the_debug_representation_never_carries_retained_plaintext`).

## Bindings and CLI, summary level

Not wiped by any of them. What each adds to the core inventory:

| Host | Copies outside the core's ownership | Where |
| --- | --- | --- |
| Node (N-API) | `scan`, `redact`, `scanAndRedact`, `append` take an owned `String` the N-API layer builds from the JS string, dropped when the call returns. Result text is copied into a new JS string. Callbacks get metadata only. `Utf16Index` holds offsets only and is cleared on terminal transitions. | `bindings/node/src/lib.rs:695`, `:766`, `:818`; `incremental.rs:63-121`, `:474-520` |
| WASM | `&str` arguments are the JS string encoded into linear memory by `wasm-bindgen`. Linear memory never shrinks, so a freed buffer keeps its bytes until reused. `scanAndRedact` returns through `takeText` and `free()` since #1077 (no second copy). The **incremental** result still clones `text` and `findings` in its getters, and the TypeScript wrapper never calls `free()` on it. Callbacks get metadata only. | `bindings/wasm/src/lib.rs:223-297`; `result.rs:19-48`; `callbacks.rs:43-99`; `incremental.rs:247-262`, `:381-424`; `packages/javascript/src/runtime/wasm-binding.ts:288-295`, `:333-368` |
| Python (PyO3) | `text` is borrowed from the caller's `str` (`extract_text`, `lib.rs:539-545`); CPython may materialize and cache a UTF-8 copy inside that `str` object for non-ASCII text, owned by the host. Since #1077 the result text is one Python `str` and the Rust `String` is dropped on return (`lib.rs:1310-1315`). Host rejection during `append` aborts the session (`incremental.rs:601-611`), and `__exit__` aborts an accepting session (`:658-672`). Detection runs with the interpreter lock released (`lib.rs:1009-1014`). | as listed |
| CLI | Whole file: `read_file_text` reads into a `Vec<u8>` that grows by doubling, then a `String` with no copy (`input.rs:130-142`, `:114-119`), and `check_file` drops it after the scan (`modes.rs:123-126`). Stream: a reusable read buffer, and `Utf8Stream::push` copies every chunk into an owned `Vec<u8>` and then a `String` (`input.rs:42-61`), dropped after `append` (`modes.rs:213-219`). A failed read, decode or write calls `abort` (`modes.rs:241-244`). Reports carry metadata only. | as listed |

## Findings

What the audit found that a maintainer can act on. Drafts of the issues are in
the #1079 thread, not here, so their numbers can be recorded there.

| ID | Finding | Sites | Direction |
| --- | --- | --- | --- |
| R1 | `ForbiddenMatchedText` copied matched values into owned `String`s | `redact.rs:66-85` | Fixed by #1076 in #1081. Verified borrowed at `f4618965`. |
| R2 | Detectors lowercase whole candidate values and whole lines to compare case-insensitively | D1 to D4, D6, D9 | New issue: allocation-free comparison, byte-identical findings. |
| R3 | The private-key tracker copies the whole piece to scan a junction | D10 | New issue. |
| R4 | The incremental flush frees an un-wiped buffer holding every released unit's plaintext, once per closing `append`, and `retained` and `scanned` reallocate by doubling | I2, I3 | Input to #1080: wipe the old buffer before it is replaced, and pre-size from `max_buffered_bytes`. |
| R5 | `finalize_unit` copies each redacted unit twice, and `Released.text` reallocates | I11, I12 | New issue: write the redaction into the output buffer, pre-size. |
| R6 | WASM incremental results clone text and findings, and the wrapper never frees the handle | `incremental.rs:247-262`, `wasm-binding.ts:288-295` | New issue: the `take*` and `free()` pattern from #1077. |
| R7 | `split_before_last_line` copies and re-appends the last line | I10 | New issue, low priority. |
| R8 | Payment-card display digits and email domain copies | D8, D9 | Fold into R2. |
| R9 | CLI `Utf8Stream::push` copies each chunk twice even with nothing carried | `input.rs:42-61` | New issue, low priority. |
| R10 | Nothing stops a new owned copy of matched plaintext from entering a detector | all of D1 to D11 | The review rule in the ADR. A mechanical check is proposed below. |

## Structural tests and instrumentation

**Existing before this change**: abort of an open construct and of an open
private-key block, limit failures (token, input), policy, formatter and
placeholder failures, wrong-state, and debug output, all asserting `retained`
is empty with zero capacity and `scanned` is `None`
(`incremental.rs` test module, `assert_nothing_retained`).

**Added by this change** (test-only, no production edit, no public API change):

- `assert_nothing_retained` now also checks `lead_len`, `unit_start`,
  `unit_ends` and `aws_held_line`, which the earlier helper did not cover.
- `assert_terminal_state_holds_nothing` adds that `unit_ends` has no allocation.
- `finalize` with an open multiline private-key block and a retained lookbehind;
  the tracker is checked through what it reports (no open block, no `BEGIN`),
  because its fields are private to the detector module. Checking its
  `lookbehind` buffer directly needs a `#[cfg(test)]` accessor in
  `detectors/private_key.rs`, a guarded path for the changelog gate, so it
  needs the `no-changelog` label on its pull request.
- A failure while `finalize` judges the last unit.
- A terminal transition (`abort` and `finalize`) with an owned normalized
  `scanned` copy.
- A terminal transition (`abort` and `finalize`) with a retained lead.
- After a flush, `retained` holds exactly the open tail and no released text.

These tests assert that the session no longer owns the text. They do not
assert, and cannot assert, that the freed bytes were overwritten.

**Proposed, not implemented**:

1. A maintainer-local canary allocator harness (a `GlobalAlloc` wrapper in a
   bench or example, which needs a scoped `unsafe` allowance the core crate
   forbids, so it lives outside `crates/secret-scan-core/src`). It counts, per
   path, how many distinct heap blocks held a synthetic canary at free time.
   That turns "how many plaintext-bearing allocations does a scan make" into a
   number that R2, R3, R5 and R6 can be shown to reduce. It measures copies,
   not erasure.
2. A regression rule, stated in the ADR: a change that adds an owned copy of
   input-derived text in a detector or the pipeline states its rationale in
   the pull request. A mechanical version (a reviewed list of allowed
   `to_ascii_lowercase` and `to_owned` sites, checked in CI like the SAST
   baseline) is a follow-up once R2 leaves a baseline small enough to keep.
3. When #1080 lands a zeroization feature, a test per terminal state with the
   feature on, using the same field checks as above plus a check that the
   buffer was overwritten before release, through whatever hook #1080
   provides.

## What this record does not establish

- What is in freed memory, or in the allocator's free lists, at any point.
- Stack frames, registers and spilled temporaries, which no source-level
  inventory can enumerate.
- The behavior of `napi`, `wasm-bindgen`, `pyo3`, the JavaScript engines and
  CPython beyond their documented copies.
- Panic handling in each host.
- The plaintext that user-supplied policy and formatter callbacks, or custom
  `Detector` implementations, keep: the core passes callbacks metadata only,
  but cannot control what a callback closure captures.
