# Evidence: #986, open-construct checks without rescanning the retained unit

**Result:** an incremental session no longer takes quadratic time when an
open contextual assignment or `Authorization` header is followed by
whitespace-only lines. `API_KEY=` followed by 40,000 lines of eight spaces
drops from 8.8 s to 43 ms. Output is byte-identical on every workload
measured, and the full test suite passes unchanged.

Issue [#986](https://github.com/redact-secret/redact-secret/issues/986),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The research comment on #986 set the scope this change implements.

## What was quadratic

`IncrementalSanitizer::append` asks `has_open_single_line_construct` after
every closed line whose unit is not inside a private-key block. On `main`
(`04b3e212`) that call:

1. rebuilt the scan copy of the whole retained unit
   (`NormalizedInput::new(&self.retained)`), a full pass, plus a full copy
   when the unit holds non-ASCII text;
2. ran `has_open_contextual_assignment` and `has_open_bearer_authorization`,
   which skip all trailing whitespace backward, including every blank line
   since the construct opened;
3. ran the Heroku, Twilio and Confluent lookback checks, which read only the
   last few lines (`rsplit('\n').take(k)`) and were already bounded;
4. looked up each of those three detector ids in the registry, a linear scan
   over about 92 ids.

An open assignment stays open across whitespace-only lines, so steps 1 and 2
grow with the unit, and the session cost grows with the square of the
retained unit. The only bound is `max_token_bytes`, which is 1 MiB in the
CLI.

## What changed

- **The scan copy is maintained as pieces arrive.** `append_retained`
  already normalized each piece for the private-key tracker. The session now
  keeps that result. While no piece of the unit has lost an invisible code
  point, the scan copy is `retained` itself and nothing is copied. After the
  first piece that did, a separate copy is kept and appended to. Normalization
  removes code points one at a time and never removes ASCII, `\n` or `\r`, so
  normalizing piece by piece equals normalizing the unit.
- **The two tail checks are cached.** Both checks skip trailing
  `is_js_whitespace` and read only what precedes it, so appending
  whitespace cannot change either result (`is_open_tail_neutral` in
  `detectors/mod.rs`). The session stores their combined result and the
  scan-copy length it covered. It recomputes the result only when the text
  appended since then has other content. A recomputation stops at the last
  non-whitespace character, which is in the new text, except that after an
  `=` or `:` it crosses one gap back to the name. Each gap is therefore
  crossed a bounded number of times, and the total is linear.
- **The three lookback checks run as before.** They are already bounded.
- **The registry lookups happen once, at construction.** The registry does
  not change after that.
- **All cached state resets with the unit.** `discard_retained` runs on every
  unit boundary, failure and abort, and now clears the scan copy and the tail
  cache along with the private-key tracker. `assert_nothing_retained` checks
  both.

`generic_token.rs` and `bearer_token.rs` are unchanged.

## Differential test

In test builds, `has_open_single_line_construct` also computes the result the
old way: it renormalizes the whole unit and reruns all five checks. It
asserts that the maintained scan copy, the cached tail result and the final
answer are all equal to that reference. This runs after every closed line of
every crate unit test that drives a session. Two new unit tests drive it
specifically:

- `the_maintained_open_construct_state_matches_a_rescan_over_generated_inputs`:
  300 deterministic pseudo-random sequences built from the pieces the five
  checks react to:
  - names, operators and quotes;
  - `Authorization` variants and `bearer`;
  - Heroku, Twilio, Confluent and PEM layout lines;
  - every whitespace kind the tail checks skip, and invisible code points.

  Each sequence runs whole, one character per chunk, and at every two-chunk
  split, under `full` and `pii:global`. Every partition must also reproduce
  the one-chunk output.
- `the_maintained_open_construct_state_matches_a_rescan_across_whitespace_gaps`:
  assignments, `:=` and quoted JSON names, `Authorization` headers, and the
  Heroku, Twilio, Confluent and PEM layouts, separated by gaps of blank
  lines, space lines, `\r\n` with tabs, U+2028/U+FEFF/U+00A0, and U+200B.
  U+200B makes the scan copy diverge in the middle of the unit.

The core's source check (`scripts/check-rust-workspace.py`) forbids
`include_str!` anywhere under `src/`. That rules out reading
`conformance/fixtures/incremental-corpus.json` from a unit test, so the
rescan assertion cannot run over the corpus directly. The corpus still
exercises the cached state through the public API:

- `tests/incremental_partitions.rs` compares every UTF-8 and `&str` partition
  with the whole-input reference.
- `tests/incremental_batching.rs` (#985) compares chunked runs with one line
  per `append`.

**Mutation checks.** Treating `=` as tail-neutral fails both unit tests at
the `cached tail checks` assertion. Treating `:` as tail-neutral fails the
generated-input test.

`tests/adversarial_bounds.rs` gains
`whitespace_lines_after_an_open_assignment_stay_linear_in_a_session`:
`API_KEY=` followed by 40,000 blank lines and by 40,000 eight-space lines,
in 64 KiB and 1 KiB chunks. Each session must match the whole-input
reference within a declared 500 ms. Like the rest of that file, the budget
is multiplied by 32 in an unoptimized build and the test runs under the
file's timing lock. On `04b3e212` the release build fails it on the first
case (721 ms, blank lines). With this change the whole test takes 0.14 s in
release and 1.7 s in debug.

## Numbers

**Host:** Apple M4, macOS, `rustc 1.98.1`, release profile. The host was
not idle.

**Method:** a throwaway probe binary (not committed) that depends on the
crate by path, built once against `04b3e212` and once against this branch.
It runs one `IncrementalSanitizer` over the workload in 64 KiB `append`
calls and then `finalize`. Limits are large enough that nothing trips
(`max_token_bytes` 16 MiB). It prints the median of 3 or 5 runs and a hash of
the concatenated text and findings. The hashes are identical between the two
builds for every row.

| Workload | Bytes | `04b3e212` median | This change median |
| --- | ---: | ---: | ---: |
| `API_KEY=` + 10,000 blank lines | 10 KB | 39.8 ms | 4.3 ms |
| `API_KEY=` + 80,000 blank lines | 80 KB | 2,706 ms | 36.6 ms |
| `API_KEY=` + 10,000 eight-space lines | 90 KB | 740 ms | 9.8 ms |
| `API_KEY=` + 40,000 eight-space lines | 360 KB | 8,840 ms (1 run) | 43.1 ms |
| `API_KEY=` + 10,000 `\r`-terminated space lines | 90 KB | 551 ms (1 run) | 7.7 ms |

Controls, where the construct closes on every line, are unchanged within the
noise of this loaded host. Interleaved runs gave 171/179 ms (base) against
182/176 ms (change) for 10,000 log lines (906 KB, one line in 50 carrying an
assignment), and 474/435 ms against 479/420 ms for 10,000 dense `pii:global`
lines (1.0 MB). Those units are one line long, so the whole-unit pass that
was removed was already cheap on them.

**#981 harness.** On `open-assignment-whitespace-10k` (`API_KEY=` then
10,000 lines of eight spaces, incremental in 64 KiB chunks), `main` plus the
harness (`5c814dc9`) takes 440 ms, and this change 7.8 ms. The whole-input
scan of the same bytes takes 6.2-6.5 ms in both. These are medians of three
interleaved rounds of 11 runs on the same host. The method and the other
workloads are in [#985's evidence](../985/README.md#numbers). None of those
other workloads moved with this change, because their units close on every
line.
