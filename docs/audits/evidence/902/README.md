# Evidence: #902, linear PII context association

**Result:** PII context association no longer grows faster than linearly
with the number of PII candidates. On the benchmarks `validator-heavy`
workload (94,720 bytes, `pii:global`) a whole-input scan goes from 164 ms to
6.6 ms, and each doubling of the input now doubles the time instead of
multiplying it by about 3.7. On one line of PII records the old code took
21 s for 125 records; the new code takes 1.4 ms for them and 22 ms for
2,000. Findings, ranges, ids, actions and redacted text are byte-identical,
no dependency was added, and nothing public changed.

Issue [#902](https://github.com/redact-secret/redact-secret/issues/902),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The #985 record [names this cost](../985/README.md) as the reason the
incremental session runs PII per unit. Base: `main` at `8f97f14d`, which
includes #985 and #990.

## Cause, confirmed

The issue named two causes. Both were present, and a third one mattered
most on multi-line input. All three were in `context_matches` in
`crates/secret-scan-core/src/pii.rs`, which ran once per candidate:

1. **Line bounds from offset 0.** `logical_line_bounds` walked every
   character from the start of the input to the candidate to find its line
   start. That is O(k·n) per call for k candidates in n bytes, and it
   dominated multi-line input.
2. **Candidate-by-candidate rescans.** The before and after barriers
   compared the candidate with every other candidate (O(k²) per call). For
   every context label that passed the distance limits,
   `equidistant_from_candidates` built a set of every candidate range and
   renormalized the line from its start up to each candidate on the line.
   On one line that is O(k) labels × O(k) candidates × O(line) text, so
   125 records on one line took 21 s.
3. **Static vocabulary renormalized per candidate.** Every `(entry, form)`
   pair went through `normalize_context` (an allocation and an NFC pass) for
   every candidate. This is a constant factor per candidate, not a
   quadratic.

A macOS `sample` of the old probe on `validator-heavy` (8,192 lines) put
2,905 of about 3,300 samples in `PiiDomain::detect` itself, with the three
loops inlined into it, and only 39 in the out-of-line `normalize_context`.
Ablation builds of the old code, `validator-heavy` 4,096 lines, `pii:global`,
whole input, two interleaved rounds on a loaded host (medians of 7, ms):

| Build | Round 1 | Round 2 |
| --- | ---: | ---: |
| old | 333.3 | 235.2 |
| old + vocabulary normalized once per call | 280.6 | 215.0 |
| old + line bounds from a per-call break index | 84.0 | 64.6 |
| new | 9.2 | 7.9 |

The line index removes about three quarters of the multi-line cost. The
barriers and equidistance rescans account for most of the rest. Normalizing
the vocabulary once per call helps a little whole-input but makes the
incremental path about three times slower (23 ms to 64-78 ms), because that
path calls PII once per line. That is why the vocabulary is normalized when
the adapter is built instead.

## What changed

File references are to `crates/secret-scan-core/src/pii.rs`.

- **Vocabulary normalized once.** `ContextVocabulary::new` runs every form
  of the generated `pii-context/v2` table through `normalize_context` and
  records its scalar count. `PiiDomain::new` builds it once per adapter, so
  a registry or an incremental session pays for it once. The generated
  table and its generator are unchanged.
- **Line bounds by binary search.** `LogicalLines` records every logical
  line break once per call. A candidate's bounds are two `partition_point`
  lookups with the same rule as before: from just after the last break
  that starts before the range to the first break at or after its end.
- **Barriers by binary search.** Candidate starts and ends are sorted once.
  The before barrier is the largest other end at or before the candidate's
  start, and the after barrier is the smallest other start at or after its
  end, each clamped to the line as before.
- **Line offsets in one pass.** Candidates are grouped by
  `(line start, line end)`. For each group, every offset the rules need (the
  barriers, the candidate ends and the start of every range on the line) is
  computed in one forward pass over the line (`LineOffsets`). The pass
  keeps the running state of `normalize_context` (`ContextScalars`) and
  commits it only at a character NFC never joins with what comes before:
  an ASCII scalar or a precomposed Hangul syllable
  (`starts_normalization_segment`). No canonical composition takes either
  as its second element, and canonical reordering never moves a mark across
  a starter, so NFC of the text splits there. Governed invisible code points
  are never ASCII or Hangul syllables, so removing them first does not move
  a split. Each offset is therefore exactly
  `normalize_context(&line[..x]).chars().count()`, as before.
- **Equidistance in O(log k).** `LineOccurrences` keeps each distinct range
  on the line once (issue #922) as `(end, start)` in view coordinates,
  sorted by end, with the two smallest starts of every suffix. Only the two
  nearest candidates on each side can make the minimum distance tie, so a
  label is equidistant exactly when two of those at most four distances are
  equal and smallest. A field label skips candidates that end before it,
  as before (issue #924).
- **Match positions counted forward.** Within one view, matches arrive in
  position order, so the scalar count before each match is carried forward
  instead of recounted from the view's start.
- **Candidate lookup by binary search.** `contextualized` finds each
  alternative's context by `binary_search` in the sorted, distinct candidate
  list instead of a linear `position`.

Unchanged: the forward-only field labels, the 16- and 64-scalar distance
limits, the word boundaries and the positive field-label `|` delimiter
(issues #940 and #943), the ASCII case folding of every language (issue
#927), the English and Korean vocabulary, the occurrence sort and overlap
acceptance, and every family's detection. `normalize_context` itself is
unchanged except that its invisible and separator tests are now named
functions shared with `ContextScalars`.

## Equivalence

`src/pii/context_association_tests.rs` keeps the pre-#902 functions
verbatim in an `oracle` module (`normalize_context`, `context_matches`,
`logical_line_bounds`, `equidistant_from_candidates` and their helpers) and
the pre-#902 `contextualized` next to it. The tests require the new result
to equal the oracle's:

- **PII conformance corpus.** Every `input` of the seven PII conformance
  fixtures (`pii-cross-family`, `pii-email`, `pii-iban`,
  `pii-network-address`, `pii-payment-card`, `pii-phone`, `pii-us-ssn`),
  on the raw text and on the scan copy with invisible code points removed.
  The candidate lists are the ones the adapter builds (distinct established
  alternatives) and, as a stress case, every alternative of every family.
  The fixtures are included by
  `crates/secret-scan-core/tests/fixture_texts/pii_conformance.rs`, a
  `#[cfg(test)]` module outside `src/`, because a file under `src/` may not
  name `include_str!` (`scripts/check-rust-workspace.py`).
- **Identity-evaluation path.** The full `contextualized` output (identity,
  sensitivity, confidences, specificities, obfuscation) of the all-family
  domain and of each family's `IdentityEvaluator` domain, compared as their
  `Debug` text, on the same inputs. This is the join
  `examples/pii_identity_evaluation.rs` reads.
- **Joined fixtures.** The same inputs joined eight at a time with a space,
  `\n`, ` | ` and `\r\n`, so candidates of different cases share a line or
  sit on neighbouring ones.
- **Generated corpus.** 3,000 deterministic texts (xorshift64*) built from
  vocabulary forms in random ASCII case with `_`, `-`, doubled-space and
  zero-width separators, synthetic documentation values, joiners (`=`,
  `: `, `|`, quotes, tab, NBSP, ideographic space), every logical line
  break, combining marks, conjoining jamo, Hangul fillers, variation
  selectors, compatibility and singleton decompositions. Each text runs
  with the adapter's candidate lists and with up to ten random ranges
  (overlapping, spanning line breaks, the same range under two identity
  domains), in order and reversed. More than 1,500 of the candidates
  associate with at least one entry.
- **Offsets.** `LineOffsets` equals `normalize_context(&text[..x])`'s
  scalar count at every character boundary of 500 generated texts.

Two mutations were checked: counting a natural-language label as never
equidistant fails three of the four tests, and treating U+0300-U+036F as a
normalization split fails the offsets test.

`tests/adversarial_bounds.rs`
`many_pii_candidates_on_one_line_associate_context_in_linear_time` scans 700
records (65 KB, one line, one CLI read and one incremental unit) under
`pii:global` and `pii:us`, whole-input and in a 64 KiB session, against the
file's usual 500 ms budget (×32 unoptimized) and pins the 700 findings.
It takes about 30 ms optimized and under 1 s unoptimized for all four
scans. The old code took 21 s optimized for 125 of these records.

## Measurements

Host: Apple M4, macOS 26.5.2, `rustc 1.98.1`, release profile. The #981
harness has no PII workload and builds only the built-in registry, so a
throwaway probe example (never committed) timed the public
`scan_and_redact` with `DetectorRegistry::with_built_in_and_pii`, and an
`IncrementalSanitizer::with_built_in_and_pii` session fed in 64 KiB chunks
with the CLI's 1 MiB token and multiline limits. Each figure is the median
of 11 runs after one warm-up. The old and new binaries ran interleaved,
three rounds; the table shows the range of the round medians. Each
workload's output text and findings hashed identically in both builds.

**`validator-heavy`** is the eight lines of `redact-secret-benchmarks`
`qualification/pii-profile-cost-workloads-v1.json` (`client_ip=192.0.2.1`,
`email=test@example.com`, `payment_card=4111111111111111`,
`iban=GB82WEST12345698765432`, `ssn=890-62-6879`, `phone=+1 202-555-0142`,
`payment_card=4111111111111112`, `ssn=000-00-0000`) repeated to N lines,
LF-separated. 4,096 lines is that file's own size (94,720 bytes).

| Selector | Lines | Whole, old | Whole, new | Incremental, old | Incremental, new |
| --- | ---: | ---: | ---: | ---: | ---: |
| `pii:global` | 1,024 | 12.7-13.0 | 1.64-1.67 | 3.8 | 2.3 |
| `pii:global` | 2,048 | 44.1-44.4 | 3.30-3.32 | 7.5-7.8 | 4.5-4.6 |
| `pii:global` | 4,096 | 164.1-165.1 | 6.55-7.43 | 14.9-15.0 | 8.9-10.2 |
| `pii:global` | 8,192 | 634-651 | 13.2-13.4 | 30-39 | 17.8-17.9 |
| `pii:us` | 1,024 | 17.0-24.1 | 1.98-2.02 | 4.7-6.1 | 2.7-2.8 |
| `pii:us` | 2,048 | 57.8-82.3 | 3.96-4.18 | 9.3-11.5 | 5.3-5.4 |
| `pii:us` | 4,096 | 213.7-346.1 | 7.93-8.10 | 18.7-26.7 | 10.6-10.8 |
| `pii:us` | 8,192 | 820-840 | 16.1-16.2 | 37.7-37.8 | 21.4-21.7 |

Milliseconds. Whole-input, old, grows 3.4x, 3.7x and 3.9x per doubling
under `pii:global`; new grows 2.0x each time. The incremental path was
already near linear because it runs PII once per line (#985), and still
takes 30-50% less time, mostly from normalizing the vocabulary once.

**One line of records.** `client_ip=192.0.2.1 email=test@example.com
iban=GB82WEST12345698765432 card 4111111111111111 ` repeated N times, then
`\n`. Every record yields one finding (the IBAN); the address, reserved
domain and test card are established but suppressed, so all four reach
context association.

| Selector | Records | Bytes | Whole, old | Whole, new | Incremental, old | Incremental, new |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `pii:global` | 125 | 11,626 | 21,114 | 1.44 | 21,771 | 1.54 |
| `pii:global` | 500 | 46,501 | not run | 5.81 | not run | 6.12 |
| `pii:global` | 2,000 | 186,001 | not run | 22.3 | not run | 23.4 |
| `pii:us` | 125 | 11,626 | 21,138 | 1.38 | 28,255 | 1.48 |
| `pii:us` | 2,000 | 186,001 | not run | 22.5 | not run | 23.6 |

The old figures are single runs. The old code was not run at 500 records
or more: its cost grows faster than k² there, so it would take hours.

## Left out

- The email family's `is_email_label_key` (`pii/pii_email.rs`) still
  normalizes its at most seven email label forms when a local part holds a
  `=` or `|`. That is a constant per such candidate, not a rescan.
- The incremental session still runs PII once per unit (#985). With the
  association linear, PII could join the batch; that is a separate change
  to the batching contract and is not made here.
