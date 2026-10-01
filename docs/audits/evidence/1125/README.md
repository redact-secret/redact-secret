# Issue #1125: residual incremental local-view and formatter mapping costs

[Audit archive](../../README.md) ·
[Issue #1125](https://github.com/redact-secret/redact-secret/issues/1125) ·
[Parent #1068](https://github.com/redact-secret/redact-secret/issues/1068) ·
[Built on #1124](../1124/README.md) ·
[Spec: engine](../../../specs/engine.md)

Written 2026-10-01. Base `44382b3f3006a3a34a2bab917711d00e2e53284a`; #1124
at `25b00e2b`. Synthetic data only. No public API, finding id, span, type,
confidence, action, ordering or sanitized-error behavior changed.

## Verdict

| Item in the issue | Verdict |
|---|---|
| 1-2. Drop the unit-local finding list and the per-callback binary search | adopted, by a different mechanism than "an ordinal map" (below) |
| 3. Reusable scratch with a bounded shrink policy | not adopted: nothing left worth reusing (below) |
| 4. Node / WASM / Python conversion timing | not measured; native allocation and instruction counts and WASM size only |
| 5. Huge append with isolated accents | not touched, not measured |

#1124 stands on its own (it was adopted, so the dependency held).

## Mechanism

The issue proposed an ordinal mapping from formatter callback to global
finding. The mapping is not needed. `redact_into` now has a sibling,
`redact_shifted_into(input, findings, shift, placeholders_before, ...)`
(`redact.rs`), over the #1124 ordered view with a `shift`: the view proves
each finding's range, less `shift`, lies in the unit's text on character
boundaries, and exposes unit-local spans. The incremental session passes the
unit's text, the unit's slice of `released.findings` (global ranges), the
unit's global start as `shift` and the placeholders already issued as
`placeholders_before`. The formatter therefore receives the global finding
itself and the logical placeholder number directly, so there is no local
`Vec<Finding>`, no `relocated_without_id` clone (removed from `types.rs`), no
wrapping closure and no binary search. This also answers the warn/allow-gap
caveat: the callback ordinal never has to be translated, because the formatter
is called with the finding, not an index. Placeholder numbering is
`placeholders_before + n` for the n-th replaced finding of the unit,
identical to the old `placeholder_offset + local_index`. The replaced count
now comes back from the redaction instead of a second filter pass over the
unit's findings.

A range that starts below the unit, or that ends past it, is
`InvalidFindings`, as an out-of-range local range was before; the old
`InvalidCandidate` from building a local range cannot occur any more.

## Measurements

Apple silicon, rustc 1.98.0, release, fat LTO, unchanged `Cargo.lock`. Probe:
[`inc_probe.rs.txt`](inc_probe.rs.txt) (copy to
`crates/secret-scan-core/examples/inc_probe.rs`; it reuses the `scan_cost`
workload generators). Session construction is outside the counted window.
Allocation = `GlobalAlloc` alloc plus realloc calls. Instructions =
`/usr/bin/time -l` "instructions retired" minus an empty-run start-up, two
alternating rounds each. "base" is `25b00e2b` (#1124 only); the #1124 change
does not touch these rows' allocations.

| Workload (chunk) | alloc calls base -> new | requested bytes base -> new | instructions base -> new |
|---|---:|---:|---:|
| mixed-10m (64 KiB) | 260,929 -> 250,690 (-3.9%) | 66,814,124 -> 62,554,700 (-6.4%) | 4.1859G / 4.1873G -> 4.1742G / 4.1771G (-0.27%) |
| provider-tables-64k (4 KiB) | 5,434 -> 5,322 (-2.1%) | 754,208 -> 707,616 (-6.2%) | 40.76M / 42.45M -> 41.37M / 42.42M (noise) |
| minified-json-256k (64 KiB) | 3,150 -> 3,143 | 1,660,051 -> 1,607,219 (-3.2%) | 118.5M / 120.1M -> 119.3M / 120.2M (noise) |
| scale-logs-256k (4 KiB, 64 KiB, whole) | unchanged | unchanged | unchanged (few findings) |

Peak live bytes are unchanged on every row. The saving is about one
allocation per finding (about 10,200 findings in `mixed-10m`) and a
proportional copy, worth roughly 0.3% of instructions. Consistent with the
research comment, which warned that removing a container is not automatically
a material latency win (#1095 gave about 1.1% on dense input), this is a
small deterministic reduction and a simplification, not a throughput claim.
Wall-clock was not used: the machine was shared with concurrent builds. The
research row 316 ms whole vs 517 ms incremental is a different fixture and its
gap is detection, not redaction; nothing here closes it.

### Scratch reuse (item 3): not adopted

After this change a unit with findings allocates only the placeholder vector
and the formatter's own strings. The `Vec<String>` would be the only reusable
scratch, one allocation per finalized unit that has findings, and its
contents are formatter output that must be dropped each unit. A retained
vector would add a capacity bound, a shrink policy and a new field for well
under the 0.3% already measured. No bound was designed. Not-batched
(`unbatched` test mode and the single-unit fallback) share `finalize_unit`, so
they get the same change without extra code.

### WASM size

`cargo build --release --target wasm32-unknown-unknown -p redact-secret-wasm`
(cdylib before `wasm-bindgen`; `wasm-opt` is not installed here, so this is
not the published artifact size). Raw bytes / gzip -9 bytes:

| State | full | common |
|---|---:|---:|
| base `44382b3f` | 1,058,639 / 296,837 | 868,984 / 235,459 |
| #1124 `25b00e2b` | 1,059,075 / 297,057 | 869,420 / 235,692 |
| #1125 `15cf45c2` | 1,058,691 / 296,972 | 869,036 / 235,559 |

Net against base: +52 bytes raw, +135 bytes gzip (full). `flush_batch` still
takes `dyn Iterator`; nothing was made generic, so no dyn-versus-generic
codegen comparison applies. Native rlib size was not measured.

## Tests

- `shifted_redaction_equals_local_redaction_with_offset_numbering`
  (`redact.rs`): 6,000 seeded units with a random prefix, mixed actions,
  sorted and reversed global findings, and forged findings that start below
  or run past the unit. Asserts the shifted result equals local redaction
  with the same text, that the formatter sees the caller's own findings in
  order with numbers `before + 1..`, the replaced count, a prefilled buffer
  untouched on every error, and zero formatter calls on `InvalidFindings`.
- Existing coverage, all passing unchanged: `lib` unit tests (1,772, incl.
  the batch/partition equivalence in `incremental/batch_tests.rs`),
  `incremental`, `incremental_batching`, `incremental_partitions`,
  `incremental_partition_gaps`, `incremental_rebuilds_1060`,
  `incremental_line_checks_1074`, `policy_redaction`, `public_api`,
  `whole_input_limits`, `canonical_corpus`, `sanitize_golden_path_1078`,
  `pipeline`. These cover one-byte and UTF-8 split chunks, mixed actions,
  global IDs and offsets, custom global-range formatters, formatter / policy
  / limit / placeholder failures and the abort, finalize and drop states.

## Not done

- No Node, Python or WASM callback/output conversion timing; the change is
  below the bindings and does not alter what crosses them.
- No frozen #1068 budget and no `redact-secret-benchmarks` intake.
- Item 5 (huge append with isolated accents), and the #1090 memory-hygiene
  work, were left alone.
