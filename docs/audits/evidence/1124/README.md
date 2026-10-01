# Issue #1124: ordered-finding storage in redaction

[Audit archive](../../README.md) ·
[Issue #1124](https://github.com/redact-secret/redact-secret/issues/1124) ·
[Parent #1068](https://github.com/redact-secret/redact-secret/issues/1068) ·
[Spec: engine](../../../specs/engine.md)

Written 2026-10-01 against base `44382b3f3006a3a34a2bab917711d00e2e53284a`.
Synthetic data only. No public API, finding id, span, action, error code or
sanitized-error behavior changed.

## Verdict

| Part | Verdict |
|---|---|
| Crate-private validated ordered view (`OrderedFindings`) | adopted |
| Compact placeholder storage (one concatenated buffer plus end offsets) | rejected |
| Built-in formatter specialization | not attempted: the formatter is `&dyn PlaceholderFormatter`, so it needs identity detection plus a second code path for one `format!`, and the formatter `String` allocation is the caller's contract |

The view is a small, behavior-preserving change with a deterministic but
modest gain. The 2.977 ms versus 1.942 ms gap in the research comment is not
explained by sorting: see Measurements.

## What changed

`redact_into` used to build a `Vec<&Finding>` and sort it on every call. It
now validates once and borrows the caller's slice when it is already ordered
and disjoint (every pipeline result). Unordered input still sorts into a
reference vector, then runs the same overlap check. The view type is the only
way to reach the placeholder phase, so range, alignment and disjointness proof
precedes every formatter call and every output append. The anti-reproduction
index (`ForbiddenMatchedText`) is unchanged and still covers `warn` and
`allow` values.

## Measurements

Apple silicon, rustc 1.98.0, release profile with fat LTO, unchanged
dependencies (`Cargo.lock`). Fixture: 49,000 synthetic findings of match
length 3-40, `Action::Redact`, one `redact()` call per row. The probe is
[`alloc_probe.rs.txt`](alloc_probe.rs.txt) (copy it to
`crates/secret-scan-core/examples/alloc_probe.rs` to run it). Allocation
counts are `GlobalAlloc` alloc plus realloc calls; instructions are
`/usr/bin/time -l` "instructions retired" for the whole probe process (three
`redact` calls plus fixture construction, identical in every column).

| Row | base | view (adopted) | view + buffer (rejected) |
|---|---:|---:|---:|
| sorted, default formatter: alloc calls | 49,033 | 49,031 | 49,049 |
| sorted, default formatter: requested bytes | 7,632,614 | 6,848,614 | 7,372,956 |
| sorted, default formatter: peak live extra bytes | 4,619,334 | 4,227,334 | 3,607,478 |
| sorted, 42-byte placeholder: alloc calls | 196,033 | 196,031 | 196,048 |
| sorted, 42-byte placeholder: requested bytes | 15,390,296 | 14,606,296 | 17,096,693 |
| sorted, 42-byte placeholder: peak live extra bytes | 8,664,122 | 8,272,122 | 5,815,518 |
| reversed, default formatter: alloc calls | 49,033 | 49,033 | 49,051 |
| process instructions, three runs | 1.4255G / 1.4281G / 1.4258G | 1.4272G / 1.4256G / 1.4303G | 1.4435G / 1.4416G / 1.4441G |

- The view removes one 392 KB reference vector per sorted call (-10.3%
  requested bytes, -2 alloc calls); instructions are within run-to-run noise
  of base (about 0.2%). Sorting an already sorted slice is linear, so the
  sort was not a cost.
- The concatenated placeholder buffer lowers peak live memory (-22%
  default, -33% 42-byte) but adds 16 alloc calls, raises requested bytes by
  11% for 42-byte placeholders (two growing buffers copy more than one
  vector of strings) and costs about +1.2% instructions. It does not meet the
  gate (no time or call-count win) and is not kept.
- Wall-clock `scan_cost dense-findings-redact` runs were taken against a
  machine with concurrent builds: interleaved base/new medians for the
  default formatter ranged 32-98 ms with ranges that overlap completely, so
  no latency claim is made. Instruction counts are the binding figure.
- The 256-byte placeholder row is dominated by the anti-reproduction index
  walk (about 4.5 s for 49,000 findings), which this change does not touch
  and must not weaken.

WASM raw and gzip size, and the incremental path, are recorded in the
[#1125 evidence](../1125/README.md).

## Tests

`crates/secret-scan-core/src/redact.rs` keeps the pre-#1124 validation
verbatim as a test oracle and adds:

- `arbitrary_finding_order_matches_the_always_sorting_oracle`: 6,000
  seeded cases of sorted, reversed, shuffled, forged-overlap and
  forged-out-of-range findings with mixed actions. Compares result, error
  code, formatter call order, and that a prefilled `redact_into` buffer is
  untouched on every failure and equals prefix plus `redact()` otherwise.
  It asserts both outcomes are reached (over 1,000 successes and 500
  rejections).
- `placeholder_length_boundary_is_exactly_the_maximum`: 256 accepted, 257
  rejected, output capacity equal to length.

The existing tests still cover warn/allow values reproduced by sibling
placeholders, Unicode alignment, formatter failure sanitization, default,
typed and custom formatters, and exact output capacity.

## Not done

- No `redact-secret-benchmarks` intake and no frozen #1068 budget: figures
  above are exploratory.
- No Node, Python or WASM timing: the change is below the binding layer and
  has no conversion cost.
