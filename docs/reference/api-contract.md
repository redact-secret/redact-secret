# API concepts and contracts

[Documentation home](../README.md)

| Operation | JavaScript | Python / Rust | Result |
| --- | --- | --- | --- |
| Detect and apply policy | `scan` | `scan` | Findings |
| Replace supplied ranges | `redact` | `redact` | Text |
| Both together | `scanAndRedact` | `scan_and_redact` | Text and findings |

Bindings adapt arguments and results; they do not copy detector logic. Rust
additionally takes a registry, policy, and formatter. Python uses optional
`policy` and `formatter`; JavaScript uses an options object with `policy` and
`placeholderFormatter`.

Whole-input operations are bounded by default to 64 MiB of input and 50,000
findings (`decision-bound-whole-input-operations-by-default`). Exceeding a
bound fails with `INPUT_LIMIT_EXCEEDED` or `FINDING_LIMIT_EXCEEDED` rather
than truncating. Raise or lower it with JavaScript's
`limits: { maxInputBytes, maxFindings }` option, Python's
`limits=WholeInputLimits(...)`, or Rust's `WholeInputLimits` with
`scan_with_limits`, `redact_with_limits`, and `scan_and_redact_with_limits`.

## Findings and coordinates

Each finding has `id`, `type`, `detector`, `confidence`, `action`,
`obfuscation`, `start`, and `end` (Rust exposes methods and a range object).
`obfuscation` is `none`, or `invisible-characters` when zero-rendering or
format code points were removed from the matched span before detection. No
matched value is included.
Ranges are half-open: `start` is included and `end` excluded.

| Surface | Unit | Exported `RANGE_UNIT` |
| --- | --- | --- |
| JavaScript | UTF-16 code units | `utf16-code-units` |
| Python | Unicode code points | `unicode-code-points` |
| Rust and CLI | UTF-8 bytes | `utf8-bytes` |

All offsets refer to original input. For example, `🔑 ` before a finding adds
3 JavaScript units, 2 Python code points, or 5 UTF-8 bytes. Do not copy numeric
positions between runtimes without converting against the same input. The
conformance corpus's schema label `utf8-byte` names the same byte coordinate
system; it is a separate field from runtime `rangeUnit`.

Within a scan, findings are sorted by position and numbered from `finding-1`.
Incremental sessions use absolute positions and continuous numbering. CLI
multi-file reports renumber findings across the run. IDs are not persistent
identities across changed inputs or separate scans.

## Overlap and replacement

Candidate precedence is resolved-action severity (`block` > `redact` > `warn`
> `allow`, by the default classification), specificity, confidence, narrower
span, detector order, then emission order. The pipeline selects the
non-overlapping subset with the greatest total evidence weight, not a greedy
walk, so a weaker candidate never displaces an overlapping stricter one, but
several disjoint candidates can outweigh one overlapping candidate that ties
them on the stronger keys. A policy runs on the selected findings afterward.

Direct `redact` accepts unsorted findings, sorts them, and rejects overlaps,
invalid bounds, and ranges off character boundaries. It does not resolve
conflicting caller-supplied findings. Use the same original input that was
scanned; validation cannot establish that a finding belongs to that input.

Only `redact` and `block` consume placeholders. Default labels are `<SECRET_1>`,
`<SECRET_2>`, etc.; `warn` and `allow` preserve input. Placeholders are not an
encoding of the removed text and cannot be used to recover it.

## Detector profiles

Two detector profiles exist: `full` (every built-in detector, the default and
compatibility baseline everywhere) and `common` (a smaller, opt-in
structural/contextual subset for preventive use). The `@redact-secret/core`
root and `./common` entry points (in Node, browser, and `workerd` builds;
`./common/node-stream` and `./common/web-stream` bind streams to `common`)
and the Rust `DetectorRegistry`/
`IncrementalSanitizer` constructors expose which profile they were built
from — the `PROFILE` constant in JavaScript (`"full"` on the root export,
`"common"` on `./common`), and `DetectorRegistry::profile()` /
`IncrementalSanitizer::profile()` in Rust. JavaScript `initialize()` rejects
with `INITIALIZATION_FAILED` if the loaded artifact reports a
different profile than the entry point that loaded it, the same detail-free
rejection an unusable or version-mismatched artifact already gets. Python and
the CLI expose `full` only. See [detection coverage](detection.md#detector-profiles)
for profile membership and the false-negative tradeoff, and the
[JavaScript](../guides/javascript.md#detector-profiles) and
[Rust](../guides/rust.md#detector-profiles) guides for per-runtime usage.

## Errors and extensions

Failures use fixed codes and input-free messages. JavaScript exposes
`SecretScanError`; Python has subclasses of the same name; Rust returns
`SecretScanError` in `Result`. [Troubleshooting](../troubleshooting.md) covers
common causes. Policy and formatter callbacks are supported across languages;
custom detector callbacks are a direct Rust surface only.
