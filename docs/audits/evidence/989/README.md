# Evidence: #989, removing the quadratic templated-lookup check from `generic-token`

**Result:** one 256 KiB line of minified JSON took 2.13 s to scan on
`main` (`04b3e212`) and takes 20 ms after this change. A 256 KiB line of
dense `"api_key":"…"` pairs goes from 575 ms to 29 ms. Findings, ranges,
confidence and redacted text are unchanged on every workload measured, on
the conformance corpus, the `generic_token` unit tests and
`incremental_partitions`. The regression came in with #911 (`12a984eb`),
which is in the frozen Beta.11 candidate `1db8ff3` and not in
`v0.1.0-beta.10`.

Issue [#989](https://github.com/redact-secret/redact-secret/issues/989),
split out of [#984](https://github.com/redact-secret/redact-secret/issues/984)'s
research; parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
Harness: [#981](../981/README.md).

## Cause

`is_templated_lookup_path` (#911) decides whether an assignment sits inside
a `{{ ... }}` template still open on its line. It ran for every
`name`/operator/value pair the assignment loop produced, before
`assignment_confidence`, and each run did an `rfind` back to the line start,
then an `rfind("{{")` and a `contains("}}")` over the same stretch. On one
long line that is quadratic in the line length. Precomputing line starts
would not have helped, because the brace scans still ran back to the line
start.

## Changes

| Commit | Change |
| --- | --- |
| `8135faf` | Run the check after `assignment_confidence`, so only a pair that would be reported pays for it. Every check involved is pure, so the result is the same. |
| `2d22bb6` | `OpenTemplateTracker` carries "a `{{` is open on this line" forward through the assignment loop. Each byte is folded in once, so the check is O(1) amortized per pair and the scan is O(n). The value-shape half (`is_secret_manager_path`) is unchanged and runs first. |
| `a161f64` | `adversarial_bounds`: `a_long_single_line_of_assignments_scans_in_linear_time`, plus the CHANGELOG entry. |

### Equivalence

The tracker answers exactly what the look back answered: the last `{{`
between the line start (after the last `\n` or `\r`) and the query offset,
open unless a `}}` follows it there. The last `{{` of a brace run starts on
the run's second-to-last `{`, which is where a new `{` after a `{` re-opens
the state, and a `}}` needs two `}` after it, which the tracker checks with
the previous byte. `{`, `}`, `\n` and `\r` are ASCII, so walking bytes
never splits a UTF-8 sequence. A query behind the current position (the
loop never makes one) restarts from offset 0 rather than answering wrongly.

Unit tests in `generic_token.rs` keep the #911 function verbatim as a
reference and compare against it:

- every string of up to seven symbols over `{`, `}`, `\n`, `\r`, `a`
  (97,656 strings, every offset), which covers `{{{`, `}}}`, `{{}}`,
  `}}{{`, and templates split by either line break;
- named cases, including `{{{}}}`, `{{ a }}} b {{{ c`, `\r\n` inside a
  template and non-ASCII text;
- 2,000 generated lines (fixed LCG seed) queried at skipping offsets with
  path and non-path values, through the full `is_templated_lookup_path`;
- a backward query.

Dropping the `closed = false` reset on a new `{{` fails three of the four
tests.

### Linear-time pin

`a_long_single_line_of_assignments_scans_in_linear_time` scans a 256 KiB
single line of minified JSON and one of dense `"api_key":"…"` pairs through
the whole-input pipeline, under the file's `timed()` isolation, against a
500 ms budget (16 s in a debug build, the file's 32x allowance). Measured on
the host below:

| Build | Code | Minified JSON 256 KiB | Dense pairs 256 KiB |
| --- | --- | ---: | ---: |
| release | `main` | 1,389 ms | 575 ms |
| release | this branch | 24 ms | 29 ms |
| debug | `main` | 149,715 ms | 58,409 ms |
| debug | this branch | 800 ms | 696 ms |

Both profiles fail on `main` and pass here with a margin of about 20x.

## Measurements

Host: Apple M4 (macOS, aarch64), `rustc 1.98.1`, release profile, shared
with other agents (load average 7-13 during the runs).

**Harness** (`cargo bench -p redact-secret --bench scan_cost -- --filter
<workload> --runs 11 --json`). Three builds ran interleaved (before, #989,
#984, #984, #989, before), each workload filtered separately, giving two run
medians per build; the table shows their median, ms. "Before" is the
harness commit `5c814dc` (`main` product code); "after" is `a161f64`, the
last #989 commit, with the harness copied in. The #984 build is reported in
[#984's record](../984/README.md).

| Workload | Path | Before | After |
| --- | --- | ---: | ---: |
| `minified-json-64k` | whole | 121.65 | 5.10 |
| `minified-json-64k` | incremental 64 KiB | 121.99 | 5.16 |
| `minified-json-64k` | `generic-token` `detect()` | 117.09 | 0.70 |
| `minified-json-256k` | whole | 2,125.66 | 19.29 |
| `minified-json-256k` | incremental 64 KiB | 1,691.47 | 19.53 |
| `minified-json-256k` | `generic-token` `detect()` | 2,066.84 | 2.70 |
| `scale-logs-64k` | whole | 6.46 | 4.62 |
| `scale-logs-64k` | incremental 64 KiB | 11.13 | 8.20 |
| `scale-logs-64k` | `generic-token` `detect()` whole / per line | 0.78 / 0.94 | 0.57 / 0.61 |

Findings counts per workload (41, 162, 0) match on both sides. The
`scale-logs-64k` whole and incremental rows moved with host load
(before's two runs were 8.39 and 4.52 ms whole); the `generic-token` row is
the direct effect: every `status=200`-style pair used to pay the look back.

**Dense credential-named pairs** are not a harness workload, so they come
from the throwaway probe the #984 research used (public API only,
`scan` + `redact`, 21 runs, medians, ms; output hashed and identical):

| Input | `main` | step 1 only (`8135faf`) | this branch |
| --- | ---: | ---: | ---: |
| minified JSON 64 KiB | 102.9 | 5.5 | 5.9 |
| minified JSON 256 KiB | 1,389.4 | 20.5 | 24.4 |
| dense `"api_key":"…"` 64 KiB | 40.2 | 40.9 | 7.1 |
| dense `"api_key":"…"` 256 KiB | 574.9 | 530.9 | 29.2 |
| logs 64 KiB | 5.3 | 5.4 | 5.4 |

Step 1 alone fixes ordinary JSON; the dense case, where every pair clears
`assignment_confidence`, needs step 2.

## Checks

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked
-- -D warnings`, `cargo test --workspace --locked` (conformance,
`incremental_partitions`, `adversarial_bounds`, binding parity) and
`npm run rust:check` pass. No SAST baseline entry is in the touched files.

## Reproduce

```sh
cargo bench -p redact-secret --bench scan_cost -- --filter minified-json --runs 11
cargo test -p redact-secret --lib -- open_template templated_lookup
cargo test -p redact-secret --test adversarial_bounds a_long_single_line
```
