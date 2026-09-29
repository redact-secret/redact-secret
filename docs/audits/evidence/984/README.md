# Evidence: #984, `generic-token` assignment-walk quick wins

**Result:** the two per-check `format!` calls for opencode references are
now static literals, and the assignment loop reuses one buffer for each
pair's normalized name instead of allocating one per parsed pair. Output is
unchanged. The effect on the scan is within noise on the #981 workloads
(`generic-token` `detect()` on `scale-logs-64k` 0.57 → 0.56 ms whole, 0.61
→ 0.64 ms per line). The structural backward-anchoring rewrite is deferred,
as the research comment recommended, and a forward ASCII skip was tried and
not kept (below).

Issue [#984](https://github.com/redact-secret/redact-secret/issues/984),
research comment "Research (main 04b3e212)"; parent
[#980](https://github.com/redact-secret/redact-secret/issues/980). The
quadratic the research found moved to [#989](../989/README.md), which
landed first on the same branch.

## Changes (`2d4398d`)

- `text.rs`: `OPENCODE_REFERENCE_KINDS` (`["env", "file"]`) becomes
  `OPENCODE_REFERENCE_OPENERS` (`["{env:", "{file:"]`), and
  `is_opencode_reference` compares against it directly. It had built
  `format!("{{{kind}:")` for each kind on every call.
- `generic_token.rs`: `starts_with_opencode_prefix` uses the same constant
  instead of its own `format!`.
- `generic_token.rs`: `normalize_name_into` writes the normalized name into a
  caller's buffer; `normalize_name` wraps it and keeps its signature for its
  other callers (`ruleset`, `pinecone`, `keyword_gated_keys`, `text`, the
  call-literal path and `has_open_contextual_assignment`, which is left
  untouched for #986). `assignment_candidates` keeps one buffer across the
  loop, and the JWK override writes `private_key` into it instead of
  allocating a new `String`.

The strings compared and the normalization are byte for byte the same, so
no equivalence test beyond the existing `generic_token` suite, conformance
and `incremental_partitions` was needed. The `generic_token.rs:~2524` signal
`format!` is left to #987.

## Not done

- **Backward anchoring from `=`/`:`** (revised scope item 3): deferred. Its
  payoff is at most the per-character walk, about 0.24 ms per 64 KiB, and it
  has to reproduce the tie-breaks the research lists.
- **Forward ASCII skip.** A variant of the walk skipped runs of ASCII bytes
  that cannot start a prefix (not a boundary character, `(`, `?`, `&`, `#`,
  and not after `\n`/`\r`), with a property test that every skipped offset
  is one `try_match_assignment_prefix` rejects (4,000 generated strings over
  all ASCII bytes, Unicode whitespace and U+2028/U+2029; mutation-checked).
  On a `generic-token`-only probe (301 runs, medians of interleaved rounds)
  it moved `detect()` by 0.00 ms on 64 KiB of logs (0.528 → 0.532), −0.02 ms
  on minified JSON and −0.06 ms on dense `"api_key"` pairs, inside the A/A
  spread. It was dropped: added code with no measurable gain.

## Measurements

Host: Apple M4 (macOS, aarch64), `rustc 1.98.1`, release profile, shared
with other agents (load average 7-13).

**Harness** (`cargo bench -p redact-secret --bench scan_cost -- --filter
<workload> --runs 11 --json`), interleaved with the #989 builds as
described in [#989's record](../989/README.md); median of two run medians,
ms. "Before" is `a161f64` (end of #989), "after" is `2d4398d`.

| Workload | Path | Before | After |
| --- | --- | ---: | ---: |
| `scale-logs-64k` | whole | 4.62 | 4.56 |
| `scale-logs-64k` | incremental 64 KiB | 8.20 | 8.28 |
| `scale-logs-64k` | `generic-token` whole / per line | 0.57 / 0.61 | 0.56 / 0.64 |
| `minified-json-64k` | whole | 5.10 | 5.04 |
| `minified-json-64k` | `generic-token` | 0.70 | 0.63 |
| `minified-json-256k` | whole | 19.29 | 20.17 |
| `minified-json-256k` | `generic-token` | 2.70 | 2.41 |

**`generic-token` alone** (a temporary `#[ignore]` unit test calling
`GenericTokenDetector::detect` 301 times on 64 KiB, never committed; two
interleaved rounds, median of medians, ms):

| Input | `main` | after #989 | after #984 |
| --- | ---: | ---: | ---: |
| logs | 0.909 | 0.593 | 0.528 |
| minified JSON | 121.4 | 0.656 | 0.529 |
| dense `"api_key":"…"` pairs | 54.9 | 1.970 | 1.824 |

The detector-only probe shows a 7-19% reduction in `generic-token` from the
allocation changes. That is 0.05-0.15 ms per 64 KiB, too small to see in the
whole-scan rows on this host.

## Checks

Same as [#989](../989/README.md#checks); run on the combined branch.
