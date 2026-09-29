# Evidence: #982, run-end tables without whole-input allocation

**Result:** a whole-input `scan` of 10 MiB of synthetic ASCII prose (no
findings) allocated 1,952.0 MiB in 1,211,389 allocations on main
`04b3e212`. On `beta11/980-pattern-prefilter` it allocates 32.0 MiB in 82
allocations. Peak live heap during the scan fell from 160.0 MiB to 6.0 MiB
above the pre-scan baseline. On the #981 harness, `mixed-10m` fell from
748 ms to 580 ms whole-input and from 1,510 ms to 1,185 ms incremental
(about 22%), and the 64 KiB logs workload from 4.26 ms to 3.64 ms whole and
8.14 ms to 6.86 ms incremental. No finding, range, action or output byte
changed, and no dependency was added.

Issue [#982](https://github.com/redact-secret/redact-secret/issues/982),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The research comment on #982 (main `04b3e212`) measured 1,920 MiB across
992,310 `run_ends` calls for the same kind of input and set the revised
scope implemented here.

## Method

- **Probe.** A temporary example, `crates/secret-scan-core/examples/alloc_probe_982.rs`
  (never committed), wraps the system allocator in a counting
  `#[global_allocator]` and calls the public `scan` with
  `DetectorRegistry::with_built_in(Vec::new())` and `DefaultPolicy` over
  10 MiB of deterministic synthetic prose: lowercase English words from a
  fixed list (including `grafana`, `stripe`, `discord`), commas, and a `.`
  plus newline about every 72 bytes. Allocation totals are from the first
  of five scans. Times are the median of the five.
- **Builds.** `cargo build --release`, Rust 1.98.1, on an Apple M4 (macOS
  arm64). The baseline binary was built from `git archive 04b3e212` with
  the same probe file, so both sides differ only by this change.
- **Pairing.** The two binaries ran interleaved (before, after, after,
  before) three times. The host was shared with other builds, so single
  medians moved by up to 2x. The figures below leave out the two outlier
  rounds (a `before` median of 1,380 ms and one of 2,290 ms).
- **Harness.** The #981 harness (`benches/scan_cost.rs`, head `5c814dc9`)
  was built three times: main `04b3e212` plus the harness, this issue's
  commits (`3a2ad91a`) plus the harness, and the branch with #983 on top.
  The three binaries ran interleaved in four rounds (A B C, C B A, A B C,
  C B A) with `--no-detectors --json` (5 runs for `mixed-10m`, 11 for
  `scale-logs-256k`, 21 otherwise). The tables give the median of the four
  round medians. Findings counts were identical on every build.

## Numbers

Allocation probe (10 MiB of prose):

| | main `04b3e212` | this branch |
| --- | ---: | ---: |
| Bytes allocated per 10 MiB scan | 1,952.0 MiB | 32.0 MiB |
| Allocations per scan | 1,211,389 | 82 |
| Peak live heap above baseline | 160.0 MiB | 6.0 MiB |
| Probe scan median (ms), clean rounds | 1,159, 1,166, 1,167, 1,177 | 1,047, 1,047, 1,048, 1,054, 1,088 |

#981 harness, milliseconds (this issue alone; #983 is recorded in
[its own evidence](../983/README.md)):

| Workload | Path | main `04b3e212` | after #982 |
| --- | --- | ---: | ---: |
| `mixed-10m` (10,239 findings) | whole | 748.5 | 579.9 |
| | incremental 65536 | 1,510.0 | 1,184.6 |
| `scale-logs-256k` | whole | 18.44 | 14.26 |
| | incremental 4096 | 32.17 | 26.23 |
| `scale-logs-64k` | whole | 4.26 | 3.64 |
| | incremental 65536 | 8.14 | 6.86 |
| `unicode-invisible-64k` (269 findings) | whole | 4.09 | 2.98 |
| | incremental 65536 | 8.34 | 6.89 |
| `provider-tables-64k` (112 findings) | whole | 4.91 | 3.76 |
| | incremental 65536 | 8.05 | 6.68 |

## What changed

`pattern::run_ends` builds a `Vec<usize>` of `input.len() + 1` entries. The
change removes every call that built one without needing it, in three
groups, as the revised scope asked:

1. **Literal-anchored detectors build the table only after the literal
   occurs.** `firebase` (`AAAA`), `gitlab` runner (`glrt-`), `grafana`
   (`glsa_`, two tables), `microsoft-entra` (`Q~`), `notion` (`ntn_`),
   `openai` (`sk-`, two tables), `sendgrid` (`SG.`), `sentry` org
   (`sntrys_`), `stripe` `whsec_` and `terraform` (`.atlasv1.`) call
   `pattern::find_literal` (or terraform's own marker search) first. With no
   hit they return no candidates. With a hit the loop starts at that offset.
   Every offset before it failed the loop's own `starts_with` test, so
   skipping them changes nothing. This is the #950 pattern.
2. **Run tokenizers measure each run forward.** `confluent`, `datadog`,
   `heroku`, `twilio`, `keyword_gated_keys`, `mailchimp`, `pinecone`
   (legacy UUID path), `travisci`, `new_relic` (bare hex path) and
   `mailgun` (hex-triplet path) walk a line as a sequence of runs and
   resume at each run's end. New `pattern::run_end` scans forward to the end
   of the run. Each byte is visited once, as before, and no table is built.
3. **A cursor where there is no anchor, or where a literal repeats inside
   the run.** New `pattern::RunCursor` returns `run_ends(bytes)[at]` for
   any query order. It caches the last run it measured. A query inside that
   run is answered from the cache. Any other query scans forward, and a
   scan that reaches the cached run's start joins it. `discord` (which
   retries a shorter first segment and then steps back to `start + 1`) and
   `telegram` use it. `okta` (`00`), `mailgun` (`key-`) and `new_relic`
   (`eu01xx`) use it too: their literal can repeat inside the body run
   (`0000…` for okta), where a plain forward scan per hit would be
   quadratic.

Left as they were: `scan_prefixed_shapes` and `slack` already build tables
lazily after a full prefix match (#950), and `azure_devops` is already gated
by `contains(ANCHOR)`. None of them built a table on the prose input.

## Tests

- `pattern::tests::run_end_matches_the_run_end_table_at_every_offset`:
  `run_end` equals the table at every offset, for 203 random inputs and all
  twelve alphabets tested.
- `pattern::tests::run_cursor_matches_the_run_end_table_for_arbitrary_query_sequences`:
  random query sequences mixing jumps, backward steps, repeats and forward
  steps. A cursor that assumes non-decreasing queries fails it.
- `pattern::tests::run_cursor_tests_each_byte_once_for_forward_queries` and
  `run_cursor_rescans_only_the_backward_step` pin the cost in bytes tested.
- `discord::tests::out_of_order_segment_queries_stay_linear`, the discord
  analogue of `repeated_embedded_prefixes_in_one_run_stay_linear` (kept
  unchanged). Five near-miss shapes repeated 4,000 times must test at most
  3 bytes per input byte. A cursor without its cache tests 2,307,376 bytes
  for 232,000 input bytes on the first shape and fails it.
- `cargo test --workspace --locked` passes, including the conformance
  fixtures, `incremental_partitions` and `adversarial_bounds`.
