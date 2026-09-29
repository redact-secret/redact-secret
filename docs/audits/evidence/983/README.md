# Evidence: #983, a shared two-byte-pair prefilter for built-in detectors

**Result:** 75 of the 92 `full` built-in detectors now declare the
case-sensitive literals one of which every candidate they propose contains.
The pipeline builds a 1024-bit hashed set of the scan copy's byte pairs once
per call and skips a detector when no declared literal can occur. On the
#981 harness, after #982, the 64 KiB logs workload fell from 3.64 ms to
2.06 ms whole-input and from 6.86 ms to 3.56 ms incremental (48%), and
`mixed-10m` from 580 ms to 368 ms whole and from 1,185 ms to 629 ms
incremental. No finding, range, action, error or output byte changed, no
dependency was added, and the public API is unchanged.

Issue [#983](https://github.com/redact-secret/redact-secret/issues/983),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The research comment on #983 (main `04b3e212`) set the revised scope
implemented here. It estimated a ceiling of about 45% incremental on the
logs workload before #982. It was measured after #982, as the research
asked.

## What changed

- **Declaration.** `detectors::built_in_entries` and
  `common_built_in_entries` pair each detector that `built_in_detectors` and
  `common_built_in_detectors` construct with an optional `RequiredLiterals`
  (any of these literals), looked up by id in a `const` table
  (`DECLARED_LITERALS`, plus a `common`-only lookup that names only `common`
  modules). The registry stores it in a private field of
  `RegisteredDetector`. It is not on the public `Detector` trait or
  `DetectorContext`, and `tests/public_api.rs` is unchanged. A custom
  detector, one registered through `DetectorRegistry::register` (even under
  a built-in id), the PII adapter, and ruleset detectors never carry one, so
  they always run. The `built_in_detectors()` list itself is unchanged, so
  the scripts that parse it (`measure-wasm-profiles.mjs`,
  `measure-detector-cost.mjs`, the inventory generators) still work.
- **Test.** A literal may occur when every one of its consecutive byte
  pairs is in the set (AND). A detector may match when any of its literals
  may occur (OR). `re_` needs both `re` and `e_`. A hash collision, or pairs
  that occur apart, only make a detector run when it did not need to.
- **Set.** 1024 bits (`[u64; 16]`), a Fibonacci hash of the 16-bit pair,
  built on `NormalizedInput::text()`, the scan copy with invisible code
  points removed, so a literal split by an invisible character still counts.
  It is built lazily, only when a registered detector declares literals.
- **Skip.** A skipped detector still gets an empty candidate list, so the
  lists stay aligned with `detector_order`.
- **Literals come from each detector's grammar constants.** Table-driven
  detectors (`KnownFormatProviderDetector`, `TypedKnownFormatProviderDetector`,
  38 of them) declare their shapes' prefixes. Each other module declares a
  `REQUIRED_LITERALS` constant next to its grammar, built from the constants
  its scan uses (`Literals::Strs(&PREFIXES)`,
  `Literals::Prefixes(&CLASSIC_FAMILY_PREFIXES)`,
  `Literals::Shapes(&INTERIM_SHAPES)`). The declarations are plain data, and
  one non-generic function flattens them. `private_key`, `jwt` and
  `connection-string` now name their delimiter, header lead and `://` as
  constants for this. The emission paths the research flagged:
  - `github-token`: all three families (`ghp_`/`gho_`/`ghu_`/`ghr_`,
    `ghs_`, `github_pat_`).
  - `stripe-token`: the shared key table's prefixes and `whsec_`.
  - `slack-token`: the bot, user, rotation, app-level and interim
    prefixes.
  - `telegram-bot-token`: a digit followed by `:` (`0:` to `9:`).
  - `mailgun-api-key`: `key-`, and a lowercase hex byte followed by `-` for
    the triplet path. Its keyword gate is case-insensitive and not declared.
  - `mailchimp-api-key`: the `-us` datacenter suffix.
  - `connection-string`: `://` and `AccountKey=`.
- **Always run (17, `full`):** `generic-token`, `bearer-token`, both
  `twilio` detectors (including the CLI table path), `datadog` API and
  legacy application keys, `new-relic` license key, `pinecone` (its legacy
  path is keyword-gated), the `confluent` and `heroku` legacy detectors,
  `travisci`, `mistral`, `cohere`, `ai21`, `deepgram`, `discord` and
  `convex`. A unit test pins this list, so a new detector's choice is
  explicit. The `common` profile declares four of its six detectors
  (`private-key`, `jwt`, `connection-string`, `otpauth`).

## Guards against a wrong declaration

A literal list that misses an emission path would silently drop findings,
so it is checked three ways:

1. **Every debug-build scan.** In `cfg(debug_assertions)` builds,
   `collect_candidates` runs each skipped detector anyway and panics if it
   returns anything but `Ok` with no candidates. Every Rust test that scans,
   including the canonical synchronous and incremental corpora,
   `incremental_partitions` and `adversarial_bounds`, therefore checks the
   declarations. Release builds do not run it.
2. **A mutation corpus** (`tests/prefilter_soundness.rs`, debug only, eight
   parallel shards, about 10 s). Every positive fixture of the synchronous
   corpus is cut to a window around its findings. One ASCII byte near each
   finding is then changed (case swap, neighbouring digit or punctuation),
   or deleted near its start, and each variant is scanned with the `full`
   registry. A variant that breaks a declared literal while its detector
   still matches fails the debug check. Dropping `5:` from telegram's
   declaration fails it, though the unmutated corpus passes.
3. **Unit tests.** They cover the pair set's AND/OR semantics and pin the
   list of undeclared built-ins and the declaration counts (75 `full`, 4
   `common`). A registry test checks that a custom detector never carries a
   declaration, even when it reuses a built-in id.

A throwaway differential probe (never committed) ran `scan_and_redact` with
the `full` and `common` registries over 146,943 inputs on main `04b3e212`
and on this branch. The inputs were every corpus input, every single-byte
case flip in its first 64 bytes, and all of them joined. Both builds gave
268,104 findings and the same hash of the formatted results.

## Method and numbers

The #981 harness (`benches/scan_cost.rs`, head `5c814dc9`) was built three
times on one Apple M4 host (macOS arm64, Rust 1.98.1, release): main
`04b3e212`, #982 (`3a2ad91a`), and this branch (`1f54d351`), each with the
harness. The three binaries ran interleaved in four rounds (A B C, C B A,
A B C, C B A) with `--no-detectors --json` (5 runs for `mixed-10m`, 11 for
`scale-logs-256k`, 21 otherwise). The table gives the median of the four
round medians in milliseconds. Findings counts were identical on every
build.

| Workload | Path | main | after #982 | after #983 | #983 alone |
| --- | --- | ---: | ---: | ---: | ---: |
| `scale-logs-64k` | whole | 4.26 | 3.64 | 2.06 | -43% |
| | incremental 65536 | 8.14 | 6.86 | 3.56 | -48% |
| `scale-logs-256k` | whole | 18.44 | 14.26 | 8.66 | -39% |
| | incremental 4096 | 32.17 | 26.23 | 14.40 | -45% |
| | incremental 65536 | 32.70 | 26.52 | 14.21 | -46% |
| `unicode-invisible-64k` (269 findings) | whole | 4.09 | 2.98 | 1.98 | -34% |
| | incremental 65536 | 8.34 | 6.89 | 3.98 | -42% |
| `provider-tables-64k` (112 findings) | whole | 4.91 | 3.76 | 2.44 | -35% |
| | incremental 65536 | 8.05 | 6.68 | 4.04 | -40% |
| `mixed-10m` (10,239 findings) | whole | 748.5 | 579.9 | 368.4 | -36% |
| | incremental 65536 | 1,510.0 | 1,184.6 | 628.6 | -47% |

Round-to-round spread was within about ±8% on every row. The later commit
`4a45eba4` only moves the declarations into `const` data. Six interleaved runs
of it against `1f54d351` on `scale-logs-64k` were within noise of each
other (whole 2.02-2.12 ms against 2.05-2.36 ms, incremental 3.24-3.43 ms
against 3.29-3.79 ms). The research
estimated a ceiling of about 45% incremental on the logs workload, with
okta and telegram never skipped because `00` and a digit followed by `:`
occur in every timestamp line. They are not skipped here either. The
measured 48% is within noise of that estimate.

## Trade-offs

- A declared detector's literals are one more thing to keep in sync with
  its grammar. The debug check and the mutation corpus are the guard. A new
  emission path without a fixture that exercises it is still a risk, as
  with any grammar change.
- Real text will skip less than synthetic logs: a literal such as `sk-`,
  `00` or `e-` occurs in much prose. Such a detector just runs, as it did
  before.
- Debug builds still run every skipped detector to check it, so they keep
  roughly their old cost.
- WebAssembly size (`measure-wasm-profiles.mjs`, release, against #982):
  `full` grows from 521,422 to 527,276 B raw (+1.1%) and from 179,619 to
  182,021 B gzip (+1.3%). `common` grows from 341,259 to 344,319 B raw and
  from 122,584 to 123,735 B gzip (+0.9%). The first version of this change
  built the declarations from 75 iterator chains and added 34 KB raw to
  `full`. Making them `const` data brought that down to the figures above.
  The reachability guard still passes: `common` links no `provider`
  detector.
