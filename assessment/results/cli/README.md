# CLI binary baseline

This directory records the first bounded assessment of the built
`redact-secret` CLI binary for issue #197. It is inspectable evidence, not a
release gate or release authorization.

## Identity

- Source revision: `3215b76e8d061d50bf9000af3445eef801009ccf`
- Artifact: `redact-secret@0.1.0-beta.1`
- Binary: `target/release/redact-secret`, 559,213 bytes
- Binary SHA-256: `96709cc087078db35b19ac5a908722599123314df0c50ade11f0e74fb4246781`
- Host: macOS 26.5.2 (`darwin-25.5.0`), arm64
- Toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`
- Accuracy corpus: version 1; its exact SHA-256 is in
  [`accuracy-corpus.json`](./accuracy-corpus.json)
- Workload profiles: version 1; their exact SHA-256 is in
  [`scale-logs-small-whole.json`](./scale-logs-small-whole.json)

## Exact commands

```bash
cargo build --release -p redact-secret-cli
node scripts/assessment-cli-run.mjs --self-test
npm run assessment:cli -- --json-out assessment/results/cli/accuracy-corpus.json --markdown-out assessment/results/cli/accuracy-corpus.md --mismatches-out assessment/results/cli/accuracy-corpus-mismatches.json
npm run assessment:cli:performance -- --profile scale-logs-small-whole --runs 2 --json-out assessment/results/cli/scale-logs-small-whole.json --markdown-out assessment/results/cli/scale-logs-small-whole.md
```

`--binary` was left at its default (`target/release/redact-secret`); no
cross-compiled or `--target`-qualified artifact was used for this baseline.

## Result and limits

The accuracy run scored all 9 corpus fixtures through the CLI's `--json`
check mode over standard input, converting its canonical UTF-8 byte ranges to
UTF-16 code units with the same `scoring.ts` used by every other surface. The
same run also validated the documented exit codes, a malformed
standard-input decode failure (`NOT_UTF8`, fails closed), a multi-file `--`
run byte-for-byte identical to the standard-input results, and `--redact`
mode against every fixture with a `redact`/`block` finding — see
[`../../README.md#cli-runner`](../../README.md#cli-runner). The raw result
and safe mismatch metadata are in
[`accuracy-corpus.json`](./accuracy-corpus.json) and
[`accuracy-corpus-mismatches.json`](./accuracy-corpus-mismatches.json). Its 1
true positive / 1 false positive / 5 false negative / 0 policy mismatch
result matches the Rust library and installed Python baselines exactly
(see [`../rust-core/accuracy-corpus.json`](../rust-core/accuracy-corpus.json)
and [`../python/accuracy-corpus.json`](../python/accuracy-corpus.json)): the
same detector gaps the corpus already documents for those surfaces, not a
CLI-specific regression.

The performance baseline is the inspected 64 KiB `scale-logs-small-whole`
profile with two fresh-process-pair repetitions. Raw process-startup,
processing, throughput, and `processRss` samples are in
[`scale-logs-small-whole.json`](./scale-logs-small-whole.json).

- `initialization` times a `--version`-only process: startup, argument
  parsing, and exit — nothing else.
- `processing` times a `--json` process against the generated input. It is
  **process-inclusive**: it contains the same process-startup cost
  `initialization` measures on its own, because a subprocess boundary offers
  no way to time only the library work inside it. It must not be read as, or
  compared directly against, the Node/Python/Rust surfaces' in-process
  steady-state processing numbers.
- `processRss` is a separate, untimed `/usr/bin/time -l`-wrapped repetition's
  whole-process maximum resident set size. It includes process startup, the
  Rust runtime, and the entire scan, and cannot isolate steady-state or
  Rust-only memory.
- Retained incremental plaintext bytes are unavailable because the public CLI
  contract exposes no buffer-size instrumentation. Node, browser, Wasm, and
  Python heap categories are unavailable on this surface. Categories overlap
  and must not be summed.
