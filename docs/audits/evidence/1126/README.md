# #1126 — size build profile: keep opt-level 3, reject `s` and `z`

Product judgement. Final record for [#1126](https://github.com/redact-secret/redact-secret/issues/1126)
(parent #1068, epic #1065). A measured rejection. No `Cargo.toml` or workflow
changed.

## Question

Should any shipped artifact, or an opt-in recipe, build at `opt-level = "s"` or
`"z"` instead of the default `3`, given the latency cost the #1068 research saw
on a minimal Linux application?

## Method

- Source: `44382b3f3006a3a34a2bab917711d00e2e53284a` (version `0.1.0-beta.12`),
  `rustc`/`cargo` 1.98.1, `wasm-bindgen` 0.2.128, Node.js 22.16.0, Apple M4
  (macOS arm64). Not the Linux x86_64 VM of the #1068 study.
- The workspace profile is unchanged between variants (`lto = "fat"`,
  `codegen-units = 1`, Cargo's default release `strip`, `panic = "unwind"`). Only
  `CARGO_PROFILE_RELEASE_OPT_LEVEL` differs, with one `CARGO_TARGET_DIR` per
  variant and `CARGO_BUILD_JOBS=4`. Because the variable applies to the whole
  invocation, the result is the profile a final workspace root would impose;
  a dependency library cannot impose it (Cargo reads profiles from the root
  workspace only).
- The artifacts are the real ones, built the way CI builds them:
  `cargo build --release --locked -p redact-secret-cli`, `-p redact-secret-node`
  (the cdylib, `libredact_secret_node.dylib`), and
  `scripts/build-browser-artifact.mjs` for `full` and `common`, each with its
  `pii` variant (`wasm-bindgen --target web`, no `wasm-opt`, as in
  [#381](../381/README.md)). Compressed sizes use gzip level 9 and brotli
  quality 11.
- Latency: three rounds of seven samples per variant, variant order rotated each
  round, run under the shared benchmark lock. Inputs are three deterministic
  synthetic fixtures generated at run time and never committed: 64 KiB of clean
  prose, 256 KiB of log lines and 256 KiB of minified JSON, with one
  synthetic `ghp_`-shaped token every 40 to 50 records. The CLI figures are
  whole-process wall time (`--redact <file>` and `--redact` on standard input).
  Addon and WebAssembly figures are the median of seven in-process
  `scan`/`scanAndRedact` calls in a fresh Node process, and `init` is
  the time to instantiate and call `initialize`. Every cell below is the median
  of the 21 samples (3 rounds x 7), as a ratio to opt3.
- Equivalence: the SHA-256 of the redacted output (CLI) and of the redacted text
  or finding list with its count (addon, WebAssembly `full` and `common`) is
  identical across opt3, opts and optz for every fixture (15 of 15 keys). The
  profile changed no span, type, action or output byte here.

## Size

Bytes. The percentage is against opt3 on the same row.

| Artifact | opt3 raw | opts raw | optz raw | opts gzip9 | optz gzip9 | opt3 gzip9 | opts brotli11 | optz brotli11 | opt3 brotli11 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CLI (`redact-secret`) | 1,271,680 | 1,128,400 (-11.3%) | 1,123,552 (-11.6%) | 514,717 (-12.6%) | 489,702 (-16.9%) | 589,053 | 388,940 | 382,333 | 443,182 |
| Node addon cdylib | 1,521,920 | 1,384,016 (-9.1%) | 1,352,672 (-11.1%) | 593,682 | 569,139 | 679,972 | 444,775 | 436,828 | 505,984 |
| WASM `full` | 594,960 | 668,100 (+12.3%) | 714,692 (+20.1%) | 198,158 (-3.4%) | 185,043 (-9.8%) | 205,081 | 159,098 (-0.2%) | 150,523 (-5.6%) | 159,403 |
| WASM `full` + PII | 896,380 | 1,009,391 (+12.6%) | 1,068,621 (+19.2%) | 317,682 (-3.4%) | 295,354 (-10.2%) | 328,890 | 252,840 (-1.7%) | 238,455 (-7.3%) | 257,301 |
| WASM `common` | 406,687 | 490,905 (+20.7%) | 537,741 (+32.2%) | 146,573 (+2.8%) | 137,484 (-3.6%) | 142,547 | 119,189 (+4.6%) | 113,438 (-0.5%) | 113,995 |
| WASM `common` + PII | 708,175 | 832,297 (+17.5%) | 892,173 (+26.0%) | 265,123 (-0.3%) | 247,419 (-7.0%) | 265,956 | 213,795 (+0.8%) | 201,997 (-4.7%) | 212,026 |

Two facts matter more than the headline native saving.

1. `s` and `z` make the shipped WebAssembly files larger as raw files
   (+12% to +32%) in this pipeline, which runs no `wasm-opt`. The
   compressed saving is at most 10% (gzip, `z`, `full`) and is within
   0.2% to a loss for `s` under brotli, which is what a CDN serves. `common`, the
   smaller preventive artifact, gets no brotli benefit from either level.
2. The native saving is real (about 11% raw on the CLI and 9% to 11% on the
   addon), but npm and PyPI users download the compressed package, where the
   difference is smaller than the raw figure.

## Latency

Ratio to opt3, median of 21 samples (absolute opt3 median in milliseconds in
parentheses). Process start is included for the CLI.

| Measurement | opts | optz |
| --- | ---: | ---: |
| CLI file, clean 64 KiB (8.5) | 0.97x | 1.39x |
| CLI file, logs 256 KiB (16.5) | 1.01x | 1.77x |
| CLI file, minified JSON 256 KiB (25.6) | 1.16x | 2.09x |
| CLI stdin, clean 64 KiB (9.3) | 0.95x | 1.60x |
| CLI stdin, logs 256 KiB (22.1) | 1.03x | 1.93x |
| CLI stdin, minified JSON 256 KiB (28.5) | 1.08x | 2.19x |
| Addon `scan`, clean 64 KiB (2.1) | 1.14x | 2.14x |
| Addon `scan`, logs 256 KiB (9.7) | 1.13x | 2.73x |
| Addon `scan`, minified JSON 256 KiB (19.9) | 1.10x | 2.55x |
| WASM `full`, clean 64 KiB (4.5) | 1.28x | 1.89x |
| WASM `full`, logs 256 KiB (13.8) | 1.56x | 2.92x |
| WASM `full`, minified JSON 256 KiB (30.8) | 1.25x | 2.54x |
| WASM `common`, clean 64 KiB (2.8) | 1.38x | 2.44x |
| WASM `common`, logs 256 KiB (7.2) | 1.40x | 3.27x |
| WASM `common`, minified JSON 256 KiB (9.6) | 1.52x | 3.61x |
| WASM `full` init (4.8) | 0.89x | 1.23x |
| Addon init (0.22 ms) | 0.89x | 1.12x |

Peak resident set size of the CLI on the three fixtures (three runs each, bytes)
moves within 1% to 6% in either direction (opt3 2.31 to 2.98 MB, opts 2.20 to
2.95 MB, optz 2.21 to 2.83 MB), so memory is not a differentiator.

Noise, stated honestly: this was a shared developer machine with other builds
running, so single samples span up to 30x (the first call of a fresh process is
slow, and a few samples caught other work). The medians are stable enough for
direction and rough magnitude, not for a precise percentage. Do not quote the
`opts` native CLI cells (0.95x to 1.16x) as a measured speedup or a measured
slowdown: they are inside the noise. Everything for `optz`, and every
WebAssembly and addon cell for `opts` above about 1.1x, sits well outside it.
This is the same direction the #1068 study found on Linux (opts 1.5x to 2.9x,
optz 2.5x to 2.9x on the minified fixture, VM noise included).

## Decision

**Keep `opt-level = 3` for every shipped artifact. Reject `s` and `z` as a
distribution default and as a per-artifact distribution profile.**

- WebAssembly, the artifact where bytes are the product constraint, gets bigger
  raw and at most 10% smaller compressed, while scanning 1.25x to 3.6x slower.
  There is no frozen WebAssembly size budget that this trade satisfies, and the
  card requires one before a winner is chosen.
- The native CLI and addon do shrink by 9% to 12% raw, but only `s` on the CLI
  is latency-neutral within noise, and a download of that size is not a stated
  constraint of any supported deployment. `z` is rejected outright (about 2x to
  2.7x slower for 1% more shrinkage than `s`).
- No budget exists to select against. Budgets must be frozen through #1068
  before formal judgement; this record supplies the measurements that decision
  needs and does not freeze any.

### Opt-in recipe (documented here, not adopted, not endorsed)

A consumer who builds the CLI or the addon from source and has a stated
size-over-speed budget can pass the profile on their own command line. It is a
root-workspace decision, so it applies to that whole invocation and not to any
one dependency:

```bash
cargo build --release --locked -p redact-secret-cli \
  --config 'profile.release.opt-level="s"'
```

The repository does not publish, test or support that build. Its SHA and output
equivalence above hold for the measured commit only. A consumer who adopts it
owns its qualification, and should not apply it to a WebAssembly build.

### Not measured

- Thin LTO or other codegen-unit settings. Nothing in the size data justifies
  the experiment: fat LTO and one codegen unit are already the shipped
  baseline, and thin LTO would only trade size for compile time. #1126 asked for
  these "separately, justified"; no justification emerged.
- Linux x86_64, musl, Windows, Python wheels and the Node WebAssembly fallback
  in a browser engine. Numbers are macOS arm64 and Node 22 only; the wheel is the
  same cdylib as the addon plus PyO3 and is not separately built here.
- Whole versus incremental timing and allocation counts: opt-level changes
  neither, and no allocation behaviour was in question. The CLI standard-input
  rows exercise the incremental path.

## Reproduction

The harness was throwaway and is not kept: `CARGO_PROFILE_RELEASE_OPT_LEVEL`
plus `CARGO_TARGET_DIR` per variant, the three `cargo build`/`node
scripts/build-browser-artifact.mjs` invocations above, a generator for the three
fixtures from a fixed seed, and a driver that rotates the variant order and
hashes each output. Final benchmark-run artifacts, if wanted, belong in
`redact-secret-benchmarks` per
[the placement ADR](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md).
