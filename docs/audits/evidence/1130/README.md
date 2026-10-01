# #1130 — `panic = "abort"` for the standalone CLI: keep unwind

Product judgement. Final record for [#1130](https://github.com/redact-secret/redact-secret/issues/1130)
(parent #1068, epic #1065). A measured rejection. No `Cargo.toml`, workflow or
failure contract changed. It shares its toolchain and fixtures with
[#1126](../1126/README.md).

## Question

Is `panic = "abort"` worth its changed failure semantics for the standalone
`redact-secret` executable only, never for the library, Node addon, Python wheel
or WebAssembly build?

## Method

- Source `44382b3f3006a3a34a2bab917711d00e2e53284a`, `rustc` 1.98.1, Apple M4
  (macOS arm64), Node.js 22.16.0 as the harness.
- Two builds of `cargo build --release --locked -p redact-secret-cli`, one
  invocation each, in separate `CARGO_TARGET_DIR`s, with the workspace profile
  unchanged except `CARGO_PROFILE_RELEASE_PANIC=abort` for the second. Nothing
  else was built with abort: no addon, wheel or WebAssembly artifact exists in
  that target directory.
- The recipe that keeps the scope to the executable is a separate cargo
  invocation for that package. `Cargo.toml`'s `[profile.release]` is
  workspace-wide and cannot be set per package for `panic` or `lto`
  ([Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)),
  so editing it would also change every binding. `cargo test` ignores the panic
  strategy, so a passing suite says nothing about abort behaviour; the
  subprocess runs below are the only evidence.
- Fault injection used a throwaway patch to `crates/secret-scan-cli/src/modes.rs`
  that panics on an environment variable, built twice (unwind, abort) and then
  reverted; it is not in the repository. Cases: a panic after the fourth
  standard-input chunk, the same panic with a message that quotes the first 12
  characters of the current chunk (to show what a panic message can carry), and
  a panic in `--redact <file>` mode just before its single write. The input was
  400 synthetic lines, 20 of them carrying a runtime-generated synthetic
  `ghp_`-shaped token, fed in 1 KiB pieces 15 ms apart so the CLI's 8 KiB
  `BufWriter` holds sanitized text when the fault fires.

## Artifact delta (actual CLI)

| | unwind (shipped) | abort | delta |
| --- | ---: | ---: | ---: |
| Raw bytes | 1,271,680 | 1,172,800 | -98,880 (-7.8%) |
| gzip -9 | 589,053 | 554,466 | -34,587 (-5.9%) |
| brotli -11 | 443,182 | 420,644 | -22,538 (-5.1%) |

This is larger than the 24 KiB / 2.85% the #1068 study saw in a minimal Linux
application, and smaller than it looks as a user cost: the CLI is installed
once, not downloaded on every page load, and no supported deployment states a
CLI size budget.

Latency, three rotated rounds of seven samples under the shared benchmark lock,
whole-process wall time, median ratio abort / unwind (opt3 median in
milliseconds in parentheses; the machine was quiet for this run, which is why
these absolute times are lower than the #1126 run):

| Case | abort / unwind |
| --- | ---: |
| `--redact <file>`, clean 64 KiB (4.5) | 1.01x |
| `--redact <file>`, logs 256 KiB (9.0) | 1.00x |
| `--redact <file>`, minified JSON 256 KiB (15.1) | 1.03x |
| `--redact` stdin, clean 64 KiB (4.9) | 0.97x |
| `--redact` stdin, logs 256 KiB (12.8) | 0.92x |
| `--redact` stdin, minified JSON 256 KiB (16.8) | 0.97x |

All six are inside the run-to-run spread (the per-case minimum and maximum
overlap), so no latency claim is made in either direction. Output SHA-256 is
identical for all six cases. Peak resident set size is 1% to 2% lower with
abort (for example 2.95 to 2.97 MB against 2.98 to 3.00 MB on the JSON fixture),
which is not a deciding difference.

## Host-failure review

Observed (subprocess, synthetic data, exit status as reported by the OS):

| Case | Unwind | Abort |
| --- | --- | --- |
| No fault, standard input | exit 0, 400 lines | exit 0, 400 lines (byte-identical) |
| Panic after chunk 4, standard input | exit **101**, 190 sanitized lines on stdout (3,781 bytes), cut at a line boundary | killed by **SIGABRT**, **0 bytes** on stdout |
| Same, message quotes 12 characters of the chunk | identical stderr to the row above plus those 12 characters | identical stderr to unwind, same 12 characters |
| Panic in file mode before the single write | exit 101, 0 bytes on stdout | SIGABRT, 0 bytes on stdout |

- **Exit status.** Neither is the CLI's documented `2`. The README's exit-code
  table lists `0`, `1` and `2` only, so a panic is outside the documented
  contract under both strategies. Unwind exits `101`; abort dies by signal
  (shell status 134). A caller that treats any non-zero status as failure sees
  no difference. A caller that matches `2` sees neither.
- **Stdout.** Unwinding drops `main`'s `BufWriter`, which flushes the sanitized
  text it already held, so unwind leaves a sanitized prefix (here 190 lines).
  Abort never runs the drop, so whatever sat in the buffer is lost. The README
  already tells callers that a failure part way through streaming leaves a
  sanitized prefix and that the exit code must be checked first, so a shorter
  prefix does not break the contract, and a longer one does not either. Neither
  strategy ever wrote an unsanitized byte. The prefix length is a function of
  buffering and arrival timing under both, so it is not a stable property to
  build on.
- **Diagnostic privacy.** The panic hook prints the message and location before
  either strategy takes effect, so stderr is identical under both. What the
  message contains is decided by the panic site, not by the strategy: the
  injected message that quoted the chunk printed it under both, and an ordinary
  panic printed only a fixed string and a source location under both. The
  workspace denies `panic!`, `unwrap` and `expect` by lint, so the realistic
  sources are arithmetic overflow and slice or index errors inside std, whose
  messages can include small pieces of the value being sliced; that exposure
  exists today with unwind and abort changes none of it.
- **Core dumps (mechanism, not measured here).** `SIGABRT`'s default action on
  Linux is to terminate and dump core when the host permits it, and a dump holds
  the heap, where the session's un-cleared plaintext buffers live. An unwinding
  exit through `exit(101)` writes no dump. The
  [plaintext lifetime contract](../../../reference/plaintext-lifetime.md) already
  lists core and crash dumps as outside what the core addresses, but moving
  the CLI's panic from "exits with a status" to "raises a dumping signal" would
  widen that exposure for a gain of 99 KB. This was not tested on Linux, and
  that is the weakest of the review's points.
- **Destructors and memory.** Under unwind, dropping a session frees its buffers
  without clearing them (contract item 7: no abort guard on unwind). Under abort
  nothing is dropped and the OS reclaims the process. Neither erases plaintext.
  This record makes no erasure or unwind-destructor claim under either strategy.
- **Recoverable errors.** Every `Result` path (usage, not UTF-8, read, write,
  core and ruleset failures) is unchanged and still exits `2` with a fixed,
  input-free message under both, because they never panic. The abort build was
  not run against the full CLI test suite: `cargo test` ignores the strategy.
- **Host-runtime termination.** The abort build is one executable. No Node
  process, Python interpreter or browser embeds the CLI, and the bindings were
  not built with abort, so no host runtime gains a termination path. `wasm32`
  panics already trap, so a WebAssembly build is unaffected either way.

## Decision

**Keep `panic = "unwind"` for the CLI, and for everything else.** Do not add an
abort build to the release workflow.

- The measured saving is 7.8% raw and 5.1% to 5.9% compressed on an artifact
  with no stated size budget, against a latency change indistinguishable from
  noise.
- The behaviour change is not a clear win or a clear loss: abort loses a
  sanitized prefix that unwind keeps, and trades a clean `101` exit for a signal
  whose default action can write the process heap to disk. A changed supported
  failure contract would also have to be coordinated with #1066 and #1069, and
  nothing here justifies spending that.
- A 2.85% minimal-application saving, or this 7.8% CLI saving, does not clear
  the "compelling benefit" bar the card sets for changed semantics.

### Documented opt-in recipe (not adopted, not supported)

A consumer who builds the CLI from source and accepts the behaviour above can
scope abort to the executable with a separate invocation:

```bash
cargo build --release --locked -p redact-secret-cli \
  --config 'profile.release.panic="abort"'
```

Never place `panic = "abort"` in the workspace `[profile.release]`, and never
apply it to a library, the Node addon or the Python wheel: it terminates the
host process, and Cargo takes the setting from the root workspace only.

### Noted for #1066 and #1069, not changed here

A panic in the CLI exits `101` (or dies by signal), which the README's exit-code
table does not list. Whether the stable contract should say "any other status is
an internal failure" or catch panics at `main` and exit `2` is a failure-contract
decision for that card. This record changes nothing about it.

### Not measured

Linux and Windows behaviour (core dumps, `abort` exit status 134 versus the
Windows fast-fail code), the Python-embedded and Node-embedded paths, memory
under abort for long standard-input streams, and the other five `cli-release-targets`.
