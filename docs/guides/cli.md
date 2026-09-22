# Command line

[Documentation home](../README.md) · [Installation](../getting-started.md)

The `redact-secret` binary is a host adapter over the same core, for CI,
pre-commit hooks, and safe redaction pipelines.

```bash
redact-secret config.txt              # check a file
git diff --cached | redact-secret     # check a staged diff
redact-secret --json config.txt       # JSON metadata report
redact-secret --redact input.txt > sanitized.txt
redact-secret -- --leading-dash.txt   # stop option parsing
```

With no paths, the CLI reads standard input. With paths, check mode reads each
file; redaction accepts exactly one. It does not recursively walk directories
or modify files in place. Use different input and output paths: shell redirection
can truncate a file before the CLI reads it.

| Exit | Check mode | Redact mode |
| --- | --- | --- |
| 0 | Every source scanned; no findings | Whole output written successfully |
| 1 | Every source scanned; at least one finding | Unused |
| 2 | Usage, read, UTF-8, limit, or write failure | Processing failed; output may be partial |

Check exit codes are the enforcement contract. A failure outranks a finding,
and input that is not valid UTF-8 fails closed. Redaction reports `0` or `2`
only: finding something is what it is for, not a failure.

Check mode flags **any** finding, including `warn` and `allow`. Redact mode
replaces only `redact` and `block` spans under the default policy, so successful
redaction does not guarantee that every detected range was removed.

## Pipelines and CI

In Bash, enable `pipefail` so a failed producer cannot masquerade as clean input:

```bash
set -o pipefail
git diff --cached | redact-secret
```

A diff is only the text emitted by Git: it can include removed lines and omit
unchanged parts of a credential. This is a convenience check, not a complete
scan of the staged tree. Scan complete file contents when that is the intended
boundary.

Standard input is streamed through the incremental core under explicit
limits, because a credential may straddle any chunk boundary; a path is read
whole under the same total-input bound. UTF-8 decoding is strict. A failure can leave
a successfully sanitized but incomplete prefix on stdout. Accept an output
file only after exit 0. `--help` lists limits; paths and standard input share a
total-input bound, but streamed input has additional open-line and multiline
limits. Long unbroken lines can therefore fail on stdin but pass as a file.

## Reports

Use `--json` for machine consumption. It emits `version`, `rangeUnit`,
`findingCount`, `sources`, and `failures`; finding IDs are unique across a run.
Ranges count UTF-8 bytes in each original source. Output carries safe file
identity and finding metadata only: a range names a span in the input, never
the bytes in that span. Neither format prints matched file content. Text reports and diagnostics escape non-printing path characters
and backslashes; JSON decoding recovers the original path. Filenames themselves
must not contain credentials.

See the [complete CLI reference](../../crates/secret-scan-cli/README.md).
