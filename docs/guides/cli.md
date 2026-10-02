# Command line

[Documentation home](../README.md) · [Installation](../getting-started.md)

The `redact-secret` binary is a host adapter over the same core, for CI,
pre-commit hooks, and safe redaction pipelines.

Install it with `cargo install redact-secret-cli --locked --version <version>`.
While every release is a beta, `--version` is required, and no prebuilt binary
is published. The [quickstart](../quickstart.md#command-line) gives the exact
command and the expected output.

```bash
redact-secret config.txt              # check a file
git diff --cached | redact-secret     # check a staged diff
redact-secret --json config.txt       # JSON metadata report
redact-secret --redact input.txt > sanitized.txt
redact-secret -- --leading-dash.txt   # stop option parsing
redact-secret --ruleset org.rules config.txt   # add a declarative ruleset
```

`--ruleset <path>` works in check and redact mode. It loads a
[declarative ruleset](rulesets.md) and applies it to every path source in
addition to the built-in detectors. It requires an explicit path source,
because standard input's streaming session accepts no custom detector, and a
malformed ruleset fails the whole run with `INVALID_RULESET` before any source
is scanned.

PII defaults off. Repeat `--pii <selector>` to request a canonical selector
set, or use `--print-pii-activation` to print its activation identity and exit
without opening standard input or any file. `--pii pii` closes over the
available `pii:global:email`, `pii:global:iban`, `pii:global:network-address`,
`pii:global:payment-card`, and `pii:global:phone` families; use a
`pii:family:global:*` selector for
exact selection. `--pii pii:us` closes over those global families plus
`pii:us:ssn`; `--pii pii:family:us:ssn` selects only SSNs. They require reviewed
high-signal context. Under `pii-v1`, the five global families are `provisional` (not `stable`;
phone covers `+1` / NANP only) and US SSN is `pending`; see
[detection](../reference/detection.md#opt-in-pii-availability-is-not-support). Invalid, unsupported, unavailable, and conflicting
selections use fixed input-free diagnostics.

```bash
redact-secret --pii pii --print-pii-activation
# credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2
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

These three are the only statuses the CLI chooses. A status of any other value
(for example `101` after an internal panic, or death by a signal) is an
internal failure outside the contract: treat it like `2`, and discard any
output. Standard output may then hold a sanitized but incomplete prefix; the
CLI never writes an unsanitized byte
([measured](../audits/evidence/1130/README.md)).

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
