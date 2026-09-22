# redact-secret-cli

Binary name: `redact-secret`. Path: `crates/secret-scan-cli`.

Deterministic secret detection and redaction for runtime data and AI context,
from the command line: check files, staged diffs, and standard input in CI and
pre-commit hooks, or sanitize text in a redaction pipeline.

The CLI is a host adapter over the `redact-secret` core crate. It may use the
process environment, standard streams, and the filesystem; the core may not.
Every detection, policy, and redaction decision comes from the core, so a given
input produces the same findings here, in the library, and in every binding.

It checks the files and streams it is given; it does not walk Git history, so
it complements repository and history scanners rather than replacing them. It
is not a DLP platform and does not detect every secret: per-family support is
published in the generated
[support matrix](https://github.com/redact-secret/redact-secret/blob/main/docs/support-matrix.md).

```text
usage: redact-secret [--json] [--] [<path>...]
       redact-secret --redact [--] [<path>]
       redact-secret --version | -V
       redact-secret --help | -h
```

## Check mode

The default. Reads standard input when no path is given, and otherwise reads
every path in the order it was given.

```bash
redact-secret src/config.ts src/client.ts   # scan files
git diff --cached | redact-secret           # scan a staged diff
redact-secret --json .env.example           # machine-consumable report
```

Output carries safe file identity and finding metadata only. A range names a
span in the input; it never carries the bytes in that span, and no renderer
has the input available to resolve one.

```text
<source>:<start>-<end> <type> detector=<id> confidence=<level> action=<action> obfuscation=<none|invisible-characters> id=<finding>
```

`--json` writes one object with `version`, `rangeUnit`, `findingCount`, a
`sources` array of `{source, findings}`, and a `failures` array of
`{source, code, message}`. Ranges are UTF-8 byte offsets into the original
input, the unit `redact_secret::RANGE_UNIT` names. `id` is unique across the
whole report: the core numbers each scan from `finding-1` and a multi-file
check runs one scan per file, so the report renumbers run-wide rather than
handing a consumer colliding keys.

Text reports and stderr diagnostics escape source-path backslashes and
non-printing characters (for example, a newline becomes `\n`) so a filename
cannot inject another record or terminal control sequence. JSON retains the
original source identity through JSON string escaping; use it for automation.
Paths are caller-supplied labels: do not put credentials in filenames.

## Redact mode

`--redact` reads standard input, or exactly one path, and writes the sanitized
text to standard output. The input is never modified in place, and no path is
ever opened for writing.

```bash
redact-secret --redact log.txt > log.redacted.txt
kubectl logs pod | redact-secret --redact
```

Standard input is sanitized as it streams, so a failure part way through leaves
the text written so far on standard output. That prefix is sanitized — every
unit is redacted before it is written — but it is not the whole input, so check
the exit code before using the output. Buffering the whole stream until success
would trade that for unbounded memory, which is what streaming exists to avoid.

## Exit codes

| Code | Check mode | Redact mode |
| --- | --- | --- |
| `0` | Every source was scanned and nothing was found. | The whole sanitized stream was written. |
| `1` | Every source was scanned and at least one finding exists. | Never returned. |
| `2` | Usage, decoding, or processing failure. | Usage, decoding, or processing failure. |

Redaction does not report a finding through its exit code: finding something is
what redaction is for, not a failure. Run check mode when a finding should fail
a hook or a job.

In check mode a failure outranks a finding: a run that could not read or decode
part of its input has not proved that part clean, so it exits `2` even when
another source produced findings. Input that is not valid UTF-8 fails closed
rather than being scanned in part, and the diagnostic names the source and a
fixed code, never the bytes that failed.

## Streaming, limits, and retention

Standard input is streamed through the core's incremental sanitizer, because a
credential may straddle any chunk boundary; a path is read whole. Both are
bounded by the explicit limits `--help` prints: total input per source,
retained unresolved plaintext, an open single-line construct, and an open
PEM-style block.

The construct limits bound the streamed path only — a path read whole is
bounded by the input limit and, independently, the core's own default
whole-input finding-count bound (50,000;
`decision-bound-whole-input-operations-by-default`), which `--help` does not
print because it is the library's own default rather than a CLI-declared
value — so the construct limits are sized for what a pipeline actually
carries rather than for what a credential needs. The core applies the token
limit to every unresolved logical line, so a limit tuned to credential length
would reject a minified bundle, a lockfile entry, or a base64 blob on standard
input while the same file scanned by path succeeded. One mebibyte covers
those and still bounds retained plaintext.

Every failure path leaves the session holding nothing. A partial read, a
decoding failure, a limit failure, and a closed downstream pipe each either
propagate a core error the core has already discarded behind, or abort the
session, which discards what it was holding.
