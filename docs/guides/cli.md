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
redact-secret --action-policy policy.json config.txt   # change what a finding does
redact-secret --compare-action-policy next.json config.txt   # preview a policy, nothing enforced
```

`--ruleset <path>` works in check and redact mode. It loads a
[declarative ruleset](rulesets.md) and applies it to every path source in
addition to the built-in detectors. It requires an explicit path source,
because standard input's streaming session accepts no custom detector, and a
malformed ruleset fails the whole run with `INVALID_RULESET` before any source
is scanned.

`--action-policy <path>` works in check and redact mode, with a path or with
standard input. It loads a [declarative action policy](action-policy.md) (a
JSON document of ordered rules, at most 65,536 bytes) and applies it to every
finding in place of the default policy: the first matching rule picks `redact`,
`block`, `warn` or `allow`, and a finding no rule matches keeps the default
action. The file is read once, with a bounded read, before any source is
touched. A rejected policy fails the whole run with exit 2 and
`INVALID_ACTION_POLICY`, followed by the fixed rejection class and, when the
violation is inside a rule, its zero-based `rule_index`; the message never
quotes the file.

```text
redact-secret: INVALID_ACTION_POLICY: a rule action is not supported. (class=INVALID_ACTION rule_index=0)
```

The exit codes do not change: check mode still exits 1 when any finding exists,
whatever its action (an `allow` finding is still reported), and redact mode
replaces only `redact` and `block` spans. `--action-policy` and `--ruleset` can
be combined, which is how one rule makes a ruleset detection redact.

## Compare action policies

`--action-policy` and `--compare-action-policy` were introduced in
`0.1.0-beta.14`; a `0.1.0-beta.13` binary has neither.

`--compare-action-policy <path>` previews policies instead of enforcing one. It
is repeatable (1 to 3 times), needs exactly one explicit file path, and refuses
`--redact` and standard input with a usage error (exit 2). Detection runs once;
the baseline (`--action-policy <path>`, or the default policy) and every
candidate then decide the same finalized findings. Each finding line lists
`baseline=<action>(<basis>)` and `candidate-N=<action>(<basis>)`, where the basis
is `rule:<id>#<index>`, `rule-default:<id>#<index>`, `no-rule-matched` or
`default-policy`; `--json` adds `mode: "preview"`, `enforced: false`, the
detection configuration, each policy's `documentSha256` and per-action counts,
and per-finding `differs`. `--ruleset` and `--pii` apply to every side.

Exit `0`: every policy chooses the same action for every finding. Exit `1`: at
least one finding's action differs. Exit `2`: any failure, including a rejected
policy file (`INVALID_ACTION_POLICY`), with nothing on standard output. A finding
alone is not a failure here. The input is never written and never echoed. See the
[action policy guide](action-policy.md#explain-and-compare) for what a comparison
does and does not cover.

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
([measured](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1130/README.md)).

A path is a whole-input call, so exit `0` or `1` for it means every detector
inspected the whole file; standard input is incremental, so a failed
`--redact` run can leave a sanitized prefix. The CLI has no timeout or
cancellation option. See
[Completeness of `Ok`](../reference/api-contract.md#completeness-of-ok) and
[Cancellation and time bounds](../reference/api-contract.md#cancellation-and-time-bounds).

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
