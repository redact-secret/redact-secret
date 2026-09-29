# Evidence: #990, incremental output equal to the whole-input scan on the #985 gaps

**Result:** the five layouts the #985 audit found where a per-line
incremental session and a whole-input scan disagreed now give the same
text and findings at every chunk boundary. Two of them were streaming false
negatives: a credential the whole-input scan redacts was left in the
streamed output. None of the five is left as a documented exception. On the
#981 harness every workload is 3-9% faster than `main`, whole and
incremental.

Issue [#990](https://github.com/redact-secret/redact-secret/issues/990),
found by the [#985 audit](../985/README.md) ("Pre-existing
partition-invariance gaps"), parent
[#980](https://github.com/redact-secret/redact-secret/issues/980). Base:
`main` at `37a1dcd7`, which includes #985 and #986.

## What changed, per gap

File references are to `crates/secret-scan-core/src/`.

| Gap | Before (whole vs streamed) | Fix | Side changed |
| --- | --- | --- | --- |
| `generic-token` name on one line, `=`/`:` on the next: a backticked name, a quoted name glued to the text before it (`x"password"`), an escaped quoted name (`{\"password\"`), a JWK secret member (`"k"` on a `"kty"` line) | whole: finding; streamed: none (**FN**) | `has_open_contextual_assignment` (`detectors/generic_token.rs`) accepts every boundary the grammar accepts before a name (a quote or backtick on its own) and a quoted JWK secret member whose own line carries `"kty"` (`is_open_jwk_secret_member`). Its name forms are now a superset of the grammar's. | incremental |
| `Proxy-Authorization:` then `Bearer <12-15 bytes>` on the next line | whole: finding (header floor 12); streamed: none (**FN**, bare floor 16) | `has_open_bearer_authorization` (`detectors/bearer_token.rs`) holds a `Proxy-Authorization` name, using the detector's own `preceded_by_proxy_prefix`. | incremental |
| `X-Authorization:` then `Bearer <16+ bytes>` | whole: none; streamed: finding. The same line (`X-Authorization: Bearer <token>`) gave nothing whole-input either. | The detector skipped past the value after rejecting the `authorization` header match, so the bare `Bearer` match after it was never tried. A rejected header match now advances one character. Both paths report the value at the bare 16-byte floor. | whole-input |
| Lone `\r` line endings, keyword-gated families (Datadog, Mailchimp, Mailgun, New Relic, Okta, Travis CI, Mistral, Cohere, AI21, Deepgram, Heroku, Twilio, Confluent, legacy Pinecone, the JWK `"kty"` line) | whole: `\r`-separated lines read as one line; streamed: separate units | One shared `text::lines` ends a line at `\n` and after a lone `\r` (the `\r` stays in its line, as a CRLF `\r` does). It replaces ten copies of a `\n`-only splitter, `pinecone`'s `split('\n')` and `jwk_line_spans`' `split_inclusive('\n')`. The Heroku, Twilio and Confluent hints read back through `text::last_lines`. | whole-input (matches the units the session already closed) |
| Twilio CLI table under `\r`-only endings | whole: fine; streamed: `$ twilio …\r` held every later line until `TokenLimitExceeded` | Same fix: `has_open_twilio_cli_table` sees `\r`-separated lines, so the command line's unit closes at the next line. | incremental |
| PII phone `ext` at a line end | whole: judged by the next line (`ext\nhello` kept the number); streamed: judged alone (dropped it) | `has_word_extension_marker` (`pii/pii_phone.rs`) reads the payload on the marker's line: a line break ends it as the end of input does. The contract already excludes a newline-separated extension (`phone-extension-line-break`). | whole-input |

### Why lone `\r` is a line end

The incremental session ends a unit at `\n` or `\r` (`find_next_newline`).
`is_line_start` (the grammar's `^`) treats `\r` as a line terminator, and PII
context arbitration treats `\r` as a logical-line break. Only the detectors
with their own `lines` helper split on `\n` alone, and each of those helpers
already claimed to use "the same processing unit the incremental sanitizer
hands a detector". `text::lines` makes that claim true. A `\r` directly before
`\n`, or at the end of the input, stays inside its line, so the lines of LF
and CRLF input are byte-for-byte what they were: no conformance fixture
changed.

### #985's batching exclusion for lone `\r`

#985 started a new batch after a lone `\r`, because the `\n`-only detectors
read two `\r`-separated units as one line. Every such detector now ends a
line there, so the rule is removed (`starts_new_batch` in `incremental.rs`).
The batched-vs-per-line differential tests (`tests/incremental_batching.rs`)
already join every corpus with `\r` line endings and include the
`datadog\r…`, `mistral\r…` and JWK `\r` layouts. They pass without the rule.
Mutation check: with `text::lines` reverted to `\n`-only and the rule still
removed, `batching_is_invisible_across_every_layout_the_audit_found_reading_across_units`
and `batching_is_invisible_over_the_synchronous_corpus` fail.

The `continues_previous_line` exclusion (units starting with `=`, `:` or
`bearer`) is kept. The hints now hold every layout the audit found, so it
should no longer fire on a real difference, but it is cheap and guards
against a grammar and its hint drifting apart again.

## False-positive and false-negative tradeoffs

- `generic-token`, `Proxy-Authorization`, Twilio `\r`: streaming FNs removed,
  no whole-input change. The only cost is that such a line is held until the
  next non-blank line.
- `X-Authorization: Bearer <token>` (and `HTTP_AUTHORIZATION: bearer …`): a
  whole-input FN removed. No FP beyond the bare `Bearer` rule, which already
  reports the same value with no header in front of it.
- Lone `\r`: on `\r`-only input a keyword on one line no longer gates a value
  on the next (`datadog\r<32 hex>` was a `datadog_api_key` finding whole and
  nothing streamed; now nothing on both paths). Keyword gating is same-line by
  contract, so this is the documented behaviour applied to one more line
  ending. LF and CRLF input: no change.
- PII phone: `212-456-7890 ext` at a line end followed by prose used to keep
  the number whole-input; it is now dropped on both paths, like `ext` at the
  end of the input. A rare layout, and the contract excludes a
  newline-separated extension.

The spec rows are in `docs/specs/contextual-detection.md` (#990 rows after
"`connection-string` and `jwt` have no incremental retention hint") and in
the phone contract (`docs/contracts/pii/phone-v1.md`).

## Tests

`tests/incremental_partition_gaps.rs`. Each case runs at every UTF-8 byte
boundary, every `&str` boundary, one byte per `append` and one line per
`append`, and compares text and findings with the whole-input reference
under the same profile. Each case also pins the reference's finding count,
so both paths cannot agree by losing the finding.

| Test | Cases |
| --- | --- |
| `a_generic_token_name_the_grammar_joins_to_a_later_operator_is_retained` | backticked, glued `"`/`'`, escaped quoted name; JWK member (LF, CRLF, blank lines before the operator); `"kty"` on a later line (0 findings) |
| `a_bearer_credential_after_a_header_on_an_earlier_line_matches_the_whole_input_scan` | `X-Authorization` next line and same line; below the bare floor (0); `Proxy-Authorization` with a 13-byte value, colon on its own line, CRLF; `xproxy-authorization` (0) |
| `a_lone_carriage_return_ends_a_line_for_every_detector` | Datadog keyword on the previous `\r` line (0), same line (1), CRLF (0); Pinecone keyword on the previous `\r` line (0), same line (1); Twilio CLI table under `\r`; JWK `"kty"` on the previous `\r` line (0) |
| `the_incremental_corpus_is_partition_invariant_under_cr_and_crlf_line_endings` | every multi-line fixture of `incremental-corpus.json` rewritten to CR and to CRLF, every `&str` boundary and one line per `append` |
| `a_twilio_command_under_lone_carriage_returns_closes_at_its_next_line` | `$ twilio profiles:list x\r` + 3,000 `row\r` under 1 KiB construct limits, whole chunk and one line per `append` |
| `a_phone_extension_marker_is_judged_on_its_own_line` (`pii:global`) | `ext`/`ext.`/`extension` at a line end followed by prose or digits, LF/CRLF/CR (0); same-line extension and `extra` controls (1) |

All six fail on `main` (`37a1dcd7`) and pass here. Unit tests cover the
hint forms (`generic_token.rs`, `bearer_token.rs`), the bearer bare match
after a wider header name, the phone marker, and `text::lines` /
`text::last_lines` against a byte-by-byte reference over every string of up
to six symbols from `a`, `\r`, `\n` and a three-byte code point, padded
across the eight-byte search window. `tests/incremental_partitions.rs`,
`tests/incremental_batching.rs`, `tests/adversarial_bounds.rs` and the
conformance suites pass unchanged, and the #986 differential assertion
(maintained open-construct state equals a fresh rescan after every closed
line) still runs under every test that drives a session.

## Numbers

**Host:** Apple M4, macOS, `rustc 1.98.1`, release profile (`cargo bench`),
shared with other agents (load average about 4).

**Method:** the #981 harness (`benches/scan_cost.rs --no-detectors`), built
from `main` `37a1dcd7` (base) and from this change. The two binaries ran
interleaved (base then new, new then base, base then new), three rounds of
11 runs per figure (5 for `mixed-10m`). The table shows the median of the
three round medians, in ms.

| Workload | Path | base | #990 | change |
| --- | --- | ---: | ---: | ---: |
| `scale-logs-64k` | whole | 1.92 | 1.75 | -9.0% |
| `scale-logs-64k` | incremental, 64 KiB chunks | 2.54 | 2.36 | -7.2% |
| `scale-logs-256k` | whole | 7.63 | 7.09 | -7.0% |
| `scale-logs-256k` | incremental, 64 KiB chunks | 10.12 | 9.33 | -7.9% |
| `scale-logs-256k` | incremental, 4 KiB chunks | 10.19 | 9.63 | -5.5% |
| `mixed-10m` | whole | 344.1 | 316.4 | -8.1% |
| `mixed-10m` | incremental, 64 KiB chunks | 465.9 | 443.1 | -4.9% |
| `provider-tables-64k` | whole | 2.21 | 2.07 | -6.2% |
| `provider-tables-64k` | incremental, 64 KiB chunks | 3.10 | 3.01 | -3.0% |
| `unicode-invisible-64k` | whole | 1.79 | 1.64 | -8.4% |
| `unicode-invisible-64k` | incremental, 64 KiB chunks | 2.55 | 2.46 | -3.3% |
| `minified-json-64k` | whole | 2.07 | 1.89 | -8.9% |
| `minified-json-64k` | incremental, 64 KiB chunks | 2.14 | 1.96 | -8.8% |
| `minified-json-256k` | whole | 8.25 | 7.57 | -8.2% |
| `minified-json-256k` | incremental, 64 KiB chunks | 8.58 | 7.81 | -9.0% |
| `open-assignment-whitespace-10k` | whole | 2.24 | 2.10 | -6.5% |
| `open-assignment-whitespace-10k` | incremental, 64 KiB chunks | 3.53 | 3.30 | -6.7% |

Every round agreed on direction. The one outlier round (`mixed-10m` whole,
363 ms) is above both other rounds of the same build.

**Where the speedup comes from.** About a dozen detectors walk the whole
input line by line. The old helpers found each `\n` with a byte loop.
`text::lines` tests eight bytes per step for `\n` or `\r` (`next_line_byte`,
a word-at-a-time zero-byte test, no `unsafe`).

Two earlier drafts measured slower than base and were not kept:

- A byte loop testing both terminators: +4% to +8% on every workload.
- A `memchr` search per line (`str::find`): -8% on long lines, but +16% to
  +23% on `open-assignment-whitespace-10k`, whose lines are nine bytes long.
  There the per-call setup cost dominated.

The per-detector attribution run on `scale-logs-256k` showed the regression
in the line-walking detectors (`pinecone-api-key` 0.245 to 0.297 ms,
`heroku-api-key-legacy` 0.238 to 0.255 ms), which is what led to the
eight-byte search.

Not measured: a `\r`-only workload. The harness has none, and the batching
exclusion removed above only affects such input.
