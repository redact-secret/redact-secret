# Evidence: #985, processing the lines closed in one `append` as one batch

**Result:** an incremental session now runs detection once over all the
units that close in one `append` call, instead of once per closed line.
Policy and redaction still run unit by unit. Output is byte-identical: the
same text, findings, ids, ranges, actions, errors, error order and callback
calls. On the #981 harness, the incremental path takes 35-41% less time
on logs (`scale-logs-256k`: 31.7 ms to 19.8 ms) and on the 10 MiB mixed
workload (1,480 ms to 881 ms). It is now within 20% of a whole-input scan
of the same bytes.

The audit found real cases where scanning several units together would
change a unit's findings. None of them is papered over. Each one is either
excluded from batching or made impossible by construction, and each has a
differential test that fails when its safeguard is removed. Every one of
those cases is also a place where today's per-line incremental output
already differs from the whole-input scan; those gaps are listed at the end
for follow-up and are not changed here.

Issue [#985](https://github.com/redact-secret/redact-secret/issues/985),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The research comment on #985 set the scope. It builds on #986
([evidence](../986/README.md)), which made the open-construct checks
incremental.

## What changed

- **Batching (`src/incremental.rs`).** `retained` now holds the closed units
  waiting in the batch, followed by the current unit. `unit_start` marks
  where the current unit begins and `unit_ends` records where each waiting
  unit ends. When a line closes with no open construct, the unit joins the
  batch. The batch is processed at the end of the `append` call.
- **Everything that used to be per unit stays per unit.**
  - The open-construct checks, the scan copy, the tail cache and the
    private-key tracker only ever see the current unit, and they reset at
    every unit boundary.
  - The token, multiline and buffered limits are measured on the current
    unit, as before, not on `retained`.
- **Memory stays within `max_buffered_bytes`.** The waiting units are
  processed before `retained` would grow past the limit.
- **Error order is unchanged.** Before any limit failure is raised, the
  waiting units are processed, so an earlier line's policy or formatter
  failure is still the error reported.
- **One pipeline call per batch (`detect_units` in `src/pipeline.rs`).**
  - Detection runs once over the batch text.
  - The findings are split back into units, and each unit gets policy and
    `redact` on its own text. Each unit therefore keeps its own
    whole-input limits, its own forbidden-placeholder set and its own
    callback order.
  - If a candidate reaches a unit boundary, or if the batched call fails,
    the batch is scanned again one unit at a time. That reproduces any
    failure in the order per-unit processing would hit it. No callback has
    run before this fallback.
- **Local findings are built once.** Global and unit-local findings come out
  of one loop. The placeholder formatter finds each finding's global form by
  position (binary search on the start offset) instead of through a
  per-unit `HashMap`.

### What is guaranteed by construction

- **Overlap ties resolve as in a single unit.** `EvidenceWeight` breaks a
  final tie on `candidate_order`, the detector's emission index. Over a
  batch, that index would count candidates from earlier lines, so a unit's
  exact tie could flip (research comment, `pipeline.rs:252-261`).
  `detect_units` counts `candidate_order` within the candidate's own unit.
  The raw index is kept separately (`emission_index`) for the shadow lookup.
  - With every candidate inside one unit, the optimal disjoint selection
    breaks down into one selection per unit: candidates from different
    units never overlap, and an earlier unit's total is added to both sides
    of every comparison.
  - The severity, specificity and confidence tiers use `base^rank` with
    `base` = n + 1. They compare the same way for any base larger than the
    unit's own candidate count, so the batch's larger base changes nothing.
- **No candidate reaches a unit boundary.** A candidate that ends at or
  crosses the end of any unit except the last makes `detect_units` return
  `Ok(None)`, and the session falls back to per-unit scanning.
- **PII runs per unit.** Inside `detect_units`, the PII detector
  (`pii-domain`) is called once per unit on that unit's slice, and its
  ranges are shifted. This removes both PII risks the audit found (below):
  - PII context arbitration costs O(k·n + k² log k) per call. Over a 64 KiB
    batch that measured 6.5x slower on phone-dense input.
  - A phone number followed by a word extension marker reads the next line.

### What the session excludes from batching

`IncrementalSanitizer::starts_new_batch` flushes the waiting units before
adding a unit, so that unit starts a new batch, in two cases:

1. **After a lone `\r`.** The unit before ends in `\r` and this unit does not
   start with `\n`. Units end at `\n` or `\r`, but many detectors split lines
   at `\n` only, so two `\r`-separated units would read as one line. A `\r\n`
   pair is two units, the second a lone `\n`, and stays batchable.
2. **When a detector can continue the unit from an earlier line**
   (`continues_previous_line` in `detectors/mod.rs`). The unit's first
   non-whitespace text is `=`, `:` or `bearer` (any case).
   - `generic-token` skips whitespace, line terminators included, between a
     name and its operator.
   - `bearer-token` does the same inside `authorization : bearer`.

## Per-detector audit

Method:

- Every `impl Detector` was read against one rubric: backward reads across
  a line terminator, forward reads past the unit's end, whole-input
  properties, start/end-of-input asymmetry, emission order, and multi-line
  layouts versus their retention hints.
- Every RISK below was confirmed with a throwaway probe that scanned the
  unit alone and scanned it with the neighbouring text.
- File references are to `crates/secret-scan-core/src/`.

| Detector(s) | Verdict | Evidence | How batching handles it |
| --- | --- | --- | --- |
| Prefix and shape providers: `stripe-token`, `pypi-token`, `huggingface-token`, `docker-token`, `digitalocean-token`, `supabase-token`, `supabase-management-token`, `vercel-token`, `npm-token`, `google-api-key`, `grafana-cloud-access-policy-token`, `pulumi-access-token`, `datadog-application-key`, `replicate-api-token`, `groq-api-key`, `xai-api-key`, `openrouter-api-key`, `perplexity-api-key`, `fireworks-ai-api-key`, `anthropic-token`, `apify-api-token`, `atlassian-api-token`, `aws-access-key`, `azure-devops-personal-access-token`, `cloudflare-token`, `composio-api-key`, `convex-deployment-key`, `databricks-personal-access-token`, `doppler-token`, `e2b-api-key`, `elevenlabs-api-key`, `firebase-server-key`, `firecrawl-api-key`, `github-token`, `gitlab-token`, `gitlab-runner-authentication-token`, `grafana-service-account-token`, `helicone-api-key`, `inngest-signing-key`, `langfuse-secret-key`, `langsmith-api-key`, `linear-token`, `microsoft-entra-client-secret`, `neon-api-key`, `netlify-token`, `notion-token`, `onepassword-service-account-token`, `posthog-token`, `postman-api-key`, `postman-collection-access-key`, `resend-api-key`, `sendgrid-token`, `shopify-token`, `telegram-bot-token`, `terraform-cloud-token`, `together-ai-api-key`, `tavily-api-key`, `trigger-dev-token`, `vault-token`, `wandb-api-key`, `slack-token`, `openai-token`, `sentry-user-auth-token`, `sentry-org-auth-token`, `discord-bot-token`, `aws-bedrock-long-term-api-key`, `aws-bedrock-short-term-api-key`, `new-relic-user-api-key` | line-local | `pattern::scan_prefixed_shapes`/`run_ends`/`boundary_ok` (`detectors/pattern.rs:235-459`) and the hand-written scanners use prefixes, run alphabets and boundary sets that contain neither `\n` nor `\r`. Offset 0 behaves like a preceding terminator, and end of input like a following one. Fixed lookbacks (Entra, Terraform) fail on a terminator just as they fail at offset 0. Post-checks read only inside the match or the next byte. Multi-pass detectors (`github`, `notion`, `stripe`, `slack`) keep their relative order within a unit. | batched |
| `jwt`, `otpauth-uri`, `connection-string` | line-local | Segment, URI and authority scans stop at `\n`/`\r` in both directions (`detectors/jwt.rs:172`, `detectors/otpauth.rs:133`, `detectors/connection_string.rs:196,492`). | batched |
| `private-key` | multi-line, hint-covered | The unit stays open while `PrivateKeyRetentionTracker` has an open block. At every unit boundary the parser state is clean (`detectors/private_key.rs:112-145`). | batched; the tracker resets at every unit boundary |
| `heroku-api-key-legacy`, `twilio-auth-token`, `twilio-api-key-secret`, `confluent-cloud-api-secret-legacy` (layouts) | multi-line, hint-covered | Each retention hint uses the same predicates over the same line window the detector reads back (`heroku.rs:517`, `twilio.rs:284`, `confluent.rs:327`). The windows are suffix-monotone, so when a hint reports closed, no later line can read context from before the boundary. | batched |
| same four, plus `new-relic-license-key`, `datadog-api-key`, `datadog-application-key-legacy`, `mailchimp-api-key`, `mailgun-api-key`, `mistral-api-key`, `cohere-api-key`, `ai21-api-key`, `deepgram-api-key`, `okta-api-token`, `travisci-api-token`, `pinecone-api-key` (legacy pass), `generic-token` (JWK `"kty"` lines) | **RISK: lone `\r`** | These split lines at `\n` only (`lines()`, `split('\n')`, `split_inclusive('\n')`), and a same-line keyword gate reads the whole `\n`-line. Units also end at a lone `\r`. Examples: `datadog\r` + `<32 hex>\r` finds nothing when the second unit is scanned alone, and finds `datadog_api_key` Medium when the two are scanned together; `# pinecone\r` + `api_key=<uuid>\n` changes the finding from `generic-token` to `pinecone-api-key`. | a unit after a lone `\r` starts a new batch |
| `generic-token` (assignment grammar) | **RISK: name on an earlier line** | `parse_name_and_operator` skips `is_js_whitespace` before the operator (`detectors/generic_token.rs:2000`). The retention hint's boundary and name sets (`:297`, `:334`) are narrower than the grammar's (`:1949`) for a backtick, a glued or escaped quote, and JWK members. Examples: `` `password\n `` + `= V\n`; `x"password"\n` + `: "V"\n`; `{"kty":"oct","k"\n` + `: "V"}\n`. The second unit alone gives nothing; scanned together it gives a finding. | a unit whose first non-whitespace text is `=` or `:` starts a new batch |
| `bearer-token` | **RISK: header on an earlier line** | `match_scheme_at` skips `is_js_whitespace` around the `:` of `authorization:` (`detectors/bearer_token.rs:280-293`). The hint holds only an `authorization` that no identifier character precedes (`:311`). Examples: `X-Authorization:\n` + `Bearer T\n` (the second unit alone gives a finding; together the header path blocks it); `Proxy-Authorization:\n` + `Bearer T\n` (the reverse). | a unit whose first non-whitespace text is `:` or `bearer` starts a new batch |
| `pii-domain`: `pii:global:phone` | **RISK: reads the next line** | `has_word_extension_marker` trims ASCII whitespace, line terminators included, after `ext`/`ext.`/`extension` (`pii/pii_phone.rs:256-268`). `phone: 212-456-7890 ext\n` alone drops the number; followed by `hello\n` it keeps it. | PII runs per unit |
| `pii-domain`: email, IBAN, payment card, US SSN, network address; context arbitration | line-local | Scans stop at non-atext, non-domain, non-digit bytes. Context arbitration only consults candidates and text within `logical_line_bounds`, and `\n` and `\r` are logical-line breaks (`pii.rs:822-1060`). | PII runs per unit (cost) |
| `pii-domain` context arbitration | **cost** | Over one call: `logical_line_bounds` scans from offset 0 for every candidate (O(k·n)), the barriers are O(k²), and equidistance builds a set of all k ranges per match. Batched over 64 KiB of phone lines it measured 347 ms against 54 ms per line. | PII runs per unit |
| Ruleset detectors (`generic-token-ruleset-names`, `RulesetDetector`) | RISK, unreachable | A ruleset name never holds a unit open, and `parse_prefix` accepts a lone `\r` inside a prefix. No incremental constructor accepts a ruleset (`from_registry` is crate-private). | not reachable |
| any detector: overlap tie | **RISK: tie-break** | `candidate_order` counted across the batch can flip an exact tie inside a unit. The test's `TieDetector` fixture flips it for whole-input scanning. | `candidate_order` counted per unit |
| any detector: candidate at a boundary | guard | A candidate ending at or crossing a unit boundary could interact with the next unit. | `detect_units` returns `Ok(None)` and the session falls back to per-unit scanning |

`DetectorContext::input_len` is read by no built-in detector.

## Differential tests

Two layers of differential tests check that batching changes nothing. Both
compare the concatenated text, the findings and the error code; the
callback cases also compare the full log of policy and formatter calls.

- **Public API.** `tests/incremental_batching.rs` feeds each input in chunks
  and compares the result with the same input fed one line per `append`. No
  `append` then closes more than one line, so that run is the previous
  behaviour.
- **Crate internals.** `src/incremental/batch_tests.rs` compares a session
  with the same session in its unbatched test mode (`unbatched`, which
  flushes after every unit). The core may not `include_str!` under `src/`,
  so the corpora are driven from `tests/`.

| Test | Inputs |
| --- | --- |
| `incremental_batching`: `…over_the_incremental_corpus` | every fixture of `incremental-corpus.json` in whole, 64-byte and 7-byte chunks; all fixtures joined into one document with LF, CRLF and CR line endings, in 64 KiB, 4 KiB and 333-byte chunks, under `full`, `common` and `pii:global` |
| `incremental_batching`: `…over_the_synchronous_corpus` | the 2,874 non-adversarial fixtures of `synchronous-corpus.json`, each whole and all joined (LF/CRLF/CR; 64 KiB and 4 KiB chunks for `full`, 64 KiB for `pii:global`) |
| `incremental_batching`: `…over_the_adversarial_corpus` | the 114 adversarial fixtures under the CLI's 1 MiB construct limits, in 64 KiB chunks |
| `incremental_batching`: `…over_the_pii_corpus_with_pii_active` | every `input` of the seven PII conformance files under `pii:global`, each whole and joined |
| `incremental_batching`: `…across_every_layout_the_audit_found_reading_across_units` | every RISK example above, alone, between plain lines, and repeated, under `full` and `pii:global` |
| `batch_tests`: `an_exact_overlap_tie_resolves_as_in_its_own_unit_when_batched` | four synthetic detectors whose candidates on a `tie-` line form two disjoint pairs that tie on every key except emission order. A `pre-<n>` line before it shifts one detector's emission order. The test asserts that the tie flips under whole-input scanning, and that `detect_units` and the session match the per-unit result |
| `batch_tests`: `failures_and_callbacks_keep_the_unbatched_order` | policy and formatter failures on different findings of one chunk, a limit failure after closed lines, and a buffer small enough to force mid-chunk flushes; compares outcome and call log |
| `batch_tests`: `a_detection_failure_in_a_batch_is_met_in_unit_order` | a detector whose candidate is rejected as malformed on a later line, with and without a policy failure on an earlier line |
| `batch_tests`: `closed_units_waiting_in_a_batch_never_outgrow_the_buffer_limit` | the peak of `retained` stays within `max_buffered_bytes` |
| `batch_tests`: `closed_lines_in_one_append_are_detected_together` | the batched path is taken, not the fallback |

`tests/incremental_partitions.rs`, `tests/adversarial_bounds.rs` and the rest
of the suite pass unchanged.

**Mutation checks.** Each safeguard was removed in turn, and at least one
test failed each time:

| Safeguard removed | Failing test |
| --- | --- |
| rule 1 (lone `\r`) | `incremental_batching` layouts |
| rule 2 (`=`, `:`, `bearer`) | `incremental_batching` layouts |
| PII per unit (PII scanned over the batch) | `incremental_batching` PII corpus and layouts |
| `candidate_order` per unit (raw index instead) | `batch_tests` overlap tie |
| flushing the batch before a limit failure | `batch_tests` failures and callbacks |
| flushing before `max_buffered_bytes` | `batch_tests` buffer limit |

Scanning PII over the batch also failed the PII *corpus* test. So the PII
conformance fixtures hold at least one cross-unit dependency besides the
phone case found by reading the code. Running PII per unit covers it,
whatever it is.

## Numbers

**Host:** Apple M4, macOS, `rustc 1.98.1`, release profile (`cargo bench`).
The host was shared with other agents.

**Method:** the #981 harness (`benches/scan_cost.rs`, `--no-detectors`),
built from three trees:

- `base`: `main` `04b3e212` plus the harness, i.e. `origin/beta11/981-bench-harness` at `5c814dc9`;
- `#986`: this branch after the #986 commit and the harness merge (`d59f8fad`);
- `#985`: this change.

The three builds ran interleaved (base, #986, #985, then the reverse), in
three rounds of 11 runs per figure (5 for `mixed-10m`). The table shows the
median of the three round medians, in ms.

| Workload | Path | base | #986 | #985 | #985 vs #986 |
| --- | --- | ---: | ---: | ---: | ---: |
| `scale-logs-64k` | incremental, 64 KiB chunks | 8.03 | 8.06 | 4.99 | -38% |
| `scale-logs-256k` | incremental, 64 KiB chunks | 31.69 | 30.58 | 19.84 | -35% |
| `scale-logs-256k` | incremental, 4 KiB chunks | 31.21 | 31.08 | 19.71 | -37% |
| `mixed-10m` | incremental, 64 KiB chunks | 1,495.0 | 1,480.1 | 880.6 | -41% |
| `provider-tables-64k` | incremental, 64 KiB chunks | 7.94 | 7.97 | 5.63 | -29% |
| `unicode-invisible-64k` | incremental, 64 KiB chunks | 8.10 | 7.53 | 4.85 | -36% |
| `minified-json-64k` | incremental, 64 KiB chunks | 111.6 | 113.8 | 112.3 | one line: nothing to batch |
| `open-assignment-whitespace-10k` | incremental, 64 KiB chunks | 440.0 | 7.83 | 7.80 | (#986) |
| `scale-logs-256k` | whole | 17.71 | 17.59 | 16.56 | unchanged path |
| `mixed-10m` | whole | 764.4 | 761.3 | 751.9 | unchanged path |

Every round agreed on direction; the per-round medians are in the table
below.

| Workload / path | base rounds | #986 rounds | #985 rounds |
| --- | --- | --- | --- |
| `scale-logs-64k` incremental | 8.1, 8.0, 7.9 | 8.1, 8.3, 7.9 | 5.0, 5.5, 4.9 |
| `scale-logs-256k` incremental 64 KiB | 30.4, 31.7, 32.6 | 30.6, 29.8, 32.8 | 20.8, 19.8, 19.6 |
| `mixed-10m` incremental | 1495.0, 1506.8, 1436.1 | 1514.0, 1480.1, 1300.8 | 883.3, 880.6, 804.2 |

**PII.** The harness has no PII workload, so a throwaway probe (not
committed) ran `pii:global` sessions in 64 KiB appends. Interleaved medians
of 7 runs, same host. The hashes of the output text and findings were
identical between the builds.

| Workload | Bytes | base | #985 |
| --- | ---: | ---: | ---: |
| 3,000 lines each with email, phone, IP, card and SSN | 304 KB | 95 / 103 ms | 88 / 93 ms |
| 3,276 lines of `phone: 212-456-7890` | 66 KB | 48 / 46 ms | 36 / 34 ms |
| 8,000 log lines, one in four with email and phone | 554 KB | 103 / 92 ms | 65 / 67 ms |

Before PII was moved to per-unit scanning, the second row measured 139-193
ms batched against 69-75 ms for base, and the first 347-393 ms against
132-218 ms. That regression is why PII runs per unit.

## Pre-existing partition-invariance gaps (not changed here)

The module docs of `incremental.rs` state that incremental output equals the
whole-input reference at every partition. Every RISK row above is a counter
example today: per-line incremental processing and whole-input scanning
already disagree on those inputs. Batching keeps the incremental side
exactly as it was, so this change neither fixes nor widens them.

For follow-up:

- **Lone `\r` line endings.** The keyword-gated families listed above.
- **`generic-token` hint under-retention.** A backticked, glued or escaped
  quoted name, or a JWK member, whose operator is on the next line.
- **`bearer-token` hint under-retention.** `X-Authorization:` and
  `Proxy-Authorization:` followed by `Bearer` on the next line.
- **PII phone extension.** `ext` at a line end is judged by the next line in
  a whole-input scan, and by nothing in the incremental session.
- **Twilio CLI table under `\r`-only line endings.** A unit that starts with
  `$ twilio …\r` never closes. `$ twilio profiles:list x\r` followed by
  3,000 `row\r` lines fails with `TokenLimitExceeded`.
