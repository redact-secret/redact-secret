# #1121 - residual temporary allocations in generic assignment classification

Verdict: **adopted** (behavior-preserving). Parent: #1068. Baseline: `44382b3f`.
All fixtures are synthetic and generated in
`crates/secret-scan-core/examples/alloc_attribution.rs`; no value is printed.

## Method

1. Maintainer-only harness (`examples/alloc_attribution.rs`, not published; the
   package `include` list excludes examples): a counting `System` allocator
   over one whole-input `scan` with the default registry and policy, after one
   warm-up. It counts alloc/realloc **requests** (not peak/live memory). With
   `--attribute` it attributes each request to the innermost two crate frames
   of a captured backtrace (release build with line tables).
2. Three 1,000-line fixtures: `ordinary` (`api_key = "<32 alnum>"`),
   `diverse` (five keys x five body shapes: base62, hex-40, `a-b`, base64-44,
   `word_body`), `references` (GCP, AWS ARN, Azure Key Vault, vals, bank-vaults,
   composite and filler templates).
3. A digest of `format!("{findings:?}")` (spans, types, confidence,
   order) taken on the baseline build and the new build.

## Attribution (baseline, requests per 1,000 values)

| site | ordinary | diverse | references |
|---|---:|---:|---:|
| `shannon_entropy` histogram `Vec` growth | 4000 | 3898 | 884 |
| `is_prefixed_filler_body` (collected `Vec<u8>`) | 3000 | 3682 | 2997 |
| `matches_placeholder_vocabulary` (tokens + joined `String`) | 2000 | 2413 | 3666 |
| `is_gcp_secret_manager_reference` | 1000 | 997 | 1445 |
| `is_aws_secretsmanager_arn` | 1000 | 997 | 777 |
| `is_aws_arn` | 1000 | 997 | 444 |
| `starts_with_digest_label` (lowercased copy) | 1000 | 997 | 444 |
| `is_lead_word_phrase_placeholder` | 0 | 204 | 111 |
| `is_credential_noun_phrase` / `is_bank_vaults_reference` | 0 | 0 | 222 / 111 |
| `Candidate::with_signals` (public `signals() -> &[String]`) | 3000 | 2991 | 666 |
| twilio bare-run scan, pipeline per-finding closure | 1395 | 997 + 212 | 222 + 111 |

The hot subset was therefore the filler body, entropy histogram, placeholder
vocabulary and the three structural references. The speculative DNS-label,
AWS-ARN-prefix guard and `splitn` candidates from the issue were done only as
iterator rewrites; `is_https_hostname` and `is_credential_noun_phrase` do not
show in the ordinary profile.

## Change

All in `detectors/generic_token.rs`, `detectors/text.rs`, `entropy.rs`:

- `is_prefixed_filler_body`: one streaming pass. Necessary-and-sufficient
  condition recorded in the code: the longest repeated-byte suffix is the
  trailing run, so accept iff `trailing_run >= MIN_FILLER_LEN` and
  `len - trailing_run <= MAX_FILLER_PREFIX_LEN` (no restarted filter, no
  quadratic scan).
- `matches_placeholder_vocabulary`: token iterator re-created per pass; the
  joined word is compared byte-wise (case-insensitive) against each listed
  word of equal length, never built.
- `starts_with_digest_label`: case-insensitive byte comparison, no lowercased
  copy.
- GCP / bank-vaults / `splitn(6)` AWS ARN / `splitn(7)` Secrets Manager ARN /
  DNS-label host / credential-noun phrase / lead-word phrase: iterators with
  fixed-arity destructuring and an explicit trailing-item rejection. The
  `splitn` remainder item is kept whole (colons inside the name/resource are
  accepted exactly as before). GCP additionally rejects a non-`projects/`
  prefix before walking (necessary: every accepted shape starts `projects/`).
- `shannon_entropy`: first 64 distinct symbols in a stack array, further
  symbols spill to a `Vec`. Summation stays in first-occurrence order, so the
  result is bit-identical (`f64::to_bits` equality is tested across 3/40/64/
  65/200-symbol alphabets).
- Unchanged by design: `signals() -> &[String]`, entropy order, the ASCII
  entropy histogram rejected in #1091, other detectors' allocations.

## Result (same binary harness, base vs new)

| fixture | alloc requests before -> after | requested bytes before -> after | finding digest |
|---|---|---|---|
| ordinary | 18,451 -> 5,451 (-70.5%) | 1,783,000 -> 927,000 | identical |
| diverse | 18,459 -> 4,274 (-76.8%) | 1,826,421 -> 880,268 | identical |
| references | 12,155 -> 1,054 (-91.3%) | 958,657 -> 257,843 | identical |

The 18,451 baseline reproduces the issue's 18,049 (different fixture bytes).
What remains on `ordinary` is `with_signals` (3000, public type), the twilio
bare-run scan (1395) and the pipeline closure (1000), outside this card.

Whole-path `scan` wall clock (41 samples, median, three alternating rounds
under the shared bench lock; the machine was shared so spread is wide):
ordinary 2.64/2.79/3.78 -> 2.25/2.62/2.61 ms, diverse 3.49/3.94/4.37 ->
2.93/3.43/3.72 ms, references 2.20/2.82/2.75 -> 1.82/2.23/1.97 ms. Every
round favoured the new build (about 6-30% on these assignment-dense inputs).
`scale-logs-256k` has no assignment findings and was dominated by noise; it is
not evidence either way. Not measured here: native/WASM binary size (no new
dependency or generic instantiation was added, expected neutral), live/retained
memory, and the frozen #1068 budgets. Formal run artifacts belong in
`redact-secret-benchmarks`.

## Tests

- Old helpers kept as test-only oracles (`residual_allocation_tests` in
  `generic_token.rs` and `text.rs`, bit-exact entropy oracle in `entropy.rs`):
  seeded strings with repeated/empty/extra separators, near-miss references,
  Unicode (`e`-acute, Kelvin sign, emoji), the 8/8 filler boundary grid, and
  fixed accepting/rejecting cases for every helper.
- `cargo test --workspace --locked` (all canonical corpus, whole+streaming,
  incremental, conformance suites), `cargo clippy --workspace --all-targets
  --locked -- -D warnings` and `cargo fmt --all --check` pass.
