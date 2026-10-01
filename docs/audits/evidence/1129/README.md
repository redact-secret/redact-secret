# Evidence: #1129, residual provider code duplication in the linked artifact

**Result: rejected, no code change.** Attribution of the real `full` and
`common` WebAssembly artifacts and the native CLI at `44382b3f` finds no
duplicated provider code left to remove. Byte-identical function bodies are
0.35% of the `full` code section (1,560 B) and none of them is provider
detector code. Per-provider code is 100,631 B (16.9% of the `full` artifact),
two thirds of it in 54 `Detector::detect` bodies that each parse a different
grammar. The only identical-grammar helpers found (UUID layout, mixed-case
body) total about 1.9 KB by symbol size, 0.3% of the artifact and less once
compressed, below what this gate can tell from build-to-build layout noise.
The adopt gate needs a measured raw and compressed reduction; none is
available, so no refactor was made and no latency run was needed.

Issue [#1129](https://github.com/redact-secret/redact-secret/issues/1129),
parent [#1068](https://github.com/redact-secret/redact-secret/issues/1068),
research
[comment](https://github.com/redact-secret/redact-secret/issues/1068#issuecomment-5933957873).
Related: #1095 (a generic iterator variant cost about 2 KiB of WASM and was
rejected).

## What was measured

Source `44382b3f3006a3a34a2bab917711d00e2e53284a`, `rustc`/`cargo` 1.98.1
(darwin arm64 host), `wasm-bindgen` 0.2.128, `twiggy` 0.8.0, the workspace
release profile (`lto = "fat"`, one codegen unit, `opt-level` 3), `--locked`.
WASM artifacts come from `scripts/build-browser-artifact.mjs` for `full` and
`--detector-profile common`, so they are the shipped bytes including the
`name` section. The native binary is the host release `redact-secret` CLI
(Mach-O, not the Linux ELF the research used).

| Artifact | raw B | gzip -9 B | brotli -11 B |
| --- | ---: | ---: | ---: |
| WASM `full` | 594,960 | 205,081 | 159,403 |
| WASM `common` | 406,687 | 142,547 | 113,995 |
| WASM `full` + PII | 896,380 | 328,890 | 257,301 |
| WASM `common` + PII | 708,175 | 265,956 | 212,026 |
| Native CLI (host) | 1,271,680 | 589,052 | 440,828 |

The provider pack is the difference between `full` and `common`: 188,273 B
raw, 62,534 B gzip, 45,408 B brotli. Sizes are deterministic; the scripts are
in this folder (`artifact_sizes.mjs`, `attribute_twiggy.py`,
`provider_delta.py`, `provider_split.py`, `wasm_body_duplicates.py`,
`native_attribution.py`, `wasm_strip_names.py`). They read symbol names and
sizes only.

## Ranked attribution, WASM `full` (594,960 B)

| Rank | Bucket | Bytes | Share |
| ---: | --- | ---: | ---: |
| 1 | `name` custom section | 85,328 | 14.3% |
| 2 | `generic-token` (common pack, 52 functions) | 73,527 | 12.4% |
| 3 | `.rodata` data segment | 55,914 | 9.4% |
| 4 | Engine `pipeline` | 28,506 | 4.8% |
| 5 | Engine `incremental` | 22,593 | 3.8% |
| 6 | `keyword_gated_keys` (full only, one table-driven `detect_spec` of 14,427 B) | 21,272 | 3.6% |
| 7 | `connection-string` (common pack) | 17,032 | 2.9% |
| 8 | Per-provider modules, all 155 functions (see below) | 100,631 | 16.9% |

Within the provider-pack delta (188,273 B): `.rodata` +29,868, `name`
section +25,614, and 159,565 B in 275 symbols present only in `full`. Largest
of those: `keyword_gated_keys::detect_spec` 14,427, `slack` 10,420 in 9 symbols
(the section grammar), `sort_candidates_by_start` and its `std` sort
instantiations 5,822 (a monomorphisation the `common` build never reaches),
`heroku` 4,720, `mailgun` 4,464, `confluent` 4,089. Every other provider
module is under 4 KB, most under 2.5 KB.

Per-provider module code splits into 67,635 B in 54 bespoke
`Detector::detect` implementations and 32,996 B in 101 helpers, post-checks
and closures. The shared `KnownFormatProviderDetector` /
`TypedKnownFormatProviderDetector` / `PrefixShape` path already carries the
rest; the modules that use it contribute only their `PostCheck` function
and their `const` descriptor data (the descriptor tables are the `.rodata`
growth above, which a different executor does not remove).

## Is the apparent duplication already merged?

Yes. `wasm_body_duplicates.py` hashes every function body in the `full` module
(731 functions, 448,418 B of code): 17 groups of byte-identical bodies, 1,560 B
redundant in total. They are `core` drop glue, `wasm-bindgen` closure invokers,
`RawVec::finish_grow`, the policy shim and multivalue shims. LLVM already
merged identical provider bodies, which is also why a few provider helpers
carry another module's name. No identical-grammar duplicate is left.

Nearly identical bodies are the remaining candidate. Those found:

| Shape | Where | Symbol bytes |
| --- | --- | ---: |
| UUID layout post-check | `axiom::has_uuid_layout` 260, `heroku::is_lower_uuid_after` 247, `langfuse::lowercase_uuid_v4` 330, `firecrawl::uuid_v4_nibbles` 111 | 948 |
| Mixed-case / has-uppercase body | `composio::mixed_case` 791, `clickhouse_cloud::body_has_uppercase` 115 | 906 |

They differ in dash offsets, case rules or anchoring, and a shared helper would
add its own body and a call per user. The gain is at most 1.9 KB raw
(0.3% of `full`, estimated from symbol sizes, not a build), under what
compresses away. The other post-checks (`resend`, `paddle`, `postman`,
`langsmith`, `databricks`, `helicone`) each encode a different layout, which
the issue lists as inherently distinct. Folding them would need a new rule
construct, which the issue excludes.

## Native cross-check

The host CLI ranks the same modules: `generic_token` 65,396 B, `keyword_gated_keys`
19,960, `connection_string` 15,244, `text` 14,052, `prefilter` 11,424, `aws`
10,632, `slack` 8,240; `detectors::*` is 36.4% of 723,708 B of text. The
remaining 63.6% is `std`, the CLI and the engine. The same conclusion holds:
no single provider module, and no repeated pattern across them, is a
meaningful share.

## Where the bytes are, outside this issue's scope

- The `name` section is 85,428 B in `full` and 59,814 B in `common` but
  compresses to 12,545 B gzip / 9,914 B brotli (`full`) and 9,097 / 7,604
  (`common`). Removing it from the shipped file would cut about 6% of the
  gzip size of either artifact. `scripts/measure-wasm-profiles.mjs`
  reads it for its provider-linkage guard, and it is the only symbol source for
  this kind of attribution, so keeping or stripping it is a separate decision,
  not a duplication fix.
- `generic-token` is the single largest code owner (12.4% of `full`, 18.0% of
  `common`) and is not provider duplication.

## Not done, and why

- No candidate refactor, so no conformance, whole or streaming latency, or
  allocation comparison: there is no changed binary to compare. The corpus
  checks apply to any later change.
- No release, tag, version or benchmarks-repository intake. Final benchmark
  artifacts remain the job of `redact-secret-benchmarks`; the figures here are
  product-judgement attribution, not frozen budgets.
- Reopen if the provider count grows enough that the per-provider helpers pass
  a few percent of an artifact, or if a new shape repeats across many providers
  with identical grammar.
