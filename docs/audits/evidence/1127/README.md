# Evidence: #1127, common-profile link reachability and safe preventive adoption

**Result:** existing guards suffice for detector reachability, and one real
gap is closed. The `common` WebAssembly artifact is 28.5% smaller than `full`
in brotli (113,995 B against 159,403 B), links none of the 104 provider
detectors, and reports its profile. The gap was provider helper code: the
guard let any provider module's non-detector functions into `common` without
limit. About 21 KB of `common` (5.2% of raw) is exactly such code today, by
design, and the guard now pins which seven modules may carry it. No new
profile, feature or endpoint behavior is added, and no public API changed.

Issue [#1127](https://github.com/redact-secret/redact-secret/issues/1127),
under [#1068](https://github.com/redact-secret/redact-secret/issues/1068) and
[#1065](https://github.com/redact-secret/redact-secret/issues/1065). Kind per
[DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md):
product judgement. Research baseline and the earlier measurements are in the
[#1068 comment](https://github.com/redact-secret/redact-secret/issues/1068#issuecomment-5933957873).
Every input is synthetic.

## What was measured

| Item | Value |
| --- | --- |
| Source | `44382b3f3006a3a34a2bab917711d00e2e53284a` (`main`, 2026-10-01). Runtime source is identical to `13ff1b6d` (beta.12). |
| Toolchain | rustc 1.98.1 (`48a229cea`), `wasm-bindgen` 0.2.128, Node.js v22.16.0, `[profile.release]` `lto = "fat"`, `codegen-units = 1`, no `wasm-opt` |
| Host | macOS 26.5.2, arm64 |
| Build | `node scripts/measure-wasm-profiles.mjs --guard-only`, the CI `rust-wasm` job's command, which builds all four shipped artifacts |
| Data | [`artifact-sizes.json`](artifact-sizes.json) |

Byte sizes are deterministic: two builds of the `full` and `common` pair gave
identical sizes. No wall-clock latency was measured, because no runtime code
changed.

## Shipped artifacts, same SHA

Each artifact was loaded through its own wasm-bindgen glue, and its
`profile()` and `piiActivation()` exports were read.

| Artifact | Profile reported | Raw B | gzip -9 B | brotli -11 B | SHA-256 (first 16) |
| --- | --- | ---: | ---: | ---: | --- |
| `full` | `full` | 594,960 | 205,081 | 159,403 | `e870530131bea25c` |
| `common` | `common` | 406,687 | 142,547 | 113,995 | `8d9944e04f02658d` |
| `full-pii` | `full` | 896,380 | 328,890 | 257,301 | `7a34b9f0a0afcb7b` |
| `common-pii` | `common` | 708,175 | 265,956 | 212,026 | `cdbdb8e7f49bbe97` |

`common` against `full`: 188,273 B raw (31.6%), 62,534 B gzip (30.5%),
45,408 B brotli (28.5%). The PII runtime adds 301,488 B raw to `common`
(212,026 - 113,995 = 98,031 B brotli) and is a separate lazily loaded asset.
The glue `.js` files are 35 KB per profile and are not detector-sensitive.
Both defaults carry `piiActivation` `selectors=off`, and the build guard
confirms neither links any PII runtime.

Native, same SHA, minimal stdin-to-stdout program, macOS arm64, release with
`lto = "fat"`, `codegen-units = 1`, `strip = true`:

| Constructor the program references | Raw B |
| --- | ---: |
| `DetectorRegistry::with_built_in` | 734,688 |
| `DetectorRegistry::with_common_built_in` | 517,872 (-29.5%) |
| `sanitize_with_profile(.., Profile::Common)` with a constant profile | 517,888 |
| `sanitize_with_profile(.., profile)` with a run-time profile | 734,816 |

Package tarball and registry-installed sizes were not measured: no candidate
was published, and this card authorizes none.

## Reachability qualification

### What already guards `common`

`scripts/measure-wasm-profiles.mjs --guard-only` runs in CI (`rust-wasm`) and
checks, on the real artifacts and not on source line counts:

1. `common` is smaller than `full` in raw bytes.
2. No `Detector` implementation of any provider module is in `common`'s
   `name` section (all 104 provider detectors absent), and exactly the six
   `common` detectors are (`bearer_token`, `connection_string`,
   `generic_token`, `jwt`, `otpauth`, `private_key`).
3. No undeclared detector module is linked, and `full` links provider
   detectors (so an empty inventory cannot pass).
4. All four artifacts export one surface.
5. No default artifact links any part of the PII runtime, and each `pii`
   variant does.

Rust tests pin the other side: `BUILT_IN_PACKS` equals the canonical order,
`common_built_in_detectors` equals its `Common` rows, a `common` registry and
session report `Profile::Common`, each `common` detector emits identical
candidates in both profiles over the whole corpus
(`common_profile_corpus.rs`), and `common` expectations for all 3,788 corpus
fixtures are committed in `conformance/fixtures/common-profile-expectations.json`.

### Paths the issue asked about

| Path | Result |
| --- | --- |
| Reservation check | `validate_id` reads `built_in_ids()`, which iterates `BUILT_IN_PACKS`, a `const` table of 110 `(&str, Pack)` pairs. It holds strings and no constructor, so reserving a provider id links no provider code. |
| Ruleset reserved ids | `parse_ruleset` rejects any built-in id with `ReservedDetectorId`, independent of profile, through the same table. |
| Fallback paths | `with_common_built_in` references `common_built_in_entries()` only. The wasm leaf selects the constructor with `#[cfg(feature = "full")]`, not a run-time `match`. The incremental session is routed the same way (the #381 reachability bug). |
| Feature unions | The core has no Cargo features. The only profile feature is `full` on the `redact-secret-wasm` leaf, which nothing depends on. |
| Shared helper references | **Real, bounded, and until now unpinned.** See below. |
| `sanitize_with_profile` | Links both constructors when the profile is a run-time value (734,816 B against 517,872 B). With a constant profile, LTO folds the `match` (517,888 B). The Rust guide now says to call `with_common_built_in` directly. |

### Shared helper references (the gap)

`common` carries code from seven `provider` modules, none of which registers a
detector there: `aws`, `confluent`, `heroku`, `keyword_gated_keys`, `sentry`,
`trigger_dev`, `twilio`. They are the retention predicates the incremental
session asks in every profile (`has_open_aws_secret_candidate_line_in`,
`ends_inside_heroku_netrc_entry`, `is_twilio_cli_command`, and similar). The
profile contract permits this: retention changes memory and emission timing,
never output (admission rule 3). Summing `twiggy top` shallow bytes for
those modules' functions in the `common` module gives about 21,062 B raw
(5.2%). The largest is `aws::is_named` at 6,107 B.

The old guard classified these as "helper modules" and tolerated them without
limit, so a new provider module's code reaching `common` through any non-detector
path would pass CI. The guard now fails unless every provider module found in
a `common` artifact (also `common-pii`) is in
`COMMON_PROVIDER_HELPER_MODULES`, which lists exactly the seven above. The
unit tests cover acceptance, rejection with the names reported, and that each
listed module is a real provider module of the core. Adding a module to the
list needs a reviewed reason and the helper's measured size.

Not done, on purpose: removing those 21 KB. It would need profile-aware
retention in the incremental session, which touches memory bounds and
emission timing for `common` streams. At about 5% raw, and with gzip and
brotli shares smaller than that, it is an optimization for a size card, not a
reachability defect. It is recorded as a candidate, not a recommendation.

## Capability differences (what `common` withholds)

Over the 3,788 canonical fixtures, with `full` findings from
`synchronous-corpus.json` and `common` findings from the committed
expectations (compared on detector, type and confidence):

| Outcome | Fixtures |
| --- | ---: |
| Identical to `full`: no finding on either side | 1,715 |
| Identical to `full`: same findings | 311 |
| `full` reports a provider finding, `common` reports nothing | 863 |
| `common` reports the value under a `common` detector instead (`generic-token` 754, `bearer-token` 144, `connection-string` 1) | 899 |
| `common` reports a finding where `full` reports none | 0 |

`common` never adds a finding `full` lacks. Of the `common` findings on the
corpus, `generic-token` ones carry action `redact` in 1,089 cases and `warn`
in 63, so a provider token inside a contextual assignment is usually still
redacted. Examples, by fixture id, with no values:

| Fixture | `full` | `common` |
| --- | --- | --- |
| `host-dotenv-github` | `github-token`, `github_token`, high | `generic-token`, `contextual_secret`, medium, action `warn`, same byte span |
| bare provider token in prose | the provider detector | no finding |
| legacy OpenAI-shaped value in a `Bearer` header (`public_api.rs`) | `openai-token` | `bearer-token` only |

The action changes from the provider's default to the generic one, so a
preventive consumer must not read a `common` miss as clean.

## Safe preventive adoption

Authoritative enforcement stays on `full`. `common` is a latency and size
choice for a UX check that a server scan repeats. Never select `common`
because a download is large, an artifact failed to load, or an addon is
missing: each of those must fail loudly, not narrow detection.

Rust, smallest binary:

```rust
use redact_secret::DetectorRegistry;

// Reference this constructor, not `sanitize_with_profile` with a run-time Profile.
let registry = DetectorRegistry::with_common_built_in(std::iter::empty())?;
assert_eq!(registry.profile(), Some(redact_secret::Profile::Common));
```

Browser:

```ts
import { initialize, scanAndRedact, PROFILE } from "@redact-secret/core/common";

await initialize(); // rejects INITIALIZATION_FAILED on a load or profile mismatch
if (PROFILE !== "common") throw new Error("unexpected profile");
```

- Do not catch `INITIALIZATION_FAILED` and continue with an unscanned or
  narrowed path. Block the preventive action or show that scanning is
  unavailable.
- Send the same text to the server, which scans with `full`. A `common`
  result is advisory.
- Streaming uses `@redact-secret/core/common/web-stream` or
  `/node-stream`. The unsuffixed factories open `full`.
- Python and the CLI have no `common`. The CLI is the enforcement tool.
- A custom detector or ruleset cannot reuse any of the 110 built-in ids in
  either profile (`InvalidDetector`, `ReservedDetectorId`), including provider
  ids `common` does not register.

## Acceptance

| Requirement | Verdict |
| --- | --- |
| Prove missing reachability coverage, or record that existing guards suffice | Existing guards suffice for detectors and PII. One gap (helper modules) is closed by a pinned allowlist. |
| Real shipped raw/gzip/brotli sizes and profile declarations | Above, from the built artifacts and their `profile()` export. |
| No new profile, feature matrix or endpoint change | Held. The only code change is the guard in the measurement script. |
| Recipes, reserved-id behavior, overlap examples without values | Above. |
| Docs coordination with #1070 | The Rust guide gained one paragraph on constructor reachability. See follow-ups. |

## Follow-ups for the orchestrator

- `docs/guides/javascript.md` says raw release sizes are in
  `docs/reference/api-contract.md#detector-profiles`, which has none. #1070
  can add the table above, or drop the sentence.
- The shipped `.wasm` keeps its 85,428 B (`full`) and 59,814 B (`common`)
  `name` section. Without it, brotli would be 149,489 B and 106,391 B
  (-6.2% and -6.7%). The reachability guard reads that section, so any
  stripping must happen after the guard. This belongs to a size card.

## Reproduce

```bash
CARGO_TARGET_DIR=$PWD/target node scripts/measure-wasm-profiles.mjs --guard-only
node --test scripts/tests/measure-wasm-profiles.test.mjs
twiggy top -n 5000 target/wasm-profiles/common/redact_secret_wasm_common_bg.wasm
```
