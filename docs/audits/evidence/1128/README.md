# Evidence: #1128, additional named provider profiles

**Result:** no new profile for Beta.13. Five plausible provider-group profiles
were built and measured. The best saves 20.4% of `full`'s brotli WebAssembly
size (devtools and package registries, 23 detectors), and the most plausible
agent profile saves 17.2%. Each keeps only 17 to 43 of the 104 provider
detectors, and each captures at most 72% of the saving `common` already offers.
No single provider group is worth 10% of `full`: the largest, cloud, saves
7.5%. The accepted profile contract sets that gate, and no issue names a
consumer and a budget. 64% of `full`'s brotli size is the engine floor, which no
profile can remove. The profile contract stands unchanged, and no ADR is
needed.

Issue [#1128](https://github.com/redact-secret/redact-secret/issues/1128),
under [#1068](https://github.com/redact-secret/redact-secret/issues/1068) and
[#1065](https://github.com/redact-secret/redact-secret/issues/1065). Kind per
[DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md):
product judgement. The earlier suggestion of caller-selected provider Cargo
features was not implemented: it conflicts with the
[profile contract](../../../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)
(reviewed named profiles only, no consumer composition, no provider features on
the core). Reachability findings are reused from [#1127](../1127/README.md).
Every input is synthetic. No profile, feature, package, API or release was
created.

## What was measured

| Item | Value |
| --- | --- |
| Source | `44382b3f3006a3a34a2bab917711d00e2e53284a` |
| Toolchain | rustc 1.98.1 (`48a229cea`), `wasm-bindgen` 0.2.128, Node.js v22.16.0, `lto = "fat"`, `codegen-units = 1`, no `wasm-opt` |
| Host | macOS 26.5.2, arm64 |
| Shipped artifacts | `full` and `common`, built by `scripts/measure-wasm-profiles.mjs --guard-only` |
| Candidate profiles | Scratch builds, never committed: the `DETECTORS` table of `built_in_detectors()` patched with `buildPatchedSource` from `scripts/measure-detector-cost.mjs`, then built as the default `redact-secret-wasm` and bound with `wasm-bindgen`. The source was restored after each build. |
| Data | [`variant-sizes.json`](variant-sizes.json), [`timing.json`](timing.json) |

A patched table keeps the `BUILT_IN_PACKS` id table and the prefilter
declarations, which are data, so a candidate is slightly larger than a
purpose-built constructor would be. The same patch method gave #378 results
within 0.15% of the real `common` artifact (#381).

## Engine floor against detector code

| Artifact | Detectors | Raw B | gzip -9 B | brotli -11 B | Native raw B |
| --- | ---: | ---: | ---: | ---: | ---: |
| `full` (shipped) | 110 | 594,960 | 205,081 | 159,403 | 734,688 |
| `common` (shipped) | 6 | 406,687 | 142,547 | 113,995 | 517,872 |
| engine floor, zero rows | 0 | 366,356 | 127,660 | 102,070 | 368,944 |

- The floor is **61.6% of `full` raw and 64.0% of `full` brotli** (native:
  50.2%). It holds the pipeline, incremental session, ruleset and PII-selector
  code, `generic-token` (the session calls it for retention), the provider
  retention helpers from #1127, and the 56,468 B `name` section.
- The six `common` detectors add 40,331 B raw and 11,925 B brotli over it. The
  104 provider detectors add 188,273 B raw and 45,408 B brotli: about 1,810 B raw
  and 437 B brotli each, down from the 2,964 B and 767 B average in #378.
- `full` brotli has doubled since #378 (77,407 B to 159,403 B). The floor
  explains 69% of that growth (45,183 B to 102,070 B), detectors 31%. Trigger 2
  of the profile contract fired because of the floor as much as because of
  detector count.

## Candidate profiles

All sit between `common` and `full`, are order-preserving subsequences of the
canonical order, and are unions of whole groups plus the six `common`
detectors. Group membership is `GROUPS` in `scripts/measure-detector-cost.mjs`;
`mainstream-42` is the 36 provider detectors of the #378 composition.

| Candidate | Detectors | Raw B | gzip -9 B | brotli -11 B | Brotli saved vs `full` | Brotli over `common` | Share of `common`'s saving | Native raw B |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| devtools and package registries | 23 | 455,550 | 158,611 | 126,852 | 32,551 (20.4%) | +12,857 | 72% | not built |
| AI inference and agent tooling | 31 | 474,285 | 165,947 | 132,040 | 27,363 (17.2%) | +18,045 | 60% | 601,728 |
| SaaS | 25 | 488,704 | 169,777 | 134,376 | 25,027 (15.7%) | +20,381 | 55% | not built |
| cloud and infrastructure | 49 | 503,451 | 174,989 | 138,225 | 21,178 (13.3%) | +24,230 | 47% | not built |
| `mainstream-42` (#378 set) | 42 | 505,657 | 175,203 | 138,642 | 20,761 (13.0%) | +24,647 | 46% | 618,368 |

Removing one group from `full`, the form the contract's 10% gate uses:

| Group removed | Detectors removed | Raw B saved | Brotli B saved |
| --- | ---: | --- | --- |
| cloud | 43 | 54,101 (9.1%) | 11,925 (7.5%) |
| AI | 25 | 35,895 (6.0%) | 9,498 (6.0%) |
| SaaS | 19 | 38,893 (6.5%) | 7,988 (5.0%) |
| devtools | 11 | 15,956 (2.7%) | 3,491 (2.2%) |
| package registries | 6 | 272 (0.0%) | 192 (0.1%) |

The five groups' savings sum to 33,094 B brotli, less than the 45,408 B of
removing all 104, because the shared provider code (`pattern`, retention
helpers) goes only when the last user goes.

## Runtime

Fresh node process per sample, 9 interleaved rounds, medians, under
`/tmp/rs-bench.lock`, on a shared laptop. Not frozen budgets, and not an
acceptance claim.

| Artifact | Compile ms | Registry build ms | Scan 64 KiB clean ms | Scan 256 KiB mixed ms |
| --- | ---: | ---: | ---: | ---: |
| `full` | 1.75 | 1.57 | 1.99 | 11.78 |
| `common` | 1.41 | 1.06 | 1.58 | 6.61 |
| devtools and package registries | 1.42 | 1.29 | 1.37 | 6.41 |
| AI | 1.61 | 1.42 | 1.51 | 6.93 |
| cloud | 1.41 | 1.19 | 1.43 | 6.82 |
| SaaS | 1.35 | 1.28 | 1.68 | 7.57 |
| `mainstream-42` | 1.41 | 1.33 | 1.59 | 7.75 |
| engine floor | 1.46 | 0.84 | 0.27 | 1.05 |

The mixed workload finds the same 148 values in every artifact, `common`
included, because its secrets sit in contextual assignments and headers. It
shows what each artifact costs, not what it detects. Initialization differences
are 0.1 to 0.4 ms. The scan time that profiles remove is mostly provider
prefilter work, and the six `common` detectors already cost most of the
remainder. A profile cannot recover more than `common` does.

## What each candidate withholds

Every candidate rejects all 110 built-in ids as custom or ruleset ids,
because the reservation table is data and does not change (#1127). Per-detector
invariance holds: a kept detector emits the same candidates in every profile
that holds it. A withheld provider token falls back to `generic-token` or
`bearer-token` when a context catches it, otherwise it goes unreported, exactly
as in `common`.

Over the 3,788 canonical fixtures, 1,762 have a provider finding in `full`.
Fixtures with at least one finding the candidate withholds:

| Candidate | Fixtures with a withheld finding |
| --- | ---: |
| `common` | 1,762 (100%) |
| devtools and package registries | 1,431 (81.2%) |
| SaaS | 1,435 (81.4%) |
| AI | 1,325 (75.2%) |
| `mainstream-42` | 1,196 (67.9%) |
| cloud | 1,095 (62.1%) |

Fixture counts reflect where test effort went, not how often each credential
leaks, so read this as relative coverage loss only. The qualitative issue is
sharper: the AI profile would withhold GitHub, GitLab, AWS, Google, Stripe and
Slack tokens, which agent logs and tool output carry. The devtools profile
would withhold the AI keys a developer pastes. Each named group fits one
deployment story but breaks the next one.

## Qualification multiplication

A profile is a supported surface, so the contract requires membership,
per-detector invariance, committed expectations, a reserved-id test, an
artifact identity check and a reachability guard for each one. Today's `common`
shows what that costs in this repository:

- A reviewed expectations file of 3,788 fixtures, 445,638 B
  (`conformance/fixtures/common-profile-expectations.json`), and a
  corpus test.
- Two more WebAssembly artifacts (default and `pii`), each with its own glue,
  and a four-way exports and PII-link guard that becomes six-way.
- Three `package.json` subpath exports in `@redact-secret/core`, seven
  `common`-named source files in `packages/javascript/src`, and matching
  Node, browser and `workerd` runtime entries.
- 85 mentions of `common` across five release and qualification workflows, 45
  lines in each release's artifact inventory, and Chromium, Firefox and WebKit
  qualification passes.
- Node addon functions (`scan_common`, `profile_common` and the incremental
  equivalents) and documentation in two guides, the API contract and the
  detection reference.

Each candidate would repeat that, to save 13% to 20% of one asset that a
browser downloads once. Profiles also multiply for every future detector,
because an addition must declare its pack and each profile's expectations must
be reviewed.

## Decision

**Keep `full` and `common`. Add no profile for Beta.13.** This is the contract's
own gate applied to fresh numbers:

| Gate in the profile contract | Reading |
| --- | --- |
| Trigger 1: 63 built-ins | Fired (110). |
| Trigger 2: `full` brotli at 96,759 B or more | Fired (159,403 B), mostly from the floor. |
| Trigger 3: an issue names a consumer, runtime and budget that `common` misses on coverage and `full` misses on cost | **Not met.** No issue names one. |
| A named pack needs trigger 3 and a group worth at least 10% of `full` brotli | **Not met.** The largest group is 7.5%. |

No ADR amendment and no spec change is needed beyond a record that the
triggers were revisited. `docs/specs/engine.md` gains one row for that.
Nothing here changes a public surface, so there is nothing to resolve before the
#1066 contract freeze.

Reopen when a concrete consumer supplies a runtime and a byte or latency budget
that `common` misses on coverage and `full` misses on cost. Then measure that
consumer's detector list as a union of whole groups against this table, and
propose it with the qualification cost above. A smaller `full` is a better lever
than a third profile: the floor is 64% of its brotli size, and the `name`
section is a further 6% ([#1127](../1127/README.md#follow-ups-for-the-orchestrator)).
Those are size cards, and neither needs a profile.

## Limits

- Candidates are source-patched scratch builds, not shipped artifacts, and only
  WebAssembly was built for all five. Native sizes exist for two.
- The runtime numbers use Node, not a browser, one host and synthetic text; the
  #381 browser protocol was not rerun.
- Fixture coverage shares are corpus-weighted, as noted above.
- No allocation or retained-memory figure was taken: no code changed.
