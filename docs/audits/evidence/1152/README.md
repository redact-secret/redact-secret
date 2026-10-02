# #1152 - performance measurement moved out of the core repository

Product judgement. Final record for
[#1152](https://github.com/redact-secret/redact-secret/issues/1152) (parent
[#1068](https://github.com/redact-secret/redact-secret/issues/1068), under #1065); the
decision it executes is [#1151](../1151/README.md). It changes no detector, no
public API and no shipped behavior, and authorizes no version, tag, publication
or deployment. The cutover criteria that unblocked it were decided in
`redact-secret/redact-secret-benchmarks#608`.

## What moved

Allocation-request counting moved to the separate measurement engine. It is a
separate package that counts with the pinned third-party `stats_alloc` crate
and has no `unsafe` in this repository's crates. It runs against pinned,
immutable core commits through the public API only. Its artifact is
`redact-secret-allocation-counts.json`, kept there, not copied here.

In this repository:

- Deleted `crates/secret-scan-core/examples/alloc_attribution.rs` (it had
  `unsafe impl GlobalAlloc`, `std::env::args` and a file-level
  `#![allow(unsafe_code, ...)]`).
- Removed the five `false_positive` entries it needed from `sast/baseline.json`
  (`7c43c2c2df9e761b`, `e7fd43aea41a1c6a`, `8b680f0b9c3e096d`,
  `808f2967a2836257`, `dae7668416b650ca`). Nothing else referenced the example
  (no other example, test, bench, script or workflow). One unrelated entry for
  `scripts/check-rust-workspace.py` moved from line 646 to 662 because the
  script gained lines above it.
- Added the no-`unsafe` check to `scripts/check-rust-workspace.py`
  ([#1151](../1151/README.md#what-the-check-enforces)) and updated
  `docs/rust-workspace.md`.
- Every evidence README with a "Temporary in-repo measurement" section got a
  closing update pointing here.

The deleted harness is recoverable. The last commit that modified it is
`ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda` (#1145), and the file is in the tree
of every commit on `main` up to this change (tip before deletion:
`7173c0c7714958290cb2000567f24046a19d6b3e`):

```
git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs
```

## What was reproduced

All counts are allocation requests through the public API; fixtures are
synthetic and generated; findings are identical before and after in every row.

| Card | Workload | Before -> after |
|---|---|---|
| #1121 | ordinary, per 1,000 assignments | 18,451 -> 5,451 |
| #1121 | diverse | 18,459 -> 4,274 |
| #1121 | references | 12,155 -> 1,054 |

The #1121 baseline reproduces **exactly** and is gated by a release test in the
engine's CI, over pinned core commits `44382b3f` -> `be5fee95` -> `ad877c03`.
Two cards that were never measured in this repository are measured for the
first time:

| Card | Workload | Before -> after |
|---|---|---|
| #1131 | azure single | 17 -> 16 |
| #1131 | azure repeated-records(100) | 636 -> 536 |
| #1131 | azure duplicate-keys(100) | 966 -> 402 |
| #1131 | benign | 3 -> 3 |
| #1135 | overlap disjoint / sparse / pairs / dense | 5,081 / 5,090 / 20,106 / 30,107, unchanged before and after |
| #1135 | rejected prototype, pairs | 5 -> 15,003 |

The engine's workloads also include the #1145 OTP cases (`otp-dense`,
`otp-sparse` and the #1145 fixtures), which the removed example had carried.

## What was lost

Two paths cannot be reached through the public API:

| Path | Card | Reason | Proxy |
|---|---|---|---|
| `azure-probe` | #1131 | crate-private helper; measuring it would have widened the core's public API, which is forbidden | end-to-end azure rows above |
| `overlap-probe` | #1135 | crate-private helper; same reason | end-to-end overlap rows above |

The proxies are whole-scan counts: they include the rest of the pipeline, so
their absolute values are not the helper-level counts quoted in the #1131 and
#1135 READMEs (for example the five helper calls of #1135 against 5,081
whole-scan requests). They show direction, not a reproduction of the helper
number. Losing a private-helper reproduction path is a documented outcome the
card allowed.

**Latency.** The engine established no timing direction for any card on a
hosted 2-vCPU runner; the one "faster" signal for #1131 did not reproduce with
identical binaries. No timing claim in this repository's evidence is changed,
extended or withdrawn by the move. The reverse patches and harness `.txt` files
below are the only record of the private-helper timing harnesses.

## Final inventory

Disposition of every row of the #1152 inventory table:

| Asset | Used by | Disposition |
|---|---|---|
| `crates/secret-scan-core/examples/alloc_attribution.rs` | #1121, #1145 | **moved, then deleted.** Reproduced exactly in the separate measurement engine; the five `sast/baseline.json` entries are removed |
| `docs/audits/evidence/1131/`, `1133/`, `1135/` `removed-timing-harness.patch.txt` | #1131, #1133, #1134, #1135 | **kept as history** (inert reverse patches, not built or scanned). The engine measures the public API only, so it replaces none of them; they hold the only record of the private-helper timing harnesses |
| `docs/audits/evidence/1145/`, `1146/`, `1147/` (`measurement-harness.patch.txt`, `discovery-variants-harness.patch.txt`), `1148/`, `1149/` harness `.txt` files | #1145-#1149 | **kept as history**, same reason; the #1145 allocation workloads moved to the engine |
| `docs/audits/evidence/1160/` to `1169/` harness `.txt`, `.py.txt` and raw outputs | #1160-#1169 | **kept as history** (added after the inventory table was written; none placed a measurement file outside `docs/audits/evidence`) |
| `docs/audits/evidence/1129/*.py`, `1121/` scripts | #1121, #1129 | **kept as evidence.** The `1129` scripts read build artifacts and symbol names and contain no allocator; the `1121` directory has only its README (its harness was the deleted example above) |

`crates/` now contains no measurement code and no `unsafe`; `grep -rn unsafe
crates/` finds only `forbid(unsafe_code)` declarations and prose.

## Maintenance

A later performance card that wants allocation counts runs the engine against
its exact core commits, not an in-repo harness. A card that adds a measurement
file to this repository records it in its evidence README under "Temporary
in-repo measurement" and removes it before merge, as the #1160-#1169 batch did.
Nothing in this change is consumer-observable.
