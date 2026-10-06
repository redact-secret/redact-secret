# Evidence: #1224, Batch 2 ApiKey, JWT and X encoded carriers

**Result:** the contract for the four G4 rows (adopted in PR #1231, with the
representation decision) was tested by the independent benchmarks#739 round 2
against the published `0.1.0-beta.13` and the candidate `a148dadf`. No gap was
reproduced and no code changes for this package. `elastic:cloud-api-key` and
`elastic:ece-api-key` fail on the published baseline and pass on the candidate
through the Batch 1 `Authorization: ApiKey` fix ([#1212](../1212/README.md)),
reused. `jfrog:access-token` and `x:app-only-bearer-token` are existing coverage
validated by the benchmark; the X percent-containing and escaped forms stay an
accepted policy limit, observed and not scored, with a redacted prefix never
reported as full coverage. The independent replay of a fixed candidate does not
apply to this package (nothing was fixed for it), but it is covered by the
whole-corpus regression replay stated under "Handoff".

Issue [#1224](https://github.com/redact-secret/redact-secret/issues/1224)
(measurement child benchmarks
[#743](https://github.com/redact-secret/redact-secret-benchmarks/issues/743)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md); the
decision is
[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](../../../decisions/2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The four proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). For X it records the Bearer role, an unspecified byte format, and percent-containing shapes only as a scanner-corroborated lead (`artifacts-bearer-leading-run-and-percent`), not a provider-proven encoding. |
| Independent baseline | benchmarks#739: [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) at merge `fe7a5d1a` of PR #761 (readiness at merge `6a1a7a64` of PR #755). Identities under "Independent measurement and dispositions". |
| Product policy (this record) | `Authorization: ApiKey` grammar ([#1212](../1212/README.md)), the `bearer-token` grammar, the `jwt` detector, `decision-defer-encoded-input-decoding` and the representation decision above. |

## Adopted contracts

| Question | Decision |
| --- | --- |
| Cloud `ApiKey` (`elastic:cloud-api-key`) | Batch 1 is reused as is. For a reviewed layout that is `Authorization: ApiKey <value>` or `Proxy-Authorization: ApiKey <value>` (raw HTTP, quoted curl `-H`, JSON header map): `authorization_credential`, exactly the undecoded authorization-alphabet run (`[A-Za-z0-9+/=_-]`, at least 12 bytes, `=` padding included), always redacted. Not split into id and key, not decoded, no width or alphabet claim, no Elastic attribution. |
| ECE (`elastic:ece-api-key`) | Nothing is asserted: the carrier is unconfirmed. ECE is not read as the Cloud `ApiKey` because of its name or product family, and no scheme, header or vocabulary entry is added for it. If its reviewed carrier is the same `ApiKey` scheme, the existing path applies with no ECE attribution; any other carrier needs its own evidence first. |
| JFrog JWT and Bearer overlap (`jfrog:access-token`) | The carrier is unresolved. When a value is a JWT, the existing `jwt` detector and, behind an explicit Bearer header, the `bearer-token` detector see the same bytes; the contract is one final finding, exactly the JWT bytes, redacted, generic type, no exclusive attribution. A JWT is not an exclusive JFrog grammar, so no JFrog type is produced, nothing is decoded and no token is validated. A JFrog reference token that is not a JWT has no source-established representation and is unassertable. |
| X app-only Bearer, raw (`x:app-only-bearer-token`) | Where a reviewed layout names an explicit `Authorization: Bearer` carrier for the raw value: `bearer_token`, exactly the value, redacted, under the RFC 6750 alphabet with the 12-byte floor after an explicit header (16 bare). The provider states the format is unspecified, so no prefix, width or alphabet is claimed. |
| X, percent-containing or escaped | Unsupported and unassertable until a separate representation decision. The Bearer alphabet is not broadened to pass a generated example, nothing is decoded, and a case that needs it is not an FN, TN or pass. Where the grammar ends a value at `%`, the product redacts the prefix it read and the residual bytes stay in the output; that prefix is never reported as full credential coverage. See the decision for the trade-off and the reopening bar. |
| Exclusions and controls | Placeholders, references and masks (shared rules); bare `ApiKey` prose; `X-Authorization:` and `Authorization-Info:`; a newline between scheme and value; the consumer key and secret that generate an X bearer token (not this row's credential); JWTs of other providers. |
| Default action | `redact` for `authorization_credential`, `bearer_token` and `jwt` (always-redact); a user action policy overrides it as before. |

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| `GET /x HTTP/1.1`, then `Authorization: ApiKey <47 bytes, ends in ==>` | one `authorization_credential`, high, redact, over the whole 47 bytes including `==` (38-85) |
| `Authorization: Bearer <JWT: 20 + 27 + 34 bytes, two dots>` | one `jwt` finding, high, redact, over the whole JWT (22-105); no separate `bearer_token` and no provider type |
| `jfrog token: <the same JWT>` (no Bearer header) | one `jwt` finding, high, redact, over the whole JWT (13-96) |
| `Authorization: Bearer <50 alphanumeric bytes>` | `bearer_token`, high, redact, over the value (22-74) |
| `Authorization: Bearer <24>%2B<12>` | `bearer_token`, high, redact, over the 24 bytes before `%` (22-46); `%2B` and the 12-byte tail stay in the output |
| `Authorization: Bearer <42>%2B<12>%3D` | `bearer_token`, high, redact, over the 42 bytes before the first `%` (22-64); `%2B<12>%3D` stays in the output |
| `Authorization: Bearer <7>%2B<...>` | no finding (leading run under the 12-byte floor), so the whole value stays |
| `Authorization: Bearer <42>+<12>` (literal backslash-u escape) | `bearer_token` over the 42 bytes before the backslash (22-64); the escape and tail stay |

## Independent measurement and dispositions

**Independent measurement.** benchmarks
[#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)
measured all 58 rows in two rounds (PRs
[#755](https://github.com/redact-secret/redact-secret-benchmarks/pull/755) and
[#761](https://github.com/redact-secret/redact-secret-benchmarks/pull/761), both
merged; permalinks at their merge commits `6a1a7a64` and `fe7a5d1a`): the
[readiness inventory](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/readiness.md) (first version at merge `6a1a7a64` of PR #755), the [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), the [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and the [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (58 rows, schema 4). Frozen round-2
corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`
(1935 cases; first freeze `8e447629`, three documented errata before the
re-measurement; round 1's corpus `74fed382`, 486 cases, 30 rows, is separate).
Case ids are `<family>:r2:<layout>:<kind>` in `benchmarks/batch2/corpus-r2.mjs`
(round 1: `<family>:<layout>:<kind>` in `corpus.mjs`) and are listed per row in the
ledger. Expectations were authored from credential-evidence `65602481` and the
adopted contract (PR #1231), frozen before any scan, and were not edited.

**Identities.** Published: `@redact-secret/core`, `@redact-secret/wasm` and the
darwin-arm64 addon `0.1.0-beta.13` from npm (core integrity
`sha512-qZkqRN7CIJ+pc0IteRCXSucr1l9KtTc/nJaM5wPL0NvCiZ4AGWLCyrLy8KD95a2MBgxo8vuUJ/UaKhrny7gMJQ==`),
PyPI `redact-secret` `0.1.0b13`, crates.io `redact-secret-cli` `0.1.0-beta.13`.
Candidate: the unpublished commit `a148dadf4a43b5441ed88386d055428b2e278f25`
(core main after PR #1231, no candidate package published). Surfaces: Node, WASM,
Python and the CLI (the Rust surface; no separate Rust harness), whole and
streamed at 7-byte and 1-byte chunks, darwin-arm64, Node v22.16.0; the four
surfaces agreed on every case and stream equalled whole. Peers were not run. The
fixed candidate is **not** an identity the benchmark has measured: this change
was replayed locally on the CLI surface only (see the #1223 record).

**Result (candidate `a148dadf`).** 4 rows, 0 positives failing and 0 controls
flagged on the candidate; on the published baseline 22 positive cases fail, all on the
two Elastic rows and all the ApiKey envelope fixed by #1212 / PR #1215 (11 cases
each); the other two rows are clean on both. The evidence now names a carrier for
each row: Elastic ECE `authorization-apikey-carrier` (the same `ApiKey` scheme as
Cloud, so the contract's "same path, no ECE attribution" branch applies and ECE is
still not read as Cloud by name), JFrog `authorization-bearer-header` (Bearer,
with a JWT value read as one `jwt` finding), X an explicit Bearer carrier with
percent-containing shapes only as an unscored variant. The local CLI replay of
this change (see the [#1223 record](../1223/README.md#independent-measurement-and-dispositions))
left every G4 observation unchanged.

**Disposition legend.** *Existing coverage, validated by the benchmark: no
code* means the row's in-contract positives and controls passed on the published
baseline and on the candidate on every surface and stream, and the record
changes nothing for it. *Reproduced gap, fixed by this PR* names the issue.
*Batch 1 fix reused* means the row fails on the published baseline and passes on
the candidate through an earlier core fix. *Accepted policy limit* and
*source-unresolved / unmeasured* are never counted as a miss, a clean result or
coverage. Variants the contract leaves unassertable (prefixed or upper-case
names, single quotes, lower-case schemes, percent values, legacy layouts) are
observed and not scored in every row. A row is not claimed covered beyond what the
ledger measured.

### G4: 4 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `elastic:cloud-api-key` | ApiKey header | 11 / 6 / 2 (+ 12 round-1) | pos 0 fail, ctl 0 flagged (published: 11, 0) | Batch 1 fix reused (#1212 ApiKey envelope, PR #1215): fails on the published baseline, passes on the candidate; no new gap. |
| `elastic:ece-api-key` | ApiKey header | 11 / 6 / 2 | pos 0 fail, ctl 0 flagged (published: 11, 0) | Batch 1 fix reused (#1212 ApiKey envelope, PR #1215): fails on the published baseline, passes on the candidate; no new gap. |
| `jfrog:access-token` | explicit Bearer header; Bearer JWT | 29 / 14 / 12 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `x:app-only-bearer-token` | explicit Bearer header | 15 / 7 / 8 (+ 20 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. Percent-containing and escaped forms: accepted policy limit, observed and not scored. |

## Handoff

Final for the benchmarks side: the ApiKey expectation for `elastic:cloud-api-key`
and `elastic:ece-api-key` (`authorization_credential`, undecoded run, redact, no
Elastic attribution), the single `jwt` finding with no JFrog attribution for a
JFrog JWT, and the raw Bearer expectation for `x:app-only-bearer-token`, all
validated by the measurement; the X percent-containing and escaped forms as
unsupported and unassertable (never an FN, TN or pass). The Elastic rows depend on
the Batch 1 fix that is already merged and published only in the candidate line:
the published `0.1.0-beta.13` fails them, so a user on the published package has
the ApiKey gap until the next release.

**What the benchmarks side replays (open).** Build the merge commit of this
change (the maintainer names it; not chosen here) as the fixed candidate (`npm
ci`, `npm run js:build`, the napi addon, `npm run wasm:build`, `npm pack` of core,
addon and wasm, `maturin develop --release`, `cargo build --release --locked -p
redact-secret-cli`), then run the round-2 corpus `a312308a...` (all 1935 cases) on
Node, WASM, Python and the CLI, whole and at 7-byte and 1-byte chunks, with
`scripts/measure-batch1.mjs` and `scripts/report-batch2-r2.mjs`, and the Batch 1
and round-1 corpora for regression. Expected: 0 positives failing and 0 controls
flagged on all 58 rows; observations identical to `a148dadf` except the 25 cases
listed above; stream equal to whole; the four surfaces identical.

No pin, version or release changes; this record chooses none.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze each ready row's layout, admission, span, attribution, default action and exclusions in final product evidence and spec rows | Met. The class contract and spec rows are adopted (PR #1231) and the independent measurement tested them per row; the evidence contracts of credential-evidence remain proposed or draft, which is that repository's state, not a product gap. |
| Link independent baseline case ids and identities; disposition every row | Met. Identities and permalinks are above and every row has its disposition in the per-row table, with case ids in the ledger and the corpus. |
| Repair only demonstrated gaps | Met. No G4 gap was demonstrated on the candidate; the two Elastic failures on the published baseline are the already-merged #1212 fix, reused. The `%` prefix behaviour is an accepted, recorded limit. |
| Deterministic conformance for changed logic | Met, nothing changed for this package; the ApiKey grammar is pinned by the Batch 1 `apikey_*` tests and the Bearer and `jwt` behaviour by their unit tests. |
| Shared parser fix once | Not applicable. No shared parser fix was needed for G4 (the one shared fix of this batch, #1232, does not touch these rows). |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Partly. Baseline and candidate `a148dadf` were measured by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical. For this change: the Rust core under whole input, every two-chunk UTF-8 byte partition and per-line sessions (`tests/batch2_gaps_1232_1234.rs`), and the CLI replay above. Open: Node, WASM and Python with the fixed candidate, which share the Rust core and are the benchmark replay. |
| Exact candidate revision and digests to benchmarks; accept independent replay | Open. The fixed candidate does not exist as a measured identity until the change is merged and built; what to replay is stated above. Offered: the merge commit and the build recipe of the benchmark README, no pin, version or release change. |
| Record no-code conclusions for existing coverage | Met for `jfrog:access-token` and `x:app-only-bearer-token` (existing coverage, no code) and for the two Elastic rows (the Batch 1 fix reused, no new code), as the benchmark ledger measured them. |

## Tradeoffs

* Not broadening the Bearer alphabet leaves a real residual: a token whose bytes
  continue with `%XX` is partly visible in the redacted output. The alternative
  widens a grammar shared by every Bearer user to fit one scanner lead for one
  provider that documents no format. The decision records this and the reopening
  bar.
* `ApiKey` and a JWT are not unique to one provider, so nothing here attributes a
  finding to Elastic, JFrog or X; a caller that needs attribution adds it from
  its own context.
* A JWT under Bearer is one `jwt` finding. A caller that expected a
  `bearer_token` type for that value sees `jwt`; the bytes redacted are the same.

## Tests

None added for this package. The grammar is pinned by the Batch 1 `apikey_*`
tests and the `bearer-token` and `jwt` tests; the independent measurement is the
benchmarks side's, with its own corpus and scorer. The product observations above
are pinned by this record only.


## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written; the statements below are superseded
and this section is the current state. Replay facts shared by all Batch 2 records
(candidate, corpus digests, results, the 25 differing cases) are in the
[#1223 record](../1223/README.md).

The accepted replay is benchmarks
[#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`) of the exact candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db` on the frozen round-2 corpus
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (1935
cases), with round 1 `74fed382...` and Batch 1 as regression, on Node, WASM,
Python and the CLI, whole and at 7-byte and 1-byte chunks
([round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md),
[ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)).

| Earlier statement (in this record) | State now |
| --- | --- |
| "The independent replay of a fixed candidate does not apply to this package ... but it is covered by the whole-corpus regression replay stated under Handoff" (Result) | The regression replay ran and is accepted. None of the 25 cases that differ from `a148dadf` belongs to a G4 row, and the ledger records no change versus the previous candidate for any of the four. |
| "What the benchmarks side replays (open)" (Handoff) | Done: benchmarks #771. |
| Gates "Node/WASM, Python, Rust and CLI ...: Partly" and "Exact candidate revision ...; accept independent replay: Open" | Met, see below. |
| Elastic rows "reused" (Disposition legend) | Unchanged in substance. The ledger label is `fixed in candidate by an existing core fix (no new gap)`. |

### Dispositions at `4e004108`

| Row | Ledger disposition | Positives failing / controls flagged | Whole equals stream (7-byte, 1-byte), four surfaces identical |
| --- | --- | --- | --- |
| `elastic:cloud-api-key` | fixed in candidate by an existing core fix (no new gap): the Batch 1 [#1212](../1212/README.md) fix | 0 / 0 | 76/76, 76/76; 19/19 cases |
| `elastic:ece-api-key` | fixed in candidate by an existing core fix (no new gap) | 0 / 0 | 76/76, 76/76; 19/19 cases |
| `jfrog:access-token` | already-covered / no-code | 0 / 0 | 220/220, 220/220; 55/55 cases |
| `x:app-only-bearer-token` | already-covered / no-code | 0 / 0 | 120/120, 120/120; 30/30 cases |

The round-3 report keeps the percent-containing forms of `x:app-only-bearer-token`
as observed and not scored: they still redact only the prefix before the first
`%`, as the representation decision states. This package changed no code.

### Gates of the issue at `4e004108`

| Gate | State |
| --- | --- |
| Node/WASM, Python, Rust and CLI whole and stream behavior | **Met.** Replayed by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical (the CLI is the Rust surface). |
| Exact candidate revision and digests to benchmarks; accept independent replay | **Met.** Candidate `4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No candidate package was published, so no package digest is claimed. |
| All other gates | Met, unchanged. |

The figures are read from the merged report and ledger; the harness was not
re-run for this addendum.
