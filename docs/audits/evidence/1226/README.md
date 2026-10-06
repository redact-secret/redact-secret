# Evidence: #1226, Batch 2 Atlas password, API private key and service-account secret

**Result:** the contract for the three G6 rows (adopted in PR #1231, with the Atlas
password stance) was tested by the independent benchmarks#739 round 2 against the
published `0.1.0-beta.13` and the candidate `a148dadf`. `mongodb-atlas:database-user-password`
passed every positive and reproduced one false positive, the `YOUR_PASSWORD`
placeholder under a password name (a medium `warn`), fixed by
[#1234](../1234/README.md); its percent-escaped URI password stays an accepted
policy limit, observed and not scored. `mongodb-atlas:service-account-secret` is
existing coverage validated by the benchmark. `mongodb-atlas:programmatic-api-private-key`
has no wire carrier (a client-side Digest input): only controls were observed, all
clean, and the row is source-unresolved, not covered. The independent replay of
the fixed candidate is open.

Issue [#1226](https://github.com/redact-secret/redact-secret/issues/1226)
(measurement child benchmarks
[#745](https://github.com/redact-secret/redact-secret-benchmarks/issues/745)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md); the
representation decision is
[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](../../../decisions/2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The three proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). It records the password as a write-only, caller-chosen request property with no generated grammar and an unresolved percent-encoding question; the private key as a client-configured Digest input whose wire header holds a hash, returned unredacted once at creation; and the service-account secret as carried in an HTTP Basic header with `mdb_sa_sk_` plus an ellipsis only a truncated example and `mdb_sa_id_` a public id. It also holds three public-sibling records (the public key, the credential object id, the client id). |
| Independent baseline | benchmarks#739: [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) at merge `fe7a5d1a` of PR #761 (readiness at merge `6a1a7a64` of PR #755). Identities under "Independent measurement and dispositions". |
| Product policy (this record) | The connection-string grammar (`connection_string_password`, valid percent escapes not decoded), the contextual vocabulary and its confidence gate (`decision-warn-unconditionally-on-high-signal-contextual-names`), the Basic envelope ([#1213](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1213/README.md)) and the representation decision above. |

## Adopted contracts

| Question | `mongodb-atlas:database-user-password` | `mongodb-atlas:programmatic-api-private-key` | `mongodb-atlas:service-account-secret` |
| --- | --- | --- | --- |
| Layout kinds in contract | (1) The password in `mongodb://` and `mongodb+srv://` URI userinfo, through the connection-string detector. (2) A documented password field (assignment, form body, JSON or YAML member) through the contextual vocabulary, for a reviewed layout. | None asserted. The Digest `Authorization` header carries a hash, not the key, and is out of contract. Only a reviewed plaintext slot (for example a create-response member or a client configuration field) can be in contract, and the existing field grammar then applies. | An `Authorization: Basic` envelope (the token request, as the evidence records it), and a `client_secret`-style field only where a reviewed layout names one. |
| Value admission and span | URI: the password substring after the userinfo `:`, undecoded, exactly the substring; host, path and query stay outside. Field: the shared contextual grammar, 8-byte floor, exactly the value, ending at the form delimiter. | The existing field grammar for the slot. No width, alphabet or prefix is claimed. | Basic: the whole encoded envelope, never decoded, 12 bytes or more. Field: the shared grammar, exactly the value. |
| Finding type | URI: `connection_string_password`. Field: `contextual_secret`. No provider type. | `contextual_secret` (the `private_key` name family is already high-signal); not a PEM block and not typed as one. | Basic: `authorization_credential`. Field: `contextual_secret`. No provider type and no `mdb_sa_sk_` detector. |
| Default action | URI: redact (always-redact) at any confidence. Field: redact at high confidence (a random value of 16 bytes or more), warn at medium (for example a 14-byte or punctuation-bearing password), nothing under 8 bytes. | As the field. | Basic: redact. Field: as the field. |
| Controls and exclusions | Username, database name, URI host, path and query, placeholders, references, masks. | The 8-character public key, the credential object id, redacted later responses and masks, the Digest `response` hash, `username`, `realm`, `nonce`, `uri`, `qop`, `nc` and `cnonce`. | The public `mdb_sa_id_` client id, the secret's object id, the masked or truncated display (`mdb_sa_sk_` plus an ellipsis), placeholders, references, masks. |

### Stated blind spots and the explicit dispositions

* **User-chosen passwords are not a grammar.** The product claims the carrier,
  not the password. A password under the 8-byte contextual floor is not read in a
  field; a password under 16 bytes or of low entropy in a field is `medium` and
  `warn` (high confidence needs 16 bytes and the entropy threshold), which the
  accepted default leaves in the text and a user action policy may escalate; a
  password in a carrier the core does not read (a command-line flag, an SDK
  argument, an interactive prompt, a configuration shape the evidence has not
  named) is not read; and a password whose raw punctuation the carrier grammar
  treats as a delimiter (`&` in a form body, an unquoted space, a closing quote)
  is cut there and the residue stays in the output. The product does not claim
  all passwords are protected and invents no provider grammar.
* **Percent encoding.** In a URI userinfo, or a form or assignment value, a
  password containing `%XX` is kept as written inside the span and not decoded.
  Whether Atlas itself requires the encoding in a connection string is the
  evidence's question and is not decided here. The general rule for a carrier
  that ends a value at `%` is the decision above.
* **The API private key.** A curl invocation that passes `<public>:<private>`
  with `--user ... --digest` is a layout the product does not read today (no
  finding was observed). Making it in contract is a new carrier decision with
  its own benign corpus, not a repair, and the evidence has not named it.
* **No bare grammar.** A bare `mdb_sa_sk_...` value in prose, outside a credential
  slot, is not read. The evidence records no width or alphabet.

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| a `mongodb+srv` URI with a user name, a 14-byte password in the userinfo, a host, a database path and a `retryWrites` query | `connection_string_password`, high, redact, over exactly the 14-byte password (21-35); host, path and query silent |
| a `mongodb` URI with a one-letter user name, a 3-byte password in the userinfo, a host and a database path | `connection_string_password`, medium, redact (12-15) |
| a `mongodb` URI with a one-letter user name, a 13-byte password in the userinfo that contains valid percent escapes, a host and a database path | `connection_string_password`, high, redact, over the 13-byte password with its escapes undecoded (12-25) |
| JSON `{"password":"<20 random>"}`, YAML `password: <20 random>` | `contextual_secret`, high, redact, over the value (13-33; 10-30) |
| JSON `{"password":"<14 mixed>"}` | `contextual_secret`, medium, warn (30-44 in a two-line input) |
| JSON `{"password":"<14, punctuation>"}` | `contextual_secret`, medium, warn (13-27) |
| JSON `{"password":"<6 bytes>"}` | no finding |
| form `username=app&password=<17, with two %XX escapes>&roles=x` | `contextual_secret`, high, redact, over the whole 17-byte value to the `&`, escapes included (22-39) |
| JSON `{"privateKey":"<36, UUID-shaped>","publicKey":"<8>"}` (the shape is invented, not claimed as Atlas's) | `contextual_secret`, high, redact, over the `privateKey` value only (85-121 in a two-line input); `publicKey` silent |
| `"privateKey":"********-****-****-************"` | no finding |
| `Authorization: Digest username=".", realm="MMS Public API", nonce=".", uri=".", response="<32 hex>", qop=auth, nc=00000001, cnonce="."` | no finding |
| `curl --user "<8>:<36>" --digest <url>` | no finding |
| `Authorization: Basic <48 bytes>` | `authorization_credential`, high, redact, whole envelope (37-85 after a request line) |
| `client_id=mdb_sa_id_<24 hex>` then `client_secret=mdb_sa_sk_<24>` | `contextual_secret`, high, redact, over the 34-byte secret only (59-93); the client id silent |
| JSON `{"clientSecret":"mdb_sa_sk_<24>"}` | `contextual_secret`, high, redact, over the value (17-51) |
| `client_secret=mdb_sa_sk_...`; JSON `maskedSecretValue` with `mdb_sa_sk_...<4>`; a bare `mdb_sa_sk_<24>` in prose | no finding |

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

**Result (candidate `a148dadf`; published identical).** `mongodb-atlas:database-user-password`:
19 positives pass, 1 control flagged (`password-member-placeholders`, #1234), the
percent-escaped URI case is the recorded conflict observation (the contract keeps
escapes inside the span, the evidence records the encoding as unresolved; not
scored). `mongodb-atlas:service-account-secret`: 10 positives and 7 controls as
expected. `mongodb-atlas:programmatic-api-private-key`: the evidence marks it
`ready` but its input is a Digest computation with no wire carrier, so the
benchmark has no positive; the Digest header, the public key and a redacted read
were observed as controls only, clean (round 1).

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

**Local replay of this change (CLI surface only).** The benchmark's own runner
(`scripts/measure-batch1.mjs --corpus benchmarks/batch2/corpus-r2.mjs --cli
<release build of this branch>`, 7-byte and 1-byte chunks) and scorer
(`score-r2.mjs`) were run at the merge `fe7a5d1a` of benchmarks PR #761 over all
1935 cases, whole and streamed. Result: 0 positives failing and 0 controls
flagged on every row (the candidate `a148dadf` had 8 positive cases and 16 control
cases failing). Against the
candidate's CLI observations exactly 25 cases differ: the 15 empty-form-value
controls of #1232 (now clean), the 8 HubSpot positives of #1233 (now exact), the
mongodb-atlas placeholder control of #1234 (now clean), and the unscored
`personalAccessKey-legacy-portals` observation (no finding before, a finding now:
the name is read wherever it appears; the legacy layout stays unresolved and
unasserted). Nothing else changed. This is a local diagnostic, not the
benchmark's measurement: Node, WASM and Python were not replayed with the fixed
candidate.

### G6: 3 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `mongodb-atlas:database-user-password` | JSON/YAML member `password`; URI userinfo | 19 / 11 / 6 (+ 15 round-1) | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (placeholder control), fixed by this PR (#1234); other cases covered. The percent-escaped URI password is the accepted policy limit: observed, not scored. |
| `mongodb-atlas:programmatic-api-private-key` | none (Digest input, no wire carrier) | 0 / 0 / 0 (+ 7 round-1) | controls only, clean | Source-unresolved / unmeasured: the evidence marks it ready but its input is a client-side Digest computation with no wire carrier, so there is no positive. Only the controls both sides agree on were observed (clean). Not claimed covered. |
| `mongodb-atlas:service-account-secret` | Basic envelope | 10 / 7 / 4 (+ 14 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |

## Handoff

Final for the benchmarks side: the URI-userinfo and password-field expectations
for `mongodb-atlas:database-user-password` (exact undecoded password,
`connection_string_password` / `contextual_secret`), including that a documented
placeholder (`YOUR_PASSWORD`, `<password>`) is silent after
[#1234](../1234/README.md), with user-chosen short, low-entropy and
punctuation-bearing passwords as blind spots and percent-escaped passwords
unassertable; the whole-envelope Basic expectation for the service-account secret;
and for the private key nothing beyond the controls, until the evidence names a
plaintext slot (source-unresolved: not covered, not a miss).

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
| Repair only demonstrated gaps | Met. One false positive was demonstrated (`YOUR_PASSWORD` under a password name) and repaired by [#1234](../1234/README.md); the password blind spots and the percent-escaped URI password are accepted, recorded limits. |
| Deterministic conformance for changed logic | Met. `tests/batch2_gaps_1232_1234.rs` (`a_your_password_placeholder_under_a_password_name_is_silent` and the real-value, short-value and glued-placeholder controls). |
| Shared parser fix once | Not applicable. #1234 is a placeholder-vocabulary fix, not a parser fix. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Partly. Baseline and candidate `a148dadf` were measured by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical. For this change: the Rust core under whole input, every two-chunk UTF-8 byte partition and per-line sessions (`tests/batch2_gaps_1232_1234.rs`), and the CLI replay above. Open: Node, WASM and Python with the fixed candidate, which share the Rust core and are the benchmark replay. |
| Exact candidate revision and digests to benchmarks; accept independent replay | Open. The fixed candidate does not exist as a measured identity until the change is merged and built; what to replay is stated above. Offered: the merge commit and the build recipe of the benchmark README, no pin, version or release change. |
| Record no-code conclusions for existing coverage | Met for `mongodb-atlas:service-account-secret` and for the in-contract positives and controls of the password row, as the benchmark ledger measured them. `mongodb-atlas:programmatic-api-private-key` is source-unresolved and is not a no-code conclusion. |

## Tradeoffs

* A `warn` for a moderate-length password under a documented field leaves the
  text unchanged by default. Raising it to `redact` would redact every 8 to 15-byte
  or low-entropy literal under `password`, including prose false positives that
  `decision-warn-unconditionally-on-high-signal-contextual-names` records. The
  accepted default stays; a caller that wants redaction sets its action policy.
* The URI reading redacts at any confidence, so a placeholder-like short
  password in a connection string is redacted: security-first and unchanged.
* Treating the private key and service-account secret by existing names and the
  Basic envelope means a Basic envelope also hides the public client id. A key
  in a layout the product does not read, such as the curl `--user` form, stays
  visible, and that is disclosed rather than fixed here.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs` pins #1234 (see
[#1234](../1234/README.md#tests)); the URI grammar, the contextual vocabulary and
the Basic envelope are pinned by their existing tests (`connection_string` and
`generic_token` unit tests, `batch1_credential_slots_1209_1213.rs`). The
observations above are pinned by this record only. The independent measurement is
the benchmarks side's.


## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written; the statements below are superseded
and this section is the current state. Replay facts shared by all Batch 2 records
(candidate, corpus digests, results, the 25 differing cases) are in the
[#1223 record](../1223/README.md).

### The accepted replay and the three G6 rows

The accepted replay is benchmarks
[#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`) of the exact candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db` on the frozen round-2 corpus
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (1935
cases), with round 1 `74fed382...` and Batch 1 as regression, on Node, WASM,
Python and the CLI, whole and at 7-byte and 1-byte chunks
([round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md),
[ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)).

| Row | Ledger disposition at `74c88531` | Positives failing / controls flagged | Whole equals stream (7-byte, 1-byte), four surfaces identical |
| --- | --- | --- | --- |
| `mongodb-atlas:database-user-password` | fixed by candidate `4e004108`, replay verified ([#1234](../1234/README.md)); the `password-member-placeholders` control is clean. Percent-escaped URI password: observed, not scored (6 round-2 variants and 2 round-1 variants unscored) | 0 / 0 | 148/148, 148/148; 37/37 cases |
| `mongodb-atlas:programmatic-api-private-key` | `contract-evidence conflict`: no positive exists, only the agreed controls, all clean | 0 / 0 | 0/0 entries (no scored case) |
| `mongodb-atlas:service-account-secret` | already-covered / no-code | 0 / 0 | 84/84, 84/84; 21/21 cases |

| Earlier statement (in this record) | State now |
| --- | --- |
| "The independent replay of the fixed candidate is open" (Result, Handoff "What the benchmarks side replays (open)") | Done and accepted: benchmarks #771. |
| "The fixed candidate is **not** an identity the benchmark has measured" (Identities) and "Node, WASM and Python were not replayed" (Local replay) | Measured: `4e0041081aad22d0101bd52db52017b67b5bd3db`, all four surfaces. |
| Gates "Node/WASM, Python, Rust and CLI ...: Partly" and "Exact candidate revision ...; accept independent replay: Open" | Met, see the gate table below. |
| "has no wire carrier ... source-unresolved" and "No layout is asserted until the evidence names a plaintext slot" for the API private key | Superseded as to the evidence: credential-evidence [#256](https://github.com/redact-secret/credential-evidence/issues/256) is closed by PR #258 (merged 2026-10-06T11:06:11Z, merge `d53e7e3a7ad1860b7735625aa6c0a7faa866fbdf`), which names two plaintext slots (below). "No wire carrier" was true of the request wire only. The benchmarks round 3 merged earlier (10:34:34Z) and so still records the row as a conflict with no positive. |

### The Atlas API private key: two named slots

The evidence note
[`atlas-private-key-slots.md`](https://github.com/redact-secret/credential-evidence/blob/d53e7e3a7ad1860b7735625aa6c0a7faa866fbdf/docs/handoffs/atlas-private-key-slots.md)
and the updated
[Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/d53e7e3a7ad1860b7735625aa6c0a7faa866fbdf/docs/handoffs/batch-2-bounded-carriers.md)
(project-authored, not independent; the contract stays draft) establish:

| Slot | Exact spelling |
| --- | --- |
| Creation response member | `privateKey` of the answer to `createOrgApiKey` and `createGroupApiKey`, unredacted when first created and redacted afterwards |
| Atlas CLI profile property | `private_api_key`, next to `public_api_key`, set with `atlas config set` |

Not established, and therefore not in contract: an environment variable, a
command-line flag, a Terraform argument, the curl `--user` layout, and any byte
grammar, prefix, length or alphabet. The evidence authors no Case for these slots:
a must-flag expectation is a project-policy decision it has not taken.

**Product contract for the two slots.** Both are in-contract carriers read by the
existing field grammar, with no new vocabulary entry, detector or type: a
`contextual_secret` over exactly the value, redacted at high confidence and warned
at medium (default `redact` for a random value of 16 bytes or more), with no
width, alphabet or prefix claim and no Atlas attribution. The 8-character public
key, the credential object id, a masked later response and the Digest header
fields stay silent. This applies the "a reviewed plaintext slot then falls under
the existing field grammar" rule of the adopted contract; it changes no behaviour.

**Observed at core `efe71496`** (CLI `0.1.0-beta.14`, release build, check mode;
the only detector change since `4e004108` is the Square placeholder prefixes of
#1236, which do not touch these inputs). Synthetic inputs built at run time, the
36-byte values UUID-shaped and invented (the shape is not claimed as Atlas's),
the public key 8 random characters, values not shown:

| Input (synthetic) | Observed finding |
| --- | --- |
| JSON creation response `{"id":..,"publicKey":"<8>","privateKey":"<36>","roles":[]}` | one `contextual_secret`, `generic-token`, high, redact, over exactly the 36-byte `privateKey` value; `publicKey` and `id` silent |
| TOML profile `[default]` with `org_id`, `public_api_key = "<8>"`, `private_api_key = "<36>"` | one `contextual_secret`, high, redact, over exactly the 36-byte value; the others silent |
| YAML `public_api_key: <8>` and `private_api_key: <36>` | one `contextual_secret`, high, redact, over exactly the value |
| `"privateKey":"********-****-****-************"` with a public key | no finding |
| `private_api_key = "<6 bytes>"` | no finding (under the 8-byte floor) |
| `atlas config set private_api_key <36>` (command-line layout) | no finding: a command-line flag or argument is not read and is not named by the evidence |
| `MONGODB_ATLAS_PRIVATE_API_KEY=<36>` | one `contextual_secret`, high, redact, by name. Observation only: the evidence does not name this variable, so it is not in contract and not claimed |

These observations are pinned by this record only; no test in `crates/` names
either slot yet. The benchmarks row stays a `contract-evidence conflict` until a
positive expectation is frozen there: this is not coverage, and the row is not
claimed covered.

### Percent-escaped URI password: what is decided and what is not

The product behaviour is decided and was not "unresolved": in a `mongodb://` or
`mongodb+srv://` URI userinfo a password containing valid `%XX` escapes is
`connection_string_password`, high, redact, over exactly the password with its
escapes kept as written and never decoded; host, path and query stay outside. The
unit test `a_percent_encoded_reserved_delimiter_in_the_password_is_kept_undecoded`
(`crates/secret-scan-core/src/detectors/connection_string.rs`, a `postgres`
scheme) pins the grammar, and the CLI at `efe71496` gave the same result on
synthetic `mongodb+srv` and `mongodb` URIs with two escapes (`%40`, `%3A`) and
with one escape (`%40`, `%2F`): one finding over the whole escaped password, the
span ending at the `@`. A `%` that is not followed by two hex digits invalidates
the userinfo (the unit test `malformed_percent_escape_invalidates_the_authority`)
and the same `mongodb+srv` input gave no finding: a stated blind spot, not
decided as protection. What stays unresolved is the provider fact, whether Atlas
requires the encoding in a connection string: the evidence handoff at
`d53e7e3a` still records it as unresolved, and the round-3 report keeps the
case observed and not scored. Both statements of the sections above that call it
"unresolved" refer to that provider question only.

### Gates of the issue at `4e004108`

| Gate | State |
| --- | --- |
| Node/WASM, Python, Rust and CLI whole and stream behavior | **Met.** Replayed by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical (the CLI is the Rust surface). |
| Exact candidate revision and digests to benchmarks; accept independent replay | **Met.** Candidate `4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No candidate package was published, so no package digest is claimed. |
| Record no-code conclusions for existing coverage | Met (unchanged) for `service-account-secret` and the in-contract positives and controls of the password row. The API private key is **not** a no-code conclusion: it has named slots and a product contract but no benchmark positive, so it is not claimed covered. |
| All other gates | Met, unchanged. |

### Not verified here

The replay figures are read from the merged report and ledger; the harness was
not re-run. The slot spellings are as the credential-evidence note states them;
the provider sources behind them were not re-read. The probes above ran on one
host with a build of `efe71496`, not on `4e004108` itself.

## Closure statement (2026-10-06)

What this issue can honestly claim after the Groups C, D and E measurement rounds.

No scored case of Groups C, D or E exercises this issue, so the group measurement adds no row claim to it. No Group C, D or E row is an Atlas row. The claims of this issue stay the ones in the records above, which cite the Batch 2 evidence; do not cite the Groups C-E report for a row claim here. The Atlas API private key
remains not claimed as covered, as the record above says.

The closeout also added tracked policies that these records do not claim as covered:
the `curl -u` password slot ([redact-secret#1247](https://github.com/redact-secret/redact-secret/issues/1247)), the JFrog `AKCp` bare
reader, deferred ([redact-secret#1248](https://github.com/redact-secret/redact-secret/issues/1248)), the bare `token` member
([redact-secret#1256](https://github.com/redact-secret/redact-secret/issues/1256), rule [#1241](../1241/README.md)), the existing Case
contradictions ([credential-evidence#264](https://github.com/redact-secret/credential-evidence/issues/264)) and the percent-escaped X layout
confirmation ([credential-evidence#265](https://github.com/redact-secret/credential-evidence/issues/265)).

Source: the [round-3 report of Groups C, D and E](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md) (section 7, [dispositions](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#6-final-disposition-of-all-43-rows)),
its [scores](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/scores.json) and
[identity](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/identity.json), at benchmarks commit
`c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291`, measuring candidate
`c6dd685974b8df6a84514e07e41e35afa711a2ac` (unpublished, 0.1.0-beta.14) on one
host. Project-authored, maintainer-only evidence, not independent validation;
the fixes target measured failures and no generalisation is claimed.
