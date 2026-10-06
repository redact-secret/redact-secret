# Evidence: #1232, an empty form value takes the next parameter as its value

**Result:** a measured gap, fixed once in the shared unquoted-value scan. An
empty value followed by `&name=` (`refresh_token=&other=1`,
`client_secret=&grant_type=x`) produced one medium, `warn` `contextual_secret`
whose span was the next parameter (`&other=1`, bytes 14-22). It now produces no
finding. One change covers all 15 benchmark families (the `oauth_token_secret`
row also belongs to [#1225](../1225/README.md)); the other positives and controls
of those rows were already passing and still do. No vocabulary, detector,
registry entry or type changes.

Issue [#1232](https://github.com/redact-secret/redact-secret/issues/1232),
found by the independent Batch 2 round-2 measurement of
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739).
Package: [#1223](../1223/README.md). The contract it enforces is the class table
of #1223: "exactly the value, ending at the form delimiter (`&`)".

## Sources

| Role | Source |
| --- | --- |
| Independent oracle | [benchmarks#761 round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (merge `fe7a5d1a`), frozen corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (`benchmarks/batch2/corpus-r2.mjs`). Its expectations were not edited. |
| Baselines | Published `0.1.0-beta.13` and the unpublished candidate `a148dadf4a43b5441ed88386d055428b2e278f25`, identical results, Node, WASM, Python and CLI, whole and streamed at 7-byte and 1-byte chunks. |
| Product policy | #816 (the `&name=` end rule), the #1223 class table and `decision-warn-unconditionally-on-high-signal-contextual-names`. |

## Root cause

`unquoted_assignment_value` walks an unquoted value up to the first boundary byte
and also stops at the `&` of a next `&name=` parameter (#816), but only after the
first byte of the value (`cursor > start`). With an empty value the first byte is
that `&`, so the guard did not apply, and the walk read `&other=1` to the next
boundary and returned it as the value. The same path serves every contextual
name, so `access_token`, `refresh_token`, `client_secret` and `oauth_token_secret`
all showed it.

## The change

`unquoted_assignment_value_with` returns no value when the value would start at
`&name=` (`starts_query_parameter` at `start`): the value is empty and the `&` is
the form delimiter. The check sits before the reference and flow-mapping checks
and covers both the bounded-reach path and the full walk. Nothing else changes:
a parameter after the empty one is scanned on its own terms.

## Before and after, benchmark cases

Before: published `0.1.0-beta.13` and candidate `a148dadf`, all surfaces, whole
and streamed. After: the CLI built from this change, the same frozen corpus (all
1935 cases, whole and 7-byte streamed), scored with the benchmark's own
`score-r2.mjs`. The other three surfaces share the Rust core; the replay of the
fixed candidate on them is the benchmarks side's step and stays open.

| Case id (`<family>:r2:<name>-form-empty-null:control`) | Name | Before | After |
| --- | --- | --- | --- |
| `meta:user-access-token` | `access_token` | flagged (`&other=1`, warn) | clean |
| `airtable:oauth-refresh-token`, `asana:oauth-refresh-token`, `box:oauth-refresh-token`, `dropbox:refresh-token`, `hubspot:oauth-refresh-token`, `x:oauth2-refresh-token` | `refresh_token` | flagged | clean |
| `asana:oauth-client-secret`, `box:oauth-client-secret`, `dropbox:app-secret`, `hubspot:app-client-secret`, `salesforce:external-client-app-consumer-secret`, `zendesk:oauth-client-secret`, `zoom:oauth-app-client-secret` | `client_secret` | flagged | clean |
| `x:oauth1-access-token-secret` | `oauth_token_secret` | flagged | clean |

On the CLI surface the replay of all 1935 cases left 0 controls flagged for the
15 cases of this issue, and no other case's observation changed because of this
fix.

## Boundary and tradeoffs

| Input shape | Result |
| --- | --- |
| `name=&other=1`, `name=&a=1&b=2`, `?name=&other=1`, `a=1&name=&other=1`, `name = &other=1`, `name: &other=1` | no finding |
| `name=`, `name=\n`, `name=\r\nother=1`, `name=;x=1`, `name=,x=1`, `name= &x=1`, `name=""`, `name=''&x=1`, JSON `"name":""`, YAML `name: ""` | no finding (unchanged) |
| `refresh_token=&client_secret=<value>`, `access_token=&refresh_token=&client_secret=<value>` | one finding, exactly the last value |
| `name=<value>&other=1`, `name=<value>`, JSON and YAML members | one finding, exactly the value (unchanged) |
| `password=` followed by `&` and a value (an `&` that is not `&name=`) | still reported (unchanged) |

* False positive removed: a `warn` over a public parameter, which a user policy
  that escalates `warn` to `redact` would have masked.
* False negative added: a real password whose own first bytes read as `&name=`
  (`password=&a=b`) is no longer reported as that one value. It is the same cut
  #816 already accepts after the first byte, now applied at the first byte; the
  form reading wins because an empty value before a form delimiter is the
  frequent case.
* Policy: no new decision. This applies the #816 delimiter rule and the #1223
  "ending at the form delimiter" span to the one position it missed, so it is a
  spec row and this evidence, not an ADR.
* Not changed: a quoted value closed directly before `&` (`name="<value>"&x=1`)
  is not accepted by the quoted-value boundary set, so it yields no finding. That
  is existing behavior, not part of this issue.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs`: the five names
(`access_token`, `refresh_token`, `client_secret`, `oauth_token_secret`,
`password`) with an empty value before `&name=` in assignment, query, form and
spaced layouts; the empty value at the end of the input, before a newline, CRLF,
`;`, `,` and a space, as an empty quoted string and in JSON and YAML; a credential
in the parameter after an empty one (exact span); the same names with real
values unchanged; a value that merely starts with `&`; and the minimal repros
(no span starts at `&`). Every input also runs under whole-input, every two-chunk
UTF-8 byte partition and per-line incremental parity.

## Gates of the issue

The 8 gates are stated per package in the [#1223 record](../1223/README.md#gates-of-the-issue).
This record closes the shared-parser-fix and deterministic-conformance gates for
the empty value; the independent replay of the fixed candidate stays open.

## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written; the statements below are superseded
and this section is the current state. Replay facts shared by all Batch 2 records
are in the [#1223 record](../1223/README.md).

The fix is in candidate `4e0041081aad22d0101bd52db52017b67b5bd3db` (PR #1235) and
was replayed by the benchmark: benchmarks
[#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`), frozen round-2 corpus
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (1935
cases), Node, WASM, Python and the CLI, whole and at 7-byte and 1-byte chunks
([round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md),
[ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)).

| Earlier statement (in this record) | State now |
| --- | --- |
| "the replay of the fixed candidate on them is the benchmarks side's step and stays open" (Before and after) and "the independent replay of the fixed candidate stays open" (Gates) | Done and accepted: benchmarks #771. |
| "On the CLI surface the replay ... left 0 controls flagged" (local, CLI only) | Confirmed by the benchmark on all four surfaces: all 15 cases are `clean`. Of the 25 cases that differ from `a148dadf`, 15 are these controls (`airtable`, `asana` x2, `box` x2, `dropbox` x2, `hubspot` x2, `meta`, `salesforce`, `x` x2, `zendesk`, `zoom`, one `...-form-empty-null:control` each); the replay lists them case by case. |

Dispositions at `74c88531`: the 15 rows of this issue, 14 in G1 to G3 of
[#1223](../1223/README.md) and `x:oauth1-access-token-secret` of
[#1225](../1225/README.md), are `fixed by candidate 4e004108, replay verified on
Node, WASM, Python and CLI (whole, 7-byte and 1-byte streams)`, with 0 positives
failing and 0 controls flagged and no regression. The accepted trade-off was
checked: the frozen corpora contain no positive whose expected value starts with
`&` (round 2 0, round 1 0, Batch 1 0). A one-off synthetic probe with the
candidate build, not a corpus case and not scored, confirms `password=&name=<run>`
yields no finding.

Gate "independent replay of the fixed candidate": **met**, candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No
package digest is claimed (no candidate package was published). Figures are read
from the merged report and ledger; the harness was not re-run for this addendum.
