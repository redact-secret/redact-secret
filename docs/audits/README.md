# Temporary review index

[Documentation home](../README.md)

This folder holds only temporary reviews: a review or evidence unit written
while work is in progress, with an owner and a retirement trigger. Everything
that was finished has left the tree. The retired bodies stay in git history, and
a 40-hex permalink cites them; nothing here is a status dashboard or an
archive.

## Lifecycle

[`decision-retire-historical-audit-bodies-before-release-qualification`](../decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md)
fixes the rules. In short:

- The entry file of every unit (`<name>.md` or `evidence/<unit>/README.md`)
  starts with a front matter block: `owner`, `reviewed_source` (a 40-hex
  commit), `status` (`in-progress`, `final`, `deferred` or `retained`) and
  `retire_on` (`before-qualification`, `after-issue:#N` or
  `after-release:<version>`). A `final` unit also carries `record`.
- A `final` unit is retired before release qualification. Its conclusions move
  to the authoritative spec, contract, decision or release record, and its body
  is deleted without a stub or a replacement index row.
- Anything a script or CI reads is a live input and does not belong here.
- Benchmark and scanner results belong in
  [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks).
  An exploratory log stays in an issue comment.
- Cleanup is a reviewed pull request merged before the source SHA is recorded
  for qualification. Publication changes no file.

The index lists only what is in the tree. It grows when a unit is added and
shrinks when a unit is retired; it keeps no row for a retired unit.

## Units in the tree

| Unit | Owner | Status | Retires |
| --- | --- | --- | --- |
| [beta.15 candidate public-contract review](beta15-candidate-public-contract-review.md) | [#1320](https://github.com/redact-secret/redact-secret/issues/1320) | `retained`: candidate review, not release approval | after release `0.1.0-beta.15` |
| [#1003 us-ssn identity-only mismatch, public investigation](evidence/1003/README.md) | [#1003](https://github.com/redact-secret/redact-secret/issues/1003) | `deferred`: the protected half of the issue is open | after #1003 |

## History

Every earlier review, evidence unit and close-out is in the commit history. The
pin below contains each of them byte-identical to the tree that was removed:

- Pin: `2816897f96c405c3eb8c87a0c70eba5df273c121`
- Link form: `https://github.com/redact-secret/redact-secret/blob/` + the pin + `/docs/audits/` + the path
  (use `tree` instead of `blob` for a folder)

Three units written after that pin were retired when their triggers fired and
live at a second pin, `0c62fd38bca75c5b28b042dc79789b708ebf1d17` (the
`0.1.0-beta.14` release source): the beta.14 candidate public-contract review
(`beta14-candidate-public-contract-review.md`, whose conclusions are in the
[beta.14 release record](../releases/0.1.0-beta.14/README.md)) and the
`evidence/1219` and `evidence/1220` WebAssembly size records (their figures are
in the action policy decisions).

The deferred quality backlog (`deferred-quality-backlog.md`, 25 findings, owner
#80) was retired by epic #1259 and lives at a third pin,
`871207e201664ed17a654cbe2cfa9ab4433a06fc`. Ten of its findings were still
valid and are tracked by [#1273](https://github.com/redact-secret/redact-secret/issues/1273),
[#1274](https://github.com/redact-secret/redact-secret/issues/1274),
[#1275](https://github.com/redact-secret/redact-secret/issues/1275) and
[#1276](https://github.com/redact-secret/redact-secret/issues/1276); the rest
were closed or stale.

The first pin has one exception: `evidence/367/README.md` and `evidence/475/README.md`
were edited by #1262 when the files they described moved, so the pin holds
their complete text and the later commit holds only the edited pointer. The
live files moved to
[`docs/contracts/precision/`](../contracts/precision/) and
[`docs/coverage/`](../coverage/).

`python3 -B scripts/check-historical-permalinks.py` verifies every such
permalink against the local history, and `--retirement-pin <sha> --retire
<paths>` proves a pin before a deletion. The closed issue a retired unit
belonged to carries its permalink as a comment
([#1264](https://github.com/redact-secret/redact-secret/issues/1264)), and
`git log --diff-filter=D --name-only -- docs/audits/` lists what was removed.

## Adding a unit

1. Write `docs/audits/<name>.md` or `docs/audits/evidence/<unit>/README.md` with
   the front matter block above.
2. Add one row to the table here, linking the entry file. The
   `audits-index:check` gate fails on a unit that has no link.
3. When the unit is final, record its permalink, move the conclusions to the
   authoritative document, delete the body and the row.
