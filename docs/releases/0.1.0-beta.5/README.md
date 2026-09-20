# 0.1.0-beta.5 release evidence

Published on 2026-09-20 from `rc/0.1.0-beta.5`, using the approved and
qualified source `0cc48374d005a44334bf727e49125165ec7d4157`. All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and
all nine Python distribution files are published. Python spells this version
`0.1.0b5`; npm and Cargo use `0.1.0-beta.5`.

## Qualification and approval

[CI 35527412955](https://github.com/redact-secret/redact-secret/actions/runs/35527412955),
[SAST 35527412967](https://github.com/redact-secret/redact-secret/actions/runs/35527412967),
[Artifact qualification 35527413163](https://github.com/redact-secret/redact-secret/actions/runs/35527413163),
and [Package Release Rehearsal 35527425700](https://github.com/redact-secret/redact-secret/actions/runs/35527425700)
passed at the frozen source revision, including both musl Node lanes. The
qualification inventory records the conformance fixture hashes and
installed-candidate results. Publication was then explicitly authorized for
that source revision.

## Original partial publication

[Release run 35528414802](https://github.com/redact-secret/redact-secret/actions/runs/35528414802)
published both crates, all nine PyPI files, and nine of the ten npm packages
(the wasm runtime and all eight native platform packages, including both musl
lanes). Every one of those nine packages had, in fact, already published
successfully; npm's registry propagation lag caused their post-publish
verification step to time out before the registry became queryable, so the
job reported failure even though publication had succeeded. The npm facade
(`@redact-secret/core`), the registry-install matrix, and the tag remained
pending, since the facade publish job depends on the (falsely) failed
dependency jobs. The preserved [artifact inventory](artifact-inventory.json)
is the qualification artifact from that run, with its eight Python wheel
entries corrected as described below; every other entry is unmodified. Its
exact partial manifest is embedded under `release_evidence.original_manifest`
in [manifest.json](manifest.json).

## Authorized recovery

[Dry run 35530191051](https://github.com/redact-secret/redact-secret/actions/runs/35530191051)
verified the preserved manifest and inventory, independently content-matched
all nine already-published npm dependency packages against their qualified
shasums, and planned publication only of the facade.
[Recovery run 35530799370](https://github.com/redact-secret/redact-secret/actions/runs/35530799370)
published `@redact-secret/core`, but npm processing again exceeded the
workflow's one-minute metadata-verification window — the same false-negative
shape as the original release run, now on the single remaining package.
Independent verification against npm's immutable per-version registry
endpoint (bypassing the aggregate `npm view` cache, which the same lag can
leave stale) confirmed the published shasum matched the qualified content
exactly before any further action was taken. Final
[recovery run 35531013273](https://github.com/redact-secret/redact-secret/actions/runs/35531013273)
re-verified the same already-matching content (idempotent — nothing was
republished), passed clean installs on all eight published Node targets and
Chromium, and created annotated tag `v0.1.0-beta.5` at the frozen source
revision.

The final recovery run provides the registry-backed JavaScript install
evidence. On 2026-09-20, the operator's agent also installed
`redact-secret-cli@0.1.0-beta.5` with `cargo install --locked` into an empty
temporary root and ran its version and clean-input checks, then installed
`redact-secret==0.1.0b5` from PyPI into a new virtual environment and
exercised `scan_and_redact` on clean input. Registry metadata was observed
again for this record on the same date.

## Known discrepancy: non-reproducible Python wheel builds

`release.yml` builds the Python wheels twice from the same source revision:
once in the standalone `python-wheels.yml` job, whose output `publish-pypi`
actually uploads, and independently again inside `artifact-qualification.yml`,
whose output feeds the `Artifact inventory` job. Byte-for-byte comparison
found that all eight published wheels differed from that inventory job's own
recorded hashes; each pair differed by only 1–5 bytes in file size, the
signature of a non-deterministic build input (most likely an embedded
timestamp) rather than different content. The sdist, which has no compiled
step, matched exactly. `docs/releases/0.1.0-beta.4/README.md` records that the
equivalent comparison matched exactly for all nine beta.4 files, so this is
not a structural inevitability of the dual-build design; it appears specific
to this release's wheel build and is unexplained.

This was caught only because beta.5 needed PyPI reconciliation evidence to
begin with — the dual build has apparently always existed, and nothing
previously compared its two outputs. The actually-published wheels were
verified correct by three independent means: downloading each file directly
from `files.pythonhosted.org` and hashing it locally (not trusting API-reported
metadata), confirming those hashes equal what PyPI's JSON API reports, and a
real `pip install redact-secret==0.1.0b5` into a fresh virtual environment
followed by a clean `scan_and_redact` call and an exact-version assertion,
both passing. Both `manifest.json`'s `registries.pypi:redact-secret.files` and
[the preserved inventory](artifact-inventory.json)'s eight wheel entries now
record these independently-verified, actually-published bytes; the inventory's
Python entries were corrected post-hoc from `artifact-qualification.yml`'s own
(differently-built) output for this reason, which is why it is not a byte-exact
copy of that job's output the way the rest of the inventory is. Worth a
follow-up issue to either make the wheel build reproducible or have
`publish-pypi`'s upload also become the qualified artifact
`artifact-qualification` reports on, the way the npm and crate publish jobs
already reuse their qualified build rather than rebuilding.

## Durable record

Reconcile Release intentionally emits no replacement manifest. This checked-in
manifest is therefore marked `reconstructed`: it combines the immutable
original manifest and inventory with final registry checksums, the complete
recovery history, clean-install results, and annotated-tag object and target.
No GitHub Release was expected or created, and qualified CLI binaries remain
Actions artifacts rather than a separate distribution channel.
