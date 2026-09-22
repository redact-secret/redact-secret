# Beta.2 final review — reproduction probes

[Audit archive](../../README.md) · [Beta.2 final code review](../../beta2-final-code-review.md)

Two offline, synthetic-input probes behind the parent review's confirmed
findings for issues #234–#238. They report defects; they are not a CI pass
gate. Neither probe prints retained secret text — only error codes,
session states, sizes, booleans, and safe offsets.

## `reproduce.mjs`

Loads a freshly built Node addon directly via `process.dlopen` (path given
as the first argument, default `target/debug/libredact_secret_node.dylib`)
and exercises:

- **#234** — appending an invalid chunk (a number, an unpaired surrogate)
  to an incremental session mid-stream: records the error code, the
  session's state afterward, and whether a `finalize()` call re-emits
  previously accepted text.
- **#235** — a leading BOM (`﻿`) ahead of a matched credential,
  streamed with the split point at every byte offset 0–3: compares each
  streamed result's text and first finding's `start` offset against the
  whole-input result, to confirm the BOM is neither stripped nor shifts
  offsets.
- **#236** — 150,000 short matching lines appended directly (all findings
  present) versus through the byte-stream adapter, to observe whether
  argument-count accumulation still fails at that density.

## `reproduce.py`

Loads a freshly built Python extension the same way (`importlib`, path
given as the first argument, default
`target/debug/libredact_secret_python.dylib`) and exercises:

- **#234** — the same invalid-append probe as `reproduce.mjs`, against the
  Python incremental binding.
- **#237** — loads `scripts/verify-recovery-artifact.py` directly and feeds
  `verify_pypi` an inventory whose PyPI-reported file set is a strict
  subset of the local qualified set, to confirm the mismatch is rejected
  rather than treated as recovery-complete.
- **#238** — runs `.github/workflows/release.yml`'s `state` step verbatim
  under `bash -c` with an `npm` stub forced to fail, to confirm a registry
  query failure is recorded as `unknown` rather than defaulting to
  `not-published` or `published`.

Requires PyYAML. Build the reviewed code first (`npm run js:build` and
`cargo build -p redact-secret-node -p redact-secret-python --locked`); an
old local binary with a matching version number is not evidence for the
current source. Full invocation:
`docs/audits/beta2-final-code-review.md`'s [Reproduction evidence](../../beta2-final-code-review.md#reproduction-evidence).
