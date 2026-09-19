---
decision_id: decision-publish-musl-node-addons
status: accepted
scope: workspace
title: Publish the musl Node addon packages
decided_at: 2026-09-19
---

# Publish the musl Node addon packages

## Decision

Extend `node-publish-targets` in the root `Cargo.toml` from six triples to the
full eight `node-addon-targets` already builds and qualifies, adding
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. Concretely:

- `bindings/node/npm/linux-x64-musl/package.json` and
  `bindings/node/npm/linux-arm64-musl/package.json` are added, each shaped
  exactly like the six existing platform manifests
  (`@redact-secret/node-linux-<arch>-musl`, `"os": ["linux"]`,
  `"cpu": ["<arch>"]`, `"libc": ["musl"]`), so `scripts/check-artifact-matrix.py`
  requires nothing new of the check itself: `platform_names()` already reads
  `linux-x64-musl`/`linux-arm64-musl` from
  `scripts/qualify-node-addon.mjs`'s `TARGET_PLATFORM_NAMES`, which the musl
  qualification lane already relies on.
- `packages/javascript/package.json` gains two `optionalDependencies` entries
  for those packages, pinned to the same version as the other six.
- `packages/javascript/src/runtime/node.ts`'s host-to-package mapping gains a
  libc dimension **for `linux` only**: `resolveAddonSpecifier()` selects
  between the `gnu` and `musl` package for a given architecture by detecting
  the running host's libc, not by trying one and falling back to the other.
  Detection uses `process.report.getReport().header.glibcVersionRuntime`:
  present means glibc, absent on Linux means musl. Selection is by detection
  because it must be: an addon linked against the wrong libc does not fail at
  `require()`/`dlopen` the way a missing or corrupt addon does — the failure
  surfaces later, at the first unresolved symbol touch, as an unrecoverable
  process-fatal `symbol lookup error`, not a catchable exception. A
  probe-then-fall-back loader would crash the process on exactly the host
  this decision exists to support instead of reaching
  `INITIALIZATION_FAILED`.
- `.github/workflows/release.yml`'s `publish-native-dependencies` matrix
  gains the two corresponding `{ target, platform }` entries. Every step in
  that job (download the qualified `node-addon-<target>` artifact, assemble,
  pack, content-check, publish, verify, record registry state) is already
  generic over `matrix.target`/`matrix.platform`, so no step changes.
- `scripts/validate-release-records.py`'s expected npm dependency-package
  list gains the two new package names.
- `README.md` and `docs/qualification.md` are updated to state that npm now
  ships musl addons, replacing the "npm ships glibc only" language with the
  new eight-triple story and the libc-detection behavior above.

The CLI's own musl gap is unaffected: `cli-release-targets` stays the six
non-musl triples. A static musl CLI binary is a distinct, unqualified
artifact this decision does not create.

## Rationale

`docs/audits/repeated-release-readiness-audit.md` classifies "no shipped
musl npm... package" as an **intentional** support exclusion owned by
`decision-ship-first-release-artifact-set` (issue #79) and issue #140, with a
stated bar for reversing it: "Adding any requires a separately reviewed
contract, implementation, and full qualification." This record is that
contract.

The reversal is inexpensive because the qualification work already exists
and already passes: `node-addon-targets` has built and smoke-tested both musl
triples inside `rust:1-alpine` containers since before this decision, per
`docs/qualification.md`'s "Native targets and where they run" table and its
own "The musl addon has a qualification path, not a publication path"
section. What was missing was never a technical blocker — it was a
publication path: two npm manifests, two `optionalDependencies` entries, and
a libc dimension in the runtime's host-to-package mapping. No new qualifying
job is added by this decision; the existing `node-addon` job in
`artifact-qualification.yml` already proves the exact artifact this decision
publishes.

Publishing the native addon is also the right answer for musl specifically,
ahead of any WebAssembly fallback (`decision-add-node-wasm-fallback`): a
native artifact is already built, already qualified, and strictly faster
than a WebAssembly one, so routing musl consumers through a fallback when a
qualified native addon already exists for their exact triple would leave
them worse off than consumers on every other supported platform, not merely
different.

## Alternatives considered

- **Leave `node-publish-targets` at six and rely only on the WebAssembly
  fallback for musl hosts** (`decision-add-node-wasm-fallback`). Rejected: it
  would make musl the one platform where the qualified, faster native addon
  exists but is deliberately withheld in favor of a slower path, for no
  qualification or engineering-cost reason — the opposite of what "already
  built, already qualified" argues for.
- **Keep the status quo.** Rejected: this is the exclusion issue #443 asks to
  revisit, and revisiting it costs a publication path, not a qualification
  program — the audit's stated bar is met by this record plus the changes it
  describes.
- **Also publish a musl CLI binary in the same change.** Rejected as
  out of scope: the CLI's musl exclusion is a distinct, separately governed
  claim (`cli-release-targets`) with its own qualification question (a static
  musl executable), and issue #443 is about the npm/Node path specifically.

## Consequences

- `scripts/check-artifact-matrix.py` enforces the extended matrix the same
  way it enforces the current one: adding a target to `node-publish-targets`
  without also adding its npm manifest, `optionalDependencies` entry, and
  `runtime/node.ts` mapping (or the reverse) fails `npm run artifacts:check`.
  No change to that script itself is required.
- `packages/javascript/test/resolve-addon-specifier.test.ts` and the addon
  contract tests must cover the new libc-aware resolution, including both
  Linux branches and the non-Linux platforms where the libc dimension does
  not apply.
- Consumers who currently observe `INITIALIZATION_FAILED` on Alpine now get a
  working native addon instead, once they upgrade past this release; nothing
  changes for consumers on the six already-published platforms.
- This decision does not select a version or authorize any release, branch,
  tag, or publication. Existing release authority (`AGENTS.md`, "Release
  authority") remains in force.
