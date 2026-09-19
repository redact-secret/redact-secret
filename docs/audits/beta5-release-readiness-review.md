# Beta.5 release readiness review

Reviewed on 2026-09-19 against `main` at
`f2ad8558fe1cd1def64e89ac6cefec99535f2424`, with the readiness fixes committed
alongside this report. Release tracking:
[#421](https://github.com/redact-secret/redact-secret/issues/421).

## Decision

Integrate these fixes through review before cutting `rc/0.1.0-beta.5`. The
blockers recorded when #421 was opened against `5899654` (#414–#420 and the
pre-release fixes in PR #422) are closed. Feature work for #438–#462 merged in
the same interval. Two of those, #443 (musl Node packages and the Node
WebAssembly fallback) and #462 (Cloudflare Workers), changed the published
artifact set and the runtime paths without matching release, recovery,
record, or changelog changes. That left publishable gaps, fixed below. No
open defect remains that blocks candidate preparation.

## Fixed in this review

- **Vacuous Node install lanes.** Since #443, a Node consumer whose native
  addon fails to install or load falls back to WebAssembly and passes every
  functional check. `scripts/consumer-harness.mjs` did not assert which
  artifact ran, so the pre-publish installed-package lanes and all
  post-publish registry-install lanes would pass without the addon. The Node
  lane now requires `artifact()` to report `"addon"`. With a corrupt addon
  substituted locally, the lane fails with that message; before the change it
  passed.
- **Unverified musl publication.** `release.yml` published the two musl
  packages but registry-install-verified only six platforms, while
  `record-artifact-inventory.py` claimed all declared publish targets. The
  release now verifies all eight, the musl lanes inside `node:22-alpine` on
  x64 and arm64 runners, the same way qualification loads the musl addon.
- **No recovery path for musl.** `reconcile-release.yml` hard-coded six
  platforms for both repair and install verification. It now covers all
  eight.
- **No drift check for either.** `check-artifact-matrix.py` now requires the
  release publish and install matrices and the reconcile platform map and
  install matrix to equal `node-publish-targets`. Run against the unfixed
  workflows, it reports all three gaps. `check-rust-workspace.py` now requires
  the facade's exact `@redact-secret/*` pins to equal the product version;
  consumer qualification substitutes local tarballs, so a stale pin would
  otherwise first appear at registry install.
- **A beta.5 record could not validate.** `validate-release-records.py`
  accepted only the eleven-artifact, six-lane shape. It now keeps that shape
  for the frozen beta.1–beta.4 records and requires thirteen artifacts and
  eight Node lanes for every later release.
- **Unqualified runtime claims.** The Node WebAssembly fallback and Cloudflare
  Workers path were supported in documentation but exercised only by manual
  scripts. Artifact qualification now runs both scripts, for both profiles,
  against the `browser` job's builds, and the inventory job requires that
  job. All four runs passed locally on `aarch64-apple-darwin`.
- **Silent limit wrapping.** JavaScript passed any numeric limit to the
  bindings' `u32` conversion, so `-1` became 4 GiB, `2 ** 32 + 4` became 4,
  and `1.5` became 1, for whole-input and incremental limits alike. Those
  values now fail with `INVALID_LIMITS` before reaching the binding. Python
  already raised on them.
- **Changelog.** `Unreleased` had no entry for #443 or #462, labeled #447
  additive although Node `redact()` now rejects a finding without
  `obfuscation`, and ran to about 400 lines. It is condensed into release
  notes with a compatibility section: whole-input limits, `obfuscation`, the
  new Rust error variant, the CLI text-report field order, and
  `@redact-secret/wasm`'s new exports map. Grammar provenance stays in the
  decision records and `docs/audits/evidence/367/`.
- **Documentation.** User guides, package READMEs, the API contract, the
  crate surface table, and the release runbook still described glibc-only npm
  packages, six native packages, greedy overlap selection, and published
  adapter packages that do not exist on npm or PyPI. They now match the code.
  `SecretObfuscation` is exported beside the finding types that use it.

## Public API and default-policy review

Beta.4 had no public API diff from beta.3; beta.5 does. The changes and their
compatibility notes are in `CHANGELOG.md` under `Unreleased`:

- Breaking: default whole-input limits (#439); `obfuscation` required by Node
  `redact()` and the TypeScript types (#447); `SecretScanErrorCode` gains a
  variant on a non-`#[non_exhaustive]` enum; the CLI text report gains a field
  before `id=`; `@redact-secret/wasm` gains an `exports` map.
- Default policy: overlap resolution ranks resolved action before
  specificity (#450), which changes the winner only where a medium-confidence
  candidate overlaps a stricter-resolving one. Invisible-character
  normalization (#445) adds findings for obfuscated credentials. Seven
  provider grammars narrow (#368–#374), with the intentional false negatives
  recorded in their decision records and a measured 32/56 → 56/56 twin
  discrimination with every required positive preserved (#376).
- Additive: the `common` profile, the `Obfuscation` signal, the Node
  WebAssembly fallback with `artifact()`, two musl packages, and the `workerd`
  condition with two `.wasm` subpath exports.

## Not blocking, recorded

- `conformance/benchmark-regressions.json` keeps `benchmark-gap-292`'s
  product-conformance gate pending, though its fixtures have since run in
  `main`'s qualification, and `benchmark-gap-294`'s revalidation gate
  pending. The #429 evidence attributes the second to a stale copy of the
  benchmarks pin manifest and calls for a follow-up issue, which does not
  exist yet. Neither gate is a release gate.
- `record-artifact-inventory.py`'s `packageContents` lists only
  `@redact-secret/core` and the core crate, not the wasm, native, or CLI
  packages. This predates beta.5.
- The Workers qualification needs `wrangler`, so it runs in artifact
  qualification but not in `npm run ci`.

## Evidence

Local checks on `aarch64-apple-darwin`:

- Baseline `main` (`f2ad855`), before any change: `npm ci --ignore-scripts`,
  `npm run ci`, `npm run rust:check`, `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`, and
  `cargo test -p redact-secret-wasm --no-default-features` passed.
- With these fixes: the same commands, `npm run sast:scan` (43 findings and
  20 acknowledged scan errors, zero unresolved; seven known parse errors and
  one reviewed finding re-keyed to the lines these edits moved them to), the
  installed Node package lane with the host addon, and the Node WebAssembly
  fallback and Cloudflare Workers qualification for both profiles.

The new `package-consumer-wasm-runtimes` job runs only in full qualification,
which a pull request does not trigger; dispatch it on the branch or observe
its first `main` run. Its first real run, on `rc/0.1.0-beta.5` at `0324c80`
(run 35472611837), found a defect this local pass could not: `npx` does not
forward signals to `wrangler`, so `scripts/qualify-workerd-artifact.mjs` left
`workerd` alive holding its pipes and never exited, and the job was cancelled
at its timeout. The qualifier now stops the whole process group and releases
those pipes. The musl registry-install lanes and reconcile changes
can only run against a real publication. These checks do not qualify an RC
revision, establish cross-platform behavior, or prove the absence of
defects. After review and merge, candidate preparation follows
[the release runbook](../releasing.md#prepare-the-candidate), including
`beta5-candidate-public-contract-review.md` and
`record-artifact-inventory.py`'s pointer to it.

No version, tag, package publication, workflow dispatch, or release approval
was performed by this review.
