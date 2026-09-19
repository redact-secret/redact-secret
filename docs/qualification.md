# Cross-platform qualification

How every supported artifact of the product is built and proved from one
commit, and what that run does not yet cover.

`decision-release-bindings-in-lockstep` makes the Rust crate, the npm package,
the Python package, and the CLI one product with one version: a release
candidate must build and qualify *every* required artifact from the same
revision before any registry publication begins.
`decision-govern-cross-language-conformance` makes the top-level `conformance`
corpus the single behavioral contract each of those artifacts is measured
against. This document describes the workflow that carries both out.

Nothing here publishes anything. Publication requires the separate release
approval `AGENTS.md` defines.

## Candidate security evidence

The separate `.github/workflows/sast.yml` OpenGrep gate (#156) is required
alongside artifact qualification. It verifies the pinned tool and rules,
enforces the reviewed baseline, and records source revision, tool version,
rules digest, findings, and acknowledged scan errors. SARIF upload is
best-effort; the scan outcome remains the enforcement signal. Candidate
reviews must include that evidence at the reviewed revision, not substitute
`npm run sast:test` (which tests gate machinery) for an actual scan.
See the [SAST contract](../sast/README.md) and the
[candidate public-contract review](audits/candidate-public-contract-review.md).

## The declaration

`[workspace.metadata.redact-secret]` in the root `Cargo.toml` states the whole
supported surface once:

| Key | What it declares |
| --- | --- |
| `node-addon-targets` | Every triple the N-API addon is built and smoke-tested for |
| `node-publish-targets` | Every triple with a published `@redact-secret/node-<platform>` npm package |
| `cli-release-targets` | Every triple the CLI binary is built and smoke-tested for |
| `python-wheel-targets` | Every triple an abi3 wheel is built and smoke-tested for |
| `browser-engines` | Every engine the WebAssembly artifact is initialized and scanned in |
| `node-support-majors` | Every Node.js major `engines.node` claims, and CI therefore exercises |

The native lists are the same platform story: Linux glibc and musl on x64
and arm64, macOS on x64 and arm64, and Windows on x64 and arm64 — eight
triples. `node-addon-targets` and `node-publish-targets` are the same eight
(`decision-publish-musl-node-addons`): every addon this matrix builds and
qualifies is also published. **The CLI still ships no musl variant**, so
`cli-release-targets` remains six non-musl triples, the one deliberate
exception left, narrower than the addon's own matrix and required to stay a
subset of `node-addon-targets`. On top of that: Chromium, Firefox and
WebKit for the browser, and Node.js 20, 22 and 24.

`scripts/check-artifact-matrix.py` (run by `npm run artifacts:check`, and by
the `Artifact matrix policy` job every other job waits on) fails when any of the
places that must agree with those lists drifts:

- `bindings/node/package.json` `napi.targets` against `node-addon-targets`;
- the `addon-target`, `cli-target`, and `engine` matrices in
  `.github/workflows/artifact-qualification.yml` against their declarations, in both
  directions, so a target cannot be added to one file alone;
- `scripts/qualify-node-addon.mjs`, `scripts/qualify-cli-binary.mjs`, and
  `scripts/qualify-browser-artifact.mjs`, each of which must know every
  target or engine it may be asked to verify;
- the `node-version` matrix in `.github/workflows/ci.yml` and the per-major
  addon smoke steps against `node-support-majors`;
- for `node-publish-targets`: the platform directories under
  `bindings/node/npm/`, each directory's `package.json` `name`,
  `packages/javascript/package.json`'s `optionalDependencies`, and the
  package names `packages/javascript/src/runtime/node.ts` maps hosts to — so
  a target cannot gain or lose a publication path, and the glibc/musl
  boundary cannot drift, in one file alone.

`engines.node` itself belongs to `scripts/check-rust-workspace.py`, which
derives the exact majors from `ci.yml` and requires every lockstep manifest
— the wrapper, the N-API addon's own manifest, and every native platform
package under `bindings/node/npm/*/package.json` — to enumerate them
(`20.x || 22.x || 24.x`) rather than leave the claim open-ended: `>=20`
cannot be bound to a finite matrix, and a platform package that claims fewer
majors than the wrapper would silently narrow what an installer can run on
without that narrowing ever being reviewed. The WebAssembly npm package
(`bindings/wasm/npm/package.json`) carries no `engines.node` claim, so it is
outside that check, but its `version` is still held in lockstep with every
other package. Only one script owns the `engines.node` rule, so the two
scripts cannot contradict each other.

The same script enforces the two CI controls the release decision depends on:
every workflow declares a top-level `permissions` and every job declares its
own, with `write` only where `WRITE_SCOPE_ALLOWLIST` names it; and every
`uses:` outside this repository is pinned to a full 40-character commit SHA.

`scripts/tests/test_check_artifact_matrix.py` covers each of those
failures in both directions against a synthetic repository.

## The workflow

`.github/workflows/artifact-qualification.yml` runs on `workflow_dispatch`, on every
push to `main`, and on a pull request that changes the matrix's own machinery.
It is also `workflow_call`-able, so release automation can require it rather
than re-implement it. The full fan-out is expensive, which is why an ordinary
pull request does not trigger it.

| Job | What it proves |
| --- | --- |
| `declaration` | Every list above agrees with every file that consumes it |
| `rust` | Calls `CI`: format, lint, dependency policy, workspace tests on three hosts, MSRV, rustdoc, crate package contents, and the `wasm32-unknown-unknown` target and its `wasm-bindgen` tests |
| `python` | Calls `Python wheels`: the abi3 wheel matrix and source distribution, each smoke-tested on the abi3 floor and a current interpreter |
| `node-addon` | Builds the addon for each triple and qualifies it on Node 20, 22, and 24 |
| `browser` | Builds the WebAssembly artifact and qualifies it, and the package on top of it, in each engine |
| `cli` | Builds the CLI for each triple and qualifies the binary |
| `package-consumer-node` | Installs packed candidate packages in a clean directory and exercises public scan, incremental, and Node stream APIs on Node.js 20, 22, and 24 |
| `package-consumer-browser` | Installs the same candidates and exercises public scan, incremental, and Web stream APIs in Chromium, Firefox, and WebKit |
| `inventory` | Requires the whole declared matrix and records what was built |

Because `rust` and `python` are called workflows rather than copies, their
jobs run in the same workflow run, at the same revision, and their artifacts
land in the same artifact store the `inventory` job reads.

### Native targets and where they run

Each family uses the same runner map, and every artifact is smoke-tested on
the architecture it targets — none is "built only":

| Target | Runner | Smoke |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | host |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | host |
| `x86_64-unknown-linux-musl` | `ubuntu-latest` | `*-alpine` container (addon only) |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | `*-alpine` container (addon only) |
| `x86_64-apple-darwin` | `macos-15-intel` | host |
| `aarch64-apple-darwin` | `macos-latest` | host |
| `x86_64-pc-windows-msvc` | `windows-latest` | host |
| `aarch64-pc-windows-msvc` | `windows-11-arm` | host |

The musl rows apply to the addon only. That artifact is a cdylib, and
`musl-tools` cannot link one — its gcc wrapper ships no musl
`libgcc_s.so.1`. Routing rustc's self-contained objects through the glibc
driver instead does produce a library, and that library segfaults the moment
Node loads it. So the musl addon is built natively inside a `rust:1-alpine`
container of the same architecture, where the host triple already is the
target, and is then qualified in a musl image, which is where it runs.

## What each qualifier proves

### `scripts/qualify-node-addon.mjs`

1. The addon directory holds the generated loader, its declarations, and
   exactly one compiled `.node` whose name matches the requested target.
   Everything present is printed.
2. `bindings/node/smoke-test.mjs` runs against the real artifact, not a
   double.
3. Every canonical synchronous fixture goes through the addon's `scan`, with
   each expectation's UTF-8 byte offsets converted to UTF-16 code units by a
   reference conversion independent of the binding.
4. The published JavaScript package's public API, driven against that addon
   resolved under `@redact-secret/node-<platform>` from
   `packages/javascript/node_modules`, the way an installed consumer
   resolves it: `initialize()`, one canonical fixture through
   `scripts/qualify-runtime-fixture.mjs`, a frozen finding,
   `scanAndRedact` against `scan` then `redact`, and a real
   `createIncrementalSanitizer` session — a synthetic value split across
   chunks, including one that only closes on a later chunk, sanitized the
   same way the whole-input API would, and rejecting a post-`finalize`
   `append` with `INVALID_STATE`.

`--detector-profile common` (`decision-define-detector-profile-and-pack-contract`)
runs pass 3 against `conformance/fixtures/common-profile-expectations.json`
instead of the corpus's own `full` expectations, asserts every finding comes
from a detector in `common`'s membership, and asserts
`profile()`/`profileCommon()` report the fixed `"full"`/`"common"` strings.
Passes 4 and 5 (below) run against `@redact-secret/core/common` instead of
the root export, using `jwt-positive-structured` rather than the shared
stream fixture for the reason its own comment in the script gives (the
shared fixture is a `provider`-pack finding under `full`, which `common`
does not redact). One compiled addon links both profiles, so there is no
second `.node` file to select between — `--detector-profile` only changes
which exports, expectations, and fixture each pass uses.

### `scripts/qualify-browser-artifact.mjs`

`npm run wasm:build` (`scripts/build-browser-artifact.mjs`) compiles the
`wasm32-unknown-unknown` cdylib and generates the `web`-target glue with a
`wasm-bindgen` CLI whose version must match the crate's exactly. The qualifier
serves that directory over HTTP — with `application/wasm` on the binary, which
streaming instantiation requires — and loads two pages in each engine against
that one artifact.

The first, `scripts/browser-harness.mjs`, drives the artifact through its own
exports:

- a synchronous call before `initialize()` fails with `NOT_INITIALIZED`;
- `initialize()` is idempotent, `version()` reports the product version, and
  `profile()` reports the compiled detector profile;
- every canonical synchronous fixture matches, converted as above, and every
  finding comes from a detector in the artifact's profile;
- an incremental session fed each positive fixture in two chunks produces
  the same text and findings as `scanAndRedact` on the same artifact;
- the corpus's astral fixture is present, and prefixing or suffixing any
  positive fixture with an astral character shifts its reported span by
  UTF-16 code units rather than UTF-8 bytes;
- `scanAndRedact` equals `scan` then `redact` and no redacted span survives;
- a throwing policy surfaces `POLICY_FAILURE` carrying no input, and custom
  policy and formatter callbacks take effect.

`--detector-profile common` runs the same page against the `common` artifact
(`npm run wasm:build:common`, `bindings/wasm/pkg-common`)
(`decision-define-detector-profile-and-pack-contract`). Each fixture's
expectation is then its reviewed entry in
`conformance/fixtures/common-profile-expectations.json`, which the Rust core
asserts in `crates/secret-scan-core/tests/common_profile_corpus.rs`. The
package page below also runs for `common`, but against
`scripts/browser-package-harness-common.mjs`, which drives
`@redact-secret/core/common` instead of the root export — bundled with its
own literal `import("@redact-secret/wasm/common")` and
`import("@redact-secret/core/common")` specifiers, never the `full` ones, so
a consumer's bundler behavior is reproduced exactly rather than assumed. It
skips the Web stream adapter's checks: `@redact-secret/core/web-stream` is
not profile-aware yet (see the README's "Opt-in detector profiles" section),
and importing it at all would bundle the `full` artifact into the `common`
check.

The "astral character *within* a finding" case is not observable end to end,
because no built-in detector matches a span containing one; it is asserted at
the unit level by `bindings/wasm/src/range.rs` under the `Rust wasm32 target`
job.

The second, `scripts/browser-package-harness.mjs`, is bundled the way a
consumer bundles it — the `browser` condition selecting `dist/runtime/
browser.js` through the package's own `imports` map, and the artifact
specifier aliased to the glue being served — and drives the published
`@redact-secret/core` public API on top of the same artifact: the
`NOT_INITIALIZED` gate, `await initialize()`, `RANGE_UNIT` and `VERSION`, the
whole canonical corpus, frozen findings with exactly the seven documented
keys, `scanAndRedact` against `scan` then `redact`, a policy callback
receiving a frozen finding with numeric offsets, and a real
`createIncrementalSanitizer` session — a synthetic value split across
chunks, including one that only closes on a later chunk, sanitized the same
way the whole-input API would, and rejecting a post-`finalize` `append` with
`INVALID_STATE`. That is the layer no other check reaches: the package's own
binding glue, running on a real artifact in a real engine.

### `scripts/qualify-cli-binary.mjs`

The artifact is an executable with the expected name, and its size and SHA-256
are printed; `--version` and `--help` report the product identity; the
documented exit codes hold (0 clean, 1 findings, 2 usage error, with the usage
block on stderr and nothing on stdout); every canonical fixture matches through
one multi-source `--json` run — the CLI reports UTF-8 byte ranges, the corpus's
own unit, so no conversion is involved; and `--redact` over every positive
fixture produces exactly the text its own findings and the documented default
placeholder imply, with no match surviving.

## The inventory

`scripts/record-artifact-inventory.py` closes the run. It requires every
declared target to have produced an artifact and nothing else to have appeared,
then writes `artifact-inventory.json` and a job summary carrying:

- the source commit, ref, and workflow run — on a pull request the head
  commit, not the `refs/pull/N/merge` commit GitHub synthesizes for
  `github.sha`, which no clone can resolve;
- the product version, and `"published": false`;
- the SHA-256 of every canonical fixture file, because an artifact set only
  means something alongside the contract it was qualified against;
- the declared matrices as they stood at that revision; and
- every artifact file with its family, target, size, and SHA-256, plus the
  file-by-file contents of the npm package and the public Rust crate.

Each installed JavaScript matrix row also uploads a JSON qualification record.
The inventory requires one record for every declared Node major and browser
engine, and records it alongside the built artifacts. Each record carries the
source revision; the exact packed wrapper, native, and WebAssembly package
names and SHA-256 identities; the install and public-API commands; runtime
version; and pass/fail results for initialization, scan, incremental, and
stream behavior. The inventory rejects a missing runtime row, mismatched
revision, incomplete artifact identity, or non-passing result.

## The musl addon is published, selected by detection

`node-addon-targets` builds and qualifies eight addons, and since
`decision-publish-musl-node-addons` all eight are published:
`node-publish-targets` matches it exactly, `packages/javascript` declares
one `optionalDependencies` entry per platform including both musl triples,
and `runtime/node.ts` selects between a Linux host's `gnu` and `musl`
package by **detecting** the running libc
(`process.report.getReport().header.glibcVersionRuntime`), never by trying
one and falling back to the other. Detection is required, not merely
convenient: an addon linked against the wrong libc does not fail at
`require()` the way a missing or corrupt addon does. The failure surfaces
later, at the first unresolved symbol touch, as a process-fatal `symbol
lookup error` outside any `try`/`catch`'s reach, so the wrong candidate must
never be allowed to load in the first place. The package-level pass here
links the local build under whichever specifier the runtime resolves, which
is why it passes on musl too.

`scripts/check-artifact-matrix.py` keeps this boundary from drifting: adding
a target to `node-publish-targets` without also adding its
`bindings/node/npm/<platform>/package.json`, its
`packages/javascript/package.json` `optionalDependencies` entry, and its
`runtime/node.ts` mapping (or the reverse) fails `npm run artifacts:check`.

## The Node WebAssembly fallback

`decision-add-node-wasm-fallback` adds a second path once the addon path has
already failed for any reason: an unsupported platform or architecture, a
matching optional dependency that did not install, or a corrupt addon. Since
`decision-publish-musl-node-addons`, this no longer includes musl — that
host now has its own qualified, faster native addon — but it still covers
FreeBSD and other unsupported hosts, and a broken install on any platform.
Instead of the fixed `INITIALIZATION_FAILED` those cases used to reach
unconditionally, `initialize()` now also tries the same WebAssembly artifact
`@redact-secret/wasm` publishes for browsers, reusing its `--target web`
build unmodified: the Node loader reads the `.wasm` binary from disk and
instantiates the generated glue's `default()` export with
`{ module_or_path: <bytes> }` instead of the `fetch`-based path a browser
takes. `artifact()` reports which artifact actually loaded (`"addon"` or
`"wasm"`), so an application can log or assert it; it always reports
`"wasm"` in a browser.

`scripts/qualify-node-wasm-fallback.mjs` qualifies this path against the
real published artifact: it links the built WebAssembly package into
`packages/javascript`'s own `node_modules` at the specifier the fallback
loader resolves, deliberately without linking any addon, then drives the
published package's public API — `initialize()`, `artifact()`, a
synchronous scan, an incremental session, and the Node `Transform` stream
adapter — and asserts every one of them matches the same artifact's
whole-input result. Unlike `node-addon`/`browser`, this is not (yet) its own
CI qualification job: no host in the current matrix is missing a native
addon by design, so there is no natural place in the fan-out to run it
against every platform the way the addon and browser artifacts are. Run it
locally after `npm run wasm:build` and `npm run js:build` (see "Running it
locally" below); a dedicated CI lane is left to a follow-up.

## Incremental sanitization is qualified on every JavaScript runtime

`bindings/wasm` builds a real, bounded `IncrementalSanitizer` session
(`bindings/wasm/src/incremental.rs`), the same core session `bindings/node`
and `bindings/python` wrap, with its own chunk-by-chunk UTF-16 offset
conversion rather than the whole-input `range` module `scan`/`redact` use.
`scripts/qualify-browser-artifact.mjs`'s package-level pass (above) exercises
it on the real artifact in a real engine, the same way
`scripts/qualify-node-addon.mjs`'s package-level pass exercises Node's.

The `Rust wasm32 target` CI job additionally runs this crate's own
`wasm_bindgen_test` suite for `bindings/wasm/src/incremental.rs` under Node
(no browser needed): lifecycle misuse, a throwing policy callback, a limit
failure, `abort`, and chunk-boundary/Unicode equivalence with the whole-input
result, all against the compiled `wasm32-unknown-unknown` binary.

## The stream adapters are qualified on the same real artifacts

`packages/javascript/src/adapters/node-stream.ts` and `.../web-stream.ts`
wrap the same incremental session in a Node `Transform` and a Web
`TransformStream`; `test/adapters/*.test.ts` exercises that wrapping logic
only against the deterministic double (`test/sanitizing-binding.ts`), because
neither the compiled addon nor the WebAssembly artifact exists in a source
checkout. `scripts/qualify-node-addon.mjs`'s package-level pass drives
`NodeStreamSanitizer` over the real addon, and
`scripts/qualify-browser-artifact.mjs`'s package-level pass drives
`WebStreamSanitizer` over the real artifact in each engine: every UTF-8
byte-partition point of a Unicode-bearing canonical fixture (compared against
a whole-input pass of the same real session, not a hardcoded expectation),
frozen absolute findings, backpressure, `destroy()`/cancellation/abort, and
that a downstream failure or malformed/truncated UTF-8 keeps already-finalized
output while discarding everything still retained.

## Running it locally

```bash
npm run artifacts:check                 # the declaration and CI controls

npm --prefix bindings/node ci
npm --prefix bindings/node run build    # this host's triple
npm run js:build
npm run addon:qualify -- --target <triple>

npm run wasm:build
npx playwright install --with-deps chromium firefox webkit
npm run browser:qualify                 # or --engine chromium
npm run wasm:build:common
npm run browser:qualify -- --detector-profile common

npm run node-wasm-fallback:qualify -- --wasm-dir bindings/wasm/pkg
npm run node-wasm-fallback:qualify -- --wasm-dir bindings/wasm/pkg-common --detector-profile common

# Clean installed-candidate checks (repeat across the declared matrices).
node scripts/qualify-package-consumer.mjs --lane node \
  --wasm-dir dist/wasm-web --report installed-javascript-node-22.json
node scripts/qualify-package-consumer.mjs --lane browser --engine chromium \
  --wasm-dir dist/wasm-web --report installed-javascript-browser-chromium.json

cargo build --release --locked -p redact-secret-cli
npm run cli:qualify -- --binary target/release/redact-secret
```

Only the host's own triple can be qualified locally; the fan-out across the
other seven is what the workflow is for.
