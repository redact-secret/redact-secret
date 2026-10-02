# #1070: Stable user documentation and five-minute adoption paths

Product judgement. Final record for
[#1070](https://github.com/redact-secret/redact-secret/issues/1070) (parent
[#1065](https://github.com/redact-secret/redact-secret/issues/1065), which
states that Beta.13 is a stable-readiness cycle and not feature expansion; it
supplies the verified docs and examples that
[#204](https://github.com/redact-secret/redact-secret/issues/204) waits on). It
audits the documentation as a first-time user reads it, records what a newcomer
hit first, lists what changed, and records which snippets ran and which did
not. It changes no public API, version, tag, or release state.

## Summary

| Question | Answer |
| --- | --- |
| Could a newcomer reach a working redaction without reading architecture or governance text? | Yes for Node.js, Python, and a browser bundler, but only through three documents: the README put about 90 lines of positioning and scope before an install section that had no install command, then `getting-started.md` led with a runtime matrix before its install block. Rust and the CLI had no tested path at all. |
| Was anything wrong, not just missing? | Yes: seven corrections, listed under [Wrong or stale](#wrong-or-stale). The one that could mislead a security decision: `safe-integration.md` said whole-input APIs impose no automatic input-size or finding limits, while they default to 64 MiB and 50,000 findings. |
| Did the documented commands work? | After the fixes, yes, on the platform tried. Every quickstart lane passed against artifacts built from this checkout and against the published `0.1.0-beta.12` packages. [Verification](#verification) lists what ran and what did not. |
| Is the lifecycle explicit? | Not before: the only statement was a README paragraph of version numbers that were already out of date. [`docs/integrations.md`](../../../integrations.md) now says what the core promises and that adapters and the vault are separate, uncovered, and on their own versions. |
| What is left for other repositories? | The website's registry snapshot and a few lines in the adapters and vault repositories: [Drift in other repositories](#drift-in-other-repositories). |

## Method

- Source: this branch on `origin/main` at `7173c0c7`, plus the edits this record
  describes. Host: macOS 26 on Apple silicon (`aarch64-apple-darwin`), Node.js
  22.16.0, Python 3.14.7, `rustc` 1.98.1.
- Read as a newcomer would, from the README down, following only links, and
  counting the documents opened and commands run before a value is redacted.
  The accepted facts came from [`docs/reference/api-contract.md`](../../../reference/api-contract.md#stable-contract-1),
  [#1066](../1066/README.md), [#1067](../1067/README.md), [#1072](../1072/README.md),
  the support-matrix text, and the guides.
- Registry facts were read on 2026-10-02 with `npm view`, the npm registry and
  PyPI JSON, the crates.io API, and `gh` (read-only).
- Claims policy applied: counts carry denominators and revisions; PII
  "available" is not "qualified"; client-side scanning is preventive and
  server-side scanning is authoritative; `common` is preventive and `full` is
  authoritative.

## Audit by path

"Steps" counts documents opened and commands run before the first working
redaction, starting from the README. "Before" is `origin/main`; "after" is this
branch.

| Path | Where it started | Steps before | What a newcomer hit first | Missing or wrong | Steps after |
| --- | --- | --- | --- | --- | --- |
| Installation and version selection | README "Install and first example" at line 92, after positioning, scope, and boundary sections | 3 documents (README, `getting-started.md`, `quickstart.md`) | A runtime support matrix before the install commands; an example with no install line | No statement of what a bare `npm install`, `pip install`, `cargo add`, or `cargo install` resolves; `cargo install redact-secret-cli` without `--version` fails today and was undocumented; "CLI release binaries" implied downloads that do not exist (the v0.1.0-beta.7 release has 0 assets) | 1 (README Quick start, line 25, with a version note and a link to the tested steps) |
| JavaScript five-minute quick start | `quickstart.md` Node.js, tested in CI | 3 documents | The README snippet had no install command; the guide had none either | `javascript.md` showed a finding without its `obfuscation` field (the real object has 8 fields) | 1 |
| Python quick start | `quickstart.md` Python, tested in CI | 3 documents | Same as JavaScript | None found in the code; `python.md` had no install line | 1 |
| Rust entry | `guides/rust.md` | undefined: no install line, no tested path | A complete `sanitize` example with nowhere to run it | The profile example contained a rustdoc-only `# Ok::<...>` line and top-level `?`, so it did not compile when copied; the crates.io page had no install command | 1 (new quickstart section) |
| CLI entry | README "CLI quick start" | undefined: the binary was used before any install | `redact-secret ...` with no way to get the binary | No prebuilt binary exists and `--version` is required; the crates.io page had no install command; `guides/cli.md` had no install line | 1 (new quickstart section) |
| Browser and WebAssembly | `quickstart.md` browser lane; `javascript.md#browser-loading` | 3 documents | README "Browser and server boundaries" uses `showSecretWarning`, `serverPolicy`, `conversationStore`, and `modelGateway` without saying they are placeholders | Only Vite is exercised; the guide did not say so | 1 |
| Streaming and incremental | `guides/streaming.md` | n/a | A table that lists Rust and the CLI, followed by examples for JavaScript and Python only | No Rust example, no CLI example | n/a |
| Policy and limits | `guides/safe-integration.md` | n/a | See below | Whole-input limits misstated; nothing said that the authoritative scan uses `full` and that `common` is preventive | n/a |
| PII opt-in semantics | README, three guides, `reference/detection.md` | n/a | A 20-line PII paragraph under a heading named "JavaScript quick start" | None wrong: every guide states `provisional`, `pending`, none `stable` for the Beta.11 qualification, and the activation identity strings printed by the Node.js, Python, and CLI examples match the guides | n/a |
| Ruleset usage and contract | `guides/rulesets.md` | n/a | Fine | The JavaScript and Python snippets use undefined `input` and `text`; left as fragments, and run here with data filled in | n/a |
| AI, MCP, logging, telemetry discovery | README "Integrations", "Mask secrets in traces", "Redact secrets in logs" | 3 to 5 | Four scattered mentions, no single "which package do I need" in this repository | Versions out of date (below); the tracing adapter's current name was missing | 1 (`docs/integrations.md`, linked from the README, docs home, and quickstart) |
| Troubleshooting and supported runtimes | `troubleshooting.md`, `getting-started.md`, `javascript.md`, `qualification.md` | n/a | Troubleshooting covered only error codes; runtime support was spread over four documents with no list of what is not supported | Install failures undocumented | n/a |
| Core stable versus adapters and vault | none | n/a | No statement; the README paragraph gave adapter and vault versions as of 2026-09-28 | Stale (below); never said they are outside Stable contract 1 | n/a |

### Wrong or stale

| # | Where | Problem | Fix |
| --- | --- | --- | --- |
| 1 | `guides/safe-integration.md` | "Whole-input APIs do not impose automatic input-size or finding-count limits." They default to 64 MiB and 50,000 findings and fail closed (`api-contract.md`, `javascript.md`, `python.md`, `rust.md`) | Rewritten to the real default, and to say the bound is a ceiling and the host already holds the string |
| 2 | README "Integrations" | `@redact-secret/adapter` 0.1.2, `adapter-pino` 0.1.1, `adapter-otel` 0.1.1, `redact-secret-adapters` 0.1.0, vault `0.1.0-alpha.3` pinning core `0.1.0-beta.10`, `adapter-mcp` `0.1.0-alpha.1`, all "observed 2026-09-28". On 2026-10-02 the registries carry 0.1.7, 0.1.4, 0.1.5, 0.1.4 (PyPI), vault `0.1.0-beta.4` pinning `0.1.0-beta.12`, and `adapter-mcp` 0.1.4 | Version numbers removed from the README; the dated table in `releases/status.md` refreshed |
| 3 | `releases/status.md` adapter and vault tables | Same snapshot as row 2 | Refreshed with the 2026-10-02 observation and a note that adapters publish several times a week |
| 4 | `guides/javascript.md` | Finding example lacked `obfuscation: "none"` | Added |
| 5 | `guides/rust.md` | The common-profile example did not compile when copied | Wrapped in `fn main`, with no hidden line |
| 6 | `getting-started.md` | "CLI release binaries still do not include musl builds" implied published binaries | Rewritten: the CLI is built with `cargo install`; no binary is published for any target |
| 7 | `qualification.md` | "exactly the seven documented keys" for a finding; the harness checks eight (`browser-package-harness-core.mjs`) | "eight" |

## What changed

- **README.** `## Quick start` is now the first section after the introduction:
  the version note, one install command per runtime, the three snippets, the
  two things to know (preventive versus authoritative; an empty list is not
  proof), and a "I want to / Read" table. The positioning, scope, and boundary
  sections follow. The old "Install and first example" section is removed. The
  introduction names the five destinations, which `product-positioning:check`
  requires of the first section. The integrations paragraph is now "Integrations
  and release status": what the core promises, what the adapters and vault are,
  and links, with no version numbers.
- **`quickstart.md`.** A runtime chooser, a "Which version you get" section, new
  Rust and Command-line sections in the same `qualify=` form as the existing
  lanes, and a next-steps list. The section states what a bare install resolves
  today and what changes at `0.1.0`, without choosing a version.
- **`getting-started.md`.** Install commands first, then "Supported runtimes"
  with a "Not supported, or not claimed" list, then the source build.
- **`integrations.md`** (new). Which package fits which job, the lifecycle table
  (core beta now, Stable contract 1 from `0.1.0`; adapters `0.1.x` on their own
  trains; vault beta with an alpha persistent profile), the stable promise, and
  where plaintext still exists.
- **`troubleshooting.md`.** An "Install and setup" table (the `cargo install`
  failure, `PATH`, a lagging npm `latest`, a missing wheel, the Rust version,
  how to read the running version).
- **`streaming.md`.** Rust and CLI examples. **`safe-integration.md`.** The
  limits correction and a "Where the authoritative scan belongs" section.
  **`cli.md`, `rust.md`, `javascript.md`, `python.md`.** An install line each.
  **Crate READMEs** (`crates/secret-scan-core`, `crates/secret-scan-cli`, which
  crates.io renders): an install section each.
- **Docs home, `documentation-readiness.md`, `releasing.md`, `qualification.md`.**
  Links, the review status for #204, the two places that carry the version in
  prose with no check, and the Rust and CLI lane note.
- **Executable-docs check.** `scripts/clean-install-doc.mjs` and its test now
  read five lanes. `node`, `python`, and `browser` stay driver lanes; `cli` and
  `rust` are parsed, pinned, and shape-checked in `npm run ci` (the version in
  `--version` and `redact-secret@` must equal the product version; expected
  output must start with the version line; the synthetic input must appear).
  File names may now include one directory level (`src/main.rs`); `..`, a
  leading `/`, and a leading `.` are still rejected.

## Verification

All runs used the quickstart text as written. Reports are not committed.

**Built from this checkout** (`cargo build --release --locked -p redact-secret-cli`;
`npx napi build --platform --release --target aarch64-apple-darwin`;
`maturin build --release -m bindings/python/Cargo.toml`;
`node scripts/build-browser-artifact.mjs` for `full` and `common`;
`node scripts/pack-npm-candidate.mjs`):

| What | Result |
| --- | --- |
| `scripts/qualify-clean-install.mjs --lane node` against the candidate | passed, 1.9 s |
| `--lane python` against the candidate wheel | passed, 5.3 s |
| `--lane browser` against the candidate, Chromium / Firefox / WebKit | passed, 18.1 s / 7.5 s / 7.6 s |
| The same three lanes against the published `0.1.0-beta.12` packages (no `--candidate-dir`), Chromium | passed: node 2.2 s, python 2.5 s, browser 7.8 s |
| The installed addon and wheel against the built files | byte-identical (SHA-256 compared) |
| Quickstart `rust` and `cli` lanes, read from the page by the same parser, run in empty directories against the published `0.1.0-beta.12` crates | both matched the expected output exactly |

**Guide snippets**, extracted from the fenced blocks of the files below, run with
the candidate Node.js and Python packages, a path dependency on this checkout's
core crate, and the built CLI. "Verbatim" means the block ran unchanged.

| Files | Blocks | Result |
| --- | --- | --- |
| `javascript.md` (7 TypeScript blocks), `streaming.md` (4 JavaScript), `safe-integration.md` (1), README (1) | 13 | ran verbatim (TypeScript through `node --experimental-strip-types`); output matched the comments. One was a fragment showing a finding, checked against the real object (which is how the missing `obfuscation` field was found) |
| `python.md` (4), `streaming.md` (1), README (1) | 6 | ran verbatim; their `assert`s passed |
| `rust.md` (4), `streaming.md` (1) | 5 | compiled and ran; the common-profile block only after the fix above |
| `rulesets.md` JavaScript, Python, and CLI (3); the three `cli.md` shell blocks; the `streaming.md` shell block; the two README CLI blocks; the `getting-started.md` source-build `cargo run` block | 10 | ran with the placeholder variable or file filled in (paths such as `src/config.ts` replaced by local files, a staged diff by a pipe of the same text); a ruleset match reported `warn` and `--redact --ruleset` left the text unchanged, as documented; the stdin streaming example found a secret split across writes; `--ruleset` with standard input exited `2` |
| Released `@redact-secret/adapter-pino` and `redact-secret-adapters` snippets from the README, against the candidate core | 2 | produced `<SECRET_1>` |
| `npm run ci`, `npm run check:docs`, Biome, ruff, `cargo`, SAST | see [Checks](#checks) | |

**Not executed:**

- The README Langfuse snippets (they need the `langfuse` package and the
  `langfuse_mask.py` example file) and the two illustrative browser/server
  fragments, which call functions that exist only in the reader's code.
- `maturin develop` plus the Python test suite from `getting-started.md`.
- The post-publication quickstart for `0.1.0`, which does not exist.
- Other platforms: only `aarch64-apple-darwin`. Not run: Linux (glibc or musl),
  Windows, x86-64, Node.js 20 and 24, CPython 3.10 to 3.13, Cloudflare Workers.
  CI covers several of these for the three driver lanes; the Rust and CLI
  lanes are not run in CI.
- Published artifacts for the guide snippets; they ran against the candidate.

## Registry facts verified on 2026-10-02

| Package | Registry state |
| --- | --- |
| `@redact-secret/core`, `@redact-secret/wasm` | `latest` and `beta` are `0.1.0-beta.12` (published 2026-10-01) |
| PyPI `redact-secret` | newest `0.1.0b12`; all 12 versions are prereleases; unpinned `pip install --only-binary=:all: redact-secret` installed `0.1.0b12` |
| crates.io `redact-secret`, `redact-secret-cli` | newest `0.1.0-beta.12`; `cargo add redact-secret` wrote `0.1.0-beta.12`; `cargo install redact-secret-cli` without `--version` failed with ``could not find `redact-secret-cli` in registry `crates-io` with version `*` `` |
| GitHub Release `v0.1.0-beta.7` (newest in the list) | 0 assets; no CLI binary is published |
| `@redact-secret/adapter` | `latest` 0.1.7 (2026-10-02), peer core `^0.1.0-beta.6` |
| `@redact-secret/adapter-pino` | `latest` 0.1.4, peer `pino ^10.0.0` |
| `@redact-secret/adapter-otel` / `adapter-otel-trace` | `latest` 0.1.5 / 0.1.2; both peer `@opentelemetry/sdk-trace-base ^2.0.0`; the registry shows no deprecation on `adapter-otel` |
| `@redact-secret/adapter-ai-context` / `adapter-mcp` | `latest` 0.1.3 / 0.1.4; `alpha` tag 0.1.0 on each |
| PyPI `redact-secret-adapters` | 0.1.4, requires `redact-secret>=0.1.0b6,<0.2` |
| `@redact-secret/vault`, `vault-server` | `latest` and `beta` `0.1.0-beta.4`, `alpha` `0.1.0-alpha.3`, peer core exactly `0.1.0-beta.12` |
| PyPI `redact-secret-vault` | 0.1.0b3 |

Stable `0.1.0` is not published on any registry, and nothing here announces or
chooses a version.

## Drift in other repositories

Not edited here. Each item names the file and the proposed wording.

**`redact-secret/redact-secret-www`** (private; a registry-driven site).

- `data/release.json`, generated `2026-09-29T20:06:05Z`: the core, `wasm`, PyPI,
  and crates entries read `0.1.0-beta.11` (lines 13 to 61); the registries now
  read `0.1.0-beta.12`, and the adapter entries are older than the registries
  (adapter, pino, otel, ai-context, mcp, `redact-secret-adapters`). Re-run
  `scripts/refresh-slots.mjs`. The page text that says "is the current beta,
  observed on the registries <date>" follows from the data, so no copy change is
  needed.
- `data/integrations.json`, `vault-py.declared.version` is `0.1.0a2`, which was
  never published; PyPI's newest is `0.1.0b3`. Proposed: `0.1.0b3`, or drop
  `declared` so the registry value is used.
- `data/integrations.json` has no `adapter-otel-trace` slot while the adapters
  repository documents it as the tracing package. Proposed: add the slot and
  point the OpenTelemetry card at it.
- `i18n/en/home.json` lines 231 to 237 ("Rust is installed from crates.io; its
  first example lives in the Rust guide"): proposed "Rust and the command line
  have a tested five-minute path in the quickstart" with a link to
  `docs/quickstart.md#rust` and `#command-line`. The same string in
  `i18n/ko/home.json`.
- Anything the site says about "stable" should use the promise in
  [`docs/integrations.md`](../../../integrations.md#what-is-stable-and-what-is-not)
  and say that `0.1.0` is not published.

**`redact-secret/redact-secret-adapters`**

- README ("Not covered by anything you can install today"): calls
  `@redact-secret/adapter-otel` the "deprecated old name" of `adapter-otel-trace`,
  but `npm view @redact-secret/adapter-otel deprecated` is empty and `latest` is
  0.1.5, published 2026-10-02. Proposed: run `npm deprecate` with a message
  naming `adapter-otel-trace`, or change "deprecated old name" to "earlier name".
- README paragraph after "Current versions": says `adapter-otel-logs` "depends on
  `@redact-secret/adapter` `^0.1.7`, which ships in the next release train, so it
  does not install from npm until then". `@redact-secret/adapter@0.1.7` was
  published on 2026-10-02, so the dependency exists (the install was not run here). Proposed: drop the
  caveat and list the logs adapter in the "Which package do I need" table.
- README "Supported versions" gives the core range `^0.1.0-beta.6` without
  saying that the core is still beta. Proposed: one sentence, "The core is
  `0.1.0-beta.12`; `0.1.0` is not published."
- Neither the README nor `adapter-ai-context` and `adapter-mcp` state whether
  those two are alpha, beta, or stable: the `alpha` dist-tag holds 0.1.0 while
  `latest` is 0.1.3 and 0.1.4. Proposed: a maturity column in "Which package do
  I need".

**`redact-secret/redact-secret-vault`**

- `docs/status.md` introduction says the persistent server profile "is published
  as alpha (`@redact-secret/vault-server@0.1.0-beta.4`)". A reader installing
  `@redact-secret/vault-server@latest` gets `0.1.0-beta.4`. Proposed: "the
  default entry is beta; the `/persistent` entry in the same package is alpha".
- README quick start installs `@redact-secret/vault@0.1.0-beta.4` and says
  "Pin the exact version while the packages are beta"; correct today, and it
  changes with each core release because of the exact core pin. No change
  needed beyond keeping it current.

## Left in this repository

- The README and `getting-started.md` carry `0.1.0-beta.12` in prose with no
  check reading them. `docs/releasing.md` now lists both. A check would have to
  survive `scripts/rehearsal-version.py`, which rewrites only the two
  `DOC_PINS` files; adding the README means teaching it to leave the generated
  support-matrix block alone.
- At `0.1.0` the `@beta` qualifier in the README and the `--version` qualifiers
  in the quickstart, README, CLI guide, and crate READMEs must change; the
  quickstart's "Which version you get" section says what to expect.
- The Rust and CLI quickstart lanes are not run in CI against a candidate. A
  post-publication job for them would be the way to close that.
- Langfuse and `getting-started.md#build-this-checkout` Python steps were not
  run (see [Not executed](#verification)).

## Checks

Run locally on the branch, from the commands CI uses:

| Check | Result |
| --- | --- |
| `npm ci --ignore-scripts`, `npm --prefix bindings/node ci --ignore-scripts`, `npm run examples:install` | completed |
| `npm run check:docs` (decisions, docs reachability, doc links, product positioning, detector inventory, support matrix, site feed, audits index and the rest of that chain) | passed |
| `npm run ci` | passed, exit 0 |
| `npm run lint` (Biome) | no errors; one warning and one note, both in files this work does not touch (`packages/javascript/test/fuzz.test.ts`, `scripts/consumer-harness.mjs`) |
| `npm run rust:check` (the crate READMEs are packaged files) | passed |
| `npm run cross-repo-links:check` (124 distinct links) | 0 errors |
| `node --test scripts/tests/clean-install-doc.test.mjs` | 7 tests passed |

Not run, and why:

- OpenGrep itself: the pinned binary is not installed here. The baseline entry
  for `scripts/clean-install-doc.mjs` follows its moved line: line 56 to 69, id
  `ddfe387dd9e6db6a` to `fdf3fdaea249e3e5`, recomputed as
  `sha256(rule_id|path|start|end)[:16]`. `npm run sast:test` passes.
- `ruff` (no Python file changed) and `cargo fmt` / `cargo clippy` (no Rust file
  changed).
- GitHub Actions. The `clean-install` job reads the same page and driver this
  work ran locally, on its own runners and not on this host.
- `scripts/check-changelog-coverage.py`: no guarded path changed, so no
  `## Unreleased` entry or `no-changelog` label is needed.
