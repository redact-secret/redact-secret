# Deferred quality backlog

The 25 non-blocking findings the Rust-core migration retrospective produced,
routed here by [the release-gap disposition](./release-gap-disposition.md)
under issue #66.

- **Recorded on:** 2026-09-09, at `fdfd05a`.
- **Tracked by:** [#80](https://github.com/redact-secret/redact-secret/issues/80), which has no parent by design.
- **Status:** open work, deliberately outside Epic #60's tree. **Nothing in this
  document blocks the closeout Epic, Feature #11, or a release.**
- **Authority:** this document records deferred work. It does not authorize
  implementation changes or any release operation.

## Why these are deferred and not dropped

Each entry failed all four of issue #66's blocker clauses — it does not violate
a public contract or a security boundary, does not leave a promised platform or
artifact unqualified, does not leave lockstep release safety incomplete, and
does not leave a mandatory original criterion `partially-met` or `unverified`.
The reasoning per finding is in
[the disposition](./release-gap-disposition.md#disposition-of-all-55-findings);
the reasoning for the borderline cases is in
[the departures table](./release-gap-disposition.md#where-this-disposition-departs-from-an-inputs-severity).

Most of these are *missing guards over behavior the reviews verified correct*.
That is worth stating plainly: the reviews confirmed, at this revision, that the
built-in type names and `ALWAYS_REDACT_TYPES` agree (`C/F-04`), that the
TypeScript and Rust placeholder formatters agree (`B/F-08`), that partition
invariance holds over all 170 supported fixtures (`C/F-05`), and that the CLI's
exit codes cannot be forged (`C/F-01`). Each entry keeps the class, severity,
evidence, and exact exit condition its source review recorded, so any of them can
be picked up without re-deriving it.

Severity is the source review's, unchanged. Three entries close as side effects
of blocker work and say so.

## Backlog

### Medium

| ID | Class | Area | Finding | Exit condition (abridged; the source has the full one) |
|---|---|---|---|---|
| `C/F-03` | `evidence-gap` | conformance | `authorization_credential` is a reachable finding type with its own always-redact policy entry and zero fixtures in the canonical corpus. | At least one supported positive fixture per accepted scheme (`basic`, `token`) asserting detector, type, confidence, specificity and byte span, plus one boundary fixture at `MIN_AUTHORIZATION_VALUE_LENGTH`. **Closed by #105.** The separate `authorization_credential.host-context` breadth gap was tracked independently and closed by #190; this historical finding remains closed. |
| `C/F-04` | `evidence-gap` | core | Nothing binds the built-in type names to the default policy, so a new provider detector's type silently degrades to `warn`. The two sets agree today. | A test enumerates the type names the built-in registry can emit and asserts each is `private_key`, in `ALWAYS_REDACT_TYPES`, or on an explicit commented confidence-gated allowlist. |
| `C/F-06` | `stale-claim` | core | The crate's own rustdoc, which reaches docs.rs on publish, says the Rust core has not yet passed the shared corpus. | The sentence is corrected or removed; no crate-root rustdoc in `crates/secret-scan-core` claims non-conformance. Naturally paired with `RB-1`, which makes the corrected claim true on the canonical surface. |
| `B/F-05` | `new-risk` | bindings | `redact(input, findings)` means three different things: Node re-derives the span from the caller's offsets, the browser ignores them, Python ignores them. Unobservable while a caller obeys the documented rule. | One stated rule in `packages/javascript/src/types.ts`, pinned by a test on each runtime. |
| `B/F-08` | `new-risk` | `packages/javascript` | `formatters.ts` re-declares the core's two placeholder formatters; `toUpperCase()` is full-Unicode and `to_ascii_uppercase()` is not, so they diverge for a non-ASCII type name. Every built-in name is ASCII today. | Both helpers route to the binding's built-in, or a test asserts the two agree over every built-in type name. |
| `R/F-06` | `new-risk` | supply chain | No `id-token: write`, no `--provenance`, no `publishConfig.provenance`; a stored `NPM_TOKEN` instead of trusted publishing. | Trusted publishing with `--provenance` and a verifiable provenance statement on the first qualified publication — or the deferral recorded with its reason alongside the release process documentation. This entry *is* that deferral until it is done. |
| `R/F-11` | `new-risk` | supply chain | Inside a SHA-pinned action, three floating inputs: `maturin-version` unset, `container` action-chosen, `sccache: "true"`. | Each pinned, or the floating default accepted in writing with its reason, with the pinned values added to `SECURITY.md`'s pin-review list. |

### Low

| ID | Class | Area | Finding | Exit condition (abridged) |
|---|---|---|---|---|
| `L/G-07` | `new-risk` | CI | The full-corpus parity suite runs only in `Python wheels`, whose `pull_request` trigger is path-filtered. The filter does cover the core and the corpus. | The suite runs unconditionally, or the filter is documented as covering every input that can change corpus outcomes. **Closed as a side effect of `RB-1` (#71)**, which puts a corpus assertion in `ci.yml`'s `rust-native` job. |
| `C/F-01` | `new-risk` | CLI | A source path containing a newline injects forged lines into the text report and the stderr diagnostics. The exit code cannot be forged and no matched plaintext is involved; the JSON path escapes correctly. | Both renderers reject or escape a line terminator in a source identity, with a test that builds such a path and asserts one record per finding. |
| `C/F-02` | `new-risk` | CLI | One logical line above 1 MiB exits `0` by path and `2` on standard input; the parity test pins only 64 KiB. Fails closed — the failing redact run wrote 0 bytes. | A test pins the behavior above `MAX_TOKEN_BYTES`, or the streamed construct limit rises to `MAX_INPUT_BYTES` so both paths accept the same inputs. |
| `C/F-05` | `evidence-gap` | core | Partition invariance is asserted over the 16-fixture incremental corpus and was measured to hold over all 170 supported synchronous fixtures. | A committed Rust test runs every supported fixture through an incremental session against the whole-input reference, in `ci.yml`'s `rust-native` job. **The natural place is `RB-1`'s (#71) test file**, which already iterates that corpus. |
| `C/F-08` | `new-risk` | conformance | The corpus declares `offsetUnit: "utf8-byte"`; every runtime reports `rangeUnit: "utf8-bytes"`. | One spelling, or a sentence in `conformance/README.md` stating the two field names are deliberately distinct. Changing either string is a cross-language contract change, so the documentation option may be the right one. |
| `B/F-09` | `stale-claim` | `bindings/python` | The code-point index's comment declares a 16,512-byte buffer bound; 1.6 MB of index was measured for a 300 kB chunk. | The comment states the real bound, or `observe` prunes incrementally, with a test pinning whichever is chosen. |
| `B/F-10` | `evidence-gap` | bindings | The package's whole range contract is UTF-16 and no check covers a lone surrogate crossing either string boundary. | A shared-corpus fixture for an unpaired surrogate with a stated expectation asserted on both JavaScript runtimes, or a fixed error code in `packages/javascript/src/errors.ts` and a test. Rises if the package is placed in front of arbitrary user-typed or clipboard input. **Closed by #112**: `packages/javascript/src/runtime.ts`'s `requireString` now rejects a lone surrogate with the fixed `UNPAIRED_SURROGATE` code before the string reaches either binding, so the check and the error are identical on Node.js and in the browser by construction. |
| `B/F-12` | `evidence-gap` | `bindings/python` | The Python binding rebuilds the detector registry on every call: 3.6 µs against a 16.6 µs small-input scan, ~22% overhead at the smallest sizes, with no initialization hook. | A thread-local `OnceCell` cache (`Detector` is not `Sync`), or the cost recorded as accepted in `docs/python-packaging.md` with the measurement attached. |
| `R/F-13` | `evidence-gap` | supply chain | `deny.toml` declares seven targets; the wheel matrix declares eight, and neither musl triple is among the seven. | `deny.toml` covers every triple in `python-wheel-targets` plus `wasm32-unknown-unknown`, and a script fails when a declared wheel target is absent from the `cargo-deny` graph. |
| `R/F-14` | `evidence-gap` | CI | The MSRV has an exact workflow cross-check; the `wasm-bindgen` / `wasm-bindgen-cli` pair a comment calls mandatory has none. | `check-rust-workspace.py` reads the `--version` literal from `ci.yml` and fails on a mismatch, with a unit test. |
| `R/F-15` | `new-risk` | operational controls | `allowed_actions: "all"`, `sha_pinning_required: false`, forking enabled on a public repository — the repository requires none of what the workflows already practice. **`main` branch protection is the blocking half and belongs to `RB-8`.** | `sha_pinning_required: true` and `allowed_actions` narrowed to an allowlist covering the nine actions in use, verified by the same read-only API reads. |
| `R/F-16` | `new-risk` | CI | `ci.yml` declares no `timeout-minutes`, and workflow-level `RUSTFLAGS: -D warnings` applies to a third-party `cargo install wasm-bindgen-cli`. | Every job declares a timeout consistent with its measured duration, and the install step clears `RUSTFLAGS` or the flag moves onto the steps that build workspace code. |
| `R/F-17` | `evidence-gap` | supply chain | `SECURITY.md` prescribes a monthly advisory review with no `schedule:` trigger and no `dependabot.yml` behind it. | A scheduled workflow runs `cargo deny check advisories` and `npm audit --package-lock-only` at least as often as `SECURITY.md` claims, plus a `.github/dependabot.yml` for `github-actions`, `npm`, and `cargo` — or the cadence is rewritten to describe what exists. |
| `R/F-18` | `stale-claim` | release automation | `docs/python-packaging.md` says release qualification reuses the wheel workflow's `workflow_call`; nothing calls it. | `release.yml` calls it and requires success before publication, or the sentence is reworded. **Closed as a side effect of `RB-7` (#77).** |
| `R/F-19` | `stale-claim` | documentation | Four links in `test/conformance/README.md:66-70` resolve into `/_notes/`, which `.gitignore` excludes, in a public repository. | The four citations become tracked references — the corresponding issues, or notes moved into `docs/` — and a link check runs in `npm run ci` so a link into an ignored path fails. The ruling this finding asked #66 for is [recorded in the disposition](./release-gap-disposition.md#feature-notes-and-retrospective-audits-are-not-tracked-under-_notes): `_notes/` is deliberately untracked, so tracked files may not cite it. |
| `R/F-20` | `new-risk` | release automation | No `prepack` or `prepublishOnly`; the publish step depends on an earlier script having built `dist/` in the same checkout. | `release` builds what it publishes, so the artifact cannot be stale or empty regardless of what ran before it. May be subsumed when `RB-2` and `RB-9` change the publish target. |
| `R/F-21` | `new-risk` | supply chain | Both `upload-artifact` calls omit `retention-days`, so qualification artifacts inherit the repository default. | Both steps declare an explicit `retention-days` chosen for release-evidence retention, with pull-request runs allowed a shorter one, and the choice recorded with the release process. |
| `R/F-22` | `stale-claim` | documentation | `SECURITY.md`'s supply-chain section never mentions the publish path's `contents: write`, the `release` environment, provenance, retention, or `cargo deny`. | The section covers the publication path and the Cargo supply chain alongside the npm one, and `README.md`'s development instructions use `npm ci --ignore-scripts`. |

## Sequencing notes

- **`L/G-07` and `C/F-05` land inside `RB-1` (#71).** `RB-1` adds a Rust test that
  iterates the supported synchronous corpus in `ci.yml`'s `rust-native` job.
  `C/F-05` wants an incremental-session assertion over the same iteration, and
  `L/G-07` disappears once a corpus assertion runs unconditionally on every pull
  request. Neither is a reason to promote them; both are a reason to open
  `RB-1`'s test file with them in mind.
- **`R/F-18` lands inside `RB-7` (#77).** `RB-7` makes `release.yml` call
  `python-wheels.yml` through the `workflow_call` entry point that
  `docs/python-packaging.md` already claims is reused.
- **`C/F-06` pairs with `RB-1` (#71).** The rustdoc sentence becomes true, rather than
  merely deleted, once the canonical surface asserts the corpus itself.
- **`R/F-15` is split.** `main` branch protection is a blocker and belongs to
  `RB-8` (#78); `sha_pinning_required`, `allowed_actions`, and forking stay here.
- **`R/F-06` is itself the recorded deferral.** Its own exit condition allows
  deferring trusted publishing provided the deferral is recorded with a reason.
  The reason: the release path is being repointed by `RB-2` (#72), `RB-7` (#77), and `RB-9`
  (#79),
  and provenance should be configured against the artifact that will actually
  ship rather than the one that would ship today.

## Plaintext safety

No entry above reproduces a matched value, a fixture input, or a
credential-shaped string. Detector ids, finding types, error codes, byte
offsets, secret *names* (`NPM_TOKEN`), file paths, and measured sizes are safe
metadata.
