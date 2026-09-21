# Issue #495 — declarative ruleset implementation WebAssembly size re-measurement

[Audit archive](../README.md) · [Issue #495](https://github.com/redact-secret/redact-secret/issues/495) ·
[decision-define-declarative-detector-ruleset-contract](../../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md)

Measured at commit `f67e1e5bf10cda086f734ac356c8cbb4f581e8cd`
(`milocosmopolitan/expose-the-declarative-ruleset-detector-adapter`), the
working tree with #495's full implementation applied on top of `main`
(which already carries #483, the crate-internal parser and IR). This is the
re-measurement the ADR's Consequences section requires: "re-measure the real
compiled artifact against evidence/441's baseline once it exists ... the
same way `decision-define-detector-profile-and-pack-contract`'s own triggers
call for re-measurement with `scripts/measure-detector-cost.mjs`."

## Files

| File | Contents |
| --- | --- |
| [`artifact-sizes.json`](artifact-sizes.json) | Before ([#441](../441/README.md)'s baseline)/after WASM raw, gzip, and brotli sizes, the JS glue size, the delta, and the current `common`-profile size for reference. |

## What was measured

Unlike [#441](../441/README.md)'s prototype measurement (a representative
scaffold, reverted immediately after), this measures the real shipped
implementation: [`crates/secret-scan-core/src/ruleset.rs`](../../../crates/secret-scan-core/src/ruleset.rs)'s
parser (#483), [`crates/secret-scan-core/src/detectors/ruleset_adapter.rs`](../../../crates/secret-scan-core/src/detectors/ruleset_adapter.rs)'s
`Detector` adapter (#495), the public `load_ruleset`/`RulesetError`/
`RulesetErrorClass` API, the new `INVALID_RULESET` error code, and the
`ruleset` argument [`bindings/wasm/src/lib.rs`](../../../bindings/wasm/src/lib.rs)'s
`scan`/`scanAndRedact` now accept — all reachable in the shipped build, no
`std::hint::black_box` scaffolding needed.

1. Built the `full`-profile browser artifact with `node
   scripts/build-browser-artifact.mjs --out-dir <dir>` (release,
   `wasm-bindgen` 0.2.128, matching the pinned CLI version).
2. Measured the emitted `redact_secret_wasm_bg.wasm` with the same
   `gzipSize`/`brotliSize` helpers `scripts/measure-detector-cost.mjs`
   exports, and the emitted `redact_secret_wasm.js`'s raw byte size.
3. Repeated with `--detector-profile common`, for reference (see
   [Common profile](#common-profile) below).
4. Compared the `full` result against [#441](../441/README.md)'s `before`
   baseline directly — #483 landed after that baseline was measured and
   before this measurement, so this delta is the combined cost of #483 and
   #495 together, per the ADR's instruction.

No file was reverted: this measurement builds the tree exactly as it will
merge, not a scaffold.

## Result

| | WASM raw | WASM gzip | WASM brotli | JS glue raw |
| --- | --- | --- | --- | --- |
| Before (#441 baseline, pre-#483/#495) | 289,029 B | 99,463 B | 80,014 B | 31,344 B |
| After (#483 + #495, this commit) | 312,753 B | 108,516 B | 87,181 B | 32,261 B |
| Delta | +23,724 B | +9,053 B | +7,167 B | +917 B |
| Delta, % of before | +8.21% | +9.10% | +8.96% | +2.93% |

The ADR's own estimate, from the #441 prototype (a subset of the full
validation surface), was "a real ~2.9% brotli WASM increment ... treat that
as a lower bound: the real implementation's fuller validation (all cost
bounds, the complete error catalog, ordering enforcement) adds somewhat
more." The measured 8.96% brotli increment confirms that direction: the
shipped parser's full rejection catalog (15 classes vs. the prototype's 7),
the `Detector` adapter, the public API surface, and the new error code
together cost roughly 3x the prototype's lower-bound estimate. This stays a
one-time, `full`-profile-wide cost paid by every consumer regardless of
whether they ever load a ruleset — consistent with the ADR's "detector-
independent engine floor" framing
(`decision-define-detector-profile-and-pack-contract`) — not a per-detector
or per-scan cost, and it is still a low single-digit-to-high-single-digit
percent of the whole artifact, not the second matching engine the ADR's
Rejected Alternatives explicitly ruled out.

## Common profile

The `common`-profile artifact was also measured, for reference only: no
established pre-#483/#495 baseline exists for it specifically in
[evidence/441](../441/README.md) (that measurement covered only `full`).

| | WASM raw | WASM gzip | WASM brotli | JS glue raw |
| --- | --- | --- | --- | --- |
| Current (`common`, #483 + #495) | 253,978 B | 91,316 B | 74,379 B | 32,282 B |

## Reproduction

```sh
node scripts/build-browser-artifact.mjs --out-dir /tmp/wasm-full
node scripts/build-browser-artifact.mjs --out-dir /tmp/wasm-common --detector-profile common
node -e "
const { gzipSize, brotliSize } = await import('./scripts/measure-detector-cost.mjs');
const fs = await import('node:fs');
for (const [label, path] of [
  ['full', '/tmp/wasm-full/redact_secret_wasm_bg.wasm'],
  ['common', '/tmp/wasm-common/redact_secret_wasm_common_bg.wasm'],
]) {
  const buf = fs.readFileSync(path);
  console.log(label, 'raw', buf.length, 'gzip', gzipSize(buf), 'brotli', brotliSize(buf));
}
" --input-type=module
```
