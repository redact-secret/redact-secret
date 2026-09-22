# Beta.2 detection assessment

This is the issue [#191](https://github.com/redact-secret/redact-secret/issues/191)
assessment of candidate Node and browser WebAssembly artifacts built from
source revision `ffd0c3085df359680484a0e35d283e9948d2c1f7`. It is evidence for
release readiness, not conformance, a universal accuracy claim, a version
change, or release authorization. The product manifests still identify these
pre-release candidate packages as `0.1.0-beta.1`; “beta.2” names the assessment
target only.

The machine-readable rollup is [`summary.json`](./summary.json). Per-runtime
common-contract JSON, rendered Markdown, and safe mismatch metadata are stored
beside it. None of those outputs contains a matched value.

## Dataset scope

The fixed [`accuracy-corpus.json`](../../fixtures/accuracy-corpus.json) is
version 1 with SHA-256
`9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9`.
It has 9 hand-reviewed, whole-input fixtures: 3 logs, 2 source-code, 2 chat,
and 2 ordinary negative-text fixtures. Six fixtures carry one expected finding
each. Three fixtures are expected empty: the clean chat fixture and the two
negative-text fixtures. This small synthetic set is separate from
`conformance/`; results describe only these 9 fixtures.

The completed coverage work in
[#186](https://github.com/redact-secret/redact-secret/issues/186),
[#187](https://github.com/redact-secret/redact-secret/issues/187),
[#188](https://github.com/redact-secret/redact-secret/issues/188),
[#189](https://github.com/redact-secret/redact-secret/issues/189), and
[#190](https://github.com/redact-secret/redact-secret/issues/190) supplies
canonical breadth and overlap evidence. It is not counted as accuracy evidence
here; passing conformance coverage does not change an assessment label or its
denominator.

## Results

All four real-artifact runs completed every fixture and produced the same safe
mismatch set.

| Runtime | TP / expected | FN / expected | FP / actual | Incorrect ranges / expected (actual) | Policy-correct / evaluable | Negative fixtures with findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Node 22.16.0 | 1/6 | 5/6 | 1/2 | 1/6 (1/2) | 1/1 | 0/3 |
| Chromium 153.0.8010.12 | 1/6 | 5/6 | 1/2 | 1/6 (1/2) | 1/1 | 0/3 |
| Firefox 155.0 | 1/6 | 5/6 | 1/2 | 1/6 (1/2) | 1/1 | 0/3 |
| WebKit 26.6 | 1/6 | 5/6 | 1/2 | 1/6 (1/2) | 1/1 | 0/3 |

The common scorer requires detector, type, and range to match exactly. Its one
false positive is the emitted Bearer finding whose range disagrees with the
reviewed expected range; the same case also contributes one false negative.
No expected-empty fixture emitted a finding (0/3), so this corpus observed no
ordinary-negative false positive. Policy correctness is 1/1 only among exact
range matches. End-to-end detector/type/range/action correctness is therefore
1/6 expected findings; the Bearer action is `redact`, but its range mismatch
keeps that case out of the correct denominator.

These ratios must not be generalized beyond this deliberately small corpus.

## Mismatch dispositions

No mismatch established a new detector defect, so no conformance expectation
was changed and no regression was added merely to make the score pass. The
reviewed assessment labels also remain unchanged.

- `logs-github-token` and `logs-unicode-astral-boundary` use a classic `ghp_`
  shape with 35 suffix characters. The
  [GitHub detector](../../../crates/secret-scan-core/src/detectors/github.rs)
  intentionally requires the documented 36-character suffix. Short or
  truncated provider shapes remain a precision-favoring false-negative limit.
- `code-aws-access-key` uses 15 characters after `AKIA`; the
  [AWS detector](../../../crates/secret-scan-core/src/detectors/aws.rs)
  requires the fixed 16-character suffix. Short provider shapes remain a
  documented false-negative limit.
- `logs-contextual-secret-warn` assigns to `seed`, which is outside the
  [generic detector's reviewed setting-name allowlists](../../../crates/secret-scan-core/src/detectors/generic_token.rs).
  Treating arbitrary seed values as credentials would trade this false negative
  for more false positives, so the unsupported setting name remains explicit.
- `chat-bearer-token` expects `[48, 88)`, while every artifact reports
  `[55, 88)`. The
  [Bearer detector](../../../crates/secret-scan-core/src/detectors/bearer_token.rs)
  and its
  [overlap regression](../../../crates/secret-scan-core/tests/detectors_conformance.rs)
  deliberately select and redact the credential value, leaving the scheme.
  The secret value is removed and the action is correct, but this report keeps
  the assessment range mismatch visible instead of relabeling it.

If product requirements later classify any of the first three unsupported
shapes as mandatory, the fix must be made in the Rust core with a fresh
synthetic conformance regression and an explicit false-positive tradeoff.

## Artifact identity

The package-consumer qualifier packed and installed the candidates into clean
directories before exercising initialize, scan, incremental, and stream APIs.
All four qualification lanes passed.

| Package | Manifest version | Candidate tarball SHA-256 |
| --- | --- | --- |
| `@redact-secret/core` | `0.1.0-beta.1` | `568c68d8be8b0815482b7e25aa4401c80cb0c996afb136b5311ecda210397bce` |
| `@redact-secret/node-darwin-arm64` | `0.1.0-beta.1` | `47e536a1b12a1717212253fea6c1aa305e796f1d55673666e3dd88ac71b40f34` |
| `@redact-secret/wasm` | `0.1.0-beta.1` | `3f8527292987296a6bc7a159ff4c755131d24bf125388ce62a5a872ac225f77b` |

The exact qualification records were pruned by
[#594](https://github.com/redact-secret/redact-secret/issues/594) and remain
as historical evidence at
[`package-node-qualification.json`](https://github.com/redact-secret/redact-secret/blob/77eb43a122ce4c3f5683019bd77cc4c7fc57894c/assessment/results/beta.2/package-node-qualification.json),
[`package-browser-chromium-qualification.json`](https://github.com/redact-secret/redact-secret/blob/77eb43a122ce4c3f5683019bd77cc4c7fc57894c/assessment/results/beta.2/package-browser-chromium-qualification.json),
[`package-browser-firefox-qualification.json`](https://github.com/redact-secret/redact-secret/blob/77eb43a122ce4c3f5683019bd77cc4c7fc57894c/assessment/results/beta.2/package-browser-firefox-qualification.json),
and [`package-browser-webkit-qualification.json`](https://github.com/redact-secret/redact-secret/blob/77eb43a122ce4c3f5683019bd77cc4c7fc57894c/assessment/results/beta.2/package-browser-webkit-qualification.json).

## Reproduction

These commands build the same minimal real artifacts and run only the 9-fixture
accuracy corpus. On another platform, replace the Node package link name with
the specifier exported by `packages/javascript/dist/runtime/node.js`.

```bash
npm ci
npm --prefix bindings/node ci
npm --prefix bindings/node run build
npm run js:build
npm run wasm:build
mkdir -p packages/javascript/node_modules/@redact-secret
ln -s "$(pwd)/bindings/node" packages/javascript/node_modules/@redact-secret/node-darwin-arm64
npm run assessment:node -- --json-out assessment/results/beta.2/node.json --markdown-out assessment/results/beta.2/node.md --mismatches-out assessment/results/beta.2/node-mismatches.json
npm run assessment:browser -- --engine chromium --json-out assessment/results/beta.2/browser-chromium.json --markdown-out assessment/results/beta.2/browser-chromium.md --mismatches-out assessment/results/beta.2/browser-chromium-mismatches.json
npm run assessment:browser -- --engine firefox --json-out assessment/results/beta.2/browser-firefox.json --markdown-out assessment/results/beta.2/browser-firefox.md --mismatches-out assessment/results/beta.2/browser-firefox-mismatches.json
npm run assessment:browser -- --engine webkit --json-out assessment/results/beta.2/browser-webkit.json --markdown-out assessment/results/beta.2/browser-webkit.md --mismatches-out assessment/results/beta.2/browser-webkit-mismatches.json
node scripts/qualify-package-consumer.mjs --lane node --wasm-dir bindings/wasm/pkg --report assessment/results/beta.2/package-node-qualification.json
node scripts/qualify-package-consumer.mjs --lane browser --engine chromium --wasm-dir bindings/wasm/pkg --report assessment/results/beta.2/package-browser-chromium-qualification.json
node scripts/qualify-package-consumer.mjs --lane browser --engine firefox --wasm-dir bindings/wasm/pkg --report assessment/results/beta.2/package-browser-firefox-qualification.json
node scripts/qualify-package-consumer.mjs --lane browser --engine webkit --wasm-dir bindings/wasm/pkg --report assessment/results/beta.2/package-browser-webkit-qualification.json
```

Run package qualification lanes sequentially: each uses the same temporary
tarball names. The assessment commands record source, corpus, host, runtime,
and exact invocation in their JSON and Markdown outputs.
