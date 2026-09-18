# Accuracy assessment — browser-wasm

- Profile: `accuracy-corpus`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Corpus: `3` (`438df062ddde47dcb32ae0aefc4297ed8b8c9e2c3270778c2b1f8809e40bd0dd`)
- Host: darwin-25.5.0 / arm64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-run.mjs --engine chromium --artifact-dir /Users/minhokang/orca/workspaces/redact-secret/gate-beta.5-on-precision-gains-and-positive-pres/bindings/wasm/pkg --json-out assessment-output-v4-real/browser-wasm/accuracy-corpus.json --markdown-out assessment-output-v4-real/browser-wasm/accuracy-corpus.md --mismatches-out assessment-output-v4-real/browser-wasm/accuracy-corpus-mismatches.json`

## Accuracy metrics

| Metric | Count |
| --- | --- |
| True positives | 21 |
| False positives | 1 |
| False negatives | 5 |
| Policy mismatches | 0 |

## Mismatches

| Fixture | Kind | Detector | Type | Range | Policy |
| --- | --- | --- | --- | --- | --- |
| logs-github-token | missing | github-token | github_token | [39, 78) | expected `redact` |
| logs-contextual-secret-warn | missing | generic-token | contextual_secret | [38, 75) | expected `warn` |
| code-aws-access-key | missing | aws-access-key | aws_access_key_id | [24, 43) | expected `redact` |
| chat-bearer-token | extra | bearer-token | bearer_token | [55, 88) | — |
| chat-bearer-token | missing | bearer-token | bearer_token | [48, 88) | expected `redact` |
| logs-unicode-astral-boundary | missing | github-token | github_token | [11, 50) | expected `redact` |
