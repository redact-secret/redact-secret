# Accuracy assessment — browser-wasm

- Profile: `accuracy-corpus`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.1`
- Commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Corpus: `1` (`9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9`)
- Host: darwin-25.5.0 / arm64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-run.mjs --engine chromium --artifact-dir /Users/minhokang/orca/workspaces/redact-secret/performance-and-resource-acceptance/bindings/wasm/pkg --json-out assessment/results/acceptance/browser-wasm/accuracy-corpus.json --markdown-out assessment/results/acceptance/browser-wasm/accuracy-corpus.md --mismatches-out assessment/results/acceptance/browser-wasm/accuracy-corpus-mismatches.json`

## Accuracy metrics

| Metric | Count |
| --- | --- |
| True positives | 1 |
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
