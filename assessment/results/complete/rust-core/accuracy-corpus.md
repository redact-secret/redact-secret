# Accuracy assessment — rust-core

- Profile: `accuracy-corpus`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Corpus: `1` (`9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9`)
- Host: macos-25.5.0 / aarch64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- accuracy --json-out assessment/results/complete/rust-core/accuracy-corpus.json --markdown-out assessment/results/complete/rust-core/accuracy-corpus.md --mismatches-out assessment/results/complete/rust-core/accuracy-corpus-mismatches.json`

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
