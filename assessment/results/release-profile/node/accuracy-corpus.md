# Accuracy assessment — node

- Profile: `accuracy-corpus`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.3`
- Commit: `d727f386f8fc2a88eded6f26dd38c79f6b83dc68`
- Corpus: `3` (`cc4cb42028fd700bc98dd06dacebe421c5462dd59a46cf013154a4d185849979`)
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-run.mjs --json-out assessment/results/release-profile/node/accuracy-corpus.json --markdown-out assessment/results/release-profile/node/accuracy-corpus.md --mismatches-out assessment/results/release-profile/node/accuracy-corpus-mismatches.json`

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
