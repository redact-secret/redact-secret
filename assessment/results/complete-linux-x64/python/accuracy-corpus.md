# Accuracy assessment — python

- Profile: `accuracy-corpus`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Corpus: `2` (`b50cdbc1ddb71bcac87936c26744384f35eb9174b1b654bc860f86193432c4e7`)
- Host: linux-6.17.0-1022-azure / x64 / cpython-3.12.14
- Command: `node scripts/assessment-python-run.mjs --python .venv/bin/python --json-out assessment-output/python/accuracy-corpus.json --markdown-out assessment-output/python/accuracy-corpus.md --mismatches-out assessment-output/python/accuracy-corpus-mismatches.json`

## Accuracy metrics

| Metric | Count |
| --- | --- |
| True positives | 6 |
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
