# Complete assessment v4 — Linux x86_64 accuracy-corpus re-pin (issue #376)

Genuine `ubuntu-latest` GitHub Actions evidence from a dispatched run of
[`Complete assessment`](../../../.github/workflows/complete-assessment.yml)
([run 35348737203](https://github.com/redact-secret/redact-secret/actions/runs/35348737203))
at commit `944341903d5b85686a056d3218f4c33110d7d57b`, after the beta.5
precision gate ([#376](https://github.com/redact-secret/redact-secret/issues/376))
corrected four `assessment/fixtures/accuracy-corpus.json` fixtures to the
seven frozen provider contracts from
[issue #367](https://github.com/redact-secret/redact-secret/issues/367).

Unlike the [macOS profile](../complete-v4/README.md), this evidence is fully
`accepted`: all five required surfaces report the same **21 true positives /
1 false positive / 5 false negatives / 0 policy mismatches across 18
fixtures** as the pinned macOS profile, and every performance and resource
threshold in `assessment/acceptance-criteria-linux-x64.json` passes cleanly
on this host — see [`acceptance.json`](acceptance.json) /
[`acceptance.md`](acceptance.md). Before this re-pin, evaluating this run
against the prior criteria failed on exactly
`suite:accuracy-corpus-identity-mismatch` and nothing else, confirming the
performance thresholds themselves were never the issue on a properly
qualified host — only the pinned corpus identity needed to move forward with
the corrected fixtures. `assessment/acceptance-criteria-linux-x64.json`'s
`baseline` pointer and `accuracy` block are updated accordingly; its
`performance` array is unchanged.
