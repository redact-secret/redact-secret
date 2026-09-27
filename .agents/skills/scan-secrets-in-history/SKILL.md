---
name: scan-secrets-in-history
description: Scan this repository's full git history for accidentally committed real credentials with gitleaks, independent of the product's own detectors. Use when asked to check for leaked secrets in history, before a release, or for "scan-secrets-in-history", "/scan-secrets-in-history". Report-only; never prints matched plaintext.
---

# scan-secrets-in-history

Check whether this repository's own commit history ever violated the rule it enforces on everyone else: no real credentials in source, fixtures, logs, or docs (`AGENTS.md` "Security boundary"). Use an independent scanner, not `redact-secret`'s own detectors — reviewing your own blind spots with your own tool proves nothing.

## Run

- `gitleaks version` (record it; findings can shift between versions).
- `gitleaks detect --source . --redact --report-format json --report-path <scratchpad>/gitleaks-report.json -v`

`gitleaks detect` walks the full commit history reachable from `HEAD` by default — do not narrow it with `--log-opts` unless asked to scope to a range. `--redact` is mandatory: it masks the matched secret in gitleaks' own output, so the report itself never carries plaintext.

## Triage every hit

This repository's `conformance/`, `assessment/`, and `sast/baseline.json` fixtures are a secret-detection test suite — they intentionally contain thousands of credential-shaped strings, and gitleaks will flag most of them. That volume is expected, not a finding. Per `conformance/README.md#fixture-safety-review`, every corpus `input` is required to be unmistakably synthetic or revoked, using the `SYNTHETIC…`/`SYNTHETIC_REVOKED…` labeling convention described there and in `docs/decisions/2026-09-18-resolve-real-looking-twin-fixtures-as-unmistakably-synthetic.md`.

For each gitleaks hit:

1. **Path check.** Under `conformance/`, `assessment/`, `examples/*/fixtures*`, or a test directory → almost certainly an intentional fixture. Confirm the matched line carries a `SYNTHETIC`/`SYNTHETIC_REVOKED`/similarly explicit marker or an obviously non-random, patterned body (per the ADR above). If it does, disposition as `fixture, synthetic` and move on without further scrutiny.
2. **No marker, or outside a fixture path.** Escalate. Read the surrounding commit (`git show <sha>`, redacting the value in your own output) to judge whether the value is plausibly a real, still-usable credential — a real-looking cloud key format, a real domain plus a real-looking token, a `.env`-shaped commit, etc.
3. **Plausibly real.** Stop. Do not print it anywhere, including this report. Tell the user directly which commit, file, and gitleaks rule ID matched, and that it needs private rotation and history remediation (`git filter-repo` / GitHub secret-scanning push protection review) — this is not something to fix by opening a normal PR, since the value stays in history either way until rewritten.

## Output

| Verdict | Commit(s) | Path | gitleaks rule | Disposition |
| --- | --- | --- | --- | --- |

Disposition is one of: `fixture, synthetic` (expected, no action), `needs private rotation` (escalated per step 3), or `unclear — needs maintainer judgment`. Then the gitleaks version, total raw hit count, and the count after triage. Verdict: `no real credentials found in history` or the count needing rotation.

## Rules

- Never print a matched secret value, in this report or anywhere else — not even a partial or "just the prefix" excerpt. Name the commit and rule ID instead.
- Do not rewrite history, force-push, or open an issue. This skill reports; a human decides on rotation and remediation.
- If gitleaks is not installed, say so and stop — do not substitute a weaker regex grep as a silent fallback.
