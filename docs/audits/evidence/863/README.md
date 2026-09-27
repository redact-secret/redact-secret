# Issue #863 — `openai:admin-api-key` contract reconciled with `sk-admin-` detection

[Audit archive](../../README.md) ·
[Issue #863](https://github.com/redact-secret/redact-secret/issues/863) ·
[Research #777](https://github.com/redact-secret/redact-secret/issues/777) ·
[OpenAI evidence (#657)](../657/README.md) ·
[OpenAI contract freeze (#368)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

## Verdict

The precision contract listed `openai:admin-api-key` as `pending`/T0 while the
shipped `openai-token` detector already accepted `sk-admin-`. The contract now
matches the detector:

- **Supported at T2** (tool-corroborated, not provider-documented):
  `sk-admin-` + `[58|74 of A-Za-z0-9_-]` + `T3BlbkFJ` + `[58|74 of A-Za-z0-9_-]`,
  the same marker-gated grammar as `sk-proj-` and `sk-svcacct-`.
- **Out of contract:** a marker-less `sk-admin-` body of any length,
  including the 124-byte body from trufflehog#4698. No detector change.
- T1 is not reached: no provider page states an admin-key length or
  alphabet (#657, #777).

## Evidence basis

| Property | Source | Class |
|---|---|---|
| prefix `sk-admin-` | gitleaks 8.30.1 rule; `openai/codex` credential broker names the prefix | tool; provider code (prefix only) |
| widths 58/58 (133 bytes) | gitleaks admin test vectors (all three are 58/58) | tool |
| marker `T3BlbkFJ` | gitleaks requires it on admin; family-wide watermark in `openai/codex` | tool; provider code |
| 124-byte body | trufflehog#4698 request, no source; equals 58 + 8 + 58, marker not mentioned | community |
| trufflehog 3.97.4 | explicitly excludes admin keys | tool (disagreement recorded, not resolved) |

No source measures a 74/74 admin key or a marker-less admin key. 74/74 stays
accepted because the widths are shared with `proj`/`svcacct` and cost nothing.

## Why marker-less stays out

- The only marker-less evidence is one request whose length equals the
  marker-bearing key's; reading it as a different shape is a guess.
- A free `sk-admin-` body needs an `sk-ant-`/`sk-or-` style reject list and
  would flag prose and identifiers; ADR 2026-09-21 already declined that
  shape for the generic layer beyond the 48-byte early form.
- Admin keys are rare in leaks (GitGuardian's dedicated detector reports
  about 0.07 occurrences per million commits), so the recall gained is small.

**False negatives accepted:** a real marker-less admin key would be missed by
`openai-token`. Measured on the default pipeline with a synthetic 124-byte
body: bare, unquoted `OPENAI_ADMIN_KEY=`, `export`, YAML and JSON tool-call
shapes produce no finding. `Authorization: Bearer` and quoted
credential-named assignments (`"admin_api_key": "..."`) are still redacted by
the generic layers. **False positives avoided:** placeholders
(`sk-admin-...`), prose mentions of the prefix, and key ids are not claimed.

Revisit if issuing one Admin key (checklist in the #777 research comment)
shows a marker-less body, a different width, or if provider documentation
appears.

## Verification

`crates/secret-scan-core/tests/openai_admin_key_contract.rs` (synthetic keys
built at runtime): 58/58, 74/74 and mixed positives in bare, env, export,
YAML, JSON, curl and tool-call contexts; one-byte-short and one-byte-long
twins; placeholders and marker/prefix mutations; marker-less body silent for
`openai-token` in every context, with the generic-layer outcome pinned.
`docs/audits/evidence/367/corpus-audit.json` regenerated: the admin
conformance fixtures moved from `broad-shape` to `retained`.
