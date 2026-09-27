---
name: owasp-review
description: Review the current code against OWASP guidance (ASVS 5.0, Top 10, relevant Cheat Sheets) and report which requirements it meets, misses, or cannot be judged. Use when asked for an OWASP review or compliance check ("owasp-review", "/owasp-review crates/secret-scan-core", "does this meet OWASP?"). Read-only; changes nothing.
---

# owasp-review

Review code against OWASP guidance. Report findings only; do not edit files.

## Scope

- Target: the path given as an argument, or else the current diff
  (`git diff main...HEAD`), or else `crates/secret-scan-core`.
- Read `docs/specs/threat-model.md` first, then `SECURITY.md` and
  `ARCHITECTURE.md#security-boundaries`. Judge each control only within the
  trust boundary they describe — the process running the core and its
  bindings, not a defense against co-resident code that already holds the
  original input. A documented residual risk or an explicitly out-of-scope
  limit in `docs/specs/threat-model.md` is not a finding.

## Checklist

Map the code to the OWASP areas that apply. Skip areas that do not.

| Area | Source | Check |
| --- | --- | --- |
| Sensitive data | ASVS V14, Cryptographic Storage | No matched plaintext in findings, thrown errors, logs, diagnostics, snapshots, or fixtures; placeholder text cannot fit a replaced range within its 256-UTF-8-byte bound |
| Input validation | ASVS V1/V2 | Oversized input, many-candidate input, and adversarial Unicode (unpaired surrogates, confusables, zero-width/bidi) are bounded or rejected; detector regexes are safe from catastrophic backtracking |
| Errors and logging | ASVS V16, Logging Cheat Sheet | Fixed error codes/messages; no `cause` chain or diagnostic carrying a payload; security-relevant failures fail closed |
| Extension and caller trust | `SECURITY.md` "Extension and caller trust" | Custom detectors/policies/placeholder formatters are treated as trusted in-process code, never sandboxed as untrusted; findings passed directly to `redact` are validated for metadata/ranges but not re-verified as authentic `scan` output |
| Business logic and determinism | `ARCHITECTURE.md`, `conformance/` | Same input and configuration produce the same findings/output across bindings; no environment-dependent or network-dependent behavior in the core |
| Incremental session limits | `docs/specs/threat-model.md` "retained plaintext" | Total-input, retained-plaintext, token, and multiline limits are enforced; limit and extension failures are fail-closed and do not log the raw body |
| LLM/tool output handling | OWASP Top 10 for LLM, LLM Prompt Injection Cheat Sheet | Findings or text arriving from model/tool output are treated as untrusted input to `scan`, never accepted as pre-validated `finding` objects into `redact` |
| Authoritative boundary | `ARCHITECTURE.md` "Security boundaries" | Client-side scanning is documented as preventive UX only; nothing in the reviewed code claims it as the authoritative enforcement point |
| Supply chain | NPM Security Cheat Sheet, ASVS V15, `SECURITY.md` "CI supply-chain review" | Pinned dependencies and actions (full commit SHA), `npm ci --ignore-scripts`, minimal packed files, no unreviewed install scripts |

## Output

One table, most severe first:

| Status | Severity | OWASP ref | file:line | Evidence | Fix |
| --- | --- | --- | --- | --- | --- |

- Status: `pass`, `fail`, or `n/a` (with the reason).
- Every `fail` needs a concrete scenario: input → wrong outcome.
- End with a one-line verdict and the requirements that could not be judged
  without runtime testing. Hand those to `vulnerability-test`.

## Rules

- Use synthetic values only. Never paste real secrets or a finding's matched
  plaintext into the report.
- Cite the specific requirement (for example `ASVS 5.0 V14.2.1`) when you can.
  Otherwise name the Cheat Sheet.
- Do not claim compliance or certification. Say "meets the reviewed
  requirements".
