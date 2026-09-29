# #1012 research: `openrouter:management-api-key`

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[Benchmarks research #220](https://github.com/redact-secret/redact-secret-benchmarks/issues/220)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED; the prefix itself is contested.** OpenRouter's docs and
a staff statement say management keys start `sk-or-mgmt-`. Three
independent users, reporting first-hand, say their live management keys
start `sk-or-v1-`, like inference keys. No body grammar for `sk-or-mgmt-`
exists anywhere.

If management keys are in fact `sk-or-v1-` + 64 lowercase hex, the existing
`openrouter:api-key` contract already covers them, and no separate family is
needed.

## Current product behaviour

The AI-inference detector (`crates/secret-scan-core/src/detectors/ai_inference.rs`)
claims `sk-or-v1-` + 64 lowercase hex as `openrouter:api-key`. Nothing claims
`sk-or-mgmt-`. The support-matrix reason: "a real secret, but no body
grammar is published".

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [OpenRouterTeam/docs `guides/overview/terraform.mdx` L41 @ 9e41728](https://github.com/OpenRouterTeam/docs/blob/9e4172882651f7a85099a3054d120e66ef850715/guides/overview/terraform.mdx#L41) | 2026-09-02 | provider docs | R4 (prefix claim) | "Authenticate with an OpenRouter Management API key … which starts with `sk-or-mgmt-...`" |
| 2 | [OpenRouterTeam/terraform-provider-openrouter `README.md` L39 @ 7fd0e34](https://github.com/OpenRouterTeam/terraform-provider-openrouter/blob/7fd0e341dc9c638333952e8e4159c198b7028d91/README.md#L39) | first seen 2026-07-17 | provider docs placeholder | R4 | "Management API key (`sk-or-mgmt-...`)" |
| 3 | [terraform-provider-openrouter PR #253](https://github.com/OpenRouterTeam/terraform-provider-openrouter/pull/253) (new) | 2026-08-25 | provider staff statement (author's profile names @OpenRouterTeam) | R3 = T1 as of its date (prefix) | "Management keys are a distinct credential with their own prefix, `sk-or-mgmt-…`." |
| 4 | [OpenRouterTeam/docs `guides/features/guardrails/secret-formats.mdx` L36 @ 9e41728](https://github.com/OpenRouterTeam/docs/blob/9e4172882651f7a85099a3054d120e66ef850715/guides/features/guardrails/secret-formats.mdx#L36) (new) | 2026-08-26 | provider docs (its own secret scanner) | T1 for `sk-or-v1-` | "`sk-or-v1-` followed by 64 lowercase hexadecimal characters"; no management-key row |
| 5 | [zaydiscold/hydra `server/services/key-utils.js` L4-L6 @ cf1926f](https://github.com/zaydiscold/hydra/blob/cf1926f166be543f3af93a4d50b2bc548d6b6409/server/services/key-utils.js#L4-L6) (new) | 2026-04-03 | independent implementation, first-hand | contradicts #1–#3 | "OR management keys use sk-or-v1- prefix, NOT sk-or-mgmt-" |
| 6 | [disler/inkwell-agent-sandboxes-and-software-factory issue #3](https://github.com/disler/inkwell-agent-sandboxes-and-software-factory/issues/3) (new) | 2026-08-10 | independent report, first-hand | contradicts | "Both key types have the same `sk-or-v1-…` prefix. I confirmed this on my own account" |
| 7 | [kljensen/openrouter-keymaster `crates/core/src/redaction.rs` L20-L25 @ d54808d](https://github.com/kljensen/openrouter-keymaster/blob/d54808de2de0df4fae0367a2680ab71379643642/crates/core/src/redaction.rs#L20-L25), issue #26 (new) | 2026-08-24 | independent implementation, first-hand | contradicts | a management key "carries the same `sk-or-v1-` shape an inference key does" |
| 8 | [google/osv-scalibr `veles/secrets/openrouter/detector.go` L28-L30 @ 5ab8022](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/openrouter/detector.go#L28-L30) | 2025-09-18 | peer scanner rule | none for management | `sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}` (would not match `sk-or-mgmt-`) |

Searched, nothing further: `sk-or-mgmt` in code search (111 hits: docs,
placeholders, prefix checks copied from docs; no full-width sample); issue
search (13 and 172 hits); `openrouter.ai/docs/llms-full.txt` (one
`sk-or-mgmt-...`); OpenRouter TypeScript and Python SDKs (no prefix
validation); trufflehog, betterleaks, gitleaks, noseyparker, Kingfisher,
CredSweeper, secretlint (no `sk-or-mgmt` rule).

## Exact missing evidence

- **Prefix:** `sk-or-mgmt-` (provider statements, 2026-07 to 09) or `sk-or-v1-`
  (three first-hand observers, 2026-04 to 08). A format change after
  2026-08-24 is possible but unproven. Statements cannot settle it; an
  example or issuance can.
- **Body:** length and alphabet after `sk-or-mgmt-`, from any source.

## Structure-only issuance check

Create one management key at `/settings/management-keys` with the shortest
expiry. Record: the exact prefix, total length, body alphabet (lowercase hex
only?), and that `GET /api/v1/key` reports it as a management key.
`rawValueRetained: false`, then delete.

## Residual risk

If the keys are `sk-or-v1-`, they are already redacted, under the inference
type (the role is not lexically visible). If they are `sk-or-mgmt-`, they are
redacted today only in named and Bearer contexts.
