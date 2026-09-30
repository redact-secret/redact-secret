# #1012 research: `baseten:api-key` (prepared, not ruled)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[Handoff](../860/baseten.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: DATE-GATED (prepared, not ruled).** No `b10_` key can exist before
2026-10-01 15:00 GMT. This record re-checks the docs and prepares the
post-date check; it rules nothing.

## Re-check

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Baseten docs, API keys](https://docs.baseten.co/organization/api-keys.md) | read 2026-09-29 | provider docs | T1 | unchanged: "Baseten API keys use the stable `b10_` prefix so secret-scanning tools can identify exposed credentials"; regex `b10_[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}`; "Keys created before 3:00 PM GMT on October 1, 2026, don't contain the `b10_` prefix" |
| 2 | same page, CLI and API examples | read 2026-09-29 | provider placeholders | R4 | the create outputs (personal, workspace-invoke, workspace-manage-api-keys) and the `POST /v1/api_keys` response show `b10_` + an 8-character sequential id + `.` + a 32-character sequential letters-only placeholder; the list example shows `b10_` + 8 |
| 3 | [basetenlabs/baseten-cli @ ac5ce53](https://github.com/basetenlabs/baseten-cli/tree/ac5ce53103308d3c40da326d09c6963010d2abbb) and its v1.0.0 darwin_arm64 binary | 2026-09-29 | provider CLI | negative | no `b10_` literal or pattern in source or binary strings |
| 4 | truss at 04afb13 (0.18.32); PyPI `baseten` 0.11.0 | 2026-09 | provider SDKs | negative | `b10_` only as Python identifiers; key `prefix` fields only |

No peer scanner has a Baseten rule.

## Post-date checklist (after 2026-10-01 15:00 GMT; structure only)

1. Re-read the docs page: regex and cutoff sentence unchanged.
2. Create one personal key, one workspace-invoke key and one
   workspace-manage key; record that each creation time is after the cutoff.
3. For each: total length (45?), starts `b10_`, id length 8 and its classes,
   `.` at offset 12, secret length 32, classes limited to uppercase,
   lowercase and digits, and whether the list view's prefix equals `b10_` +
   id. `rawValueRetained: false`, then revoke.
4. Optional: the total length of one untouched pre-cutoff key.

Only after a match does the detector land and the benchmarks side record
arrival, as the handoff says.
