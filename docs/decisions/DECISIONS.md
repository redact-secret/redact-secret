# Architecture decisions

These records preserve accepted project-wide choices. They provide context for
future planning and implementation but do not authorize Git or release actions.

- [Adopt a Rust-core monorepo](2026-09-09-adopt-rust-core-monorepo.md)
- [Define runtime bindings](2026-09-09-define-runtime-bindings.md)
- [Govern cross-language conformance](2026-09-09-govern-cross-language-conformance.md)
- [Release bindings in lockstep](2026-09-09-release-bindings-in-lockstep.md)
- [Ship the first release's full artifact set](2026-09-10-ship-first-release-artifact-set.md)
- [Adopt the Redact Secret naming contract](2026-09-10-adopt-redact-secret-naming-contract.md)
- [Pin OpenGrep and establish a reviewed SAST baseline](2026-09-10-pin-opengrep-and-establish-a-reviewed-sast-baseline.md)
- [Enforce OpenGrep in CI as a required, SARIF-integrated gate](2026-09-10-enforce-opengrep-in-ci-as-a-required-gate.md)
- [Define the cross-language evaluation protocol](2026-09-12-define-cross-language-evaluation-protocol.md)
- [Measure JavaScript performance externally](2026-09-12-measure-javascript-performance-externally.md)
- [Match placeholder words on token boundaries, not exact-string equality](2026-09-15-match-placeholder-words-on-token-boundaries.md)
- [A contextual assignment's value never crosses a line terminator](2026-09-15-contextual-assignment-stops-at-the-line.md)
- [Exclude a value fully delimited by `{{` and `}}` as a template reference](2026-09-15-exclude-fully-delimited-template-references.md)
- [Exclude unquoted source-code expressions from generic-token's contextual values](2026-09-16-exclude-unquoted-source-code-expressions-as-contextual-values.md)
- [Exclude secret-manager reference strings resolved at runtime](2026-09-16-exclude-secret-manager-references.md)
- [Exclude interpolation and command-substitution references beyond `${...}`, `$name`, and `{{...}}`](2026-09-16-exclude-interpolation-command-substitution-references.md)
- [Exclude cmd-style Windows environment references (`%VAR%`) and SQL named bind parameters (`:identifier`)](2026-09-16-exclude-windows-env-and-sql-bind-parameter-references.md)
- [Bound the Azure Key Vault SecretUri reference by host shape, not domain identity](2026-09-16-bound-azure-keyvault-secreturi-host-by-shape.md)
- [Detect a nested contextual assignment with no separator inside an enclosing quote](2026-09-16-detect-nested-assignments-with-no-separator-inside-a-quote.md)
