---
decision_id: decision-exclude-unquoted-source-code-expressions-as-contextual-values
status: accepted
scope: workspace
title: Exclude unquoted source-code expressions from generic-token's contextual values
decided_at: 2026-09-16
spec: contextual-detection
---

# Exclude unquoted source-code expressions from generic-token's contextual values

## Decision

Add four narrow exclusions to `generic-token`'s non-secret reference checks
(`crates/secret-scan-core/src/detectors/generic_token.rs`,
`is_non_secret_reference`, via a new `is_source_code_expression`), each
matching a distinct source-code expression shape rather than a blanket
"contains a dot" rule:

- **A known reference root.** `starts_with_code_reference_root` excludes a
  value starting with `settings.`, `config.`, `cfg.`, `options.`, `self.`,
  `this.`, `var.`, `local.`, or `data.` — a Django/Rails/NestJS
  settings-or-config object, JS/Python/Ruby instance access, or a Terraform
  `var`/`local`/`data` lookup. The root must be followed immediately by `.`,
  so `self` does not also match `selfhosted`.
- **A snake_case attribute chain.** `is_snake_case_attribute_chain` excludes
  a dotted chain of two or more `lower_snake_case` segments that contains at
  least one underscore somewhere in the chain — the shape of a Terraform
  resource or data-source attribute reference
  (`random_password.db.result`,
  `data.aws_secretsmanager_secret_version.db.secret_string`) that has no
  fixed root because the leading segment is an arbitrary resource type.
- **Generic-type or subscript syntax.** `contains_generic_or_subscript_syntax`
  excludes a value with an identifier character immediately followed by `<`
  or `[` anywhere in it: `Option<String>`, `Optional[str`, `&SecretBox<str>`.
- **A call or subscript truncated at a string literal.**
  `ends_with_open_call_or_subscript` excludes a value ending in an unmatched
  `(` or `[`. The unquoted-value scan already stops at a quote boundary, so
  `os.environ["OPENAI_API_KEY"]` is captured only as `os.environ[` and
  `std::env::var("...")` only as `std::env::var(` — both are call/subscript
  expressions cut short at their string-literal argument, not real values.

## Rationale

An unquoted value that is a member-access chain, a call, a subscript, or a
generic type names *where* a secret lives at runtime (a settings attribute, a
config object member, a Terraform resource output, a type annotation); it
contains no secret content itself. `unquoted_assignment_value` already
accepted `.`, `(`, `[`, `<`, and `&` inside a value, and the only prior
exclusions were `process.env.` / `import.meta.env.` prefixes
(`starts_with_env_reference`). Everything else in this shape — Django
`settings.DATABASE_PASSWORD`, TypeScript `config.anthropicApiKey`, Terraform
`random_password.db.result`, Python `os.environ[...]`, Rust
`Option<String>` — was reported as a high-confidence `contextual_secret`, and
the default `redact` policy action rewrote the source expression as if it
were a literal credential.

The issue's own false-negative analysis is the reason this is four narrow
checks rather than one general rule: a real unquoted passphrase can contain
`.`, `(`, or `[` (`my.pass.word`), so excluding every dotted or bracketed
value would trade a common false positive for a silent false negative on
real credentials. Each check here is anchored to a structural signal a real
passphrase is unlikely to share:

- The reference-root list is a closed, explicit set of identifiers that are
  themselves unambiguous as soon as they open — a real secret is vanishingly
  unlikely to *start* with the literal word `settings` or `self` followed by
  a dot.
- The snake_case-chain check requires an underscore somewhere in the chain.
  `random_password.db.result` and `var.db_password` both have one; a
  passphrase built from whole dictionary words like `my.pass.word` does not,
  and stays detected. This is the one check closest to a general "dotted
  identifier" rule, and it is the narrowest form of it that still covers the
  Terraform reproducer, whose leading segment (an arbitrary resource type)
  cannot be enumerated the way `var`/`local`/`data` can.
- The generic-type and call/subscript-truncation checks fire only on
  punctuation shapes (`<`, unmatched trailing `(`/`[`) that do not
  legitimately appear in an unquoted credential value in the syntaxes this
  detector targets.

Two paired regression fixtures pin the boundary these checks deliberately do
not cross: `password: SYNTHETIC.REVOKED.CONTEXT_VALUE` (a dotted value with
no known root and no lower_snake_case segment — every segment is
SCREAMING_CASE) and `password: SYNTHETIC_REVOKED_CONTEXT_VALUE` (no dot at
all) both stay detected at high confidence.

Downgrading these values to `warn` instead of excluding them outright was
considered and rejected: a `warn` action still surfaces every one of these
extremely common config-code shapes as a hit a reviewer must repeatedly
dismiss, and none of the four signals above plausibly matches real secret
content, so the same reasoning that justifies detection for an ordinary
`{{ ... }}` template reference or a `${VAR}` reference — full exclusion, not
a downgrade — applies here too.

## Consequences

- `generic_token.rs` gains `starts_with_code_reference_root`,
  `is_snake_case_attribute_chain`, `contains_generic_or_subscript_syntax`,
  `ends_with_open_call_or_subscript`, and the `is_source_code_expression`
  check that combines them, called from `is_non_secret_reference` alongside
  the existing env, path, PEM/key, template, and filler exclusions.
- The five reproducers in issue #278 (Django `settings.X`, TypeScript
  `config.x`, Terraform `random_password.db.result`, Python
  `os.environ["X"]`, Rust `Option<String>`) and the Go
  `cfg.RedisPassword` struct-field shape all produce no finding, across all
  five public surfaces, since they all share this Rust core detector.
- Negative regression fixtures cover Python, TypeScript, Rust, Go, and
  Terraform shapes in `conformance/fixtures/synchronous-corpus.json`;
  paired positive fixtures assert the SCREAMING_CASE dotted chain and the
  plain underscored value both stay detected.
- Known residual false-negative risk, accepted rather than fixed here: a real
  unquoted passphrase built from `lower_snake_case`-shaped words that happens
  to include an underscore and two or more dots (e.g. `my_pass.word_1.two`)
  would now also be excluded. This is judged rare relative to the breadth of
  source-code member-access syntax it lets through clean, and is the same
  order of risk the issue itself flagged as the central tradeoff of any fix
  here.
