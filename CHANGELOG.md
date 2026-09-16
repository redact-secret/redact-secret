# Changelog

This file records the released product contract and notable changes. Release
evidence is linked from each published version.

## Unreleased

- The `generic-token` detector no longer reports a value fully delimited by
  an interpolation or command-substitution syntax as a secret: a
  shell/`Makefile`/Kustomize `$(...)` variable or command substitution
  (`$(registryPassword)`, `$(pass show db/prod)`), an Azure Pipelines
  `$[...]` runtime expression (`$[variables.x]`), a Ruby `#{...}` string
  interpolation (`#{ENV['DB_PASSWORD']}`), an opencode `{env:...}`/
  `{file:...}` substitution (`{env:ANTHROPIC_API_KEY}`), or a
  backtick-quoted command substitution / JS template literal
  (`` `${process.env.X}` ``). This is the same class of non-secret reference
  as the existing `${...}`/`{{...}}` exclusions, and previously the default
  policy's `redact` action would rewrite the literal reference in a pipeline
  definition, shell script, or tool config. A value that only starts with
  one of these delimiters, or that has a delimited pair embedded inside a
  larger value, is unaffected and continues to be reported.
- The `generic-token` detector no longer reports an unquoted value that is a
  source-code expression as a secret: a known reference root
  (`settings.DATABASE_PASSWORD`, `config.anthropicApiKey`, `self.foo`,
  `this.bar`), a Terraform-shaped `var`/`local`/`data`/resource attribute
  chain (`random_password.db.result`,
  `data.aws_secretsmanager_secret_version.db.secret_string`), generic-type or
  subscript syntax (`Option<String>`, `Optional[str`), or a call/subscript
  expression truncated at its string-literal argument
  (`os.environ["OPENAI_API_KEY"]`, previously captured only as
  `os.environ[`). Such a value names *where* a secret lives at runtime, not
  the secret itself, and the default policy's `redact` action previously
  rewrote it as if it were a literal credential. A dotted value with no
  known root and no `lower_snake_case` segment (`SYNTHETIC.REVOKED.CONTEXT_VALUE`)
  continues to be reported.
- A `generic-token` contextual assignment's value can no longer cross a line
  terminator. Previously, a key with no value before end-of-line (a YAML
  `secret:` block opening a nested mapping, an interactive `Password:`
  prompt) could consume the next line's key name as if it were the value,
  which both produced false positives on unrelated nested keys and — the
  more serious direction — advanced the scan past that nested key's own
  boundary, so a real credential nested directly under a parent key
  (`database:\n  password: <value>`) was silently missed. Whole-input and
  incremental scanning (single chunk or split at any boundary) now agree on
  every such shape.
- The `generic-token` detector no longer reports a value made of the same
  character repeated three or more times (`********`, `••••••••`) as a
  secret — classic redaction-style filler that masked CLI prompts, config
  dumps, and `env` listings echo back in place of a real password. The
  `connection-string` detector already excluded this shape; both detectors
  now share one implementation. A value with even one differing character
  (`********x`) continues to be reported.
- The `generic-token` detector no longer reports a value fully delimited by
  `{{` and `}}` (`{{ vault_db_password }}`, `{{ .Values.postgresql.auth.password }}`,
  `{{ .ClientSecretRef }}`) as a secret, quoted or unquoted. This is the
  idiomatic reference syntax Ansible, Helm, Salt, and Go templates use to
  point at a vaulted or injected value, and previously the default policy's
  `redact` action would rewrite the literal template placeholder, corrupting
  the playbook or chart it appeared in. A value that only starts with `{{`,
  or that has a `{{...}}` pair embedded inside a larger value, is unaffected
  and continues to be reported.
- The `generic-token` and `connection-string` detectors' placeholder-word
  exclusion (`changeme`, `redacted`, `example`, and similar hardcoded
  non-secret values) now matches on token boundaries instead of whole-value
  exact-string equality. A leading/trailing separator (`" changeme"`), a
  digit appended to a distinctive placeholder word (`changeme2`), and two
  already-excluded words joined with `-`/`_` (`REDACTED-EXAMPLE`) are now
  excluded like the literal word already was; a real secret that merely
  contains a placeholder word as a substring, or alongside unrelated tokens,
  continues to be reported.
- AWS's own documented example credentials — the access key ID
  `AKIAIOSFODNN7EXAMPLE` and its paired secret access key
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — are no longer reported as
  findings. An exact-literal carve-out in the detector pipeline drops a
  candidate whose full matched text equals one of these two vendor-published
  placeholder values, regardless of which detector proposed it; no other
  detection behavior changes.
- The `generic-token` detector no longer reads a YAML flow mapping's or flow
  sequence's opening `{`/`[` as the start of an unquoted scalar. Previously,
  a credential-like key followed by inline flow syntax (`secret: {secretName:
  web-tls-cert}`) captured the nested key as if it were the value. An
  unquoted value beginning with either character is now treated as no value
  at all; a value on the same line in ordinary block style (`secret:
  <value>`) is unaffected and continues to be reported.
- The `generic-token` detector no longer reports a secret-manager reference
  string as a secret: a 1Password `op://<vault>/<item>/<field>` reference, a
  LiteLLM `os.environ/<VAR_NAME>` reference, a GCP Secret Manager resource
  name (`projects/<id>/secrets/<name>(/versions/<v>)?`), a `vals`
  `ref+<backend>://<path>#<key>` reference, a bank-vaults/Vault Agent
  injector `vault:<path>#<key>` reference, an AWS Secrets Manager ARN, or an
  Azure App Service `@Microsoft.KeyVault(...)` reference. Each of these
  names where a secret lives at runtime rather than containing one, and
  previously the default policy's `redact` action would rewrite the literal
  reference in place, corrupting the env file, config, or manifest it
  appeared in. A value with a matching scheme prefix that does not satisfy
  that scheme's full grammar (wrong segment count, an invalid identifier, a
  missing delimiter, a non-12-digit account id, and similar) is unaffected
  and continues to be reported.

## 0.1.0-beta.2 — 2026-09-13

- JavaScript and Python incremental sanitizers now treat host-side invalid
  append input as terminal: retained plaintext and offset state are discarded,
  the session reports `failed`, and later operations raise `INVALID_STATE`.
- Artifact qualification inventories now carry release-readiness pointers for
  the public API/changelog review and the post-publication registry-install
  verification boundary, keeping issue #203 evidence tied to one source
  revision without granting release authority.
- Executable browser and server integration examples now demonstrate
  preventive client scanning, authoritative block and warning enforcement,
  fail-closed downstream handling, and explicit transport, input, output,
  finding-count, and concurrency limits. Candidate qualification runs them
  against clean installs of the packed Node and browser WebAssembly artifacts.
- Fixed performance and resource thresholds, derived from the first complete
  cross-surface baseline, can now evaluate five-repetition RC evidence for the
  qualified macOS arm64 environment without treating unavailable or overlapping
  host memory metrics as zero.
- A complete assessment command and manually triggered CI workflow now evaluate
  Rust, installed Python, Node, browser WebAssembly, and CLI artifacts against
  shared whole-input and incremental profiles, fail closed on missing or
  inconsistent results, and preserve raw samples plus consolidated JSON and
  Markdown baseline evidence with explicit measurement limitations.
- Assessment tooling now includes a CLI binary runner, self-test command, and
  first checked-in correctness/performance baseline with explicit process
  startup, process-inclusive processing, and whole-process RSS measurements.
- The fixed, separate beta.2 detection assessment now records source-, corpus-,
  runtime-, and artifact-bound Node and browser results with explicit
  denominators, safe mismatch details, and linked limitation dispositions;
  conformance coverage is not presented as accuracy.
- Assessment tooling now evaluates an installed Python package through both
  whole-input and incremental APIs, normalizes code-point ranges to canonical
  UTF-8 byte spans, and records the first correctness, timing, Python-allocation,
  and whole-process RSS baseline with explicit sampling limits.
- Assessment tooling now includes a Rust library runner, self-test command,
  and first checked-in correctness/performance baseline for the `rust-core`
  surface.
- Node.js and browser packages now expose working bounded incremental
  sanitization plus Node `Transform` and Web `TransformStream` adapters.
  Candidate qualification installs packed packages outside the checkout,
  exercises those public APIs on Node.js 20, 22, and 24 and in Chromium,
  Firefox, and WebKit, and records revision- and digest-bound results.

## 0.1.0-beta.1 — 2026-09-11

[Publication evidence](docs/releases/0.1.0-beta.1/README.md).

### Product and packages

- Redact Secret provides deterministic secret detection and redaction through
  one side-effect-free Rust core, shared by JavaScript, Python, Rust, and CLI
  consumers. The canonical `conformance/` corpus defines cross-language behavior.
- The first release artifact set comprises the `redact-secret` Rust library,
  `redact-secret-cli` crate and `redact-secret` binary, the `redact-secret` PyPI
  distribution (import `redact_secret`), and the `@redact-secret/core` npm
  package with `@redact-secret/wasm` and six `@redact-secret/node-<platform>`
  runtime dependencies. All share one version and source revision.
- The TypeScript detector implementation has been removed. JavaScript exposes
  policy and placeholder formatter callbacks over safe metadata; it does not
  restore the retired custom-detector API. Rust retains its native detector
  traits and registry; custom detector callbacks do not cross language bindings.

### Public behavior and support

- Whole-input scan, redaction, and combined operations return finding metadata
  without matched values. Ranges refer to the original input: UTF-8 bytes in
  Rust and CLI, UTF-16 code units in JavaScript, Unicode code points in Python.
- Default policy blocks private keys, redacts known credential structures and
  other high-confidence findings, and warns on other findings. Redaction
  replaces `redact` and `block` spans; `warn` and `allow` preserve text. Hosts
  enforce `block`. Caller-supplied overlapping redaction ranges are rejected.
- Built-in coverage includes private keys, provider token families,
  authorization/JWT credentials, contextual assignments, credential-bearing
  connection URLs, and OTP shared-secret URIs. See the
  [detection reference](docs/reference/detection.md) for supported formats and
  precision/recall limits. Entropy alone is not a detection signal sufficient
  to classify arbitrary text.
- Rust, Python, and CLI standard input support bounded incremental sanitization.
  JavaScript session and stream factories fail with `INCREMENTAL_UNAVAILABLE`
  on both current artifacts; exported adapter contracts do not imply support.
- JavaScript is ESM with explicit `await initialize()`. Node.js 20, 22, and 24
  support glibc Linux, macOS, and Windows on x64 and arm64. npm and CLI ship six
  non-musl targets. The two additional musl addons are qualified only, with no
  npm publication path. Browsers require ES2022 and WebAssembly; qualification
  covers Chromium, Firefox, and WebKit.
- Python provides typed CPython 3.10+ abi3 wheels for eight targets: manylinux,
  musllinux, macOS, and Windows on x64 and arm64. Source builds require Rust;
  the workspace MSRV is 1.88. See the [qualification matrix](docs/qualification.md).
- CLI check mode reports safe metadata with exit codes 0 (clean), 1 (findings),
  and 2 (failure); redaction returns 0 or 2. Text source labels escape control
  characters and backslashes, and JSON preserves source identity.

### Security and release evidence

- The core has no runtime I/O, environment lookup, telemetry, or secret storage.
  Errors use fixed, input-free codes and messages; callback errors and unsafe
  placeholders fail closed. Client scanning is preventive UX; server scanning
  is authoritative. Hosts must bound whole-input resources and Python chunks.
- Version lockstep includes the private root manifest, every Cargo member,
  JavaScript facade, and all native/Wasm manifests. The legacy-identifier gate
  rejects unintended old identities, including in this changelog.
- The pinned OpenGrep engine and vendored rules are verified against the reviewed
  baseline. The CI gate fails on unresolved findings or unacknowledged scan
  errors independently of best-effort SARIF upload. A baseline pass is not a
  claim of zero findings or complete parser coverage.
- Qualification, package-content checks, and clean packed-package consumer
  tests precede publication. The release graph verifies all seven npm runtime
  dependencies before publishing the facade and records durable manifests for
  successful and failed runs. Reconciliation requires separate authorization.
- This first beta consolidates the unpublished development history; the former
  dated entry was not a published release. All packages were published from
  the original qualified RC source; recovery verified existing content before
  skipping it, and all seven registry-install lanes passed.
