# Representative lexical host-context classes

Issue [#110](https://github.com/redact-secret/redact-secret/issues/110)
(tracking-key `dacd-f3-t1`, under Epic [#98](https://github.com/redact-secret/redact-secret/issues/98))
asks for `CanonicalHostContext` (`conformance/schema.ts`) to be grouped into
explicit lexical classes with a justified representative set, rather than
treating each of the 22 declared contexts as an independent axis a detector
must be separately re-proven against.

This document is the authoritative classification.
[`evidence-requirements.md`](./evidence-requirements.md) §3 already relied on
an informal version of it to avoid a 22-types-by-22-contexts Cartesian
product; this document replaces that informal table as the source of truth
and adds the justification, the completeness check, and the gap ledger the
informal version did not carry.

It does not itself add fixtures or change a generator or CI gate — encoding
representative-context fixtures for the rows this document identifies as
gaps is issue [#111](https://github.com/redact-secret/redact-secret/issues/111).

## 1. The five classes

A host context is grouped by how it lexically delimits and surrounds a
value — not by file extension or ecosystem — so that two contexts with the
same delimiting behavior (a bare `KEY=value` line, whether it appears in a
`.env` file or a shell export) are not treated as independent evidence.

| Class | Contexts | What lexically defines the class |
|---|---|---|
| **structured-data-kv** | `dotenv`, `json`, `yaml`, `toml` | A value sits as the right-hand side of a key/value or key/mapping pair, closed by a fixed terminator (a quote, a newline, a comma, or block indentation) rather than by surrounding prose. |
| **shell-invocation** | `shell`, `powershell`, `docker-compose`, `github-actions`, `terraform`, `kubernetes` | A value sits inside a command line or a manifest field that is itself parsed as a command line (a compose/actions/kubernetes `command:`/`run:` string, a Terraform provisioner block) — word-splitting and shell quoting/escaping govern the boundary even when the outer document is YAML or HCL. |
| **source-code** | `javascript`, `typescript`, `python` | A value sits inside a string-literal grammar with language-defined quoting, escaping, and comment syntax, as an operand of an assignment or call expression. |
| **wire-and-log** | `http`, `curl`, `log`, `terminal`, `stack-trace` | A value sits in a line-oriented, non-nesting transcript of a request, a command's output, or a runtime event — bounded by whitespace, a header colon, or a line break, never by matching delimiters. |
| **prose-and-markup** | `chat`, `markdown`, `xml`, `plain-text` | A value sits inside natural-language prose or a markup document, where the surrounding text is not itself a grammar the detector's own value-boundary logic needs to parse. |

This partitions all 22 declared `CanonicalHostContext` values exactly once
(4 + 6 + 3 + 5 + 4 = 22); §5 reconciles this against
`conformance/schema.ts`'s `CONTEXTS` list and the fixtures that actually use
each value.

## 2. Lexical feature matrix

The issue requires the classes to account for quoting, escaping, comments,
assignment separators, headers, URLs, prose, and structured-data boundaries.
Each is a distinct way a class's members can bound or obscure a value; `✓`
means the feature is a defining part of at least one member's grammar, `—`
means no member of the class has it and the cell is explicitly
non-applicable (not merely undiscussed):

| Feature | structured-data-kv | shell-invocation | source-code | wire-and-log | prose-and-markup |
|---|---|---|---|---|---|
| Quoting | ✓ (`json` mandates it; `yaml`/`toml`/`dotenv` allow it) | ✓ (single/double quotes in `shell`/`powershell`, quoted scalars in the YAML-based members) | ✓ (string/template literals) | ✓ (`curl`'s shell-quoted arguments and header values) | ✓ (markdown code spans/fences; xml attribute quoting) |
| Escaping | ✓ (`json`/`toml` backslash escapes, `yaml` double-quoted-scalar escapes) | ✓ (`shell` backslash, `powershell` backtick) | ✓ (string-literal backslash escapes) | — (no member defines an escape syntax; a header or log value is taken verbatim to end-of-line) | ✓ (markdown backslash escapes, xml entity escapes) |
| Comments | ✓ for `dotenv`/`yaml`/`toml` `#`; **not applicable for `json`**, which has no comment syntax | ✓ (`#` in `shell`/`powershell` and the YAML-based members) | ✓ (`//`, `/* */`, `#`) | — (no member has a comment syntax; every line is data) | ✓ for `xml` (`<!-- -->`); **not applicable for `chat`/`markdown`/`plain-text`** |
| Assignment separators | ✓ (defining feature: `=` or `:`) | ✓ (`VAR=value`, `$env:VAR=value`, YAML `key: value`) | ✓ (`=`, typed `:`) | — (no member assigns; `http`/`curl` query strings use `=` incidentally inside a URL, not as the context's own boundary) | — (prose has no assignment grammar) |
| Headers | — (a `yaml`/`toml` `key:` pair is an assignment separator, not an HTTP-style header) | — | — | ✓ (defining feature for `http`; `curl`'s `-H "Name: value"`) | — (a markdown ATX heading is prose sectioning, not a field header) |
| URLs | — (may appear as an opaque value, not a structural feature of the class) | ✓ (image refs, provider sources, `kubectl apply -f <url>`) | ✓ (import specifiers, fetch/request targets in string literals) | ✓ (defining feature: request line / endpoint) | ✓ (defining feature for `chat`/`markdown` links) |
| Prose | — | — | — | ✓ (`log`/`terminal`/`stack-trace` are free-form text with an embedded value, not a fixed grammar) | ✓ (defining feature for `chat`/`plain-text`) |
| Structured-data boundaries | ✓ (defining feature: `{}`/`[]` in `json`, indentation blocks in `yaml`, tables in `toml`) | ✓ for the YAML-based members (`docker-compose`, `github-actions`, `terraform`, `kubernetes`); **not applicable for bare `shell`/`powershell`**, which are unstructured command lines | ✓ (object/array literals) | — (line-oriented; no nesting) | ✓ for `xml` (tag nesting); **not applicable for `chat`/`markdown`/`plain-text`** |

Every one of the eight required features is a defining (`✓`) feature of at
least one class, and every `—` cell states why the feature does not apply
rather than leaving it silent.

## 3. Representative sets

A member of a class is a *representative* when its lexical grammar is the
most demanding one in the class for value-boundary detection — the member
whose delimiting is closest to none at all, since that is where a
contextual, entropy-driven, or boundary heuristic is most likely to over- or
under-match. Requiring positive evidence in the representative context
stands in for the whole class (`evidence-requirements.md` §3's
class-level `○` requirement); the other members default to a single
`plain-text` fixture and inherit the rest, unless a type's own grammar
interacts with a specific non-representative member differently enough to
justify additional *targeted* evidence (as `connection_string_password`
already does for `log`, below).

| Class | Representative(s) | Why |
|---|---|---|
| structured-data-kv | `dotenv` | The only member with **no** enclosing delimiter at all: a bare `KEY=value` line terminated solely by a newline. `json`/`yaml`/`toml` all supply a stronger terminator (a closing quote, a comma, block indentation), which is a strictly easier boundary case once `dotenv` is handled. |
| shell-invocation | `shell` | Quoting and escaping are maximally ambiguous in POSIX shell (unquoted word-splitting, nested quote types, backslash interaction), and every YAML-based member of this class (`docker-compose`, `github-actions`, `terraform`, `kubernetes`) ultimately embeds a shell fragment inside a `run:`/`command:`/provisioner string, so shell-correctness is a prerequisite for the rest. `powershell` is a variant with its own escaping and does not need independent class-level evidence. |
| source-code | `javascript` | The widest quoting surface of the three (single, double, and template-literal backtick strings) plus `${...}` interpolation, a boundary hazard `typescript` shares syntactically and `python` does not have. |
| wire-and-log | `http` **and** `log` | This class is not lexically uniform enough for one member to stand in for it: `http` (and `curl`, which shares its shape) is the only subgroup with a fixed header/URL grammar, while `log`/`terminal`/`stack-trace` are unstructured prose with no anchor at all — arguably the harder case for a heuristic detector, since there is no delimiter to key off of. Both are named as representatives rather than picking one and treating the other as inherited. |
| prose-and-markup | `markdown` **and** `xml` | `markdown` covers the class's prose, escaping, and URL features in one member (`chat`/`plain-text` are its unstructured subset). `xml` is named separately because it alone in this class has nesting structured-data boundaries (tag pairs); `markdown` evidence does not stand in for that feature. |

## 4. Gaps and explicit non-applicability

- **`host-context` is not a requirement at all for the `incremental` and
  `binding-edge` behavior classes** (`conformance/schema.ts`'s
  `COVERAGE_REQUIREMENT_MATRIX`, both rows `not-applicable`). The
  classification in this document only governs the `provider`, `structural`,
  and `contextual` behavior classes; a lifecycle or binding-consumer row has
  no lexical-host-context cell to resolve, by construction, not by omission.
- **`contextual_secret` (`generic-token`)'s host-context breadth gap is
  closed by issue [#111](https://github.com/redact-secret/redact-secret/issues/111).**
  This section previously found the gap sharper than
  `evidence-requirements.md` §6 stated — `javascript`'s only `generic-token`
  fixture (`negative-source-map`, §5) is a near-miss negative, not a positive
  `contextual_secret` fixture, so the type's own positive evidence was
  `plain-text` only (zero of the five representative classes, not two).
  #111 adds one genuine positive `contextual_secret` fixture per remaining
  class — `contextual-host-dotenv` (`structured-data-kv`),
  `contextual-host-shell` (`shell-invocation`),
  `contextual-host-javascript` (`source-code`, distinct from
  `negative-source-map`'s near-miss), `contextual-host-http` and
  `contextual-host-log` (`wire-and-log`), and `contextual-host-chat`
  (`prose-and-markup`, beyond the existing `plain-text` fixtures) — plus two
  near-miss negatives, `contextual-negative-shell-placeholder` and
  `contextual-negative-json-env-reference`, showing the existing exclusion
  rules (a placeholder word, a `${...}` reference) hold across host syntax.
  `docs/coverage/coverage-declarations.json`'s `contextual_secret`
  `host-context` dimension now resolves `supported` at the type level.
- **The structural class's host-context breadth gap is closed by issue
  [#186](https://github.com/redact-secret/redact-secret/issues/186).**
  `connection_string_password` is the single class-level representative: its
  positive fixtures now cover `dotenv`, `shell`, `javascript`, `log`, and
  `markdown`, one context in each of the five lexical classes. The generated
  declarations resolve its `host-context` cell directly and resolve
  `private_key`, `jwt`, `bearer_token`, and `otpauth_secret` through the
  bounded `owned-elsewhere` exception. No duplicate context matrix is required
  for those four types.
- **`authorization_credential` (`generic-token`)'s host-context breadth gap is
  closed by issue [#190](https://github.com/redact-secret/redact-secret/issues/190).**
  Its own positive fixtures cover `dotenv`, `shell`, `javascript`, `log`, and
  `markdown`, one context in each of the five lexical classes. The generated
  declaration resolves `authorization_credential.host-context` directly at
  the type level; it does not borrow `contextual_secret` evidence.
- **Provider and structural breadth each has one class-level owner.** Most
  other members still carry only a `plain-text` fixture, and that is correct,
  not a gap: §3 requires representative evidence somewhere in the class, not
  on every member row. `github_token` supplies the provider evidence and
  `connection_string_password` supplies the structural evidence; the generated
  declarations point the remaining rows to the applicable owner.

## 5. Reconciliation against the current corpus

Every declared `CanonicalHostContext` value is exercised by at least one
fixture in `conformance/fixtures/synchronous-corpus.json` today; none is
orphaned from this classification, and this table is exhaustive over
`schema.ts`'s `CONTEXTS` array (22 of 22):

| Class | Context | Fixtures using it (fixture id) | Notes |
|---|---|---|---|
| structured-data-kv | `dotenv` | `host-dotenv-github`; `compound-repeated-crlf-aws` (`aws_access_key_id`); `contextual-host-dotenv` (`contextual_secret`); `connection-host-dotenv` (`connection_string_password`); `authorization-host-dotenv` (`authorization_credential`) | representative (§3) |
| structured-data-kv | `json` | `host-json-github`; `contextual-negative-json-env-reference` (near-miss negative, `generic-token`) | |
| structured-data-kv | `yaml` | `host-yaml-github` | |
| structured-data-kv | `toml` | `host-toml-github` | |
| shell-invocation | `shell` | `host-shell-github`; `host-shell-heredoc-github`; `contextual-host-shell` (`contextual_secret`); `contextual-negative-shell-placeholder` (near-miss negative, `generic-token`); `connection-host-shell` (`connection_string_password`); `authorization-host-shell` (`authorization_credential`) | representative (§3) |
| shell-invocation | `powershell` | `host-powershell-github` | |
| shell-invocation | `docker-compose` | `host-docker-compose-github` | |
| shell-invocation | `github-actions` | `host-github-actions-github` | |
| shell-invocation | `terraform` | `host-terraform-github` | |
| shell-invocation | `kubernetes` | `host-kubernetes-github` | |
| source-code | `javascript` | `host-javascript-github`; `negative-source-map` (near-miss negative, `generic-token`); `contextual-host-javascript` (`contextual_secret`'s own positive); `connection-host-javascript` (`connection_string_password`); `authorization-host-javascript` (`authorization_credential`) | representative (§3) |
| source-code | `typescript` | `host-typescript-github` | |
| source-code | `python` | `host-python-github` | |
| wire-and-log | `http` | `host-http-github`; `contextual-host-http` (`contextual_secret`) | representative (§3) |
| wire-and-log | `curl` | `host-curl-github`; `mutation-github-09-host-embedding` | |
| wire-and-log | `log` | `host-log-github`; `adversarial-dense-aws-findings` (`aws_access_key_id`); `regression-malformed-percent-authority` and `connection-host-log` (`connection_string_password`); `contextual-host-log` (`contextual_secret`); `authorization-host-log` (`authorization_credential`) | representative (§3) |
| wire-and-log | `terminal` | `host-terminal-github` | |
| wire-and-log | `stack-trace` | `host-stack-trace-github` | |
| prose-and-markup | `chat` | `host-chat-github`; `contextual-host-chat` (`contextual_secret`) | |
| prose-and-markup | `markdown` | `host-markdown-github`; `connection-host-markdown` (`connection_string_password`); `authorization-host-markdown` (`authorization_credential`) | representative (§3) |
| prose-and-markup | `xml` | `host-xml-github` | representative (§3) |
| prose-and-markup | `plain-text` | every type not listed above (354 of 399 fixtures) | default fixture (§3) |

`negative-source-map` remains a near-miss negative, not a positive
`contextual_secret` fixture — it evidences that `generic-token` does not
over-match a source-map comment in that context. `contextual_secret` now
also has its own genuine `source-code` positive fixture,
`contextual-host-javascript`, added alongside the other four representative
classes by issue #111 (§4); its earlier `plain-text`-only positive fixtures
(`contextual-positive-assignment`, `contextual-positive-escaped-quote`,
`contextual-positive-aws-secret-access-key`,
`contextual-positive-aws-session-token`) are unchanged.

Reconciled by hand against `conformance/fixtures/synchronous-corpus.json`
(399 fixtures) on 2026-09-12, after issue #190's fixtures landed; re-run this
reconciliation whenever a fixture's
`contexts` array changes. `npx vitest run conformance/schema.test.ts`
confirms every context value used above is a member of `schema.ts`'s closed
`CanonicalHostContext` union and `CONTEXTS` list — an unclassified or
misspelled context fails fixture validation before it could reach this
table.

## 6. Relationship to `evidence-requirements.md`

`evidence-requirements.md` §3 keeps a short pointer to this document instead
of its own copy of the class table, so the two cannot drift independently.
Everything else in that document — the behavior classes, the evidence
dimensions, the requirement matrix, and the exception codes — is unchanged
by this issue.
