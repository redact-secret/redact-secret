---
decision_id: decision-graduate-adapters-to-a-separate-repository
status: accepted
scope: workspace
title: Graduate logging and tracing adapters to a separate repository
decided_at: 2026-09-19
---
# Graduate logging and tracing adapters to a separate repository

## Decision

Publish pino, Python `logging`, and OpenTelemetry `SpanProcessor` host
integrations as versioned packages in a **separate repository**,
[`redact-secret/redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters),
rather than inside this repository. MCP and LangChain do not graduate; both
stay application use cases with no dedicated package (see "What does not
graduate" below).

This repository's release matrix, `registry-preflight:check` list, artifact
matrix, and qualification lanes are unchanged by this decision. Nothing here
ships a new package, adds a runtime dependency to `@redact-secret/core` or
`redact-secret`, or changes `[workspace.metadata.redact-secret] core-public-api`.

### Why a separate repository, not option 2

Issue #442 originally posed this as three in-repository options: keep
examples only, graduate a narrow set (pino, Python `logging`, OTel), or
graduate broadly (adding LangChain and MCP). All three assumed graduation, if
it happened, happened inside this repository — and priced that as a
release-matrix cost: each published adapter adds a package to the artifact
matrix, a host-SDK version to track, its own changelog, and a per-host-major
compatibility statement.

That cost is really the **lockstep cost**
(`decision-release-bindings-in-lockstep`): this repository releases the Rust
crate, npm, PyPI, and the CLI as one SemVer version from one commit, one
qualification run, one tag. An adapter does not need to move on that cadence —
it moves when a host SDK (pino, OpenTelemetry) moves, on its own schedule. A
pino patch release inside this repository would re-qualify the Rust core for
no reason; a separate repository with independently versioned packages
removes that coupling entirely. A new pino release moves
`@redact-secret/adapter-pino` and nothing else.

This also dissolves two constraints option 2 would have had to work around
inside this repository: `bindings/python/pyproject.toml` declares
`dependencies = []` as a property of the distribution, and example Python
tests here run against the standard library only, with no
dependency-install path in CI. Adapters ship as their own PyPI distribution
in the other repository, which has its own dependency-install path, so
neither constraint has to move.

### What crosses the repository boundary, and why that is safe

The adapter code's entire dependency on this repository's core is four
items: `initialize()`, `scanAndRedact()` and its result shape, whether
`finding.action` is `block` or `warn`, and that `findings` is an array —
written in TypeScript against this repository's own exported types
(`SecretAction`, `SecretFinding`, `ScanResult`, `ScanAndRedactOptions`). A
change to that surface fails the adapters repository's build instead of
degrading silently, which is what makes a cross-repository split safe rather
than merely convenient. **This decision holds only while that four-item
surface holds** — widening it (for example, an adapter needing incremental
sanitizer state, or a second entry point) reopens this decision rather than
being absorbed silently.

No adapter imports its host at runtime: every host seam is structural
(duck-typed), host types are `import type` only and erased at compile time,
and host SDKs never enter the runtime dependency graph of `@redact-secret/core`
or `redact-secret`.

### What graduated, and its evidence gaps

| Package | Registry | Core range | Host range | State |
| --- | --- | --- | --- | --- |
| `@redact-secret/adapter` | npm | `^0.1.0-beta.4` (peer) | — | `0.1.0` |
| `@redact-secret/adapter-pino` | npm | `^0.1.0-beta.4` | `pino ^10.0.0` | `0.1.0` |
| `@redact-secret/adapter-otel` | npm | `^0.1.0-beta.4` | `@opentelemetry/sdk-trace-base ^2.0.0` | `0.1.0`, **`private: true`** |
| `redact-secret-adapters` | PyPI | `>=0.1.0b4,<0.2` | stdlib `logging`; `[otel]` extra | `0.1.0` |

Test evidence was not uniform before this decision: pino (`10.3.1`, a real
`devDependency` here) and Python `logging` (stdlib) had real-host tests in
this repository's `examples/`. The OTel `SpanProcessor` and the Langfuse
callback had none — no test imported their live wrappers against a real
host at all. `@redact-secret/adapter-otel` stays `private: true` until
`otel-host.test.ts` in the adapters repository runs against a real span and
confirms `ReadableSpan.attributes` is actually mutable at both ends of the
declared range; a frozen attributes object would make the adapter a silent
no-op rather than a working one. The PyPI package's `[otel]` extra is
deliberately left with an unbounded, TODO-marked range for the same reason —
there is no evidence for a range until that test runs. That gap is evidence
work remaining in the adapters repository, not a decision this repository
needs to revisit.

Starting every package at `0.1.0` is confirmed as reasonable rather than
overridden: a `1.0` adapter that can only work against a beta core (this
repository has not shipped `1.0.0`) would promise stability the project
cannot keep.

### What does not graduate

- **MCP stays out on evidence, not preference.** `examples/mcp-redact/` wraps
  the incremental sanitizer: stateful, with a materially wider surface than
  the four-item contract above, and not protected by any declared host
  version range. It remains an example; see its README for its stated
  support level and pinned SDK versions.
- **LangChain graduates nothing, because nothing was ever built.** No
  LangChain integration exists anywhere in this repository, in `examples/`
  or otherwise. Graduating it was never on the table for this decision —
  only the README's blanket "no dedicated packages" disclaimer named it.
- **Langfuse needs no package.** Its integration is
  `examples/tracing-masking`'s shared masking walker plus one line of host
  code (`new Langfuse({ mask: ({ data }) => maskSecrets(data) })`); there is
  no wiring subtle enough, and no host SDK installed in this workspace, to
  justify a maintained package. It remains an example with its support
  level stated in that directory's README.

### Corrections this decision requires regardless of the above

- `examples/logging-redaction/pino-hook.mjs`'s module docstring claims the
  hook is pinned against pino `9.x`, while the tested and `devDependency`-
  pinned version is `10.3.1` (matching `@redact-secret/adapter-pino`'s
  declared `pino ^10.0.0` range). Corrected as part of this change,
  independent of anything else in this decision.

## Rationale

The release-matrix cost in issue #442's original write-up is a lockstep-
coupling cost, not an inherent cost of publishing an adapter. Once the
adapter code's dependency on this repository is reduced to a small,
type-checked surface (four items, structurally duck-typed, no runtime host
import), the two repositories can each release on their own cadence without
either one silently drifting: a build failure in the adapters repository is
the enforcement mechanism that replaces "one commit, one qualification run"
lockstep. This captures graduation's adoption benefit (a consumer installs a
versioned, changelogged package instead of hand-copying a file) without
this repository's release matrix, qualification lanes, or registry-preflight
list absorbing a host-SDK's own version churn.

## Alternatives considered

- **Option 1 (keep examples only)** was rejected: it does not change the
  adoption cost the issue raised — "the integration every consumer needs is
  the one thing we make them hand-roll" — for the two adapters (pino, Python
  `logging`) that already had real-host test evidence.
- **Option 2 (graduate a narrow set inside this repository)** was rejected
  in favor of a separate repository once the lockstep cost was identified as
  the real driver of the release-matrix concern: publishing inside this
  repository would tie an unrelated host-SDK release to this repository's
  one-version, one-tag, one-qualification-run release process for no
  benefit.
- **Option 3 (graduate broadly, including LangChain and MCP)** was rejected
  on the same evidence as before: MCP's incremental-sanitizer surface is
  wider than the four-item contract and unprotected by a version range, and
  no LangChain integration exists to graduate.

## Consequences

- `README.md`'s "no dedicated integration packages" paragraph is replaced
  with a pointer to `redact-secret-adapters` and a statement of what remains
  example-only (MCP, LangChain).
- `ARCHITECTURE.md`'s binding/package table gains a row naming the adapters
  repository, and records that MCP is excluded for the incremental-sanitizer
  reason above.
- `decision-adopt-redact-secret-naming-contract` gains a row for
  `@redact-secret/adapter*` / `redact-secret-adapters`, and a sentence
  disambiguating three current meanings of "adapter" in this project: stream
  adapters (`packages/javascript/src/adapters/`, inside
  `@redact-secret/core`), host adapters (the CLI and language bindings, per
  `README.md` and `ARCHITECTURE.md`'s "Command-line host behavior" section),
  and these host-integration packages.
- `examples/mcp-redact/README.md` and `examples/tracing-masking/README.md`'s
  Langfuse section each state their support level (example-only, no package,
  breakage is the integrator's own to fix) and pinned host SDK versions
  explicitly.
- `examples/logging-redaction/pino-hook.mjs`'s stale pino `9.x` docstring
  claim is corrected to match the tested `10.x` range.
- This decision does not select a version, create a release branch or tag,
  publish to any registry, or dispatch a release workflow in *this*
  repository. It records that the adapters repository already published
  `0.1.0` of each listed package under its own release authority; this
  repository's "Release authority" (`AGENTS.md`) is unchanged and does not
  extend to that repository.
- This decision holds only while the core-dependency surface named above
  (`initialize()`, `scanAndRedact()`'s result shape, `finding.action`,
  `findings` as an array) stays exactly that size. A change widening it is a
  reason to revisit this decision, not to absorb silently in either
  repository.
