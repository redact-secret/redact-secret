---
decision_id: decision-adopt-rust-core-monorepo
status: accepted
scope: workspace
title: Adopt a Rust-core monorepo
decided_at: 2026-09-09
spec: engine
---

# Adopt a Rust-core monorepo

## Decision

Restructure `omiologic/secret-scan` as one multi-language repository whose
canonical implementation is a Rust core. The core owns built-in detection,
candidate normalization and overlap resolution, default policy, redaction, and
incremental sanitization. Language packages translate their host APIs to that
core instead of reimplementing detector behavior.

The core may use Rust's standard library but must remain deterministic and
side-effect free: it performs no runtime network access, filesystem access,
environment lookup, telemetry, or secret storage.

The first stable product supports JavaScript, Python, and Rust. A CLI built on
the same core is included after library and binding parity is established. Go
support follows through a Rust FFI binding; a separate pure-Go detector
implementation is not planned.

## Rationale

Secret-detector drift fails silently. Keeping the core, bindings, and
conformance evidence in one change and one CI graph makes behavioral divergence
observable before merge. Rust provides a suitable portable implementation for
native libraries, WebAssembly, Python extensions, and a standalone CLI without
making performance the sole reason for the migration.

## Alternatives considered

- Independent TypeScript, Python, Go, and Rust implementations were rejected
  because a shared fixture corpus cannot make their source changes atomic.
- Keeping TypeScript in browsers and Rust on servers was rejected because it
  retains two authoritative detector implementations.
- Starting with `no_std` was rejected because it adds constraints without a
  current embedded-runtime requirement. It may be reconsidered by a later ADR.

## Consequences

- Rust becomes a required development and release toolchain.
- Binding-specific adapters remain responsible for host runtime integration.
- Go support is outside the first stable release and creates no stable C ABI
  commitment until a follow-up decision defines it.
