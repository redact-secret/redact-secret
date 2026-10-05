---
decision_id: decision-add-a-send-sync-built-in-only-registry-as-a-distinct-type
status: accepted
scope: workspace
title: Add a Send + Sync built-in-only registry as a distinct type
decided_at: 2026-10-05
spec: engine
---

# Add a Send + Sync built-in-only registry as a distinct type

## Context

[#1178](https://github.com/redact-secret/redact-secret/issues/1178) asks for a
thread-shareable handle. `DetectorRegistry` is `!Send + !Sync` only because the
`Detector` trait has no `Send + Sync` supertrait and a registry may hold a
custom `Detector`; a registry of only built-in detectors holds nothing that is
not thread-safe. The gateway core-bridge probe measured the cost of the
workaround: one registry per worker thread, about 15 µs each, so this is an
ergonomics request and not a blocker
([probe](https://github.com/redact-secret/gateway/blob/main/docs/probes/core-bridge-probe.md)).

[#1097](https://github.com/redact-secret/redact-secret/issues/1097) chose to
document registry reuse and named a multi-threaded handle need as one reopen
trigger; this is that need, scoped to one type and not a `Sanitizer` builder.
[#1066](https://github.com/redact-secret/redact-secret/issues/1066) froze the
public contract with `Detector` a stable, trusted extension point. Under
[`decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes`](2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md)
a new name is additive and ships in a patch release, while a new supertrait
bound on `Detector` makes every existing `impl Detector` that holds an `Rc` or
a `RefCell` stop compiling, which is breaking.

## Decision

1. **A distinct type, `BuiltInRegistry`.** It is `Send + Sync`, built only by
   `with_built_in`, `with_common_built_in`, `with_built_in_and_pii` and
   `with_common_built_in_and_pii`, and has no `register`, no custom-detector
   parameter and no ruleset parameter. It is immutable after construction.
2. **Same semantics, one pipeline.** For the same profile and PII selection its
   `scan`, `scan_with_limits`, `scan_and_redact` and
   `scan_and_redact_with_limits` methods return exactly what the
   `DetectorRegistry` functions return: findings, ids, order, ranges, output
   bytes and error codes. The constructors call the existing profile
   constructors with no custom detector and move their detectors into the
   shareable value, so validation, registration order, the profile reachability
   rule (a `common` call never reaches the `full` constructor), the activation
   identity and the cached prefilter are the existing ones, not copies. The
   pipeline is generic over a crate-private `DetectorSet` trait that both
   registries implement.
3. **`Detector` and `DetectorRegistry` are unchanged.** No supertrait is added.
   `DetectorRegistry` stays `!Send + !Sync`, pinned by `compile_fail` doctests;
   `BuiltInRegistry` is pinned `Send + Sync` by a `const` assertion in the crate
   and by tests that share one handle across threads.
4. **Safe-Rust only.** The PII adapter is the one owned detector the crate
   itself constructs, so it and its private family trait gain `Send + Sync`
   (every family is a stateless unit type). Built-ins are already
   `&'static (dyn Detector + Sync)`. The prefilter is a process-wide
   `OnceLock` that is compiled once and then only read. No `unsafe`, no new
   dependency.
5. **No new policy or formatter bound.** A `Policy` or `PlaceholderFormatter`
   is a per-call argument used on the calling thread.
6. **`IncrementalSanitizer` does not accept it.** A session owns its registry
   and its single-threaded state, and building that registry is the one
   per-session cost #1097 measured. Accepting a shared handle would be a second
   constructor family on a stateful type; it is additive and can follow if
   session start cost is shown to matter.

## Trade-offs

A distinct type adds one public name and four constructors, and a caller who
needs custom detectors or a ruleset still builds a `DetectorRegistry` per
thread. In return nothing existing changes and no unsafe code or `Arc`-wrapping
inside the core is needed. Entry points are methods on the new type and not a
generic bound on the existing functions, so existing call sites, function
pointers and turbofish uses keep compiling.

Rejected alternatives:

- Add `Send + Sync` to `Detector`. Breaking under the 0.1.x contract and
  forbidden by the request.
- An opt-in `SendSyncDetector` bound and a generic `DetectorRegistry<D>`.
  It changes a stable type's signature and its inference at every use, and
  doubles the registration API for a case the built-in-only handle covers.
- `unsafe impl Sync for DetectorRegistry`. The crate forbids `unsafe`, and it
  would be unsound for a custom detector.
- A `Sanitizer` or compiled-configuration value. #1097 deferred it; a registry
  handle meets the stated need with no policy, formatter or limits to own.
- Make the existing `scan*` functions generic over a registry trait. A source
  change to a frozen signature for no gain over methods.

## Consequences

The public root surface grows from 54 to 55 names and
`core-public-api`, `tests/public_api.rs` and the README table carry the new one.
The gateway can build one `BuiltInRegistry` at startup and share it in an `Arc`
instead of one registry per worker; results are identical, so no detection,
policy or conformance row changes. Python, JavaScript and the CLI are
unaffected. `docs/audits/evidence/1066` and the stable-contract record keep
their historical count of 54.
