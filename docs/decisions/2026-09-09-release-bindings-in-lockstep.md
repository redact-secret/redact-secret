---
decision_id: decision-release-bindings-in-lockstep
status: accepted
scope: workspace
title: Release bindings in lockstep
decided_at: 2026-09-09
spec: distribution
---
# Release bindings in lockstep

## Decision

Treat the Rust crate, npm package, Python package, and CLI as one product with
one SemVer version and one `v{version}` Git tag. A release candidate builds and
qualifies every required artifact from the same commit before registry
publication begins.

The release process records a manifest containing the source commit,
conformance revision, product version, required artifacts, and the observed
publication state of each registry. Registry publication is not transactional,
so an explicitly authorized reconcile operation may complete a partially
published matching version without rebuilding or republishing artifacts that
already succeeded.

Crate-name availability is checked before implementation selects the Rust
package name. A registry-specific name may differ from the product name without
changing the shared product version.

After the monorepo's Python binding is ready, archive the separately created
`secret-scan-python` repository(empty now) and leave a redirect to the monorepo. Do not use  
it as a source mirror or an independently released package.

## Rationale

One version identifies the exact core and binding combination qualified
together. A release manifest makes partial registry success visible and
repairable instead of pretending that one tag makes multiple publications
atomic.

## Alternatives considered

- Independent binding versions were rejected because consumers would need a
separate compatibility matrix for combinations tested from the same source.
- Core-only versioning was rejected because user-visible binding behavior is
part of the supported product contract.
- Keeping the Python repository as a mirror was rejected because it introduces
a second source and synchronization path.

## Consequences

- Even binding-specific fixes advance the shared product version and qualify
all supported artifacts.
- Release automation needs explicit partial-publication detection and
reconciliation behavior.
- This decision does not select a version or authorize a branch, tag, archive,
publication, deployment, or release. Existing release authority remains in
force.

