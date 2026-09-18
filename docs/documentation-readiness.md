# User documentation readiness

[Documentation home](README.md)

This is the content inventory and follow-up checklist for
[issue #204](https://github.com/redact-secret/redact-secret/issues/204).
Repository Markdown remains the source during beta. A separate web-app
repository versus GitHub Wiki is **undecided**. This page records preparation;
it does not claim that public delivery or stable-release qualification is done.

## Required content before stable release

Every required topic has a repository entry point today. Presence is not final
release sign-off: review these pages against the candidate's public contracts
and record the source revision, commands, outcomes, and remaining gaps in the
implementation PR or release review.

| Topic | Current content | Final content verification |
| --- | --- | --- |
| Installation | [Setup](getting-started.md), [target matrix](qualification.md), [Python wheels](python-packaging.md) | Check supported runtimes, source setup, and clean installation of the selected artifacts; distinguish candidates from published packages. |
| Quick start | [JavaScript](guides/javascript.md), [Python](guides/python.md), [Rust](guides/rust.md), [CLI](guides/cli.md) | Execute each runtime's documented example with small synthetic input and verify sanitized output, safe metadata, and CLI exit status. |
| API | [Contracts](reference/api-contract.md), [JavaScript inventory](../packages/javascript/README.md#public-api), [Python binding](../bindings/python/README.md), [Rust inventory](../crates/secret-scan-core/README.md#public-api), [CLI reference](../crates/secret-scan-cli/README.md) | Compare operations, callbacks, errors, and original-input range units with the final exports and shared conformance contract. |
| Streaming | [Incremental and stream guide](guides/streaming.md) | Execute split-token examples on real Node, browser, Python, Rust, and CLI artifacts; check finalization, limits, cancellation, and partial-output caveats. |
| Policy | [Safe integration](guides/safe-integration.md), [runnable integration examples](../examples/safe-integration/README.md) | Verify redact, block, warn, allow, and failure behavior; confirm host rejection precedes downstream use and callbacks receive safe metadata only. |
| Limitations | [Detection limits](reference/detection.md), [reliability evidence](reference/detection-reliability.md) | Reconcile supported formats and false-positive/false-negative tradeoffs; retain resource bounds and the distinction between preventive client UX and authoritative server enforcement. |
| Profiles | [Detection limits](reference/detection.md#detector-profiles), [API concepts](reference/api-contract.md#detector-profiles), [JavaScript guide](guides/javascript.md#detector-profiles), [Rust guide](guides/rust.md#detector-profiles), [README](../README.md#opt-in-detector-profiles) | Confirm `full` stays the default and the only profile Python and the CLI expose; verify the `common` import switch, `PROFILE`/`profile()`, the `INITIALIZATION_FAILED` mismatch rejection, and the stream-factory limitation against the current exports. |
| Troubleshooting | [Troubleshooting](troubleshooting.md) | Reproduce documented initialization, range, callback, limit, and lifecycle failures with synthetic inputs; confirm fixed input-free diagnostics. |

## Content follow-up

These are concrete repository tasks for refinement, not newly created GitHub
issues. Each feature PR updates the affected rows' linked guides and includes
inspectable evidence; it need not wait for a delivery platform.

- **C1: Reconcile evolving feature content.** Review streaming and integration
  guides against [#179](https://github.com/redact-secret/redact-secret/issues/179)
  and [#180](https://github.com/redact-secret/redact-secret/issues/180). Exit:
  examples, runtime support, and limits describe the implemented behavior.
- **C2: Review the final content inventory.** Reconcile all seven topics with
  the outputs of [#199](https://github.com/redact-secret/redact-secret/issues/199),
  [#200](https://github.com/redact-secret/redact-secret/issues/200),
  [#201](https://github.com/redact-secret/redact-secret/issues/201), and
  [#202](https://github.com/redact-secret/redact-secret/issues/202). Exit: a
  candidate-revision review records coverage and disposition of each gap.
- **C3: Record executable-example evidence.** Use the smallest synthetic input
  for each documented behavior. Run `npm run ci` (including integration-example
  tests and JavaScript checks), Rust doctests, and the relevant installed-artifact
  checks in [qualification](qualification.md#running-it-locally). Execute the
  guide snippets themselves as well: passing related tests alone does not prove
  every Markdown example runs. Exit: evidence identifies each example, runtime,
  artifact/version, command, and outcome without matched plaintext in reports.

## Delivery follow-up after a decision

Do not create a site or choose a platform as part of this readiness work. Once
the choice is explicitly made, record it and create focused delivery tasks with
owners and links back here. Refine the following exits for the chosen platform:

| Task to create | Required exit evidence |
| --- | --- |
| D1: Adapt navigation and links | Starting from the selected public home, every required topic is reachable; home/back links, relative links, anchors, and code fences work in the actual renderer. Record the public URLs and link-check results. |
| D2: Verify delivered examples | Run examples copied from the rendered pages against matching installed artifacts, including browser asset loading and stream examples. Record runtime, artifact identity, commands, and safe results. |
| D3: Verify version labels and public access | Distinguish beta, development checkout, and stable content; match labels to approved artifacts and the changelog. Confirm anonymous access to the selected public path and record the reviewed source revision. |

For a wiki, check its page names and link rewriting; for a web app, check its
routes and asset paths. Repository-relative link checks cannot establish that
either delivery behaves correctly. Keep D1-D3 pending until the selected
platform exists and the evidence is recorded. Do not close the delivery work
based only on repository tests or this inventory.

## Version and release boundary

These pages describe the checkout in which they are read. Use a reviewed source
revision for candidate documentation; a development manifest version is not
proof of registry publication. Final delivery must label the approved version
and distinguish it from ongoing beta/development documentation.

This checklist does not select a version, create a repository, authorize a tag,
publication, deployment, or release. Follow [release authority](../AGENTS.md#release-authority)
and the [release process](../CONTRIBUTION.md#releases) for those actions.
