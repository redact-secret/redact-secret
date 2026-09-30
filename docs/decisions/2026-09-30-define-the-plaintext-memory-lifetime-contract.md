---
decision_id: decision-define-the-plaintext-memory-lifetime-contract
status: accepted
scope: workspace
title: Define the plaintext memory-lifetime contract as copy minimization and bounded retention, with no erasure claim
decided_at: 2026-09-30
spec: engine
---

# Define the plaintext memory-lifetime contract as copy minimization and bounded retention, with no erasure claim

## Context

The project already keeps matched plaintext out of findings, errors and debug
output. That is an output-safety contract. It says nothing about how long
input text sits in process memory while the core scans, and the core cannot
avoid holding it: detection needs the text, and an incremental session must
keep unresolved text until a detector window closes
([#1079](https://github.com/redact-secret/redact-secret/issues/1079)).

The audit in [`docs/audits/evidence/1079`](../audits/evidence/1079/README.md)
found what the core owns. A whole-input scan borrows the caller's `&str` and
makes one owned copy only when invisible code points are removed. An
incremental session owns `retained`, an optional normalized `scanned` copy, a
one-line lead and a bounded private-key lookbehind, and releases all of them on
`finalize`, `abort` and every failure. Nothing overwrites any buffer before it
is freed: releasing is `String::new()` or `None`. Growth by appending and the
per-flush rebuild of `retained` free earlier allocations that held matched
text. The bindings and the CLI make further copies the core does not own.

Rust documents that dropped or removed `Vec` data is not guaranteed erased and
that an ordinary overwrite may be optimized away. Overwriting with a dedicated
primitive covers only the current allocation, not earlier reallocations,
caller or host copies, registers, swap, dumps or microarchitectural state.

## Decision

The core's memory-lifetime contract is **copy minimization plus bounded
retention**. It is not erasure.

1. **Vocabulary.** "Released" or "discarded" means the core dropped its owner.
   "Zeroized" means the bytes were explicitly overwritten by a write the
   optimizer cannot remove. Documentation, code comments and errors never use
   the two interchangeably, and never say drop or deallocation erases memory.
2. **No erasure claim without a mechanism.** A statement that a buffer is
   zeroized is allowed only when the implementation provides an overwrite
   primitive, names the buffers, the build mode and the transition, states what
   stays outside it (earlier reallocations, caller and host copies, registers,
   allocator history, swap, dumps, microarchitectural effects), and has a test
   for every terminal incremental state. Until then no build makes the claim.
   Whether and how to provide one is
   [#1080](https://github.com/redact-secret/redact-secret/issues/1080), which
   decides inside this vocabulary.
3. **What the core promises** is stated in
   [`docs/reference/plaintext-lifetime.md`](../reference/plaintext-lifetime.md):
   bounded owned copies on the whole-input path; bounded incremental
   retention; terminal release of everything the session derived from input;
   action-aware output, since `warn` and `allow` leave the value in the text.
4. **Runtimes are stated separately.** Native Rust, the CLI, Node, WebAssembly
   and Python each have their own rows. A statement about one is not carried
   to another. WebAssembly linear memory is readable in full by the host and
   never shrinks, so it is never described by the native allocator's rules.
5. **Review rule.** A change that adds an owned copy of input-derived text in
   the core, to a detector or to the pipeline, states the reason in its pull
   request and updates the inventory, or removes the copy instead. Borrowing a
   span beats copying it, and bounding an owned copy beats leaving it
   unbounded. The order for any necessary copy is: do not copy; bound its
   lifetime and capacity; overwrite it when its use ends, if #1080 provides
   that.
6. **Caller and host memory is out of scope.** The input the caller passes and
   the output the core returns belong to the caller, and the core makes no
   promise about them.

## Trade-offs

This decision gives up a blanket "secrets are wiped" sentence, which would be
false for the caller's input, the returned output, every host copy and every
earlier allocation. It keeps the core small and deterministic, leaves a
possible opt-in mechanism to #1080 without changing what is promised today, and
keeps the security note true when a reader compares it with the code.

Rejected alternatives:

- Claim erasure on drop. Rust does not provide it.
- An unconditional overwrite dependency in the default core. It would add size
  and cost to every build for a guarantee that covers the current allocation
  only, and would invite the claim above.
- Say nothing about memory. Integrators then assume either no retention or
  full erasure, and both are wrong.

## Consequences

The plaintext-lifetime note and the #1079 inventory become the place to look
for "where can plaintext exist, for how long, who owns it". The engine spec
carries the rule. The remediation candidates the audit found (#1076 is done;
the others are listed under Findings in the inventory) are tracked against the
review rule, and #1080
starts from the inventory's terminal-transition table rather than from a
blanket wrapper around the scanner. The decision changes no code, API or
detection behavior.

Follow-up, not a change to this decision: the measured zeroization design for
#1080 is in [`docs/audits/evidence/1080`](../audits/evidence/1080/README.md).
It stays a proposal until a maintainer rules and a new ADR amends the core's
no-Cargo-features rule; this decision's vocabulary and "no erasure claim
without a mechanism" rule apply to it unchanged.
