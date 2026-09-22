---
decision_id: decision-measure-javascript-performance-externally
status: accepted
scope: workspace
title: Measure JavaScript performance externally
decided_at: 2026-09-12
spec: evidence-and-gates
---

# Measure JavaScript performance externally

## Decision

Measure Node and browser WebAssembly initialization, steady-state processing,
throughput, and memory with repository-only assessment runners over real built
artifacts. Do not add telemetry or public instrumentation APIs to the product.

Preserve raw repeated samples and derived distributions. Time `initialize()`
separately from warmed processing, keeping profile validation, input generation,
partitioning, sink checks, aggregation, and rendering outside timing boundaries.
Report Node heap, RSS, external memory, browser JavaScript heap, WebAssembly
linear memory, and streaming-buffer observations separately; never sum
overlapping categories. An inaccessible metric carries a reason. Memory maxima
are boundary-sampled observations and are never described as true peaks.

## Rationale

External runners make measurements repeatable without widening the product's
security or compatibility surface. Raw samples permit later re-aggregation,
while explicit availability and sampling-limit fields prevent a missing or
sampled metric from being mistaken for a precise zero or guaranteed peak.

## Consequences

- Assessment result schema version 2 replaces the single peak-memory value with
  raw distributions and per-category memory observations.
- A Node repetition uses a fresh process and a browser repetition a fresh
  context, while operation timers exclude that isolation overhead.
- The browser may report a non-standard JavaScript heap observation when its
  engine exposes one. Private WASM linear memory and retained stream buffers
  remain unavailable unless a future test-only mechanism can observe them
  without changing the public product contract.
