# Corrected release-build assessment

All 15 runs completed on this macOS arm64 host: accuracy and two bounded
performance profiles, five repetitions per profile, across Rust, Python, Node,
Chromium WebAssembly, and CLI. [Summary](summary.json), [baseline](baseline.md),
and [build evidence](build-evidence.json) preserve samples and identities.

This is a local current-checkout measurement, not an installed-registry beta.3
comparison or a clean release-candidate qualification. The checkout retains
beta.3 manifest versions but includes later source commits. The runner changes
are uncommitted; build-evidence.json marks that explicitly and hashes source
inputs and built artifacts. All bindings were rebuilt locally with release
optimization before measuring. Build processes were finished before measurement.

The 18-fixture v3 corpus still yields 21 TP / 1 FP / 5 FN on all five surfaces.
The Bearer range disagreement contributes one FP and one FN. Historical labels
were not altered. Rust performance now has explicit release-build provenance;
its command records executable argv rather than a reconstructed Cargo command.
CLI measures process-inclusive check mode, while other surfaces scan and redact.
Five samples on one host are observations, not production throughput guarantees.

Rebuild artifacts with the commands in build-evidence.json, install the resulting
Python wheel into an isolated environment, then rerun assessmentCommand with a
new output directory. Raw samples from earlier debug runs remain unmodified.
