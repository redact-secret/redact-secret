# Rust

[Documentation home](../README.md) · [Installation](../getting-started.md)

The `redact-secret` crate is imported as `redact_secret`. It has no normal
runtime dependencies and performs no network or filesystem access.

```rust
use redact_secret::{
    DefaultPolicy, DetectorRegistry, SecretScanError,
    default_placeholder_formatter, scan_and_redact,
};

fn main() -> Result<(), SecretScanError> {
    let registry = DetectorRegistry::with_built_in([])?;
    let result = scan_and_redact(
        "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )?;
    assert_eq!(result.text(), "API_KEY=<SECRET_1>");
    assert_eq!(result.findings().len(), 1);
    Ok(())
}
```

Reuse the registry for repeated scans. `scan` returns policy-evaluated findings;
`redact` takes the original input, findings, and a formatter. `scan_and_redact`
combines those operations. Ranges are half-open UTF-8 byte offsets on character
boundaries. Never apply them to redacted output or log the selected input span.

`DefaultPolicy` redacts known credentials and blocks private-key material.
`block` still replaces the range; the host must reject downstream use itself.
`Policy` and `PlaceholderFormatter` support trusted callbacks with safe metadata.
The direct Rust API also exposes custom detector traits; these receive input
and are trusted code. The JavaScript and Python bindings do not expose custom
detector callbacks.

`IncrementalSanitizer` requires explicit `IncrementalLimits`. Derive the buffer
minimum with `IncrementalLimits::minimum_buffered_bytes`; do not copy internal
retention constants. See [streaming](streaming.md) for lifecycle and failure rules.

`scan`, `redact`, and `scan_and_redact` default to `WholeInputLimits::default()`
(64 MiB of input, 50,000 findings —
`decision-bound-whole-input-operations-by-default`), failing closed with
`InputLimitExceeded`/`FindingLimitExceeded` rather than truncating. Call the
`_with_limits` sibling to raise or lower the bound explicitly:

```rust
use redact_secret::{
    DefaultPolicy, DetectorRegistry, SecretScanError, WholeInputLimits,
    default_placeholder_formatter, scan_and_redact_with_limits,
};

fn main() -> Result<(), SecretScanError> {
    let registry = DetectorRegistry::with_built_in([])?;
    let limits = WholeInputLimits::new(128 * 1024 * 1024, 100_000)?;
    let result = scan_and_redact_with_limits(
        "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
        &limits,
    )?;
    assert_eq!(result.text(), "API_KEY=<SECRET_1>");
    Ok(())
}
```

## Detector profiles

`DetectorRegistry::with_built_in` builds `full`: every built-in detector, and
the default and compatibility baseline. `DetectorRegistry::with_common_built_in`
builds the smaller, opt-in `common` profile — only the structural and
contextual detectors — for size- or latency-sensitive preventive use.
`IncrementalSanitizer::with_common_built_in` builds the equivalent incremental
session. Both profile constructors report their identity through `profile()`,
which returns `Some(Profile::Full)`, `Some(Profile::Common)`, or `None` for a
registry assembled through `DetectorRegistry::new()`.

```rust
use redact_secret::DetectorRegistry;

let registry = DetectorRegistry::with_common_built_in(std::iter::empty())?;
assert!(registry.contains("private-key"));
assert!(!registry.contains("github-token"));
# Ok::<(), redact_secret::SecretScanError>(())
```

A profile constructor's `custom` detectors reject any id already reserved by
`full`'s built-in set, including a `provider` id this profile does not itself
register — a custom `github-token` inside `common` would otherwise emit
findings under a built-in id with different behavior. `DetectorRegistry::register`
applies no profile's reserved-id rule, so a successful call — even one that
adds a detector whose id a profile constructor would have rejected — clears
`profile()` to `None`: the registry is no longer guaranteed to match a
canonical profile once it is hand-extended. Python and the CLI stay `full`
only. See [detection coverage](../reference/detection.md#detector-profiles)
for the false-negative tradeoff.

The [core API inventory](../../crates/secret-scan-core/README.md#public-api)
lists the full surface. Generate local rustdoc with
`cargo doc -p redact-secret --no-deps --locked`.
