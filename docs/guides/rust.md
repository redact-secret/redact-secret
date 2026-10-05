# Rust

[Documentation home](../README.md) · [Installation](../getting-started.md)

The `redact-secret` crate is imported as `redact_secret`. It has no normal
runtime dependencies and performs no network or filesystem access. Add it with
`cargo add redact-secret`, which selects the newest beta while no stable
release exists; the [quickstart](../quickstart.md#rust) pins an exact version
and shows a complete program.

For the supported defaults, one call is enough. `sanitize` uses the `full`
profile, `DefaultPolicy`, the default placeholder formatter, and the default
`WholeInputLimits`, returns the same `ScanResult` as `scan_and_redact`, and
reports the same errors. `sanitize_with_profile(input, Profile::Common)` selects
the `common` profile. It builds the built-in registry on each call (about 18 µs)
and supports no custom detectors.

```rust
use redact_secret::{SecretScanError, sanitize};

fn main() -> Result<(), SecretScanError> {
    let result = sanitize("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE")?;
    assert_eq!(result.text(), "API_KEY=<SECRET_1>");
    Ok(())
}
```

The advanced API follows. Use it for custom detectors, PII activation, a custom
policy or formatter, explicit limits, or a registry reused across scans.

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

Reuse the registry for repeated scans. A `DetectorRegistry` is `!Send` and `!Sync`
(a custom `Detector` carries no thread-safety bound), so each thread builds its own.
To build one registry and share it across threads, use `BuiltInRegistry`: the
`full` or `common` built-ins plus optional PII, no custom detector, `Send + Sync`,
with `scan`, `scan_with_limits`, `scan_and_redact` and `scan_and_redact_with_limits`
methods that return exactly what the `DetectorRegistry` functions return
(`BuiltInRegistry::with_built_in()`, `with_common_built_in()`,
`with_built_in_and_pii(&selection)`, `with_common_built_in_and_pii(&selection)`).
Wrap it in an `Arc` to hand it to workers. `IncrementalSanitizer` still builds its
own registry per session. `scan` returns policy-evaluated findings;
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

An `Ok` from these calls means every detector of the registry inspected the
whole input, and every error comes with no partial result. The calls cannot be
cancelled and have no deadline; the limits above are the only bounds. See
[Completeness of `Ok`](../reference/api-contract.md#completeness-of-ok) and
[Cancellation and time bounds](../reference/api-contract.md#cancellation-and-time-bounds).

## Detector profiles

`DetectorRegistry::with_built_in` builds `full`: every built-in detector, and
the default and compatibility baseline. `DetectorRegistry::with_common_built_in`
builds the smaller, opt-in `common` profile — only the structural and
contextual detectors — for size- or latency-sensitive preventive use.
`IncrementalSanitizer::with_common_built_in` builds the equivalent incremental
session. The linker keeps only the constructors a program references, so call
`with_common_built_in` directly to get the smaller binary: with a `Profile`
value only known at run time, `sanitize_with_profile` references both
constructors and links every detector (a minimal program measured 517,872 B
with `with_common_built_in` and 734,816 B through `sanitize_with_profile` with
a run-time `Profile`; see [evidence](../audits/evidence/1127/README.md)).
Both profile constructors report their identity through `profile()`,
which returns `Some(Profile::Full)`, `Some(Profile::Common)`, or `None` for a
registry assembled through `DetectorRegistry::new()`.

```rust
use redact_secret::{DetectorRegistry, SecretScanError};

fn main() -> Result<(), SecretScanError> {
    let registry = DetectorRegistry::with_common_built_in(std::iter::empty())?;
    assert!(registry.contains("private-key"));
    assert!(!registry.contains("github-token"));
    Ok(())
}
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

## PII activation

`PiiSelection::parse` validates and canonicalizes selectors.
`DetectorRegistry::with_built_in_and_pii` and
`with_common_built_in_and_pii` capture that selection and expose its canonical
identity through `activation_identity()`. Empty selection preserves the
legacy credential-only registry byte for byte. `pii` or `pii:global` activates
`pii:global:email`, `pii:global:iban`, `pii:global:network-address`,
`pii:global:payment-card`, and `pii:global:phone`; each exact
`pii:family:global:*` selector activates
only its family. `pii:us` closes over those global families plus `pii:us:ssn`,
while `pii:family:us:ssn` selects only SSNs. They share one
`pii-domain` adapter and require reviewed high-signal context.
Under `pii-v1`, the five global families are `provisional` (not `stable`;
phone covers `+1` / NANP only) and US SSN is `pending`; see
[detection](../reference/detection.md#opt-in-pii-availability-is-not-support). Known
unavailable families or jurisdictions fail closed; see the
[email contract](../contracts/pii/email-v1.md) and
[IBAN contract](../contracts/pii/iban-v1.md),
[payment-card contract](../contracts/pii/payment-card-v1.md),
[phone contract](../contracts/pii/phone-v1.md), and the
[US SSN contract](../contracts/pii/us-ssn-v1.md).
