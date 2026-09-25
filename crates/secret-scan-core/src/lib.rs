//! Deterministic secret detection and redaction core.
//!
//! This crate is the canonical implementation that every language binding
//! translates to (`decision-adopt-rust-core-monorepo`). It uses `std` but is
//! side-effect free by policy:
//!
//! - no runtime network access,
//! - no filesystem access,
//! - no process-environment lookup,
//! - no telemetry or logging sinks,
//! - no secret storage,
//! - no user interface.
//!
//! The crate-level lints below make the policy visible at compile time, and
//! `scripts/check-rust-workspace.py` rejects dependencies that would breach it.
//! Ranges reported by this crate use UTF-8 byte offsets; each binding converts
//! them to its documented native unit (`decision-define-runtime-bindings`).
//!
//! # Pipeline contract
//!
//! [`run_detector_pipeline`] runs every detector in a [`DetectorRegistry`]
//! in registration order, validates each [`Candidate`], resolves overlapping
//! candidates with the documented precedence (specificity, confidence,
//! narrower span, registration order, emission order), and numbers the
//! disjoint survivors by input offset. [`scan`] then evaluates a [`Policy`]
//! once per finding. Identical input and configuration always produce
//! identical findings and ids.
//!
//! Every failure is a [`SecretScanError`] with a fixed code and message and
//! no payload; no public value carries an input fragment or a matched value.
//!
//! [`redact`] then applies [`Finding`] actions to the input in one ordered
//! pass, replacing `redact`/`block` ranges with placeholders from a
//! [`PlaceholderFormatter`] and validating that formatter's output.
//! [`scan_and_redact`] runs both and returns a [`ScanResult`].
//!
//! [`scan`], [`redact`], and [`scan_and_redact`] apply a default
//! [`WholeInputLimits`] before doing any work — [`DEFAULT_MAX_INPUT_BYTES`]
//! and [`DEFAULT_MAX_FINDINGS`] — and fail with
//! [`SecretScanErrorCode::InputLimitExceeded`] or
//! [`SecretScanErrorCode::FindingLimitExceeded`] rather than truncating.
//! [`scan_with_limits`], [`redact_with_limits`], and
//! [`scan_and_redact_with_limits`] accept an explicit [`WholeInputLimits`]
//! instead (`decision-bound-whole-input-operations-by-default`).
//!
//! # Public surface
//!
//! | Concern | API |
//! | --- | --- |
//! | Scan | [`scan`], [`scan_with_limits`], [`run_detector_pipeline`] |
//! | Redact | [`redact`], [`redact_with_limits`], [`MAX_PLACEHOLDER_LENGTH`] |
//! | Scan and redact | [`scan_and_redact`], [`scan_and_redact_with_limits`] |
//! | Whole-input limits | [`WholeInputLimits`], [`DEFAULT_MAX_INPUT_BYTES`], [`DEFAULT_MAX_FINDINGS`] |
//! | Incremental | [`IncrementalSanitizer`], [`IncrementalLimits`], [`SessionState`], [`IncrementalPolicy`], [`IncrementalPolicyContext`] |
//! | Policy | [`Policy`], [`PolicyContext`], [`DefaultPolicy`], [`Action`] |
//! | Formatter | [`PlaceholderFormatter`], [`PlaceholderContext`], [`default_placeholder_formatter`], [`typed_placeholder_formatter`] |
//! | Finding | [`Finding`], [`DetectedFinding`], [`ByteRange`], [`Confidence`], [`Specificity`], [`Obfuscation`] |
//! | Result | [`ScanResult`], [`IncrementalResult`] |
//! | Sanitized error | [`SecretScanError`], [`SecretScanErrorCode`], [`DetectorFailure`], [`PolicyFailure`], [`FormatterFailure`] |
//! | Custom detectors | [`Detector`], [`Candidate`], [`DetectorContext`], [`DetectorRegistry`], [`RegisteredDetector`] |
//! | Declarative rulesets | [`load_ruleset`], [`RulesetError`], [`RulesetErrorClass`] |
//! | Profiles | [`Profile`] |
//! | Identifiers and units | [`is_identifier`], [`MAX_IDENTIFIER_LENGTH`], [`RANGE_UNIT`], [`VERSION`] |
//! | Detector building blocks | [`shannon_entropy`] |
//!
//! That table is the whole surface — it lists every name this crate root
//! exports, and `[workspace.metadata.redact-secret] core-public-api` in the
//! workspace manifest repeats it so a name cannot join or leave without a
//! reviewed manifest change. Everything else is private. In particular, the
//! built-in detector set of each profile is reached only through
//! [`DetectorRegistry::with_built_in`] (`full`) and
//! [`DetectorRegistry::with_common_built_in`] (`common`), and the retention
//! tuning the incremental session depends on is derived through
//! [`IncrementalLimits::minimum_buffered_bytes`] rather than exposed as a
//! constant, so both can change without breaking a caller.
//! `decision-define-detector-profile-and-pack-contract` fixes which built-in
//! detectors each [`Profile`] holds and its compatibility class.
//!
//! # Examples
//!
//! ```
//! use redact_secret::{
//!     DefaultPolicy, DetectorRegistry, default_placeholder_formatter, scan_and_redact,
//! };
//!
//! let registry = DetectorRegistry::with_built_in([])?;
//! let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000\nplain text";
//!
//! let result = scan_and_redact(input, &registry, &DefaultPolicy, &default_placeholder_formatter)?;
//!
//! assert_eq!(result.text(), "API_KEY=<SECRET_1>\nplain text");
//! // Ranges index the original input, in UTF-8 bytes.
//! let range = result.findings()[0].range();
//! assert_eq!(&input[range.start()..range.end()], "ghp_SYNTHETICREVOKED00000000000000000000");
//! # Ok::<(), redact_secret::SecretScanError>(())
//! ```
//!
//! # Incremental sanitization contract
//!
//! [`IncrementalSanitizer`] runs the same built-in detectors, default
//! policy, and redaction over text supplied in chunks. It is a bounded,
//! four-state session (`accepting`, `finalized`, `aborted`, `failed`) that
//! emits only text whose detection window is closed, never rescans
//! finalized input, and accepts input independently of how a caller
//! partitions it into chunks. See the module documentation for the full
//! contract.
//!
//! Until the Rust core passes the shared conformance corpus, the
//! TypeScript implementation in `src/` remains the behavioral oracle
//! (`decision-govern-cross-language-conformance`).

#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]

mod detectors;
mod entropy;
mod error;
mod evidence;
mod incremental;
mod invisible_table;
mod limits;
mod normalize;
mod pipeline;
mod policy;
mod redact;
mod registry;
mod ruleset;
mod types;

pub use entropy::shannon_entropy;
pub use error::{
    DetectorFailure, FormatterFailure, PolicyFailure, SecretScanError, SecretScanErrorCode,
};
pub use incremental::{
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer, SessionState,
};
pub use limits::{DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_BYTES, WholeInputLimits};
pub use pipeline::{
    run_detector_pipeline, scan, scan_and_redact, scan_and_redact_with_limits, scan_with_limits,
};
pub use policy::DefaultPolicy;
pub use redact::{
    MAX_PLACEHOLDER_LENGTH, default_placeholder_formatter, redact, redact_with_limits,
    typed_placeholder_formatter,
};
pub use registry::{DetectorRegistry, Profile, RegisteredDetector};
pub use ruleset::{RulesetError, RulesetErrorClass, load_ruleset};
pub use types::{
    Action, ByteRange, Candidate, Confidence, DetectedFinding, Detector, DetectorContext, Finding,
    MAX_IDENTIFIER_LENGTH, Obfuscation, PlaceholderContext, PlaceholderFormatter, Policy,
    PolicyContext, ScanResult, Specificity, is_identifier,
};

/// The shared product version. Every crate, binding, and package in the
/// workspace reports the same version (`decision-release-bindings-in-lockstep`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The string-index unit used by every range this crate reports.
///
/// Bindings convert to their host unit without changing the selected span:
/// JavaScript uses UTF-16 code units and Python uses Unicode code points.
pub const RANGE_UNIT: &str = "utf8-bytes";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn range_unit_is_utf8_bytes() {
        assert_eq!(RANGE_UNIT, "utf8-bytes");
    }
}
