//! Default, overridable bounds for whole-input operations
//! (`decision-bound-whole-input-operations-by-default`).
//!
//! Unlike [`IncrementalLimits`](crate::IncrementalLimits), which an
//! incremental session always requires explicitly, [`WholeInputLimits`] has a
//! [`Default`]: [`scan`](crate::scan), [`redact`](crate::redact), and
//! [`scan_and_redact`](crate::scan_and_redact) apply it silently so an
//! ordinary caller is protected without changing a call site.
//! [`scan_with_limits`](crate::scan_with_limits),
//! [`redact_with_limits`](crate::redact_with_limits), and
//! [`scan_and_redact_with_limits`](crate::scan_and_redact_with_limits) accept
//! an explicit [`WholeInputLimits`] for a caller that needs to raise or
//! lower it.

use crate::error::{SecretScanError, SecretScanErrorCode};

/// The default `max_input_bytes`: 64 MiB, the same bound
/// `crates/secret-scan-cli` already declares for a whole file or a streamed
/// total input, so the product has one whole-input bound rather than two.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// The default `max_findings`: 50,000. Sized so every legitimate workload
/// and every fixture in the conformance corpus stays well under it, while
/// still being a real, reachable ceiling for a deliberately dense-packed
/// adversarial input well before that input reaches
/// [`DEFAULT_MAX_INPUT_BYTES`] — a second, independent bound, not a
/// restatement of the byte bound
/// (`decision-bound-whole-input-operations-by-default`).
pub const DEFAULT_MAX_FINDINGS: usize = 50_000;

/// Explicit byte and finding-count bounds a whole-input operation checks
/// before doing detection work.
///
/// Exceeding either bound fails the whole call with a fixed, input-free
/// error rather than truncating input or findings.
///
/// # Examples
///
/// ```
/// use redact_secret::WholeInputLimits;
///
/// let limits = WholeInputLimits::new(1 << 20, 1_000)?;
/// assert_eq!(limits.max_input_bytes(), 1 << 20);
/// assert_eq!(limits.max_findings(), 1_000);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WholeInputLimits {
    max_input_bytes: usize,
    max_findings: usize,
}

impl WholeInputLimits {
    /// Validates and creates a limit set.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidLimits`] when either bound is
    /// zero.
    pub fn new(max_input_bytes: usize, max_findings: usize) -> Result<Self, SecretScanError> {
        if max_input_bytes == 0 || max_findings == 0 {
            return Err(SecretScanErrorCode::InvalidLimits.into());
        }
        Ok(Self {
            max_input_bytes,
            max_findings,
        })
    }

    /// The largest whole-input byte length this limit set accepts.
    #[must_use]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// The largest accepted finding count this limit set accepts.
    #[must_use]
    pub const fn max_findings(self) -> usize {
        self.max_findings
    }

    /// Checks `input` against `max_input_bytes`.
    ///
    /// A cheap length check with no allocation; callers run it before any
    /// normalization or detection work.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InputLimitExceeded`] when
    /// `input.len()` exceeds `max_input_bytes`.
    pub fn check_input(&self, input: &str) -> Result<(), SecretScanError> {
        if input.len() > self.max_input_bytes {
            return Err(SecretScanErrorCode::InputLimitExceeded.into());
        }
        Ok(())
    }

    /// Checks `count` against `max_findings`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::FindingLimitExceeded`] when `count`
    /// exceeds `max_findings`.
    pub fn check_findings(&self, count: usize) -> Result<(), SecretScanError> {
        if count > self.max_findings {
            return Err(SecretScanErrorCode::FindingLimitExceeded.into());
        }
        Ok(())
    }
}

impl Default for WholeInputLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_declared_constants() {
        let limits = WholeInputLimits::default();
        assert_eq!(limits.max_input_bytes(), DEFAULT_MAX_INPUT_BYTES);
        assert_eq!(limits.max_findings(), DEFAULT_MAX_FINDINGS);
    }

    #[test]
    fn new_rejects_a_zero_input_bound() {
        assert_eq!(
            WholeInputLimits::new(0, 10).unwrap_err().code(),
            SecretScanErrorCode::InvalidLimits
        );
    }

    #[test]
    fn new_rejects_a_zero_finding_bound() {
        assert_eq!(
            WholeInputLimits::new(10, 0).unwrap_err().code(),
            SecretScanErrorCode::InvalidLimits
        );
    }

    #[test]
    fn check_input_accepts_exactly_at_bound() {
        let limits = WholeInputLimits::new(5, 10).unwrap();
        assert!(limits.check_input("abcde").is_ok());
    }

    #[test]
    fn check_input_rejects_one_over_bound() {
        let limits = WholeInputLimits::new(5, 10).unwrap();
        assert_eq!(
            limits.check_input("abcdef").unwrap_err().code(),
            SecretScanErrorCode::InputLimitExceeded
        );
    }

    #[test]
    fn check_findings_accepts_exactly_at_bound() {
        let limits = WholeInputLimits::new(5, 10).unwrap();
        assert!(limits.check_findings(10).is_ok());
    }

    #[test]
    fn check_findings_rejects_one_over_bound() {
        let limits = WholeInputLimits::new(5, 10).unwrap();
        assert_eq!(
            limits.check_findings(11).unwrap_err().code(),
            SecretScanErrorCode::FindingLimitExceeded
        );
    }
}
