//! The JavaScript-visible finding and range types [`scan`](crate::scan) and
//! [`scan_and_redact`](crate::scan_and_redact) return.
//!
//! [`FindingJs`] wraps a [`redact_secret::Finding`] behind an opaque handle: its
//! getters expose only safe metadata (with the range converted to UTF-16 code
//! units), and it carries the original UTF-8-byte-range finding privately so
//! [`redact`](crate::redact) can accept the exact values [`scan`](crate::scan)
//! returned without asking JavaScript to convert a range back to UTF-8 bytes.

use wasm_bindgen::prelude::wasm_bindgen;

use crate::range;

/// A `[start, end)` range in UTF-16 code units, matching how JavaScript
/// indexes a `string`.
#[wasm_bindgen(js_name = "Range")]
#[derive(Clone, Copy, Debug)]
pub struct RangeJs {
    start: u32,
    end: u32,
}

#[wasm_bindgen(js_class = "Range")]
impl RangeJs {
    /// The inclusive start offset, in UTF-16 code units.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn start(&self) -> u32 {
        self.start
    }

    /// The exclusive end offset, in UTF-16 code units.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn end(&self) -> u32 {
        self.end
    }
}

/// A finding as returned to JavaScript: safe metadata plus the policy
/// action, with no matched value.
#[wasm_bindgen(js_name = "Finding")]
#[derive(Clone, Debug)]
pub struct FindingJs {
    inner: redact_secret::Finding,
    range: RangeJs,
}

#[wasm_bindgen(js_class = "Finding")]
impl FindingJs {
    /// The deterministic finding id (`finding-1`, `finding-2`, ...).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.inner.id().to_owned()
    }

    /// The finding type (for example `"jwt"`, `"aws_access_key_id"`).
    #[wasm_bindgen(getter, js_name = "type")]
    #[must_use]
    pub fn type_name(&self) -> String {
        self.inner.type_name().to_owned()
    }

    /// The id of the detector that produced this finding.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn detector(&self) -> String {
        self.inner.detector().to_owned()
    }

    /// The confidence: `"low"`, `"medium"`, or `"high"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn confidence(&self) -> String {
        self.inner.confidence().as_str().to_owned()
    }

    /// The policy action: `"redact"`, `"block"`, `"warn"`, or `"allow"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn action(&self) -> String {
        self.inner.action().as_str().to_owned()
    }

    /// The invisible-character-obfuscation signal: `"none"` or
    /// `"invisible-characters"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn obfuscation(&self) -> String {
        self.inner.obfuscation().as_str().to_owned()
    }

    /// The finding's range, in UTF-16 code units.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn range(&self) -> RangeJs {
        self.range
    }
}

impl FindingJs {
    /// Wraps `finding`, converting its UTF-8 byte range to UTF-16 code units
    /// against `input`.
    pub(crate) fn new(input: &str, finding: redact_secret::Finding) -> Self {
        let (start, end) = range::to_utf16_range(input, finding.range());
        Self::from_range(finding, start, end)
    }

    /// Wraps `finding` with an already-converted UTF-16 code-unit range.
    ///
    /// Used by [`crate::incremental`], which never holds the whole logical
    /// session input `range::to_utf16_range` would need: its ranges come
    /// from the chunk-by-chunk `Utf16Index` instead.
    pub(crate) const fn from_range(finding: redact_secret::Finding, start: u32, end: u32) -> Self {
        Self {
            inner: finding,
            range: RangeJs { start, end },
        }
    }

    /// Unwraps the original core [`Finding`](redact_secret::Finding), with its
    /// UTF-8 byte range intact, for [`redact`](crate::redact) to consume
    /// directly.
    pub(crate) fn into_inner(self) -> redact_secret::Finding {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redact_secret::{Action, ByteRange, Confidence};

    #[test]
    fn exposes_safe_metadata_with_a_utf16_range() {
        let core_finding = redact_secret::Finding::new(
            "finding-1",
            "aws_access_key_id",
            "aws-access-key",
            Confidence::High,
            Action::Redact,
            ByteRange::new(5, 34).unwrap(),
        )
        .unwrap();
        let input = "\u{1F511} TOKEN_SYNTHETIC_REVOKED_VALUE";
        let finding = FindingJs::new(input, core_finding);

        assert_eq!(finding.id(), "finding-1");
        assert_eq!(finding.type_name(), "aws_access_key_id");
        assert_eq!(finding.detector(), "aws-access-key");
        assert_eq!(finding.confidence(), "high");
        assert_eq!(finding.action(), "redact");
        assert_eq!(finding.obfuscation(), "none");
        assert_eq!((finding.range().start(), finding.range().end()), (3, 32));
    }

    #[test]
    fn round_trips_through_into_inner_unchanged() {
        let core_finding = redact_secret::Finding::new(
            "finding-1",
            "jwt",
            "jwt",
            Confidence::High,
            Action::Redact,
            ByteRange::new(0, 3).unwrap(),
        )
        .unwrap();
        let expected = core_finding.clone();
        let finding = FindingJs::new("abc", core_finding);
        assert_eq!(finding.into_inner(), expected);
    }
}
