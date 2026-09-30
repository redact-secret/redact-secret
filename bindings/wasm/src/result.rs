//! The combined result [`scan_and_redact`](crate::scan_and_redact) returns.

use wasm_bindgen::prelude::wasm_bindgen;

use crate::finding::FindingJs;

/// The redacted text alongside every finding that produced it.
#[wasm_bindgen(js_name = "ScanAndRedactResult")]
#[derive(Clone, Debug)]
pub struct ScanAndRedactResultJs {
    text: String,
    findings: Vec<FindingJs>,
}

#[wasm_bindgen(js_class = "ScanAndRedactResult")]
impl ScanAndRedactResultJs {
    /// `input` with every `redact`/`block` finding replaced by its
    /// placeholder.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Every finding `scan` produced for `input`, in the same order `scan`
    /// alone would have returned them.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn findings(&self) -> Vec<FindingJs> {
        self.findings.clone()
    }

    /// Moves the redacted text out of the result, leaving it empty. Unlike
    /// [`text`](Self::text) this keeps no second copy in linear memory; the
    /// JavaScript wrapper reads it once and then frees the result handle.
    #[wasm_bindgen(js_name = "takeText")]
    #[must_use]
    pub fn take_text(&mut self) -> String {
        std::mem::take(&mut self.text)
    }

    /// Moves the findings out of the result, leaving it with none. Unlike
    /// [`findings`](Self::findings) this clones no [`FindingJs`].
    #[wasm_bindgen(js_name = "takeFindings")]
    #[must_use]
    pub fn take_findings(&mut self) -> Vec<FindingJs> {
        std::mem::take(&mut self.findings)
    }
}

impl ScanAndRedactResultJs {
    /// Builds a result from `text` and `findings`.
    pub(crate) const fn new(text: String, findings: Vec<FindingJs>) -> Self {
        Self { text, findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redact_secret::{Action, ByteRange, Confidence};

    fn sample() -> ScanAndRedactResultJs {
        let core_finding = redact_secret::Finding::new(
            "finding-1",
            "jwt",
            "jwt",
            Confidence::High,
            Action::Redact,
            ByteRange::new(0, 3).unwrap(),
        )
        .unwrap();
        ScanAndRedactResultJs::new(
            "<REDACTED>".to_owned(),
            vec![FindingJs::new("abc", core_finding)],
        )
    }

    #[test]
    fn take_accessors_move_the_same_values_the_getters_clone() {
        let mut result = sample();
        let text = result.text();
        let findings = result.findings();

        assert_eq!(result.take_text(), text);
        let taken = result.take_findings();
        assert_eq!(taken.len(), findings.len());
        assert_eq!(taken[0].id(), findings[0].id());
        assert_eq!(
            (taken[0].start(), taken[0].end()),
            (findings[0].range().start(), findings[0].range().end())
        );
        // Moved out: nothing is left behind to keep a second copy alive.
        assert_eq!(result.text(), "");
        assert!(result.findings().is_empty());
    }
}
