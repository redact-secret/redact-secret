//! Safe reporting for check mode.
//!
//! A report carries file identity and finding metadata, and nothing else. A
//! range names a span in the input; it never carries the bytes in that span,
//! and no renderer here has access to the input to resolve one.

use std::io::{self, Write};

use redact_secret::{Finding, RANGE_UNIT, VERSION};

use crate::failure::Failure;

/// The safe metadata reported for one finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeFinding {
    id: String,
    type_name: String,
    detector: String,
    confidence: &'static str,
    action: &'static str,
    start: usize,
    end: usize,
}

impl From<&Finding> for SafeFinding {
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.id().to_owned(),
            type_name: finding.type_name().to_owned(),
            detector: finding.detector().to_owned(),
            confidence: finding.confidence().as_str(),
            action: finding.action().as_str(),
            start: finding.range().start(),
            end: finding.range().end(),
        }
    }
}

/// One scanned source and the findings it produced.
#[derive(Clone, Debug)]
struct SourceReport {
    identity: String,
    findings: Vec<SafeFinding>,
}

/// One source that could not be scanned.
#[derive(Clone, Debug)]
struct SourceFailure {
    identity: String,
    failure: Failure,
}

/// The result of one check run over every requested source.
#[derive(Clone, Debug, Default)]
pub struct Report {
    sources: Vec<SourceReport>,
    failures: Vec<SourceFailure>,
}

impl Report {
    /// Creates an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a source that was scanned and the metadata it produced.
    ///
    /// Findings are renumbered so that `id` is unique across the whole report.
    /// The core numbers each scan from `finding-1`, and a multi-file check runs
    /// one scan per file, so without this a consumer keying findings by `id`
    /// would collide between sources. A single-source run — every standard
    /// input run, and the common single-file run — is unaffected: it already
    /// numbers from one.
    pub fn push_source(&mut self, identity: String, findings: Vec<SafeFinding>) {
        let mut ordinal = self.finding_count();
        let findings = findings
            .into_iter()
            .map(|mut finding| {
                ordinal += 1;
                finding.id = format!("finding-{ordinal}");
                finding
            })
            .collect();
        self.sources.push(SourceReport { identity, findings });
    }

    /// Records a source that could not be scanned.
    pub fn push_failure(&mut self, identity: String, failure: Failure) {
        self.failures.push(SourceFailure { identity, failure });
    }

    /// How many findings every scanned source produced together.
    pub fn finding_count(&self) -> usize {
        self.sources
            .iter()
            .map(|source| source.findings.len())
            .sum()
    }

    /// Whether any source failed. A failure outranks a finding: a run that
    /// could not read part of its input has not proved that part clean.
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Writes one line per finding, then a one-line summary to `diagnostics`.
    ///
    /// # Errors
    ///
    /// Returns [`Failure::WriteFailed`] when either stream cannot be written.
    pub fn write_text(
        &self,
        out: &mut dyn Write,
        diagnostics: &mut dyn Write,
    ) -> Result<(), Failure> {
        self.render_text(out, diagnostics)
            .map_err(|_| Failure::WriteFailed)
    }

    fn render_text(&self, out: &mut dyn Write, diagnostics: &mut dyn Write) -> io::Result<()> {
        for source in &self.sources {
            let identity = text_identity(&source.identity);
            for finding in &source.findings {
                writeln!(
                    out,
                    "{}:{}-{} {} detector={} confidence={} action={} id={}",
                    identity,
                    finding.start,
                    finding.end,
                    finding.type_name,
                    finding.detector,
                    finding.confidence,
                    finding.action,
                    finding.id,
                )?;
            }
        }
        // The findings go to a buffered stdout and the summary to an
        // unbuffered stderr. Without this flush the summary overtakes the
        // findings whenever both land on one terminal or one redirect.
        out.flush()?;

        let findings = self.finding_count();
        writeln!(
            diagnostics,
            "redact-secret: {findings} finding(s) in {} source(s); ranges are {RANGE_UNIT}",
            self.sources.len(),
        )
    }

    /// Writes one JSON object describing the whole run.
    ///
    /// # Errors
    ///
    /// Returns [`Failure::WriteFailed`] when the stream cannot be written.
    pub fn write_json(&self, out: &mut dyn Write) -> Result<(), Failure> {
        self.render_json(out).map_err(|_| Failure::WriteFailed)
    }

    fn render_json(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "{{")?;
        write!(out, "  \"version\": ")?;
        write_json_string(out, VERSION)?;
        writeln!(out, ",")?;
        write!(out, "  \"rangeUnit\": ")?;
        write_json_string(out, RANGE_UNIT)?;
        writeln!(out, ",")?;
        writeln!(out, "  \"findingCount\": {},", self.finding_count())?;

        if self.sources.is_empty() {
            writeln!(out, "  \"sources\": [],")?;
        } else {
            writeln!(out, "  \"sources\": [")?;
        }
        for (index, source) in self.sources.iter().enumerate() {
            writeln!(out, "    {{")?;
            write!(out, "      \"source\": ")?;
            write_json_string(out, &source.identity)?;
            writeln!(out, ",")?;
            if source.findings.is_empty() {
                writeln!(out, "      \"findings\": []")?;
            } else {
                writeln!(out, "      \"findings\": [")?;
            }
            for (position, finding) in source.findings.iter().enumerate() {
                writeln!(out, "        {{")?;
                write!(out, "          \"id\": ")?;
                write_json_string(out, &finding.id)?;
                writeln!(out, ",")?;
                write!(out, "          \"type\": ")?;
                write_json_string(out, &finding.type_name)?;
                writeln!(out, ",")?;
                write!(out, "          \"detector\": ")?;
                write_json_string(out, &finding.detector)?;
                writeln!(out, ",")?;
                write!(out, "          \"confidence\": ")?;
                write_json_string(out, finding.confidence)?;
                writeln!(out, ",")?;
                write!(out, "          \"action\": ")?;
                write_json_string(out, finding.action)?;
                writeln!(out, ",")?;
                writeln!(out, "          \"start\": {},", finding.start)?;
                writeln!(out, "          \"end\": {}", finding.end)?;
                writeln!(
                    out,
                    "        }}{}",
                    separator(position, source.findings.len())
                )?;
            }
            if !source.findings.is_empty() {
                writeln!(out, "      ]")?;
            }
            writeln!(out, "    }}{}", separator(index, self.sources.len()))?;
        }
        if !self.sources.is_empty() {
            writeln!(out, "  ],")?;
        }

        if self.failures.is_empty() {
            writeln!(out, "  \"failures\": []")?;
        } else {
            writeln!(out, "  \"failures\": [")?;
        }
        for (index, failure) in self.failures.iter().enumerate() {
            writeln!(out, "    {{")?;
            write!(out, "      \"source\": ")?;
            write_json_string(out, &failure.identity)?;
            writeln!(out, ",")?;
            write!(out, "      \"code\": ")?;
            write_json_string(out, failure.failure.code())?;
            writeln!(out, ",")?;
            write!(out, "      \"message\": ")?;
            write_json_string(out, failure.failure.message())?;
            writeln!(out)?;
            writeln!(out, "    }}{}", separator(index, self.failures.len()))?;
        }
        if !self.failures.is_empty() {
            writeln!(out, "  ]")?;
        }
        writeln!(out, "}}")
    }

    /// Writes one input-free diagnostic line per failed source.
    ///
    /// # Errors
    ///
    /// Returns [`Failure::WriteFailed`] when the stream cannot be written.
    pub fn write_diagnostics(&self, diagnostics: &mut dyn Write) -> Result<(), Failure> {
        for failure in &self.failures {
            writeln!(
                diagnostics,
                "redact-secret: {}: {}: {}",
                text_identity(&failure.identity),
                failure.failure.code(),
                failure.failure.message(),
            )
            .map_err(|_| Failure::WriteFailed)?;
        }
        Ok(())
    }
}

/// Keeps host-supplied paths on one line without terminal control sequences.
/// Escape backslashes too, so a literal `\n` differs from an actual newline.
fn text_identity(identity: &str) -> String {
    identity.chars().flat_map(char::escape_debug).collect()
}

/// The comma a JSON array needs after every element but its last.
fn separator(index: usize, length: usize) -> &'static str {
    if index + 1 < length { "," } else { "" }
}

/// Writes `value` as a JSON string literal.
fn write_json_string(out: &mut dyn Write, value: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    for character in value.chars() {
        match character {
            '"' => out.write_all(b"\\\"")?,
            '\\' => out.write_all(b"\\\\")?,
            '\n' => out.write_all(b"\\n")?,
            '\r' => out.write_all(b"\\r")?,
            '\t' => out.write_all(b"\\t")?,
            '\u{08}' => out.write_all(b"\\b")?,
            '\u{0c}' => out.write_all(b"\\f")?,
            control if control < '\u{20}' => write!(out, "\\u{:04x}", u32::from(control))?,
            other => write!(out, "{other}")?,
        }
    }
    out.write_all(b"\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use redact_secret::SecretScanErrorCode;

    fn finding(id: &str, start: usize, end: usize) -> SafeFinding {
        SafeFinding {
            id: id.to_owned(),
            type_name: "github_token".to_owned(),
            detector: "github-token".to_owned(),
            confidence: "high",
            action: "redact",
            start,
            end,
        }
    }

    #[test]
    fn a_clean_report_writes_no_finding_line() {
        let mut report = Report::new();
        report.push_source("<stdin>".to_owned(), Vec::new());
        let (mut out, mut diagnostics) = (Vec::new(), Vec::new());
        report.write_text(&mut out, &mut diagnostics).unwrap();
        assert_eq!(out, b"");
        assert_eq!(report.finding_count(), 0);
        assert!(!report.has_failures());
    }

    #[test]
    fn a_finding_line_names_identity_and_metadata_only() {
        let mut report = Report::new();
        report.push_source("a.txt".to_owned(), vec![finding("finding-1", 8, 48)]);
        let (mut out, mut diagnostics) = (Vec::new(), Vec::new());
        report.write_text(&mut out, &mut diagnostics).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "a.txt:8-48 github_token detector=github-token confidence=high action=redact id=finding-1\n"
        );
        assert!(
            String::from_utf8(diagnostics)
                .unwrap()
                .contains("1 finding(s) in 1 source(s)")
        );
    }

    /// One sink standing in for a terminal, or for `2>&1` into one file:
    /// findings and the summary land in the same place, in write order.
    #[derive(Clone, Default)]
    struct SharedSink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn findings_are_numbered_across_the_whole_report() {
        let mut report = Report::new();
        report.push_source("first.env".to_owned(), vec![finding("finding-1", 0, 4)]);
        report.push_source(
            "second.env".to_owned(),
            vec![finding("finding-1", 0, 4), finding("finding-2", 8, 12)],
        );

        let (mut out, mut diagnostics) = (Vec::new(), Vec::new());
        report.write_text(&mut out, &mut diagnostics).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        let ids: Vec<&str> = rendered
            .lines()
            .filter_map(|line| line.rsplit_once("id=").map(|(_, id)| id))
            .collect();

        assert_eq!(ids, ["finding-1", "finding-2", "finding-3"]);
        assert_eq!(report.finding_count(), 3);
    }

    #[test]
    fn the_summary_follows_the_findings_it_summarizes() {
        let mut report = Report::new();
        report.push_source("a.txt".to_owned(), vec![finding("finding-1", 8, 48)]);

        // Buffered stdout against unbuffered stderr is exactly the case that
        // inverts the order without a flush between them.
        let sink = SharedSink::default();
        let mut buffered = std::io::BufWriter::new(sink.clone());
        report.write_text(&mut buffered, &mut sink.clone()).unwrap();
        buffered.flush().unwrap();

        let rendered = String::from_utf8(sink.0.borrow().clone()).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("a.txt:8-48"), "got {lines:?}");
        assert!(
            lines[1].starts_with("redact-secret: 1 finding(s)"),
            "got {lines:?}"
        );
    }

    #[test]
    fn the_json_report_is_one_object_with_every_section() {
        let mut report = Report::new();
        report.push_source("a.txt".to_owned(), vec![finding("finding-1", 8, 48)]);
        report.push_failure("b.bin".to_owned(), Failure::NotUtf8);
        let mut out = Vec::new();
        report.write_json(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.starts_with("{\n"));
        assert!(rendered.ends_with("}\n"));
        assert!(rendered.contains("\"rangeUnit\": \"utf8-bytes\""));
        assert!(rendered.contains("\"findingCount\": 1"));
        assert!(rendered.contains("\"source\": \"a.txt\""));
        assert!(rendered.contains("\"type\": \"github_token\""));
        assert!(rendered.contains("\"start\": 8"));
        assert!(rendered.contains("\"end\": 48"));
        assert!(rendered.contains("\"code\": \"NOT_UTF8\""));
        assert!(report.has_failures());
    }

    #[test]
    fn json_escapes_an_awkward_identity() {
        let mut report = Report::new();
        let identity = format!("a\"b\\c{}d{}.txt", '\u{09}', '\u{01}');
        report.push_source(identity, Vec::new());
        let mut out = Vec::new();
        report.write_json(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains(r#""source": "a\"b\\c\td\u0001.txt""#));
    }

    #[test]
    fn diagnostics_name_the_source_and_a_fixed_code() {
        let mut report = Report::new();
        report.push_failure(
            "b.bin".to_owned(),
            Failure::Core(SecretScanErrorCode::InputLimitExceeded),
        );
        let mut diagnostics = Vec::new();
        report.write_diagnostics(&mut diagnostics).unwrap();
        assert_eq!(
            String::from_utf8(diagnostics).unwrap(),
            "redact-secret: b.bin: INPUT_LIMIT_EXCEEDED: Secret scan input limit exceeded.\n"
        );
    }

    #[test]
    fn text_sources_cannot_inject_records_or_terminal_controls() {
        let identity = "한글\\n\n\r\t\u{1b}[31m\u{85}\u{2028}\u{2029}.env";
        let mut report = Report::new();
        report.push_source(identity.to_owned(), vec![finding("finding-1", 8, 48)]);
        report.push_failure(identity.to_owned(), Failure::NotUtf8);
        let (mut out, mut diagnostics) = (Vec::new(), Vec::new());
        report.write_text(&mut out, &mut diagnostics).unwrap();
        report.write_diagnostics(&mut diagnostics).unwrap();
        let out = String::from_utf8(out).unwrap();
        let diagnostics = String::from_utf8(diagnostics).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert_eq!(diagnostics.lines().count(), 2);
        let escaped = r"한글\\n\n\r\t\u{1b}[31m\u{85}\u{2028}\u{2029}.env";
        assert!(out.starts_with(escaped));
        assert!(diagnostics.contains(&format!("redact-secret: {escaped}: NOT_UTF8:")));
        for rendered in [&out, &diagnostics] {
            assert!(!rendered.contains(['\r', '\t', '\u{1b}', '\u{85}', '\u{2028}', '\u{2029}']));
        }
        let mut json = Vec::new();
        report.write_json(&mut json).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["sources"][0]["source"], identity);
        assert_eq!(parsed["failures"][0]["source"], identity);
    }
}
