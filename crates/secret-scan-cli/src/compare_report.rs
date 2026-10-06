//! The report of `--compare-action-policy`.
//!
//! A comparison report is an observation of one file. It carries safe finding
//! metadata, each policy's revision binding, and each policy's action and its
//! reason per finding. It never carries input text, a matched value, a hash of
//! either, or a score, and it states in both formats that nothing was enforced.

use std::io::{self, Write};

use redact_secret::{
    ActionComparison, ActionCounts, ActionDecision, DecisionBasis, PolicyBinding, RANGE_UNIT,
    VERSION,
};

use crate::failure::Failure;
use crate::report::{separator, text_identity, write_json_string};

/// The label side `index` carries: side 0 is the baseline.
fn label(index: usize) -> String {
    if index == 0 {
        "baseline".to_owned()
    } else {
        format!("candidate-{index}")
    }
}

/// `no-rule-matched`, `rule:<id>#<index>` and so on: one token, no spaces.
fn basis_token(basis: &DecisionBasis) -> String {
    match basis {
        DecisionBasis::Rule {
            rule_id,
            rule_index,
        } => format!("rule:{rule_id}#{rule_index}"),
        DecisionBasis::RuleDefault {
            rule_id,
            rule_index,
        } => format!("rule-default:{rule_id}#{rule_index}"),
        other => other.as_str().to_owned(),
    }
}

/// Whether any finding's action differs between the compared policies.
pub fn has_differences(comparison: &ActionComparison) -> bool {
    comparison.changed_count() > 0
}

/// Writes one line per finding, then a summary to `diagnostics`.
///
/// # Errors
///
/// [`Failure::WriteFailed`] when either stream cannot be written.
pub fn write_text(
    comparison: &ActionComparison,
    source: &str,
    out: &mut dyn Write,
    diagnostics: &mut dyn Write,
) -> Result<(), Failure> {
    render_text(comparison, source, out, diagnostics).map_err(|_| Failure::WriteFailed)
}

fn render_text(
    comparison: &ActionComparison,
    source: &str,
    out: &mut dyn Write,
    diagnostics: &mut dyn Write,
) -> io::Result<()> {
    let identity = text_identity(source);
    for compared in comparison.findings() {
        let finding = compared.finding();
        write!(
            out,
            "{}:{}-{} {} detector={} confidence={} obfuscation={} id={}",
            identity,
            finding.range().start(),
            finding.range().end(),
            finding.type_name(),
            finding.detector(),
            finding.confidence().as_str(),
            finding.obfuscation().as_str(),
            finding.id(),
        )?;
        for (index, decision) in compared.decisions().iter().enumerate() {
            write!(
                out,
                " {}={}({})",
                label(index),
                decision.action().as_str(),
                basis_token(decision.basis()),
            )?;
        }
        writeln!(out, "{}", if compared.differs() { " differs" } else { "" })?;
    }
    out.flush()?;

    for (index, side) in comparison.sides().iter().enumerate() {
        let binding = match side.binding() {
            PolicyBinding::ActionPolicy { .. } => format!(
                "action-policy sha256={}",
                side.binding().document_sha256_hex().unwrap_or_default()
            ),
            other => other.kind().to_owned(),
        };
        let counts: ActionCounts = side.counts();
        writeln!(
            diagnostics,
            "redact-secret: {}: {binding} redact={} block={} warn={} allow={}",
            label(index),
            counts.redact(),
            counts.block(),
            counts.warn(),
            counts.allow(),
        )?;
    }
    writeln!(
        diagnostics,
        "redact-secret: preview only, nothing was enforced; {} finding(s), {} differ; \
         detection {} detector(s) activation={}; ranges are {RANGE_UNIT}",
        comparison.findings().len(),
        comparison.changed_count(),
        comparison.detection().detector_count(),
        comparison.detection().activation_identity(),
    )
}

/// Writes one JSON object describing the whole comparison.
///
/// # Errors
///
/// [`Failure::WriteFailed`] when the stream cannot be written.
pub fn write_json(
    comparison: &ActionComparison,
    source: &str,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    render_json(comparison, source, out).map_err(|_| Failure::WriteFailed)
}

fn write_key(out: &mut dyn Write, indent: &str, key: &str) -> io::Result<()> {
    write!(out, "{indent}\"{key}\": ")
}

fn write_decision(out: &mut dyn Write, decision: &ActionDecision) -> io::Result<()> {
    write!(out, "{{\"action\": ")?;
    write_json_string(out, decision.action().as_str())?;
    write!(out, ", \"basis\": ")?;
    write_json_string(out, decision.basis().as_str())?;
    write!(out, ", \"ruleId\": ")?;
    match decision.basis().rule_id() {
        Some(id) => write_json_string(out, id)?,
        None => write!(out, "null")?,
    }
    write!(out, ", \"ruleIndex\": ")?;
    match decision.basis().rule_index() {
        Some(index) => write!(out, "{index}")?,
        None => write!(out, "null")?,
    }
    write!(out, "}}")
}

fn render_json(comparison: &ActionComparison, source: &str, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{{")?;
    write_key(out, "  ", "version")?;
    write_json_string(out, VERSION)?;
    writeln!(out, ",")?;
    write_key(out, "  ", "rangeUnit")?;
    write_json_string(out, RANGE_UNIT)?;
    writeln!(out, ",")?;
    write_key(out, "  ", "mode")?;
    write_json_string(out, "preview")?;
    writeln!(out, ",")?;
    writeln!(out, "  \"enforced\": false,")?;
    write_key(out, "  ", "source")?;
    write_json_string(out, source)?;
    writeln!(out, ",")?;

    let detection = comparison.detection();
    writeln!(out, "  \"detection\": {{")?;
    write_key(out, "    ", "activationIdentity")?;
    write_json_string(out, detection.activation_identity())?;
    writeln!(out, ",")?;
    write_key(out, "    ", "profile")?;
    match detection.profile() {
        Some(profile) => write_json_string(out, profile.as_str())?,
        None => write!(out, "null")?,
    }
    writeln!(out, ",")?;
    writeln!(out, "    \"detectorCount\": {}", detection.detector_count())?;
    writeln!(out, "  }},")?;

    writeln!(out, "  \"policies\": [")?;
    let sides = comparison.sides();
    for (index, side) in sides.iter().enumerate() {
        write!(out, "    {{\"label\": ")?;
        write_json_string(out, &label(index))?;
        write!(out, ", \"kind\": ")?;
        write_json_string(out, side.binding().kind())?;
        write!(out, ", \"documentSha256\": ")?;
        match side.binding().document_sha256_hex() {
            Some(hex) => write_json_string(out, &hex)?,
            None => write!(out, "null")?,
        }
        let counts = side.counts();
        writeln!(
            out,
            ", \"counts\": {{\"redact\": {}, \"block\": {}, \"warn\": {}, \"allow\": {}}}}}{}",
            counts.redact(),
            counts.block(),
            counts.warn(),
            counts.allow(),
            separator(index, sides.len()),
        )?;
    }
    writeln!(out, "  ],")?;

    writeln!(out, "  \"findingCount\": {},", comparison.findings().len())?;
    writeln!(out, "  \"changedCount\": {},", comparison.changed_count())?;
    if comparison.findings().is_empty() {
        writeln!(out, "  \"findings\": []")?;
    } else {
        writeln!(out, "  \"findings\": [")?;
    }
    let findings = comparison.findings();
    for (position, compared) in findings.iter().enumerate() {
        let finding = compared.finding();
        writeln!(out, "    {{")?;
        write_key(out, "      ", "id")?;
        write_json_string(out, finding.id())?;
        writeln!(out, ",")?;
        write_key(out, "      ", "type")?;
        write_json_string(out, finding.type_name())?;
        writeln!(out, ",")?;
        write_key(out, "      ", "detector")?;
        write_json_string(out, finding.detector())?;
        writeln!(out, ",")?;
        write_key(out, "      ", "confidence")?;
        write_json_string(out, finding.confidence().as_str())?;
        writeln!(out, ",")?;
        write_key(out, "      ", "obfuscation")?;
        write_json_string(out, finding.obfuscation().as_str())?;
        writeln!(out, ",")?;
        writeln!(out, "      \"start\": {},", finding.range().start())?;
        writeln!(out, "      \"end\": {},", finding.range().end())?;
        writeln!(out, "      \"differs\": {},", compared.differs())?;
        writeln!(out, "      \"decisions\": [")?;
        let decisions = compared.decisions();
        for (index, decision) in decisions.iter().enumerate() {
            write!(out, "        ")?;
            write_decision(out, decision)?;
            writeln!(out, "{}", separator(index, decisions.len()))?;
        }
        writeln!(out, "      ]")?;
        writeln!(out, "    }}{}", separator(position, findings.len()))?;
    }
    if !findings.is_empty() {
        writeln!(out, "  ]")?;
    }
    writeln!(out, "}}")
}
