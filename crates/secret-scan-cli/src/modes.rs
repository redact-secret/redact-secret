//! The check and redact modes.
//!
//! Both modes delegate every detection, policy, and redaction decision to the
//! canonical core. Standard input is streamed through an
//! [`IncrementalSanitizer`] because a credential may straddle any chunk
//! boundary; a file is read whole under the same total-input limit. Neither
//! path ever opens its input for writing.
//!
//! Retention is the other invariant. On every failure the streaming driver
//! either propagates a core error, which the core has already discarded
//! behind, or aborts the session itself, which discards what the session was
//! holding. A partial read, a decoding failure, and a closed downstream pipe
//! all take the second path.

use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use redact_secret::{
    ActionComparison, ActionPolicy, ComparedPolicy, DefaultPolicy, DetectorRegistry, Finding,
    IncrementalPolicy, IncrementalSanitizer, Policy, ScanResult, compare_action_policies,
    default_placeholder_formatter, load_action_policy, load_ruleset, scan, scan_and_redact,
};

use crate::args::Source;
use crate::failure::Failure;
use crate::input::{Utf8Stream, read_action_policy_bytes, read_file_bytes, read_file_text};
use crate::limits::{READ_CHUNK_BYTES, incremental_limits};
use crate::report::{Report, SafeFinding};

/// Reads `path` as raw ruleset bytes and validates that it parses, so a
/// malformed `--ruleset` file fails the whole run before any source is
/// touched rather than surfacing as a per-source failure.
///
/// The core, not the CLI, performs every grammar and cost-bound check
/// (`redact_secret::load_ruleset`); this only reads the file and confirms
/// the read bytes are loadable at all. Every source scan later re-parses
/// the same bytes: [`check`] builds one registry from them and reuses it
/// for every file (issue #1059).
///
/// # Errors
///
/// [`Failure::ReadFailed`] when the file cannot be read, and
/// [`Failure::Ruleset`] when it does not parse.
pub fn load_ruleset_file(path: &Path) -> Result<Vec<u8>, Failure> {
    let bytes = read_file_bytes(path)?;
    load_ruleset(&bytes).map_err(Failure::from)?;
    Ok(bytes)
}

/// Reads `path` and loads the action policy it holds, so a rejected
/// `--action-policy` file fails the whole run before any source is touched
/// rather than surfacing as a per-source failure.
///
/// The core, not the CLI, performs every size, grammar and vocabulary check
/// (`redact_secret::load_action_policy`). The read is bounded by the core's
/// own limit plus one byte, so an oversized file is rejected by the core with
/// its fixed class.
///
/// # Errors
///
/// [`Failure::ReadFailed`] when the file cannot be read, and
/// [`Failure::ActionPolicy`] when the core rejects it.
pub fn load_action_policy_file(path: &Path) -> Result<ActionPolicy, Failure> {
    let bytes = read_action_policy_bytes(path)?;
    load_action_policy(&bytes).map_err(Failure::from)
}

/// The whole-input policy for a run: the loaded action policy, or the default.
fn whole_policy(action_policy: Option<&ActionPolicy>) -> &dyn Policy {
    match action_policy {
        Some(policy) => policy,
        None => &DefaultPolicy,
    }
}

/// The incremental policy a streamed session binds at construction.
fn session_policy(action_policy: Option<&ActionPolicy>) -> Box<dyn IncrementalPolicy> {
    match action_policy {
        Some(policy) => Box::new(policy.clone()),
        None => Box::new(DefaultPolicy),
    }
}

/// Creates the streaming session both modes use: the full built-in set with the
/// run's PII selection, the run's policy, and the default placeholder
/// formatter.
fn stream_session(
    selection: &redact_secret::PiiSelection,
    action_policy: Option<&ActionPolicy>,
) -> Result<IncrementalSanitizer, Failure> {
    Ok(
        IncrementalSanitizer::with_built_in_and_pii_policy_and_formatter(
            incremental_limits()?,
            selection,
            session_policy(action_policy),
            Box::new(default_placeholder_formatter),
        )?,
    )
}

/// Builds a registry over the built-in detectors, plus every detector
/// `ruleset` declares when given.
fn registry_for(
    ruleset: Option<&[u8]>,
    selection: &redact_secret::PiiSelection,
) -> Result<DetectorRegistry, Failure> {
    let custom = match ruleset {
        Some(bytes) => load_ruleset(bytes).map_err(Failure::from)?,
        None => Vec::new(),
    };
    Ok(DetectorRegistry::with_built_in_and_pii_custom(
        selection, custom,
    )?)
}

/// Scans every source and returns the safe report for the whole run.
///
/// A source that fails is recorded as a failure and the remaining sources are
/// still scanned: a caller that passed a directory of files learns about all
/// of them, and the run still exits as a failure.
pub fn check(
    sources: &[Source],
    stdin: &mut dyn Read,
    ruleset: Option<&[u8]>,
    action_policy: Option<&ActionPolicy>,
    selection: &redact_secret::PiiSelection,
) -> Report {
    let mut report = Report::new();
    // Built on the first file and reused for the rest: `scan` only borrows
    // it, and building it costs more than scanning a small file. A build
    // failure is recorded against the file that hit it and retried for the
    // next one, so it is reported per file as it always was.
    let mut registry = None;
    for source in sources {
        let identity = source.identity();
        match check_source(
            source,
            stdin,
            ruleset,
            action_policy,
            selection,
            &mut registry,
        ) {
            Ok(findings) => report.push_source(identity, findings),
            Err(failure) => report.push_failure(identity, failure),
        }
    }
    report
}

fn check_source(
    source: &Source,
    stdin: &mut dyn Read,
    ruleset: Option<&[u8]>,
    action_policy: Option<&ActionPolicy>,
    selection: &redact_secret::PiiSelection,
    registry: &mut Option<DetectorRegistry>,
) -> Result<Vec<SafeFinding>, Failure> {
    match source {
        // `args::parse` refuses `--ruleset` combined with standard input
        // (its incremental session accepts no custom detector), so `ruleset`
        // is always `None` on this path; nothing here needs to branch on it.
        Source::Stdin => {
            let mut session = stream_session(selection, action_policy)?;
            // Check mode never emits text. The sanitized text each closed
            // unit produces is dropped with the result that carried it.
            stream(stdin, &mut session, &mut |_sanitized| Ok(()))
        }
        Source::File(path) => check_file(path, ruleset, action_policy, selection, registry),
    }
}

fn check_file(
    path: &Path,
    ruleset: Option<&[u8]>,
    action_policy: Option<&ActionPolicy>,
    selection: &redact_secret::PiiSelection,
    registry: &mut Option<DetectorRegistry>,
) -> Result<Vec<SafeFinding>, Failure> {
    let registry = match registry {
        Some(registry) => registry,
        empty => empty.insert(registry_for(ruleset, selection)?),
    };
    let text = read_file_text(path)?;
    let findings = scan(&text, registry, whole_policy(action_policy))?;
    drop(text);
    Ok(collect(&findings))
}

/// Reads `path` whole and compares the baseline and every candidate policy
/// over one detection pass (`redact_secret::compare_action_policies`).
///
/// This is an observation. It reads the file, detects once, and evaluates each
/// policy on the same finalized findings; nothing is redacted and nothing is
/// written. Standard input is never compared: it is streamed through an
/// incremental session under enforcement, and a comparison must not change that
/// path's callback count, order or finalization.
///
/// # Errors
///
/// Every failure that stops the run, with no partial comparison: the file read,
/// the registry build, and every core error `compare_action_policies` reports.
pub fn compare(
    path: &Path,
    ruleset: Option<&[u8]>,
    baseline: Option<&ActionPolicy>,
    candidates: &[ActionPolicy],
    selection: &redact_secret::PiiSelection,
) -> Result<ActionComparison, Failure> {
    let registry = registry_for(ruleset, selection)?;
    let text = read_file_text(path)?;
    let mut sides: Vec<ComparedPolicy<'_>> = Vec::with_capacity(1 + candidates.len());
    sides.push(match baseline {
        Some(policy) => ComparedPolicy::ActionPolicy(policy),
        None => ComparedPolicy::Default,
    });
    sides.extend(candidates.iter().map(ComparedPolicy::ActionPolicy));
    let comparison = compare_action_policies(&text, &registry, &sides)?;
    drop(text);
    Ok(comparison)
}

/// Writes the sanitized form of `source` to `out`.
///
/// The input is read, never written: standard input is consumed and a file is
/// opened read-only, so redaction cannot modify its input in place.
///
/// Standard input is sanitized as it streams, which means a failure part way
/// through leaves the units already emitted on `out`. That prefix is
/// sanitized — every unit is redacted before it is written — but it is not the
/// whole input, so a caller must check the outcome before treating the output
/// as complete. Buffering the whole stream until success would trade that for
/// unbounded memory, which is the thing streaming exists to avoid.
///
/// # Errors
///
/// Returns the failure that stopped the run. Every one of them leaves the
/// session holding nothing.
pub fn redact(
    source: &Source,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    ruleset: Option<&[u8]>,
    action_policy: Option<&ActionPolicy>,
    selection: &redact_secret::PiiSelection,
) -> Result<(), Failure> {
    match source {
        // `args::parse` refuses `--ruleset` combined with standard input;
        // see `check_source`'s identical note.
        Source::Stdin => {
            let mut session = stream_session(selection, action_policy)?;
            stream(stdin, &mut session, &mut |sanitized| {
                write_text(out, sanitized)
            })?;
            Ok(())
        }
        Source::File(path) => {
            let registry = registry_for(ruleset, selection)?;
            let text = read_file_text(path)?;
            let result: ScanResult = scan_and_redact(
                &text,
                &registry,
                whole_policy(action_policy),
                &default_placeholder_formatter,
            )?;
            drop(text);
            write_text(out, result.text())
        }
    }
}

/// Drives `session` over everything `reader` produces, handing each closed
/// unit's sanitized text to `emit` and collecting its safe metadata.
///
/// # Errors
///
/// - [`Failure::ReadFailed`] when a read fails. A read that returns fewer
///   bytes than requested is not a failure; the loop simply continues, and an
///   interrupted read is retried.
/// - [`Failure::NotUtf8`] when the bytes are not valid UTF-8, including a
///   sequence left incomplete at end of input.
/// - Whatever `emit` returns, which for redaction is
///   [`Failure::WriteFailed`] when the downstream pipe has closed.
/// - Every [`IncrementalSanitizer::append`] and
///   [`IncrementalSanitizer::finalize`] failure, including the explicit
///   input, buffer, token, and multiline limits.
///
/// Whichever arrives first, the session is left holding no plaintext: the
/// core discards behind its own errors, and this function aborts the session
/// behind the host's.
fn stream(
    reader: &mut dyn Read,
    session: &mut IncrementalSanitizer,
    emit: &mut dyn FnMut(&str) -> Result<(), Failure>,
) -> Result<Vec<SafeFinding>, Failure> {
    let mut decoder = Utf8Stream::new();
    let mut findings: Vec<SafeFinding> = Vec::new();
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];

    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(abort_with(session, Failure::ReadFailed)),
        };
        let text = match decoder.push(&buffer[..read]) {
            Ok(text) => text,
            Err(failure) => return Err(abort_with(session, failure)),
        };

        let result = session.append(&text)?;
        drop(text);
        findings.extend(collect(result.findings()));
        if let Err(failure) = emit(result.text()) {
            drop(result);
            return Err(abort_with(session, failure));
        }
    }

    if let Err(failure) = decoder.finish() {
        return Err(abort_with(session, failure));
    }

    let result = session.finalize()?;
    findings.extend(collect(result.findings()));
    emit(result.text())?;
    Ok(findings)
}

/// Discards whatever the session is holding and returns `failure` unchanged.
///
/// A session the core has already failed refuses the abort; that refusal is
/// ignored on purpose, because the core discarded when it failed.
fn abort_with(session: &mut IncrementalSanitizer, failure: Failure) -> Failure {
    let _ = session.abort();
    failure
}

fn collect(findings: &[Finding]) -> Vec<SafeFinding> {
    findings.iter().map(SafeFinding::from).collect()
}

fn write_text(out: &mut dyn Write, text: &str) -> Result<(), Failure> {
    out.write_all(text.as_bytes())
        .map_err(|_| Failure::WriteFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redact_secret::{SecretScanErrorCode, SessionState};

    /// A synthetic, revoked-shaped token. It matches the built-in GitHub
    /// detector's format and authenticates nothing.
    const SYNTHETIC_TOKEN: &str = "ghp_SYNTHETICREVOKED00000000000000000000";

    fn session() -> IncrementalSanitizer {
        IncrementalSanitizer::new(incremental_limits().unwrap()).unwrap()
    }

    /// A reader that yields one byte per call, so every multi-byte character
    /// and every credential in the fixture straddles a chunk boundary.
    struct Dribble<'a> {
        remaining: &'a [u8],
    }

    impl Read for Dribble<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            match (self.remaining.split_first(), buffer.is_empty()) {
                (Some((byte, rest)), false) => {
                    buffer[0] = *byte;
                    self.remaining = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    /// A reader that fails partway through, as an interrupted device would.
    struct FailAfter {
        remaining: usize,
    }

    impl Read for FailAfter {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::from(ErrorKind::BrokenPipe));
            }
            let written = self.remaining.min(buffer.len());
            buffer[..written].fill(b'a');
            self.remaining -= written;
            Ok(written)
        }
    }

    #[test]
    fn a_partial_read_still_sees_a_credential_that_straddles_it() {
        let input = format!("API_KEY={SYNTHETIC_TOKEN}\ntail\n");
        let mut reader = Dribble {
            remaining: input.as_bytes(),
        };
        let mut session = session();
        let mut sanitized = String::new();
        let findings = stream(&mut reader, &mut session, &mut |text| {
            sanitized.push_str(text);
            Ok(())
        })
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(sanitized, "API_KEY=<SECRET_1>\ntail\n");
        assert!(!sanitized.contains(SYNTHETIC_TOKEN));
        assert_eq!(session.state(), SessionState::Finalized);
    }

    #[test]
    fn a_failed_read_aborts_the_session() {
        let mut reader = FailAfter { remaining: 8 };
        let mut session = session();
        let failure = stream(&mut reader, &mut session, &mut |_| Ok(())).unwrap_err();

        assert_eq!(failure, Failure::ReadFailed);
        assert_eq!(session.state(), SessionState::Aborted);
    }

    #[test]
    fn invalid_utf8_aborts_the_session_and_reports_nothing_of_it() {
        let payload = [b'a', 0xff, 0xfe];
        let mut reader = &payload[..];
        let mut session = session();
        let failure = stream(&mut reader, &mut session, &mut |_| Ok(())).unwrap_err();

        assert_eq!(failure, Failure::NotUtf8);
        assert_eq!(failure.code(), "NOT_UTF8");
        assert_eq!(session.state(), SessionState::Aborted);
    }

    #[test]
    fn a_truncated_character_at_end_of_input_aborts_the_session() {
        let payload = [b'a', b'\n', 0xe2, 0x82];
        let mut reader = &payload[..];
        let mut session = session();
        let failure = stream(&mut reader, &mut session, &mut |_| Ok(())).unwrap_err();

        assert_eq!(failure, Failure::NotUtf8);
        assert_eq!(session.state(), SessionState::Aborted);
    }

    #[test]
    fn a_closed_downstream_pipe_aborts_the_session() {
        let input = format!("API_KEY={SYNTHETIC_TOKEN}\nmore\n");
        let mut reader = input.as_bytes();
        let mut session = session();
        let failure = stream(&mut reader, &mut session, &mut |_| {
            Err(Failure::WriteFailed)
        })
        .unwrap_err();

        assert_eq!(failure, Failure::WriteFailed);
        assert_eq!(session.state(), SessionState::Aborted);
        assert!(
            !format!("{session:?}").contains(SYNTHETIC_TOKEN),
            "the aborted session must not describe what it was holding",
        );
    }

    #[test]
    fn an_open_construct_over_the_token_limit_fails_the_session() {
        let oversized = format!("API_KEY={}\n", "a".repeat(crate::limits::MAX_TOKEN_BYTES));
        let mut reader = oversized.as_bytes();
        let mut session = session();
        let failure = stream(&mut reader, &mut session, &mut |_| Ok(())).unwrap_err();

        assert_eq!(
            failure,
            Failure::Core(SecretScanErrorCode::TokenLimitExceeded)
        );
        assert_eq!(session.state(), SessionState::Failed);
    }

    #[test]
    fn streamed_findings_carry_metadata_and_no_matched_text() {
        let input = format!("API_KEY={SYNTHETIC_TOKEN}\n");
        let mut reader = input.as_bytes();
        let mut session = session();
        let findings = stream(&mut reader, &mut session, &mut |_| Ok(())).unwrap();

        let mut rendered = Vec::new();
        let mut diagnostics = Vec::new();
        let mut report = Report::new();
        report.push_source("<stdin>".to_owned(), findings);
        report.write_text(&mut rendered, &mut diagnostics).unwrap();

        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("github_token"));
        assert!(!rendered.contains(SYNTHETIC_TOKEN));
    }
}
