//! Dynatrace access and platform token detection (issue #1032, handoff
//! `docs/audits/evidence/1014/dynatrace.md`).
//!
//! | Part | Grammar | Evidence |
//! | --- | --- | --- |
//! | Prefix | `dt0` + `c` or `s` + 2 digits | docs prefix table (`dt0s01`…`dt0s16`) + `dt0c01` placeholder (R4), T1 |
//! | Separator | `.` | docs, T1 |
//! | Public portion | exactly 24 `[A-Z2-7]` | docs length + `dynatrace-operator` `dttoken` generator (`base32.StdEncoding`, R1), T1 |
//! | Separator | `.` | docs, T1 |
//! | Secret portion | exactly 64 `[A-Z2-7]` | docs length + provider generator (R1), T1 |
//!
//! 96 bytes in total. The span is the whole token, prefix and public portion
//! included, so a redacted output never keeps a half-token. The token
//! identifier alone (`<prefix>.<24>`) is documented as safe to log and is
//! never claimed: it fails the fixed width.
//!
//! Boundaries: the byte before `dt0` must not be `[A-Za-z0-9_.-]`, except
//! that a percent-encoded space (`%20`) directly before it is accepted,
//! because Dynatrace's OpenTelemetry exporter setup writes the header as
//! `Authorization=Api-Token%20<token>`. The byte after the token must not be
//! `[A-Za-z0-9_-]`, and a `.` after it rejects only when it continues into
//! another `[A-Za-z0-9_-]` byte, so a sentence-ending period still matches
//! and a glued `.x` does not. A lowercased copy, a portion with `0`, `1`,
//! `8` or `9`, and a future format of another width are accepted false
//! negatives; an unrelated value of exactly this layout is the accepted
//! false positive (none is known).

use crate::detectors::pattern;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "dynatrace-token";
const TYPE: &str = "dynatrace_token";
const PREFIX: &str = "dt0";
/// The only literal every match contains, for the shared prefilter.
pub(super) const REQUIRED_LITERALS: &[&str] = &[PREFIX];

const PUBLIC_LEN: usize = 24;
const SECRET_LEN: usize = 64;
/// `dt0` + type letter + 2 digits + `.` + 24 + `.` + 64.
const TOKEN_LEN: usize = PREFIX.len() + 3 + 1 + PUBLIC_LEN + 1 + SECRET_LEN;
const SIGNALS: [&str; 2] = [
    "dynatrace-documented-format",
    "dynatrace-generator-alphabet",
];

/// `[A-Z2-7]`: the RFC 4648 base32 alphabet `base32.StdEncoding` emits.
fn is_base32(byte: u8) -> bool {
    byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)
}

/// `token` is exactly the documented three-part layout.
fn has_layout(token: &[u8]) -> bool {
    let Some(rest) = token.strip_prefix(PREFIX.as_bytes()) else {
        return false;
    };
    let (kind, rest) = rest.split_at(3);
    let (public, secret) = rest.split_at(1 + PUBLIC_LEN);
    matches!(kind[0], b'c' | b's')
        && kind[1..].iter().all(u8::is_ascii_digit)
        && public[0] == b'.'
        && public[1..].iter().copied().all(is_base32)
        && secret[0] == b'.'
        && secret[1..].iter().copied().all(is_base32)
}

fn leading_ok(bytes: &[u8], start: usize) -> bool {
    start == 0 || !pattern::is_alnum_dash_dot(bytes[start - 1]) || bytes[..start].ends_with(b"%20")
}

fn trailing_ok(bytes: &[u8], end: usize) -> bool {
    match bytes.get(end) {
        None => true,
        Some(b'.') => !bytes
            .get(end + 1)
            .is_some_and(|&next| pattern::is_alnum_dash(next)),
        Some(&next) => !pattern::is_alnum_dash(next),
    }
}

/// Dynatrace `dt0[cs]NN.<24>.<64>` base32 tokens as `dynatrace_token`.
pub(super) struct DynatraceTokenDetector;

impl Detector for DynatraceTokenDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut from = 0;
        while let Some(start) = pattern::find_literal(bytes, PREFIX.as_bytes(), from) {
            let end = start + TOKEN_LEN;
            let matched = bytes.get(start..end).is_some_and(has_layout)
                && leading_ok(bytes, start)
                && trailing_ok(bytes, end);
            if let (true, Some(range)) = (matched, ByteRange::new(start, end)) {
                candidates.push(
                    Candidate::built_in(TYPE, Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(SIGNALS.iter().copied()),
                );
                from = end;
            } else {
                from = start + 1;
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// Synthetic low-entropy base32 filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(BASE32[(i * 7 + seed * 13 + i / 5) % BASE32.len()]))
            .collect()
    }

    fn token_with(kind: &str, public: usize, secret: usize) -> String {
        format!("dt0{kind}.{}.{}", filler(public, 1), filler(secret, 2))
    }

    fn token(kind: &str) -> String {
        token_with(kind, PUBLIC_LEN, SECRET_LEN)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        DynatraceTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), TYPE);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("DT_API_TOKEN={token}"),
            format!("export DT_API_TOKEN=\"{token}\""),
            format!("Authorization: Api-Token {token}"),
            format!("Authorization: Bearer {token}"),
            format!("OTEL_EXPORTER_OTLP_HEADERS=Authorization=Api-Token%20{token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("apiVersion: v1\nkind: Secret\ndata:\n  apiToken: {token}\n"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn classic_and_platform_tokens_are_detected_in_every_context() {
        for kind in ["c01", "s01", "s16"] {
            let token = token(kind);
            assert_eq!(token.len(), 96);
            for input in contexts(&token) {
                assert_single(&input, &token);
            }
        }
        assert_eq!(DynatraceTokenDetector.id(), "dynatrace-token");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let good = token("c01");
        let lower = good.replacen(&filler(PUBLIC_LEN, 1)[..1], "a", 1);
        let mut digit = good.clone();
        digit.replace_range(40..41, "8");
        for input in [
            token_with("c01", PUBLIC_LEN - 1, SECRET_LEN),
            token_with("c01", PUBLIC_LEN + 1, SECRET_LEN),
            token_with("c01", PUBLIC_LEN, SECRET_LEN - 1),
            token_with("c01", PUBLIC_LEN, SECRET_LEN + 1),
            token_with("x01", PUBLIC_LEN, SECRET_LEN),
            token_with("c1", PUBLIC_LEN, SECRET_LEN),
            good.replacen("dt0", "dt1", 1),
            good.replacen("dt0", "DT0", 1),
            lower,
            digit,
            format!("{}-{}", &good[..31], &good[32..]),
            format!("x{good}"),
            format!("_{good}"),
            format!(".{good}"),
            format!("{good}x"),
            format!("{good}.x"),
            format!("{good}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_dynatrace_text_is_not_claimed() {
        let identifier = format!("dt0s01.{}", filler(PUBLIC_LEN, 1));
        for input in [
            format!("created token {identifier} for ingest"),
            "curl -H \"Authorization: Api-Token dt0c01.abc123.abcdefg\"".to_owned(),
            "DT_API_TOKEN=${DT_API_TOKEN}".to_owned(),
            "dt0dt0dt0 dt0c dt0s01.".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = token("s01");
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert_eq!(detect(&format!("{token}\n{token}.")).len(), 2);
        assert!(detect(&token.repeat(100)).is_empty());
        assert!(detect(&"dt0".repeat(20_000)).is_empty());
        assert!(detect(&"dt0c01.".repeat(10_000)).is_empty());
    }
}
