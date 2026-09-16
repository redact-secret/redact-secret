//! Twilio Auth Token and API Key Secret detection.
//!
//! Twilio's own request-authentication documentation
//! (`https://www.twilio.com/docs/usage/requests-to-twilio`) and API-key
//! documentation (`https://www.twilio.com/docs/iam/api-keys`) publish no
//! character-class grammar for any of these four values -- only their
//! functional roles (an Account SID identifies the account, an Auth Token
//! authenticates as it; an API Key SID is a username, an API Key Secret is
//! its password) and placeholder examples of the general shape
//! (`ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`). Consulted only as external
//! behavioral references per `AGENTS.md`, gitleaks's `twilio-api-key` rule
//! and trufflehog 3.97.4's independent `twilio` and `twilioapikey`
//! detectors both converge on the same four community-observed shapes; no
//! code from either project is reproduced here, and this module's matching
//! and context-gating logic is authored independently.
//!
//! Grammar (frozen before implementation, per issue #303):
//!
//! - Account SID: the literal `AC`, then exactly 32 bytes of
//!   [`is_lower_hex`] (`[0-9a-f]`) -- 34 bytes total.
//! - Auth Token: exactly 32 bare [`is_lower_hex`] bytes, no prefix or other
//!   marker.
//! - API Key SID: the literal `SK`, then exactly 32 bytes of
//!   [`pattern::is_alnum`] (`[0-9A-Za-z]`) -- 34 bytes total.
//! - API Key Secret: exactly 32 bare [`pattern::is_alnum`] bytes, no prefix
//!   or other marker.
//!
//! All four are bounded on both sides by a byte outside their own alphabet
//! (or the edge of input), so a longer or shorter run is rejected rather
//! than truncated, matching every other fixed-length grammar in this crate.
//!
//! ## Scope and context gating
//!
//! Per the issue's explicit scope: an Account SID or API Key SID identifies
//! an account or a key, but proves nothing about what accompanies it, so
//! this module never emits a finding for either alone -- doing so would
//! repeat the exact mistake the issue calls out in gitleaks's rule, which
//! flags a bare API Key SID as if it were equivalent credential coverage.
//! Both identifiers are used here only as an internal same-line context
//! signal for the two secret-bearing detectors below.
//!
//! An Auth Token and an API Key Secret are themselves unmarked: a bare
//! 32-byte lowercase-hex run is indistinguishable by shape alone from an
//! MD5 digest, a hyphen-stripped UUID, or any other opaque hex blob, and a
//! bare 32-byte mixed-alphanumeric run is indistinguishable from countless
//! unrelated tokens. Neither format alone is "reliable Twilio context" in
//! the issue's own words. Each detector therefore requires, on the same
//! line as the candidate:
//!
//! - the paired identifier (an Account SID for an Auth Token, an API Key
//!   SID for an API Key Secret) -- [`Confidence::High`], the strongest
//!   available signal short of a network credential check this core must
//!   never perform; or, absent that,
//! - a case-insensitive `twilio` substring anywhere on the line (covering
//!   `TWILIO_AUTH_TOKEN=...`, `# twilio api key secret`, and similar naming
//!   that does not happen to include the paired identifier) --
//!   [`Confidence::Medium`], a weaker keyword heuristic.
//!
//! "Same line" is deliberately the same processing unit the incremental
//! sanitizer hands a detector one line at a time (`IncrementalSanitizer`
//! finalizes at each `\n` unless a multiline construct is open, and neither
//! format here declares one): scoping context to it keeps whole-input and
//! incremental scanning behaviorally identical. A context-bearing Account
//! SID or API Key SID on a *different* line -- for example a JSON object
//! with `accountSid` and `authToken` as separate top-level fields -- is a
//! documented, known false negative, the same tradeoff every other
//! line-scoped heuristic in this crate already makes (compare
//! [`super::generic_token::has_open_contextual_assignment`], which is also
//! scoped to the tail of a single retained line).
//!
//! A candidate that is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded even when context
//! matches: unlike every other provider grammar in this crate, this one has
//! no structural marker of its own to keep a masked or placeholder value
//! (`TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`) from otherwise
//! matching the bare alphabet outright.
//!
//! ## Action
//!
//! Both finding types are `Specificity::Provider` but intentionally left out
//! of `policy::ALWAYS_REDACT_TYPES`: the confidence gradient above is real
//! evidence-strength information, and `DefaultPolicy`'s existing
//! confidence-gated fallback (redact at `High`, warn otherwise) already
//! reflects it -- collapsing a keyword-only `Medium` match to an
//! unconditional redact would overstate the weaker heuristic's reliability.

use crate::detectors::pattern::{self, Alphabet, RunLength};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `[0-9a-f]`: the Account SID and Auth Token alphabet.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f'
}

const SECRET_LEN: usize = 32;
const CONTEXT_KEYWORD: &str = "twilio";

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line; it never affects context
/// lookups, since neither the identifier nor the `twilio` keyword scan
/// treats `\r` specially). Each byte of `input` belongs to exactly one
/// yielded range, so a caller that does bounded work per line does bounded
/// work overall, not bounded work per candidate found within a line.
fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// `true` when `needle` (ASCII, case-insensitive) occurs anywhere in `line`.
fn line_contains_ci(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    needle.len() <= bytes.len()
        && (0..=bytes.len() - needle.len()).any(|pos| text::starts_with_ci(line, pos, needle))
}

/// `true` when `line` carries a boundary-checked `prefix` + exactly
/// [`SECRET_LEN`] `alphabet` bytes -- an Account SID or API Key SID used
/// only as a context signal, never itself emitted as a candidate.
fn line_has_paired_identifier(line: &str, prefix: &str, alphabet: Alphabet) -> bool {
    !pattern::scan_prefixed_runs(
        line,
        &[prefix],
        RunLength::Exact(SECRET_LEN),
        alphabet,
        alphabet,
    )
    .is_empty()
}

/// Every non-overlapping, boundary-checked bare run of exactly
/// [`SECRET_LEN`] `alphabet` bytes, left to right. A run longer or shorter
/// than [`SECRET_LEN`] is skipped whole, the same "no truncation" guarantee
/// [`super::pattern::scan_prefixed_runs`] gives a prefixed grammar.
///
/// `boundary` is deliberately a separate, wider alphabet than `alphabet`:
/// the Auth Token's own alphabet ([`is_lower_hex`]) excludes uppercase, so
/// without a wider boundary check the two uppercase bytes of an adjacent
/// `AC`-prefixed Account SID would not block a match, and the SID's own
/// hex body would be misread as a second, independent bare candidate.
/// [`pattern::is_alnum`] is passed as `boundary` by both detectors below
/// for exactly this reason, mirroring how [`super::aws`] and
/// [`super::sendgrid`] already widen their own boundary alphabets past
/// their match alphabet for the same class of adjacency.
fn scan_bare_secret_runs(
    input: &str,
    alphabet: Alphabet,
    boundary: Alphabet,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !alphabet(bytes[start]) {
            start += 1;
            continue;
        }
        let run_end = ends[start];
        if run_end - start == SECRET_LEN && pattern::boundary_ok(bytes, start, run_end, boundary) {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

/// Shared implementation for both context-gated detectors below.
///
/// Processes one line at a time: a line's bare candidates, its paired-
/// identifier check, and its `twilio`-keyword check are each computed once
/// per line, not once per candidate, so a line packed with many candidates
/// costs no more than a line with one -- the same bounded-work guarantee
/// [`scan_bare_secret_runs`] gives a single alphabet run.
fn detect_context_gated(
    input: &str,
    alphabet: Alphabet,
    boundary: Alphabet,
    identifier_prefix: &str,
    identifier_alphabet: Alphabet,
    type_name: &str,
    identifier_signal: &str,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (line_start, line_end) in lines(input) {
        let line = &input[line_start..line_end];
        let raw_matches = scan_bare_secret_runs(line, alphabet, boundary);
        if raw_matches.is_empty() {
            continue;
        }

        let (confidence, signal) =
            if line_has_paired_identifier(line, identifier_prefix, identifier_alphabet) {
                (Confidence::High, identifier_signal)
            } else if line_contains_ci(line, CONTEXT_KEYWORD) {
                (Confidence::Medium, "twilio-keyword-cooccurrence")
            } else {
                continue;
            };

        for (relative_start, relative_end) in raw_matches {
            if text::is_repeated_character_filler(&line[relative_start..relative_end]) {
                continue;
            }
            let Some(range) =
                ByteRange::new(line_start + relative_start, line_start + relative_end)
            else {
                continue;
            };
            candidates.push(
                Candidate::new(type_name, confidence, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals([signal]),
            );
        }
    }
    candidates
}

/// Detects a Twilio Auth Token: a bare 32-byte lowercase-hex run on the same
/// line as either an Account SID or the word `twilio`.
pub(super) struct TwilioAuthTokenDetector;

impl Detector for TwilioAuthTokenDetector {
    fn id(&self) -> &'static str {
        "twilio-auth-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(detect_context_gated(
            input,
            is_lower_hex,
            pattern::is_alnum,
            "AC",
            is_lower_hex,
            "twilio_auth_token",
            "twilio-account-sid-cooccurrence",
        ))
    }
}

/// Detects a Twilio API Key Secret: a bare 32-byte mixed-alphanumeric run on
/// the same line as either an API Key SID or the word `twilio`.
pub(super) struct TwilioApiKeySecretDetector;

impl Detector for TwilioApiKeySecretDetector {
    fn id(&self) -> &'static str {
        "twilio-api-key-secret"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(detect_context_gated(
            input,
            pattern::is_alnum,
            pattern::is_alnum,
            "SK",
            pattern::is_alnum,
            "twilio_api_key_secret",
            "twilio-api-key-sid-cooccurrence",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT_SID: &str = "AC0123456789abcdef0123456789abcde0";
    const AUTH_TOKEN: &str = "fedcba9876543210fedcba9876543210";
    const API_KEY_SID: &str = "SKaB3dE5gH7jK9mN1pQ3sT5vW7yZ9AbC3d";
    const API_KEY_SECRET: &str = "zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fE";

    fn detect_auth_token(input: &str) -> Vec<Candidate> {
        TwilioAuthTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_api_key_secret(input: &str) -> Vec<Candidate> {
        TwilioApiKeySecretDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn account_sid_and_auth_token_fixtures_are_exactly_thirty_four_and_thirty_two_bytes() {
        assert_eq!(ACCOUNT_SID.len(), 34);
        assert_eq!(AUTH_TOKEN.len(), 32);
        assert_eq!(API_KEY_SID.len(), 34);
        assert_eq!(API_KEY_SECRET.len(), 32);
    }

    #[test]
    fn detects_an_auth_token_alongside_an_account_sid_at_high_confidence() {
        let input = format!("{ACCOUNT_SID} {AUTH_TOKEN}");
        let candidates = detect_auth_token(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "twilio_auth_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(AUTH_TOKEN).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + AUTH_TOKEN.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_auth_token_named_by_the_twilio_keyword_at_medium_confidence() {
        let input = format!("TWILIO_AUTH_TOKEN={AUTH_TOKEN}");
        let candidates = detect_auth_token(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        let start = input.rfind(AUTH_TOKEN).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + AUTH_TOKEN.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_auth_token_with_no_context() {
        assert_eq!(detect_auth_token(AUTH_TOKEN).len(), 0);
    }

    #[test]
    fn rejects_an_auth_token_whose_context_is_on_a_different_line() {
        let input = format!("{ACCOUNT_SID}\n{AUTH_TOKEN}\n");
        assert_eq!(detect_auth_token(&input).len(), 0);
    }

    #[test]
    fn rejects_an_uppercase_hex_run() {
        let upper: String = AUTH_TOKEN.to_ascii_uppercase();
        assert_eq!(detect_auth_token(&format!("twilio {upper}")).len(), 0);
    }

    #[test]
    fn rejects_a_run_one_byte_short_of_the_required_length() {
        let short = &AUTH_TOKEN[..AUTH_TOKEN.len() - 1];
        assert_eq!(detect_auth_token(&format!("twilio {short}")).len(), 0);
    }

    #[test]
    fn rejects_a_run_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{AUTH_TOKEN}0");
        assert_eq!(detect_auth_token(&format!("twilio {long}")).len(), 0);
    }

    #[test]
    fn rejects_a_repeated_character_filler_value() {
        assert_eq!(
            detect_auth_token(&format!("twilio {}", "0".repeat(SECRET_LEN))).len(),
            0
        );
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert_eq!(
            detect_auth_token("twilio TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}").len(),
            0
        );
    }

    #[test]
    fn does_not_flag_a_bare_account_sid_by_itself() {
        assert_eq!(detect_auth_token(ACCOUNT_SID).len(), 0);
    }

    #[test]
    fn does_not_flag_the_account_sids_own_body_as_a_second_candidate() {
        let input = format!("{ACCOUNT_SID} {AUTH_TOKEN}");
        let candidates = detect_auth_token(&input);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn detects_an_api_key_secret_alongside_an_api_key_sid_at_high_confidence() {
        let input = format!("{API_KEY_SID} {API_KEY_SECRET}");
        let candidates = detect_api_key_secret(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "twilio_api_key_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(API_KEY_SECRET).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + API_KEY_SECRET.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_api_key_secret_named_by_the_twilio_keyword_at_medium_confidence() {
        let input = format!("{{\"twilioApiKeySecret\": \"{API_KEY_SECRET}\"}}");
        let candidates = detect_api_key_secret(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        let start = input.rfind(API_KEY_SECRET).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + API_KEY_SECRET.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_api_key_secret_with_no_context() {
        assert_eq!(detect_api_key_secret(API_KEY_SECRET).len(), 0);
    }

    #[test]
    fn rejects_an_api_key_secret_whose_context_is_on_a_different_line() {
        let input = format!("{API_KEY_SID}\n{API_KEY_SECRET}\n");
        assert_eq!(detect_api_key_secret(&input).len(), 0);
    }

    #[test]
    fn does_not_flag_a_bare_api_key_sid_by_itself() {
        assert_eq!(detect_api_key_secret(API_KEY_SID).len(), 0);
    }

    #[test]
    fn rejects_a_placeholder_style_run_of_x_characters() {
        assert_eq!(
            detect_api_key_secret(&format!("twilio {}", "X".repeat(SECRET_LEN))).len(),
            0
        );
    }

    #[test]
    fn finds_a_qualified_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\ntwilio {AUTH_TOKEN}\r\n");
        let candidates = detect_auth_token(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(AUTH_TOKEN).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + AUTH_TOKEN.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("{ACCOUNT_SID} {AUTH_TOKEN}");
        assert_eq!(detect_auth_token(&input), detect_auth_token(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        // A single line with no `AC...` identifier and no `twilio` keyword,
        // packed with thousands of candidate-shaped runs: per-line (not
        // per-candidate) context checks keep this linear instead of
        // quadratic in the number of candidates on one line.
        let input = format!("{AUTH_TOKEN} ").repeat(10_000);
        assert_eq!(detect_auth_token(&input).len(), 0);
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("{ACCOUNT_SID} {AUTH_TOKEN} {AUTH_TOKEN}");
        let candidates = detect_auth_token(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::High)
        );
    }
}
