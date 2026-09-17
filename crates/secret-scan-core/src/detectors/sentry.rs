//! Sentry user and organization auth token detection.
//!
//! Sentry's own authentication documentation
//! (`https://docs.sentry.io/api/auth/`,
//! `https://docs.sentry.io/account/auth-tokens/`) describes how personal
//! ("user") auth tokens and organization auth tokens are created and scoped,
//! but publishes no character-class grammar, prefix, or length for either
//! value. Consulted only as external behavioral references per `AGENTS.md`,
//! gitleaks 8.30.1's independent `sentry-user-token` and `sentry-org-token`
//! rules and trufflehog 3.97.4's independent `sentrytoken/v2` and
//! `sentryorgtoken` detectors converge on the same two prefixed shapes below;
//! no code from either project is reproduced here, and this module's
//! matching logic is authored independently.
//!
//! Grammar (frozen before implementation, per issue #306):
//!
//! - User auth token: the literal `sntryu_`, then an exact 64-byte run of
//!   [`is_lower_hex`] (`[0-9a-f]`) -- 71 bytes total.
//! - Organization auth token: the literal `sntrys_`, then the literal `eyJ`
//!   (the documented base64 encoding of a JSON object's opening `{"`, the
//!   same structural fact both reference scanners key their patterns on), a
//!   documented-minimum run of [`is_base64_std`] (`[A-Za-z0-9+/]`, matched
//!   maximally), up to two trailing `=` padding bytes, a literal `_`, and an
//!   exact 43-byte run of [`is_base64_std`] -- the unpadded base64 encoding
//!   of a 32-byte (256-bit) signature. Cross-referencing both reference
//!   scanners and independent reporting on the format, the payload
//!   (base64-decoded) is itself a JSON object carrying at least an `iat`
//!   (issued-at) claim and a `region_url` claim; this detector does not
//!   decode or parse it, treating the structural shape alone as sufficient.
//!
//! Both prefixes (`sntryu_`, `sntrys_`) are unambiguous provider markers, so
//! -- unlike Twilio's unmarked Auth Token and API Key Secret in
//! [`super::twilio`] -- neither detector here requires surrounding context to
//! classify a match; the shape alone is `Specificity::Provider`, matching
//! every other prefixed detector in this module.
//!
//! ## Payload length
//!
//! Sentry documents no length for the organization token's base64 payload,
//! and it is not fixed in practice: it is a base64-encoded JSON object whose
//! `region_url` claim varies in length with the account's region host name.
//! [`ORG_MIN_PAYLOAD_LEN`] is set to the base64 length of the smallest
//! plausible payload -- an `iat` claim alone, `{"iat":1700000000}`, 19 bytes,
//! 26 bytes of unpadded base64 -- rather than the roughly 156-byte payload
//! one real-world sample (cross-referenced from trufflehog's fixed
//! total-length pattern) happens to carry, so a shorter self-hosted region
//! URL, or a future payload shape, is still matched. There is no documented
//! upper bound, so the payload run is matched maximally.
//!
//! ## Legacy format: out of scope
//!
//! Sentry's legacy, pre-2024 API token (gitleaks's `sentry-access-token`,
//! trufflehog's `sentrytoken/v1`) is a bare 64-byte lowercase-hex run with no
//! distinguishing prefix at all -- indistinguishable by shape alone from an
//! ordinary SHA-256 digest or any other opaque hex blob, exactly the
//! "ambiguous unprefixed value" issue #306's acceptance criteria warn
//! requires reliable context to classify. Issue #306 scopes this work to the
//! dedicated *user and organization* token formats specifically (both of
//! which do carry a distinguishing prefix); a dedicated detector for the
//! unprefixed legacy format is out of scope here and is not added. A
//! qualified `name=value` assignment naming it (e.g. `SENTRY_AUTH_TOKEN=<64
//! hex bytes>`) still gets a lower-confidence, lower-specificity contextual
//! finding through the existing [`super::generic_token`] path regardless of
//! format -- the same overlap every other unmarked legacy format in this
//! registry already relies on (compare [`super::atlassian`]'s pre-2022
//! unprefixed token, or [`super::twilio`]'s Auth Token itself).
//!
//! A public Sentry DSN (`https://<public_key>@<host>/<project_id>`) and a
//! bare organization slug or project ID share no shape with either grammar
//! above and are not classified by either detector.

use crate::detectors::pattern::{self, RunLength, is_alnum_underscore};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `[0-9a-f]`: the user auth token's secret alphabet.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f'
}

/// `[A-Za-z0-9+/]`: standard (non-URL-safe) base64, no padding.
fn is_base64_std(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

const USER_PREFIX: &str = "sntryu_";
const USER_SECRET_LEN: usize = 64;

const ORG_PREFIX: &str = "sntrys_";
const ORG_JSON_MARKER: &str = "eyJ";
/// The base64 length of the smallest plausible JSON payload (an `iat` claim
/// alone); see the module documentation's "Payload length" section.
const ORG_MIN_PAYLOAD_LEN: usize = 26;
/// Base64 padding never runs longer than two `=` bytes.
const ORG_MAX_PADDING_LEN: usize = 2;
/// The unpadded base64 length of a 32-byte (256-bit) signature.
const ORG_SIGNATURE_LEN: usize = 43;

/// Recognizes a Sentry user auth token by its documented-in-practice
/// `sntryu_` prefix and exact 64-byte lowercase-hex secret. No surrounding
/// context is required to classify a match: like every other
/// `Specificity::Provider` detector in this module, the prefixed
/// exact-length shape is treated as specific enough on its own.
pub(super) struct SentryUserAuthTokenDetector;

impl Detector for SentryUserAuthTokenDetector {
    fn id(&self) -> &'static str {
        "sentry-user-auth-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &[USER_PREFIX],
            RunLength::Exact(USER_SECRET_LEN),
            is_lower_hex,
            is_alnum_underscore,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("sentry_user_auth_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["sentry-documented-prefix", "exact-length-hex-secret"]),
            );
        }
        Ok(candidates)
    }
}

/// Recognizes a Sentry organization auth token by its documented-in-practice
/// `sntrys_eyJ...` prefix, a minimum-length base64 JSON payload, a literal
/// `_` separator, and an exact 43-byte base64 signature. No surrounding
/// context is required, for the same reason as
/// [`SentryUserAuthTokenDetector`].
pub(super) struct SentryOrgAuthTokenDetector;

impl Detector for SentryOrgAuthTokenDetector {
    fn id(&self) -> &'static str {
        "sentry-org-auth-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let base64_ends = pattern::run_ends(bytes, is_base64_std);
        let mut candidates = Vec::new();
        let mut start = 0usize;

        while start < bytes.len() {
            if !bytes[start..].starts_with(ORG_PREFIX.as_bytes()) {
                start += 1;
                continue;
            }

            let Some(end) = org_match_at(bytes, &base64_ends, start) else {
                start += 1;
                continue;
            };

            if pattern::boundary_ok(bytes, start, end, is_alnum_underscore)
                && let Some(range) = ByteRange::new(start, end)
            {
                candidates.push(
                    Candidate::new("sentry_org_auth_token", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["sentry-documented-prefix", "json-payload-signature-shape"]),
                );
            }
            start = end.max(start + 1);
        }

        Ok(candidates)
    }
}

/// Attempts an `eyJ<payload>[=[=]]_<43-byte signature>` match anchored right
/// after [`ORG_PREFIX`] at `start`. Returns the exclusive end offset on
/// success; the caller still applies the boundary check.
///
/// `base64_ends` is the precomputed maximal-run-end table from
/// [`pattern::run_ends`], so each segment's length is a table lookup rather
/// than a rescan, keeping the whole detector linear in the input length.
fn org_match_at(bytes: &[u8], base64_ends: &[usize], start: usize) -> Option<usize> {
    let payload_start = start + ORG_PREFIX.len();
    if !bytes[payload_start..].starts_with(ORG_JSON_MARKER.as_bytes()) {
        return None;
    }

    let core_end = base64_ends[payload_start];
    if core_end - payload_start < ORG_MIN_PAYLOAD_LEN {
        return None;
    }

    let mut separator = core_end;
    while separator < bytes.len()
        && bytes[separator] == b'='
        && separator - core_end < ORG_MAX_PADDING_LEN
    {
        separator += 1;
    }
    if bytes.get(separator) != Some(&b'_') {
        return None;
    }

    let signature_start = separator + 1;
    let signature_end = base64_ends[signature_start];
    if signature_end - signature_start != ORG_SIGNATURE_LEN {
        return None;
    }

    Some(signature_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_token() -> String {
        format!("{USER_PREFIX}{}", "0123456789abcdef".repeat(4))
    }

    /// Builds a syntactically valid base64 payload of exactly `len` bytes,
    /// always starting with [`ORG_JSON_MARKER`].
    fn org_payload(len: usize) -> String {
        assert!(len >= ORG_JSON_MARKER.len());
        let filler = "SYNTHETICREVOKEDSENTRYORGPAYLOADFIXTURE0123456789".repeat(4);
        format!(
            "{ORG_JSON_MARKER}{}",
            &filler[..len - ORG_JSON_MARKER.len()]
        )
    }

    /// Exactly [`ORG_SIGNATURE_LEN`] bytes of [`is_base64_std`].
    fn org_signature() -> String {
        let filler = "SigFixSYNTHETICREVOKED0123456789".repeat(2);
        filler[..ORG_SIGNATURE_LEN].to_string()
    }

    fn org_token(payload_len: usize) -> String {
        format!(
            "{ORG_PREFIX}{}_{}",
            org_payload(payload_len),
            org_signature()
        )
    }

    fn detect_user(input: &str) -> Vec<Candidate> {
        SentryUserAuthTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_org(input: &str) -> Vec<Candidate> {
        SentryOrgAuthTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    // ---- shared fixture sanity ----

    #[test]
    fn fixtures_carry_their_own_declared_lengths() {
        assert_eq!(org_signature().len(), ORG_SIGNATURE_LEN);
        assert_eq!(org_payload(ORG_MIN_PAYLOAD_LEN).len(), ORG_MIN_PAYLOAD_LEN);
        assert_eq!(user_token().len(), USER_PREFIX.len() + USER_SECRET_LEN);
    }

    // ---- user auth token ----

    #[test]
    fn detects_a_user_auth_token_bare() {
        let value = user_token();
        let candidates = detect_user(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "sentry_user_auth_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_user_auth_token_in_env_json_and_log_contexts() {
        let value = user_token();
        for input in [
            value.clone(),
            format!("SENTRY_AUTH_TOKEN={value}"),
            format!("{{\"authToken\": \"{value}\"}}"),
            format!("2026-09-16T00:00:00Z INFO uploading source maps token={value}"),
        ] {
            let candidates = detect_user(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn rejects_a_user_secret_one_byte_below_the_exact_length() {
        let short = &user_token()[..USER_PREFIX.len() + USER_SECRET_LEN - 1];
        assert!(detect_user(short).is_empty());
    }

    #[test]
    fn rejects_a_user_secret_one_byte_above_the_exact_length() {
        assert!(detect_user(&format!("{}0", user_token())).is_empty());
    }

    #[test]
    fn rejects_uppercase_hex_in_the_user_secret() {
        let value = format!("{USER_PREFIX}{}", "0123456789ABCDEF".repeat(4));
        assert!(detect_user(&value).is_empty());
    }

    #[test]
    fn rejects_the_user_token_embedded_in_a_wider_identifier() {
        let value = user_token();
        assert!(detect_user(&format!("x{value}")).is_empty());
        assert!(detect_user(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_user_token() {
        assert!(detect_user(&format!("{USER_PREFIX}{}", "*".repeat(USER_SECRET_LEN))).is_empty());
    }

    #[test]
    fn rejects_a_user_token_environment_variable_reference() {
        assert!(detect_user(&format!("{USER_PREFIX}${{SENTRY_AUTH_TOKEN}}")).is_empty());
    }

    #[test]
    fn finds_the_user_token_across_crlf_and_a_unicode_prefix() {
        let value = user_token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_user(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_user_token_findings_across_repeated_calls() {
        let input = user_token();
        assert_eq!(detect_user(&input), detect_user(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_user_prefixes() {
        let input = format!("{}!{}", user_token(), "sntryu_x!".repeat(10_000));
        let candidates = detect_user(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, user_token().len()).unwrap()
        );
    }

    // ---- organization auth token ----

    #[test]
    fn detects_an_org_auth_token_at_the_minimum_payload_length() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN);
        let candidates = detect_org(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "sentry_org_auth_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_org_auth_token_with_a_longer_payload() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN + 130);
        let candidates = detect_org(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_org_auth_token_with_base64_padding_before_the_separator() {
        let value = format!(
            "{ORG_PREFIX}{}=_{}",
            org_payload(ORG_MIN_PAYLOAD_LEN),
            org_signature()
        );
        let candidates = detect_org(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_org_auth_token_in_env_json_and_log_contexts() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN + 20);
        for input in [
            value.clone(),
            format!("SENTRY_AUTH_TOKEN={value}"),
            format!("{{\"authToken\": \"{value}\"}}"),
            format!("2026-09-16T00:00:00Z INFO release finalize auth={value}"),
        ] {
            let candidates = detect_org(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn rejects_a_payload_one_byte_below_the_minimum() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN - 1);
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_a_missing_json_marker() {
        let value = format!(
            "{ORG_PREFIX}{}_{}",
            "A".repeat(ORG_MIN_PAYLOAD_LEN),
            org_signature()
        );
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_a_missing_separator() {
        let value = format!(
            "{ORG_PREFIX}{}{}",
            org_payload(ORG_MIN_PAYLOAD_LEN),
            org_signature()
        );
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_a_signature_one_byte_below_the_exact_length() {
        let short_signature = &org_signature()[..ORG_SIGNATURE_LEN - 1];
        let value = format!(
            "{ORG_PREFIX}{}_{}",
            org_payload(ORG_MIN_PAYLOAD_LEN),
            short_signature
        );
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_a_signature_one_byte_above_the_exact_length() {
        let value = format!("{}A", org_token(ORG_MIN_PAYLOAD_LEN));
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_the_org_token_embedded_in_a_wider_identifier() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN);
        assert!(detect_org(&format!("x{value}")).is_empty());
        assert!(detect_org(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_org_token() {
        let value = format!(
            "{ORG_PREFIX}{}_{}",
            org_payload(ORG_MIN_PAYLOAD_LEN),
            "*".repeat(ORG_SIGNATURE_LEN)
        );
        assert!(detect_org(&value).is_empty());
    }

    #[test]
    fn rejects_an_org_token_environment_variable_reference() {
        assert!(detect_org(&format!("{ORG_PREFIX}eyJ${{SENTRY_AUTH_TOKEN}}")).is_empty());
    }

    #[test]
    fn finds_the_org_token_across_crlf_and_a_unicode_prefix() {
        let value = org_token(ORG_MIN_PAYLOAD_LEN);
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_org(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_org_token_findings_across_repeated_calls() {
        let input = org_token(ORG_MIN_PAYLOAD_LEN);
        assert_eq!(detect_org(&input), detect_org(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_org_prefixes() {
        let input = format!(
            "{}!{}",
            org_token(ORG_MIN_PAYLOAD_LEN),
            "sntrys_eyJ!".repeat(10_000)
        );
        let candidates = detect_org(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, org_token(ORG_MIN_PAYLOAD_LEN).len()).unwrap()
        );
    }

    // ---- cross-cutting: legacy format and public DSN are out of scope ----

    #[test]
    fn rejects_the_legacy_unprefixed_hex_token_with_no_context() {
        let legacy = "0123456789abcdef".repeat(4);
        assert_eq!(legacy.len(), 64);
        assert!(detect_user(&legacy).is_empty());
        assert!(detect_org(&legacy).is_empty());
    }

    #[test]
    fn rejects_a_public_dsn() {
        let dsn = "https://SYNTHETICPUBLICKEY0000000000000000@o000000.ingest.sentry.io/0000000";
        assert!(detect_user(dsn).is_empty());
        assert!(detect_org(dsn).is_empty());
    }
}
