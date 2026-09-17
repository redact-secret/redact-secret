//! New Relic User API Key and (ingest) License Key detection.
//!
//! New Relic's own API-key documentation
//! (`https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/`)
//! names several key types but publishes a character-class grammar for
//! neither in-scope one. What it does state, used directly below:
//!
//! - the **License Key** is "a 40-character hexadecimal string" used for
//!   data ingest (all telemetry except browser and mobile);
//! - the **User Key** authenticates NerdGraph/REST API calls and is
//!   per-user, not per-account.
//!
//! The User Key's `NRAK-` prefix itself comes from New Relic's own
//! Terraform provider documentation, not the API-keys page above:
//! `terraform-provider-newrelic`'s `migration_guide_v2.html.markdown` states
//! "Your **User API Key** has a prefix of `NRAK-`" and separately "Most User
//! API keys have the `NRAK-` prefix" -- the "most" is a documented hedge
//! against a legacy key (the same guide's diff example shows the older,
//! now-replaced `NRAA-`-prefixed admin key), acknowledged as a known false
//! negative below rather than fuzzy-matched. Consulted only as external
//! behavioral references per `AGENTS.md`, gitleaks's `new-relic-user-api-key`
//! rule and trufflehog 3.97.4's independent `newrelicuserkey` detector both
//! converge on exactly `NRAK-` followed by 27 bytes of `[A-Z0-9]` (32 bytes
//! total) with no documented counter-evidence of a different length; no code
//! from either project is reproduced here.
//!
//! ## Grammar (frozen before implementation, per issue #307)
//!
//! - **User API Key**: the literal `NRAK-`, then exactly 27 bytes of
//!   [`pattern::is_upper_alnum`] (`[A-Z0-9]`) -- 32 bytes total, bounded on
//!   both sides by a byte outside [`pattern::is_alnum`] (wider than the
//!   match alphabet, so an adjacent lowercase byte still rejects a truncated
//!   slice of a longer identifier, mirroring [`super::aws`]'s own
//!   `is_upper_alnum`/`is_alnum` pairing). `High` confidence, `Provider`
//!   specificity, always redacted -- the prefix and exact length together
//!   are specific enough to be actionable on their own, the same class every
//!   other exact-length prefixed detector in this registry gets.
//! - **License Key**: a bare run of exactly 40 [`is_lower_hex`] (`[0-9a-f]`)
//!   bytes, bounded by a byte outside [`pattern::is_alnum`]. Unlike the User
//!   Key, this format carries no marker of its own -- a 40-character hex
//!   string is indistinguishable by shape alone from a `git` commit hash, a
//!   SHA-1 digest, or countless other opaque hex blobs, and neither
//!   independent reference scanner's own attempt at a stronger structural
//!   marker (see "Rejected: an unofficial license-key suffix" below)
//!   corroborates the other. Per the issue's own "ambiguous unprefixed
//!   values require reliable context" instruction, this detector requires a
//!   case-insensitive `newrelic`/`new_relic`/`new-relic`/`new relic`
//!   substring ([`CONTEXT_KEYWORDS`]) anywhere on the same line -- the same
//!   "same line" scope [`super::twilio`] already uses for its own bare-hex
//!   formats, for the same incremental-consistency reason documented there.
//!   `Medium` confidence, `Provider` specificity, confidence-gated (not in
//!   `ALWAYS_REDACT_TYPES`) -- there is no paired-identifier signal available
//!   here the way [`super::twilio`]'s Account SID/API Key SID give its own
//!   bare formats a `High`-confidence tier, so this format never rises above
//!   `Medium`.
//!
//! A candidate that is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded from both formats:
//! both alphabets (`[A-Z0-9]`, `[0-9a-f]`) contain characters (`X`, `0`, ...)
//! a masked placeholder commonly repeats, so, per [`super::twilio`]'s same
//! precedent, neither format has a structural marker of its own that would
//! otherwise keep a masked value like `NRAK-XXXXXXXXXXXXXXXXXXXXXXXXXXX` from
//! matching the bare alphabet.
//!
//! ## Scope
//!
//! Per the issue's explicit scope ("Scope user API keys and documented
//! license/ingest credentials... exclude application IDs and public
//! configuration identifiers"), and its instruction to "explicitly review
//! browser/mobile ingestion-key policy instead of assuming client visibility
//! implies harmlessness":
//!
//! - The Browser Key and Mobile App Token are reviewed and intentionally
//!   excluded, not assumed harmless by default: New Relic's own
//!   documentation classifies both as public and client-visible by design
//!   (the Browser Key ships in every monitored page's rendered HTML; the
//!   Mobile App Token is compiled into the distributed app binary) -- an
//!   intended public-distribution mechanism, not a leak, unlike the secret
//!   License Key and User Key this module targets. Flagging a value New
//!   Relic itself designs for public embedding would treat correct usage as
//!   an incident.
//! - The legacy Insights Insert/Query Keys (`NRII-`/`NRIQ-`), the deprecated
//!   Admin Key (REST API keys reached end-of-life in 2025, per New Relic's
//!   own `whats-new-03-01-rest-api-keys-eol` notice), and the bare
//!   account-scoped "user API id" gitleaks separately detects (a 64-byte
//!   alphanumeric identifier, not a secret) are all out of the issue's
//!   explicit scope sentence above and not implemented here; they remain
//!   documented gaps for a future issue, not silently dropped.
//!
//! ### Rejected: an unofficial license-key suffix
//!
//! trufflehog's `newreliclicensekey` detector additionally requires the
//! matched 40 bytes to end in a literal `FFFFNRAL` (or, for an EU-region
//! variant, begin with `eu01xx`) -- a stronger structural marker that, if
//! real, would let a License Key be recognized at `High` confidence with no
//! context needed at all. This module does not adopt it: neither New Relic's
//! own documentation nor gitleaks (which has no License Key rule at all)
//! corroborates it, so treating a single, uncorroborated external tool's
//! reverse-engineered suffix as ground truth risks a worse outcome than the
//! keyword-gated fallback below -- a documented false negative for every
//! License Key that does not happen to carry it, for a confidence bump this
//! module cannot independently verify.
//!
//! ## Consequences and known gaps
//!
//! - A User Key issued under the legacy, pre-`NRAK-` scheme (the guide's own
//!   "most User API keys have the `NRAK-` prefix" hedge) goes undetected by
//!   this dedicated path; a qualified `name=value` assignment of one still
//!   gets a lower-confidence, lower-specificity contextual finding through
//!   the existing generic-token path regardless of format.
//! - A License Key with no `newrelic`/`new_relic`/`new-relic`/`new relic`
//!   keyword anywhere on its own line goes undetected -- the same accepted
//!   tradeoff [`super::twilio`]'s own bare hex formats already carry.
//! - A benign 40-byte lowercase-hex value (a commit SHA, a digest) that
//!   happens to share a line with one of the four keywords would false
//!   positive; this is the same class of risk every other keyword-gated
//!   bare-format detector in this registry already accepts.

use crate::detectors::pattern::{self, RunLength};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const USER_API_KEY_PREFIX: &str = "NRAK-";
const USER_API_KEY_BODY_LEN: usize = 27;
const LICENSE_KEY_LEN: usize = 40;

/// New Relic's own documented naming for the License Key credential,
/// case-insensitively, in every spelling gitleaks's independent
/// `new-relic-*` keyword lists already converge on (`newrelic`,
/// `new_relic`, `new-relic`) plus the two-word prose spelling New Relic's
/// own product name uses (`new relic`), for a same-line comment such as
/// `# New Relic license key: <hex>`.
const CONTEXT_KEYWORDS: [&str; 4] = ["newrelic", "new_relic", "new-relic", "new relic"];

/// `[0-9a-f]`: the License Key's documented "hexadecimal string" alphabet,
/// lowercase only. Matches [`super::twilio`]'s own `is_lower_hex`, which
/// documents the same rationale: an uppercase-hex run is not a coincidental
/// case variant of this format, it is a structurally different value.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f'
}

/// Detects a New Relic User API Key by its documented `NRAK-` prefix and
/// exact 27-byte uppercase-alphanumeric body.
pub(super) struct NewRelicUserApiKeyDetector;

impl Detector for NewRelicUserApiKeyDetector {
    fn id(&self) -> &'static str {
        "new-relic-user-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &[USER_API_KEY_PREFIX],
            RunLength::Exact(USER_API_KEY_BODY_LEN),
            pattern::is_upper_alnum,
            pattern::is_alnum,
        ) {
            if text::is_repeated_character_filler(&input[start + USER_API_KEY_PREFIX.len()..end]) {
                continue;
            }
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("new_relic_user_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals([
                        "new-relic-documented-prefix",
                        "exact-length-upper-alnum-body",
                    ]),
            );
        }
        Ok(candidates)
    }
}

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line). Mirrors
/// [`super::twilio`]'s own `lines` helper, which documents why "line" is the
/// right unit: it is the same processing unit the incremental sanitizer
/// hands a detector, so whole-input and incremental scanning stay
/// behaviorally identical.
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

/// `true` when any of [`CONTEXT_KEYWORDS`] occurs (case-insensitively)
/// anywhere in `line`.
fn line_has_context_keyword(line: &str) -> bool {
    let bytes = line.as_bytes();
    CONTEXT_KEYWORDS.iter().any(|needle| {
        let needle_len = needle.len();
        needle_len <= bytes.len()
            && (0..=bytes.len() - needle_len).any(|pos| text::starts_with_ci(line, pos, needle))
    })
}

/// Detects a New Relic License Key: a bare 40-byte lowercase-hex run on a
/// line that also carries a [`CONTEXT_KEYWORDS`] substring.
pub(super) struct NewRelicLicenseKeyDetector;

impl Detector for NewRelicLicenseKeyDetector {
    fn id(&self) -> &'static str {
        "new-relic-license-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            if !line_has_context_keyword(line) {
                continue;
            }

            let bytes = line.as_bytes();
            let ends = pattern::run_ends(bytes, is_lower_hex);
            let mut start = 0usize;
            while start < bytes.len() {
                if !is_lower_hex(bytes[start]) {
                    start += 1;
                    continue;
                }
                let run_end = ends[start];
                if run_end - start == LICENSE_KEY_LEN
                    && pattern::boundary_ok(bytes, start, run_end, pattern::is_alnum)
                    && !text::is_repeated_character_filler(&line[start..run_end])
                    && let Some(range) = ByteRange::new(line_start + start, line_start + run_end)
                {
                    candidates.push(
                        Candidate::new("new_relic_license_key", Confidence::Medium, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals(["new-relic-keyword-cooccurrence"]),
                    );
                }
                start = run_end;
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_API_KEY_BODY: &str = "SYNTHETICREVOKEDNEWRELICUSA";
    const LICENSE_KEY: &str = "0123456789abcdef0123456789abcdef01234567";

    fn user_api_key() -> String {
        format!("{USER_API_KEY_PREFIX}{USER_API_KEY_BODY}")
    }

    fn detect_user_api_key(input: &str) -> Vec<Candidate> {
        NewRelicUserApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_license_key(input: &str) -> Vec<Candidate> {
        NewRelicLicenseKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn fixtures_are_exactly_documented_length() {
        assert_eq!(USER_API_KEY_BODY.len(), USER_API_KEY_BODY_LEN);
        assert_eq!(LICENSE_KEY.len(), LICENSE_KEY_LEN);
    }

    #[test]
    fn detects_the_synthetic_user_api_key() {
        let value = user_api_key();
        let candidates = detect_user_api_key(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "new_relic_user_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_user_api_key_bare_in_env_and_control_contexts() {
        let value = user_api_key();
        for input in [
            value.clone(),
            format!("NEW_RELIC_API_KEY={value}"),
            format!("api_key: {value}"),
            format!("{{\"apiKey\": \"{value}\"}}"),
        ] {
            let candidates = detect_user_api_key(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn rejects_a_user_api_key_body_one_byte_short_of_the_required_length() {
        let short = &USER_API_KEY_BODY[..USER_API_KEY_BODY.len() - 1];
        assert!(detect_user_api_key(&format!("{USER_API_KEY_PREFIX}{short}")).is_empty());
    }

    #[test]
    fn rejects_a_user_api_key_body_one_byte_longer_than_the_required_length_rather_than_truncating()
    {
        let long = format!("{USER_API_KEY_BODY}A");
        assert!(detect_user_api_key(&format!("{USER_API_KEY_PREFIX}{long}")).is_empty());
    }

    #[test]
    fn rejects_a_legacy_admin_key_prefix() {
        assert!(detect_user_api_key(&format!("NRAA-{USER_API_KEY_BODY}")).is_empty());
    }

    #[test]
    fn rejects_a_lowercase_user_api_key_body() {
        let lower = USER_API_KEY_BODY.to_ascii_lowercase();
        assert!(detect_user_api_key(&format!("{USER_API_KEY_PREFIX}{lower}")).is_empty());
    }

    #[test]
    fn rejects_a_masked_user_api_key() {
        assert!(
            detect_user_api_key(&format!("{USER_API_KEY_PREFIX}{}", "X".repeat(27))).is_empty()
        );
    }

    #[test]
    fn rejects_a_user_api_key_environment_variable_reference() {
        assert!(
            detect_user_api_key(&format!("{USER_API_KEY_PREFIX}${{NEW_RELIC_API_KEY}}")).is_empty()
        );
    }

    #[test]
    fn rejects_a_user_api_key_embedded_in_a_wider_identifier() {
        let value = user_api_key();
        assert!(detect_user_api_key(&format!("x{value}")).is_empty());
        assert!(detect_user_api_key(&format!("{value}x")).is_empty());
    }

    #[test]
    fn does_not_flag_a_bare_short_application_or_account_id() {
        assert!(detect_user_api_key("accountId: 1234567890").is_empty());
    }

    #[test]
    fn finds_a_user_api_key_match_across_crlf_and_a_unicode_prefix() {
        let value = user_api_key();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_user_api_key(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_user_api_key_findings_across_repeated_calls() {
        let input = user_api_key();
        assert_eq!(detect_user_api_key(&input), detect_user_api_key(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_user_api_key_prefixes() {
        let input = format!("{}!{}", user_api_key(), "NRAK-!".repeat(10_000));
        let candidates = detect_user_api_key(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, user_api_key().len()).unwrap()
        );
    }

    #[test]
    fn detects_a_license_key_named_by_a_new_relic_keyword() {
        for input in [
            format!("NEW_RELIC_LICENSE_KEY={LICENSE_KEY}"),
            format!("newrelic.license_key: {LICENSE_KEY}"),
            format!("# New Relic license key: {LICENSE_KEY}"),
            format!("{{\"new-relic-license-key\": \"{LICENSE_KEY}\"}}"),
        ] {
            let candidates = detect_license_key(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "new_relic_license_key");
            assert_eq!(candidates[0].confidence(), Confidence::Medium);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            let start = input.rfind(LICENSE_KEY).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + LICENSE_KEY.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_a_bare_license_key_with_no_context() {
        assert!(detect_license_key(LICENSE_KEY).is_empty());
    }

    #[test]
    fn rejects_a_license_key_whose_context_is_on_a_different_line() {
        let input = format!("# new relic\n{LICENSE_KEY}\n");
        assert!(detect_license_key(&input).is_empty());
    }

    #[test]
    fn rejects_an_uppercase_hex_run() {
        let upper = LICENSE_KEY.to_ascii_uppercase();
        assert!(detect_license_key(&format!("newrelic {upper}")).is_empty());
    }

    #[test]
    fn rejects_a_license_key_one_byte_short_of_the_required_length() {
        let short = &LICENSE_KEY[..LICENSE_KEY.len() - 1];
        assert!(detect_license_key(&format!("newrelic {short}")).is_empty());
    }

    #[test]
    fn rejects_a_license_key_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{LICENSE_KEY}0");
        assert!(detect_license_key(&format!("newrelic {long}")).is_empty());
    }

    #[test]
    fn rejects_a_masked_license_key() {
        assert!(
            detect_license_key(&format!("newrelic {}", "0".repeat(LICENSE_KEY_LEN))).is_empty()
        );
    }

    #[test]
    fn rejects_a_license_key_environment_variable_reference() {
        assert!(
            detect_license_key("newrelic NEW_RELIC_LICENSE_KEY=${NEW_RELIC_LICENSE_KEY}")
                .is_empty()
        );
    }

    #[test]
    fn finds_a_qualified_license_key_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nnewrelic {LICENSE_KEY}\r\n");
        let candidates = detect_license_key(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(LICENSE_KEY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LICENSE_KEY.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_license_key_findings_across_repeated_calls() {
        let input = format!("newrelic {LICENSE_KEY}");
        assert_eq!(detect_license_key(&input), detect_license_key(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_license_key_candidates() {
        let input = format!("{LICENSE_KEY} ").repeat(10_000);
        assert_eq!(detect_license_key(&input).len(), 0);
    }

    #[test]
    fn every_license_key_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("newrelic {LICENSE_KEY} {LICENSE_KEY}");
        let candidates = detect_license_key(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::Medium)
        );
    }
}
