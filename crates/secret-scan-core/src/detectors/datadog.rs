//! Datadog API Key and Application Key detection.
//!
//! Datadog's account-management documentation
//! (`https://docs.datadoghq.com/account_management/api-app-keys/`) and
//! authentication documentation
//! (`https://docs.datadoghq.com/api/latest/authentication/`) publish no
//! character-class grammar for either key's body -- only their functional
//! roles ("Requests that write data require reporting access and require an
//! API key. Requests that read data require full access and also require an
//! application key") and the names a caller sends them under: the HTTP
//! headers `DD-API-KEY` / `DD-APPLICATION-KEY` and the environment variables
//! `DD_API_KEY` / `DD_APPLICATION_KEY`. Consulted only as external behavioral
//! references per `AGENTS.md`, gitleaks 8.30.1's `datadog-access-token` rule
//! and trufflehog 3.97.4's independent `datadogapikey` and `datadogtoken`
//! detectors both converge on the same two community-observed lengths (32
//! and 40 bytes); no code from either project is reproduced here, and this
//! module's matching and context-gating logic is authored independently.
//!
//! Grammar (frozen before implementation, per issue #304):
//!
//! - API Key: exactly 32 bare [`is_lower_hex`] (`[0-9a-f]`) bytes, no prefix
//!   or other marker.
//! - Application Key: two live generations (issue #671, applying the
//!   existing current/legacy split policy recorded in
//!   `docs/specs/detector-families.md` -- see
//!   [`super::confluent`] and [`super::heroku`] for the same pattern applied
//!   to their own provider families) -- see below.
//!
//! Both gitleaks and trufflehog match a broader `[A-Za-z0-9-]` alphabet as a
//! looser catch-all heuristic for the legacy Application Key shape; this
//! module instead freezes the tighter lowercase-hex shape actually issued by
//! the platform historically, per issue #304's own scope note to cover "API
//! and application key values, with context for opaque hex formats". A key
//! body outside `[0-9a-f]` is a known, intentionally unsupported variant of
//! the *legacy* shape: narrowing the alphabet meaningfully reduces false
//! positives against the broader catch-all.
//!
//! Both the API Key and the legacy Application Key are bounded on both sides
//! by a byte outside their own alphabet (or the edge of input), so a longer
//! or shorter run is rejected rather than truncated, matching every other
//! fixed-length grammar in this crate.
//!
//! ## Application Key: current (`ddapp_`-prefixed) and legacy (bare hex)
//!
//! Datadog's own documentation
//! (`docs.datadoghq.com/account_management/personal-access-tokens/` and
//! `docs.datadoghq.com/account_management/service-access-tokens/`, observed
//! 2026-09-22) states, in the comparison table shared by both pages:
//! "Identifiable prefix … `ddapp_` (new)" in the Application keys column.
//! That page establishes the identifying prefix on Datadog's own domain but
//! gives no body length or alphabet.
//!
//! Datadog-owned code (consulted only as external behavioral corroboration
//! per `AGENTS.md`; no code from any of these is reproduced here) supplies
//! the rest of the grammar and consistently treats both generations as live
//! side by side:
//!
//! ```text
//! DataDog/datadog-agent pkg/privateactionrunner/util/keys.go:
//!   ^([a-f0-9]{40}|ddapp_[a-zA-Z0-9]{34})$
//! DataDog/cloudformation-template aws_quickstart (AllowedPattern):
//!   ([0-9a-f]{40})|(ddapp_[a-zA-Z0-9]{34})
//! DataDog/terraform-module-datadog-agentless-scanner azure/arm (ValidatePattern):
//!   ^([0-9a-f]{40}|ddapp_[a-zA-Z0-9]{34})$
//! DataDog/cloudformation-template CHANGELOG.md (4.5.2, 2026-02-17):
//!   "support identifiable app keys (ddapp_ prefix) in addition to the
//!   legacy 40-character hex format"
//! ```
//!
//! AWS's Secrets Manager partner documentation
//! (`docs.aws.amazon.com/secretsmanager/latest/userguide/mes-partner-DatadogApplicationKey.html`)
//! agrees exactly: "Starts with ddapp_ followed by 34 alphanumeric
//! characters." Two independently reported empirical observations
//! corroborate the same shape against real, console-issued keys:
//! `DataDog/datadogpy#930` ("My application keys are generated with a
//! `ddapp_` prefix … removing the prefix … resulting in `ERROR:
//! Unauthorized`", 2026-04-01, confirming the prefix is part of the secret
//! rather than decoration) and a third-party report that "Newer tenants
//! issue keys as `ddapp_<base62>`" against a real tenant's credentials.
//! Datadog's own Agent log/config scrubber (`pkg/util/scrubber/default.go`)
//! additionally admits `_` inside the body (`ddapp_[a-zA-Z0-9_]{30}...`),
//! but every validator -- the Agent's own app-key *acceptance* check in
//! `keys.go`, the `CloudFormation` and ARM templates, and AWS's independent
//! doc -- agrees on a strict `[a-zA-Z0-9]` body; a scrubber is deliberately
//! lenient (it exists to redact, not to authenticate), so this module
//! follows the validators and AWS rather than the scrubber, matching the
//! issue's own acceptance criterion of "34-character alphanumeric".
//!
//! - **Current.** The literal `ddapp_` prefix, then exactly
//!   [`CURRENT_APPLICATION_KEY_BODY_LEN`] (34) bytes of
//!   [`pattern::is_alnum`] (`[A-Za-z0-9]`), 40 bytes total. This shape needs
//!   no surrounding context: the six-byte literal prefix is evidence enough
//!   by itself, the same "documented literal prefix" precedent
//!   [`super::confluent::CONFLUENT_CLOUD_API_SECRET`] and
//!   [`super::heroku::HEROKU_API_KEY`] already establish for their own
//!   current-generation shapes. Reported at [`Confidence::High`] and
//!   [`Specificity::Provider`], type `datadog_application_key`, detector id
//!   `datadog-application-key`.
//! - **Legacy.** The same "40 bare lowercase-hex bytes" shape this module
//!   originally shipped, now scoped to type `datadog_application_key_legacy`
//!   and detector id `datadog-application-key-legacy`. Datadog's own code
//!   states plainly that pre-existing keys are still accepted alongside the
//!   new prefixed shape (every validator above matches `[a-f0-9]{40}` as an
//!   alternative, not a replacement), so this generation stays live and
//!   detectable exactly as before: gated on the same-line context signals
//!   described below, since a bare hex run carries no marker of its own.
//!
//! No dedicated ADR governs this split: it applies the existing
//! current/legacy policy already recorded for [`super::confluent`] and
//! [`super::heroku`] to one more provider family, per
//! `docs/decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md`'s
//! "one more instance is a spec-file row, not a new ADR" rule; see
//! `docs/specs/detector-families.md`. The original freeze
//! (`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`)
//! still governs the legacy shape's own grammar and context gating
//! unchanged.
//!
//! Out of scope: `ddpat_`-prefixed Personal Access Tokens and
//! `ddsat_`-prefixed Service Access Tokens are documented as distinct
//! credential families on the same comparison table (their own dedicated
//! full grammar is published for PATs but not corroborated here) and are not
//! covered by this module; a value under an application-key marker that is
//! actually a `ddpat_`/`ddsat_` token is an intentional false negative for
//! this family. A future PAT/SAT detector is separate scope.
//!
//! ## Scope and context gating (API Key, and the legacy Application Key)
//!
//! A bare 32-byte lowercase-hex run is indistinguishable by shape alone from
//! an MD5 digest, a hyphen-stripped UUID, or any other opaque hex blob; a
//! bare 40-byte lowercase-hex run is equally indistinguishable from a SHA-1
//! digest. Neither format alone is "reliable Datadog context" in the issue's
//! own words, and neither key carries a paired public identifier the way a
//! Twilio Account SID or API Key SID does (see [`super::twilio`]), so each
//! bare-hex detector here gates on same-line keyword signals instead of a
//! paired identifier:
//!
//! - a same-line, case-insensitive marker that names the specific key type
//!   together with the vendor (`datadog_api_key`, `dd-api-key`,
//!   `DD_APPLICATION_KEY`, and the other literal forms on
//!   [`API_KEY_MARKERS`] / [`LEGACY_APPLICATION_KEY_MARKERS`], covering the
//!   documented header and environment-variable names above along with
//!   their common `-`/`_`-joined config-key spellings) -- [`Confidence::High`],
//!   the strongest available signal short of a network credential check this
//!   core must never perform; or, absent that,
//! - a bare case-insensitive `datadog` substring anywhere on the line --
//!   [`Confidence::Medium`], a weaker keyword heuristic.
//!
//! The bare two-letter `dd` short form is deliberately never checked as an
//! unanchored substring: unlike `datadog` or `twilio`, it collides with
//! ordinary English inside common identifiers (`address`, `middleware`,
//! `redirect`, `odd`), so admitting it as a standalone keyword would trade a
//! small false-negative reduction for a much larger false-positive increase.
//! It is still reachable, safely, as part of the longer literal markers
//! above (`dd_api_key`, `dd-application-key`, ...), which is how the
//! documented `DD_API_KEY` / `DD_APPLICATION_KEY` environment variables are
//! actually covered at `High` confidence. A line that mentions `dd` alone
//! with no key-type wording and no `datadog` substring is a documented,
//! accepted false negative.
//!
//! "Same line" is the same processing unit the incremental sanitizer hands a
//! detector one line at a time (`IncrementalSanitizer` finalizes at each
//! `\n` unless a multiline construct is open, and neither format here
//! declares one): scoping context to it keeps whole-input and incremental
//! scanning behaviorally identical. A context-bearing marker on a *different*
//! line -- for example a JSON object with `apiKey` and `applicationKey` as
//! separate top-level fields under a shared `datadog` parent -- is a
//! documented, known false negative, the same tradeoff [`super::twilio`]
//! already makes.
//!
//! A bare-hex candidate that is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded even when context
//! matches: unlike the `ddapp_`-prefixed grammar, the legacy shape has no
//! marker of its own to keep a masked or placeholder value
//! (`DD_API_KEY=00000000000000000000000000000000`) from otherwise matching
//! the bare alphabet outright. The `ddapp_`-prefixed shape needs no such
//! exclusion -- its literal prefix is itself the marker, matching
//! [`super::heroku`]'s and [`super::confluent`]'s own current-generation
//! shapes, both of which accept an all-valid-alphabet doc-style placeholder
//! rather than special-case it.
//!
//! Scope excludes Datadog key *record IDs* (the short public identifiers
//! shown alongside a key in the UI/API to reference it without revealing the
//! value) and dashboard/monitor identifiers: both are structurally shorter
//! than every frozen length above, so the exact-length gates already keep
//! them out without a dedicated exclusion.
//!
//! ## Action and metadata
//!
//! `datadog_api_key` and `datadog_application_key_legacy` are both
//! `Specificity::Provider` but intentionally left out of
//! `policy::ALWAYS_REDACT_TYPES`: the confidence gradient above is real
//! evidence-strength information, and `DefaultPolicy`'s existing
//! confidence-gated fallback (redact at `High`, warn otherwise) already
//! reflects it, mirroring [`super::twilio`]. `datadog_application_key` (the
//! current, `ddapp_`-prefixed shape) is unconditionally `Confidence::High`
//! and *is* in `policy::ALWAYS_REDACT_TYPES`, the same "documented literal
//! prefix needs no confidence gate" precedent
//! [`super::confluent::CONFLUENT_CLOUD_API_SECRET`] and
//! [`super::heroku::HEROKU_API_KEY`] already set. All three finding types
//! stay distinct detector ids and type names rather than merged, which is
//! how this module records in metadata -- per issue #304's scope note -- that
//! an API key is an ingestion credential and an Application key (either
//! generation) is broader application-API authority, even though the core
//! applies different policy classes across the confidence gradient.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `[0-9a-f]`: the API Key and legacy Application Key alphabet.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f'
}

const API_KEY_LEN: usize = 32;
const LEGACY_APPLICATION_KEY_LEN: usize = 40;
const VENDOR_KEYWORD: &str = "datadog";

/// Literal markers naming an API key specifically, covering the documented
/// `DD-API-KEY` header and `DD_API_KEY` environment variable and their
/// common config-key spellings. Checked case-insensitively.
const API_KEY_MARKERS: &[&str] = &[
    "datadog_api_key",
    "datadog-api-key",
    "datadogapikey",
    "dd_api_key",
    "dd-api-key",
    "ddapikey",
];

/// Literal markers naming an application key specifically, covering the
/// documented `DD-APPLICATION-KEY` header and `DD_APPLICATION_KEY`
/// environment variable, the shorter `app_key` spelling some client
/// libraries accept, and their common config-key spellings. Checked
/// case-insensitively. Used only by the legacy (bare-hex) detector: the
/// current `ddapp_`-prefixed shape needs no marker of its own.
const LEGACY_APPLICATION_KEY_MARKERS: &[&str] = &[
    "datadog_application_key",
    "datadog-application-key",
    "datadogapplicationkey",
    "datadog_app_key",
    "datadog-app-key",
    "datadogappkey",
    "dd_application_key",
    "dd-application-key",
    "ddapplicationkey",
    "dd_app_key",
    "dd-app-key",
    "ddappkey",
];

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line; it never affects context
/// lookups, since neither a marker nor the `datadog` keyword scan treats
/// `\r` specially). Each byte of `input` belongs to exactly one yielded
/// range, so a caller that does bounded work per line does bounded work
/// overall, not bounded work per candidate found within a line.
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

/// Every non-overlapping, boundary-checked bare run of exactly `exact_len`
/// `alphabet` bytes, left to right. A run longer or shorter than `exact_len`
/// is skipped whole, the same "no truncation" guarantee
/// [`super::pattern::scan_prefixed_runs`] gives a prefixed grammar.
fn scan_bare_secret_runs(
    input: &str,
    exact_len: usize,
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
        if run_end - start == exact_len && pattern::boundary_ok(bytes, start, run_end, boundary) {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

/// Shared implementation for both bare-hex, context-gated detectors below
/// (API Key, and the legacy Application Key).
///
/// Processes one line at a time: a line's bare candidates, its
/// specific-marker check, and its `datadog`-keyword check are each computed
/// once per line, not once per candidate, so a line packed with many
/// candidates costs no more than a line with one -- the same bounded-work
/// guarantee [`scan_bare_secret_runs`] gives a single alphabet run.
fn detect_context_gated(
    input: &str,
    exact_len: usize,
    type_name: &str,
    specific_markers: &[&str],
    specific_signal: &str,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (line_start, line_end) in lines(input) {
        let line = &input[line_start..line_end];
        let raw_matches = scan_bare_secret_runs(line, exact_len, is_lower_hex, pattern::is_alnum);
        if raw_matches.is_empty() {
            continue;
        }

        let (confidence, signal) = if specific_markers
            .iter()
            .any(|marker| line_contains_ci(line, marker))
        {
            (Confidence::High, specific_signal)
        } else if line_contains_ci(line, VENDOR_KEYWORD) {
            (Confidence::Medium, "datadog-keyword-cooccurrence")
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
            let (confidence, signal) = if confidence == Confidence::Medium
                && text::is_provider_named_assignment(line, relative_start, &[VENDOR_KEYWORD])
            {
                (Confidence::High, "datadog-named-assignment")
            } else {
                (confidence, signal)
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

/// Detects a Datadog API Key: a bare 32-byte lowercase-hex run on the same
/// line as either a specific `*_api_key`-shaped marker or the word
/// `datadog`.
pub(super) struct DatadogApiKeyDetector;

impl Detector for DatadogApiKeyDetector {
    fn id(&self) -> &'static str {
        "datadog-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(detect_context_gated(
            input,
            API_KEY_LEN,
            "datadog_api_key",
            API_KEY_MARKERS,
            "datadog-api-key-marker-cooccurrence",
        ))
    }
}

const CURRENT_APPLICATION_KEY_PREFIX: &str = "ddapp_";
/// The documented body length following [`CURRENT_APPLICATION_KEY_PREFIX`]:
/// 40 bytes total minus the six-byte prefix.
const CURRENT_APPLICATION_KEY_BODY_LEN: usize = 34;

const CURRENT_APPLICATION_KEY_SIGNALS: [&str; 2] = [
    "datadog-application-key-documented-prefix",
    "datadog-application-key-documented-length",
];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier -- the
/// widest boundary class this crate uses for a prefixed alnum shape,
/// matching [`super::heroku::CURRENT_BOUNDARY`]'s and
/// [`super::confluent`]'s own reasoning: a directly-glued wider identifier
/// is always joined by `_` or `-` at exactly this position.
const CURRENT_APPLICATION_KEY_BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// The current, `ddapp_`-prefixed Datadog Application Key: the literal
/// `ddapp_` prefix plus exactly 34 bytes of `[A-Za-z0-9]`, 40 bytes total,
/// unconditionally [`Confidence::High`] and [`Specificity::Provider`] -- no
/// context needed. See the module doc for the full evidence trail.
pub(super) const DATADOG_APPLICATION_KEY: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "datadog-application-key",
        "datadog_application_key",
        &[PrefixShape::exact(
            CURRENT_APPLICATION_KEY_PREFIX,
            CURRENT_APPLICATION_KEY_BODY_LEN,
            pattern::is_alnum,
            &CURRENT_APPLICATION_KEY_SIGNALS,
        )],
        CURRENT_APPLICATION_KEY_BOUNDARY,
    );

/// Detects a legacy (pre-`ddapp_`) Datadog Application Key: a bare 40-byte
/// lowercase-hex run on the same line as either a specific
/// `*_app(lication)_key`-shaped marker or the word `datadog`. See the module
/// doc for why this generation stays live and detectable.
pub(super) struct DatadogApplicationKeyLegacyDetector;

impl Detector for DatadogApplicationKeyLegacyDetector {
    fn id(&self) -> &'static str {
        "datadog-application-key-legacy"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(detect_context_gated(
            input,
            LEGACY_APPLICATION_KEY_LEN,
            "datadog_application_key_legacy",
            LEGACY_APPLICATION_KEY_MARKERS,
            "datadog-application-key-marker-cooccurrence",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY: &str = "3f2504e04f8940c496395c07f7c60000";
    const LEGACY_APPLICATION_KEY: &str = "fedcba9876543210fedcba9876543210fedcba98";
    const KEY_RECORD_ID: &str = "a1b2c3d4e5";

    /// Exactly [`CURRENT_APPLICATION_KEY_BODY_LEN`] bytes of `[A-Za-z0-9]`.
    /// Locally constructed synthetic value; never provider-issued.
    const CURRENT_APPLICATION_KEY_BODY: &str = "SYNTHETIC0REVOKED0AppKeyBody012345";

    fn detect_api_key(input: &str) -> Vec<Candidate> {
        DatadogApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_application_key_legacy(input: &str) -> Vec<Candidate> {
        DatadogApplicationKeyLegacyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_application_key_current(input: &str) -> Vec<Candidate> {
        DATADOG_APPLICATION_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn current_application_key() -> String {
        format!("{CURRENT_APPLICATION_KEY_PREFIX}{CURRENT_APPLICATION_KEY_BODY}")
    }

    #[test]
    fn fixtures_are_the_documented_lengths() {
        assert_eq!(API_KEY.len(), 32);
        assert_eq!(LEGACY_APPLICATION_KEY.len(), 40);
        assert_eq!(
            CURRENT_APPLICATION_KEY_BODY.len(),
            CURRENT_APPLICATION_KEY_BODY_LEN
        );
    }

    #[test]
    fn detects_an_api_key_named_by_a_specific_marker_at_high_confidence() {
        let input = format!("DD_API_KEY={API_KEY}");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "datadog_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(API_KEY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + API_KEY.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_api_key_via_the_documented_header_marker() {
        let input = format!("DD-API-KEY: {API_KEY}");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn detects_an_api_key_named_by_the_datadog_keyword_at_medium_confidence() {
        let input = format!("my datadog secret is {API_KEY}");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        let start = input.rfind(API_KEY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + API_KEY.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_api_key_with_no_context() {
        assert_eq!(detect_api_key(API_KEY).len(), 0);
    }

    #[test]
    fn rejects_a_bare_dd_mention_with_no_key_type_wording() {
        assert_eq!(detect_api_key(&format!("dd {API_KEY}")).len(), 0);
    }

    #[test]
    fn rejects_an_api_key_whose_context_is_on_a_different_line() {
        let input = format!("DD_API_KEY=\n{API_KEY}\n");
        assert_eq!(detect_api_key(&input).len(), 0);
    }

    #[test]
    fn rejects_an_uppercase_hex_run() {
        let upper = API_KEY.to_ascii_uppercase();
        assert_eq!(detect_api_key(&format!("datadog {upper}")).len(), 0);
    }

    #[test]
    fn rejects_a_run_one_byte_short_of_the_required_length() {
        let short = &API_KEY[..API_KEY.len() - 1];
        assert_eq!(detect_api_key(&format!("datadog {short}")).len(), 0);
    }

    #[test]
    fn rejects_a_run_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{API_KEY}0");
        assert_eq!(detect_api_key(&format!("datadog {long}")).len(), 0);
    }

    #[test]
    fn rejects_a_key_record_id_by_length() {
        assert_eq!(
            detect_api_key(&format!("DD_API_KEY={KEY_RECORD_ID}")).len(),
            0
        );
    }

    #[test]
    fn rejects_a_repeated_character_filler_value() {
        assert_eq!(
            detect_api_key(&format!("datadog {}", "0".repeat(API_KEY_LEN))).len(),
            0
        );
    }

    #[test]
    fn rejects_a_placeholder_style_run_of_x_characters() {
        assert_eq!(
            detect_api_key(&format!("DD_API_KEY={}", "x".repeat(API_KEY_LEN))).len(),
            0
        );
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert_eq!(detect_api_key("datadog DD_API_KEY=${DD_API_KEY}").len(), 0);
    }

    #[test]
    fn finds_a_qualified_match_in_json() {
        let input = format!("{{\"datadog_api_key\": \"{API_KEY}\"}}");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn finds_a_qualified_match_in_yaml() {
        let input = format!("datadog:\n  api_key: {API_KEY}\n");
        // The key name and the value are on different lines in this YAML
        // shape, so only the bare `datadog` top-level key on the first line
        // provides context -- and that is a different line from the value,
        // so this is a documented false negative, not a match.
        assert_eq!(detect_api_key(&input).len(), 0);
    }

    #[test]
    fn finds_a_qualified_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nDD_API_KEY={API_KEY}\r\n");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(API_KEY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + API_KEY.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("DD_API_KEY={API_KEY}");
        assert_eq!(detect_api_key(&input), detect_api_key(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{API_KEY} ").repeat(10_000);
        assert_eq!(detect_api_key(&input).len(), 0);
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("DD_API_KEY={API_KEY} {API_KEY}");
        let candidates = detect_api_key(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::High)
        );
    }

    // -- Current (`ddapp_`-prefixed) Application Key detector --------------

    #[test]
    fn detects_the_current_application_key_with_no_context_needed() {
        let value = current_application_key();
        let candidates = detect_application_key_current(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "datadog_application_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_current_body_one_byte_short_of_the_documented_length() {
        let short_body = &CURRENT_APPLICATION_KEY_BODY[..CURRENT_APPLICATION_KEY_BODY_LEN - 1];
        assert!(
            detect_application_key_current(&format!(
                "{CURRENT_APPLICATION_KEY_PREFIX}{short_body}"
            ))
            .is_empty()
        );
    }

    #[test]
    fn rejects_a_current_body_one_byte_longer_than_the_documented_length() {
        assert!(
            detect_application_key_current(&format!(
                "{CURRENT_APPLICATION_KEY_PREFIX}{CURRENT_APPLICATION_KEY_BODY}a"
            ))
            .is_empty()
        );
    }

    #[test]
    fn rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("ddap_{CURRENT_APPLICATION_KEY_BODY}"),
            format!("DDAPP_{CURRENT_APPLICATION_KEY_BODY}"),
            format!("ddapi_{CURRENT_APPLICATION_KEY_BODY}"),
            format!("ddapp-{CURRENT_APPLICATION_KEY_BODY}"),
        ] {
            assert!(detect_application_key_current(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_a_body_containing_an_underscore() {
        // The Agent's own app-key *validator* (and AWS, and every other
        // Datadog-owned template) requires `[A-Za-z0-9]`; only the lenient
        // log-scrubbing replacer admits `_`, so this module follows the
        // stricter, authentication-facing grammar. See the module doc.
        let body_with_underscore = format!(
            "{}_",
            &CURRENT_APPLICATION_KEY_BODY[..CURRENT_APPLICATION_KEY_BODY_LEN - 1]
        );
        assert_eq!(body_with_underscore.len(), CURRENT_APPLICATION_KEY_BODY_LEN);
        assert!(
            detect_application_key_current(&format!(
                "{CURRENT_APPLICATION_KEY_PREFIX}{body_with_underscore}"
            ))
            .is_empty()
        );
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(
            detect_application_key_current(&format!("legacy_{}", current_application_key()))
                .is_empty()
        );
        assert!(
            detect_application_key_current(&format!("{}_backup", current_application_key()))
                .is_empty()
        );
    }

    #[test]
    fn accepts_a_doc_style_x_filled_placeholder_built_from_valid_alphabet_characters() {
        // The body alphabet is `[A-Za-z0-9]`, the same wide alnum class
        // every other infra-provider exact-length shape in this crate uses
        // (`super::heroku`'s own
        // `accepts_a_doc_style_x_filled_placeholder_built_from_valid_alphabet_characters`):
        // an `x`-filled placeholder is built entirely from valid alphabet
        // characters, so it is indistinguishable from a genuine key and is
        // accepted, not rejected. The literal prefix is its own marker, so
        // no repeated-character-filler exclusion applies here.
        assert_eq!(
            detect_application_key_current(&format!(
                "{CURRENT_APPLICATION_KEY_PREFIX}{}",
                "x".repeat(CURRENT_APPLICATION_KEY_BODY_LEN)
            ))
            .len(),
            1
        );
    }

    #[test]
    fn accepts_env_json_yaml_and_quoted_contexts() {
        let value = current_application_key();
        for input in [
            format!("DD_APPLICATION_KEY={value}"),
            format!("{{\"applicationKey\": \"{value}\"}}"),
            format!("application_key: {value}"),
            format!("application_key=\"{value}\""),
        ] {
            let candidates = detect_application_key_current(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.rfind(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn finds_a_current_match_across_crlf_and_a_unicode_prefix() {
        let value = current_application_key();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_application_key_current(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_current_findings_across_repeated_calls() {
        let value = current_application_key();
        assert_eq!(
            detect_application_key_current(&value),
            detect_application_key_current(&value)
        );
    }

    #[test]
    fn reports_a_repeated_identical_current_value_once_per_occurrence() {
        let value = current_application_key();
        let input = format!("{value} {value}");
        assert_eq!(detect_application_key_current(&input).len(), 2);
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_current_near_miss_prefixes() {
        let short_body = &CURRENT_APPLICATION_KEY_BODY[..CURRENT_APPLICATION_KEY_BODY_LEN - 1];
        let input = format!("{CURRENT_APPLICATION_KEY_PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect_application_key_current(&input).len(), 0);
    }

    // -- Legacy (bare 40-byte hex, keyword-gated) Application Key detector -

    #[test]
    fn detects_an_application_key_named_by_a_specific_marker_at_high_confidence() {
        let input = format!("DD_APPLICATION_KEY={LEGACY_APPLICATION_KEY}");
        let candidates = detect_application_key_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "datadog_application_key_legacy");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(LEGACY_APPLICATION_KEY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_APPLICATION_KEY.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_application_key_via_the_documented_header_marker() {
        let input = format!("DD-APPLICATION-KEY: {LEGACY_APPLICATION_KEY}");
        let candidates = detect_application_key_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn detects_an_application_key_via_the_shorter_app_key_marker() {
        let input = format!("DD_APP_KEY={LEGACY_APPLICATION_KEY}");
        let candidates = detect_application_key_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn detects_an_application_key_named_by_the_datadog_keyword_at_medium_confidence() {
        let input = format!("{{\"note\": \"datadog\", \"value\": \"{LEGACY_APPLICATION_KEY}\"}}");
        let candidates = detect_application_key_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
    }

    #[test]
    fn rejects_a_bare_application_key_with_no_context() {
        assert_eq!(
            detect_application_key_legacy(LEGACY_APPLICATION_KEY).len(),
            0
        );
    }

    #[test]
    fn rejects_an_application_key_whose_context_is_on_a_different_line() {
        let input = format!("DD_APPLICATION_KEY=\n{LEGACY_APPLICATION_KEY}\n");
        assert_eq!(detect_application_key_legacy(&input).len(), 0);
    }

    #[test]
    fn rejects_an_application_key_run_one_byte_short_of_the_required_length() {
        let short = &LEGACY_APPLICATION_KEY[..LEGACY_APPLICATION_KEY.len() - 1];
        assert_eq!(
            detect_application_key_legacy(&format!("datadog {short}")).len(),
            0
        );
    }

    #[test]
    fn rejects_an_application_key_that_is_really_an_api_key_length() {
        // A 32-byte value on a line naming the application key specifically
        // is not itself a 40-byte run, so the legacy application-key
        // detector finds nothing -- the exact-length gate, not the marker,
        // is what distinguishes the two types.
        assert_eq!(
            detect_application_key_legacy(&format!("DD_APPLICATION_KEY={API_KEY}")).len(),
            0
        );
    }

    #[test]
    fn does_not_cross_match_an_api_key_marked_line_as_an_application_key() {
        assert_eq!(
            detect_application_key_legacy(&format!("DD_API_KEY={LEGACY_APPLICATION_KEY}")).len(),
            0
        );
    }

    #[test]
    fn a_ddapp_prefixed_value_is_not_also_reported_by_the_legacy_detector() {
        // The current shape's `_` and mixed-case body already fail the
        // legacy detector's `[0-9a-f]` alphabet; this pins that the two
        // detectors never double-report the same value.
        let value = current_application_key();
        let input = format!("DD_APPLICATION_KEY={value}");
        assert_eq!(detect_application_key_legacy(&input).len(), 0);
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls_for_application_key() {
        let input = format!("DD_APPLICATION_KEY={LEGACY_APPLICATION_KEY}");
        assert_eq!(
            detect_application_key_legacy(&input),
            detect_application_key_legacy(&input)
        );
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_application_key_candidates() {
        let input = format!("{LEGACY_APPLICATION_KEY} ").repeat(10_000);
        assert_eq!(detect_application_key_legacy(&input).len(), 0);
    }
}
