//! Okta management API token detection ("SSWS" authorization contexts).
//!
//! ## Grammar (frozen before implementation, per issue #315)
//!
//! Okta's own "Create an API token" guide
//! (`developer.okta.com/docs/guides/create-an-api-token/-/main/`, observed
//! 2026-09-23) is the only current, provider-hosted source this module
//! relies on for shape: it shows the token used in an HTTP request header as
//! `Authorization: SSWS 00QCjAl4MlV-WPXM...0HmjFx-vbGua` -- a literal `SSWS`
//! authorization scheme, one space, then a value beginning with `00`. The
//! guide's own prose never states an exact length or a complete character
//! class (the example itself is elided with `...`), so -- consulted only as
//! external behavioral references per `AGENTS.md`, with no code from either
//! project reproduced here -- the exact body grammar rests on the two
//! external tools the issue names:
//!
//! - gitleaks 8.30.1's `okta-access-token` rule requires an `okta` keyword
//!   within roughly 50 bytes before an assignment-like operator, then
//!   captures `(00[\w=\-]{40})` -- a literal `00` followed by exactly 40
//!   bytes of `[A-Za-z0-9_=-]`.
//! - trufflehog 3.97.4's `okta` detector matches the bare token
//!   `\b00[a-zA-Z0-9_-]{40}\b` anywhere, gated on the same input carrying an
//!   `.okta` substring and a matching Okta tenant domain
//!   (`\b[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com\b`) elsewhere.
//!
//! Both tools agree on the literal `00` prefix and the 40-byte body length
//! (42 bytes total), matching the official example's own `00`-prefixed
//! value. They disagree only on whether `=` belongs to the body alphabet:
//! gitleaks includes it, trufflehog does not. Unlike [`super::mailgun`]'s own
//! resolution of a similar disagreement, no independently observed real
//! token value was found here to arbitrate one way or the other, and the
//! official guide's own truncated example (`...`) shows no `=`. Per
//! `AGENTS.md`'s instruction to freeze against **current**, evidence-backed
//! grammar rather than the broadest possible reading, this module adopts
//! trufflehog's narrower [`is_body_byte`] (`[A-Za-z0-9_-]`) as the frozen
//! alphabet; a real token whose body happens to contain `=` is a known,
//! accepted false negative (see "Consequences and known gaps" below).
//!
//! ## Context gating and confidence
//!
//! A bare `00` + 40-byte value is not specific enough to redact on sight --
//! the same reasoning [`super::mailgun`] and [`super::twilio`] already give
//! their own unprefixed or short-prefixed shapes, and exactly the concern
//! issue #315 raises directly ("ambiguous unprefixed values require reliable
//! context"). This module recognizes two independent signals, scored the
//! same way [`super::twilio`]'s own paired-identifier/keyword gate is:
//!
//! - The literal `SSWS` authorization scheme immediately before the
//!   candidate on the same line, separated only by horizontal whitespace and
//!   itself boundary-checked so it is never the tail of a longer word
//!   ([`ssws_scheme_immediately_precedes`]) -- Okta's own documented,
//!   provider-unique scheme name, matched case-insensitively per this
//!   crate's usual keyword-matching convention. `Confidence::High`.
//! - Absent that, a case-insensitive `okta` substring anywhere on the same
//!   line ([`CONTEXT_KEYWORD`]) -- the same keyword gitleaks' and
//!   trufflehog's own independent rules both key their gate on.
//!   `Confidence::Medium`.
//! - Neither present: the candidate is discarded, per the issue's own
//!   instruction.
//!
//! `Specificity::Provider` throughout; this type is deliberately left out of
//! `policy::ALWAYS_REDACT_TYPES` (see that module's doc comment), so
//! `DefaultPolicy`'s existing confidence-gated fallback already redacts the
//! `SSWS`-adjacent `High` case and only warns on the keyword-only `Medium`
//! case, without this module needing its own policy carve-out.
//!
//! A candidate whose body is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded, the same masked-
//! placeholder precedent [`super::mailgun`], [`super::new_relic`], and
//! [`super::twilio`] already establish. A match is never a slice of a wider
//! `[A-Za-z0-9_-]` identifier ([`BOUNDARY`]).
//!
//! ## Scope
//!
//! Per the issue's stated boundary ("Exclude tenant domains, user/group/
//! application IDs, and OAuth client IDs. Reuse existing JWT detection for
//! JWTs rather than claiming every JWT is an Okta management token."):
//!
//! - An Okta tenant domain (`*.okta.com`, `*.oktapreview.com`,
//!   `*.okta-emea.com`, per trufflehog's own domain rule) never satisfies
//!   this grammar: it is not `00`-prefixed and contains a `.`, which is
//!   outside [`is_body_byte`].
//! - This repository could not independently confirm Okta's current
//!   user/group/application-id or OAuth-client-id grammar from the
//!   provider's own documentation in this environment (the interactive API
//!   reference did not yield static, citable content); exclusion here
//!   therefore rests structurally on this grammar's exact 42-byte length and
//!   both-sided boundary check, not on asserting a specific competing id
//!   shape. A same-length, same-alphabet id that happens to begin with `00`
//!   would still false-positive when it shares a line with `okta` or
//!   immediately follows `SSWS`; this is the same class of shape-collision
//!   risk every other keyword- or scheme-gated format detector in this
//!   registry already accepts.
//! - A JWT (Okta's own OAuth access and ID tokens) is a dot-delimited
//!   three-segment value; `.` is outside [`is_body_byte`], so this grammar's
//!   line-scoped `00`-prefixed run stops at the first segment boundary and
//!   never spans a whole JWT. The existing dedicated JWT detector, not this
//!   one, is the one that claims those tokens, per the issue's own
//!   instruction -- no exclusion logic is needed here beyond the alphabet
//!   already excluding `.`.
//!
//! ## Consequences and known gaps
//!
//! - A token with no `SSWS` scheme immediately before it and no `okta`
//!   substring anywhere on its own line goes undetected -- for example a
//!   JSON response field named only `apiToken` with no `okta` substring
//!   nearby. The same accepted tradeoff [`super::mailgun`]'s own module doc
//!   already carries.
//! - A real token whose 40-byte body happens to contain `=` is not matched,
//!   per the alphabet-disagreement resolution above.
//! - A benign `00`-prefixed 42-byte value that is not an Okta credential,
//!   sharing a line with the word "okta" or immediately following "SSWS" by
//!   coincidence, would false positive; the same class of risk every other
//!   keyword- or scheme-gated format detector in this registry already
//!   accepts.

use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const TOKEN_PREFIX: &str = "00";
const BODY_LEN: usize = 40;

/// Okta's own HTTP `Authorization` scheme name, per the provider's current
/// API-token guide.
const SSWS_SCHEME: &str = "SSWS";

/// Okta's own product name, matched the same case-insensitive way gitleaks'
/// and trufflehog's own independent rules key their keyword gate on.
const CONTEXT_KEYWORD: &str = "okta";

/// `[A-Za-z0-9_-]`: the frozen token-body alphabet (see the module doc's
/// alphabet-disagreement resolution).
fn is_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier.
const BOUNDARY: Alphabet = is_body_byte;

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line). Mirrors
/// [`super::mailgun`]'s own `lines` helper, which documents why "line" is
/// the right unit: it is the same processing unit the incremental sanitizer
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

/// `true` when [`CONTEXT_KEYWORD`] occurs (case-insensitively) anywhere in
/// `line`.
fn line_has_context_keyword(line: &str) -> bool {
    let bytes = line.as_bytes();
    let needle_len = CONTEXT_KEYWORD.len();
    needle_len <= bytes.len()
        && (0..=bytes.len() - needle_len)
            .any(|pos| text::starts_with_ci(line, pos, CONTEXT_KEYWORD))
}

/// `true` when [`SSWS_SCHEME`] appears immediately before `start` in `line`,
/// separated only by horizontal whitespace, matched case-insensitively, and
/// itself boundary-checked so it is never the tail of a longer word. At
/// least one whitespace byte must separate the scheme from the candidate,
/// matching Okta's own documented `SSWS <token>` header syntax; a scheme
/// glued directly to the token with no separating space is not matched here
/// (it is also rejected as a candidate at all by [`BOUNDARY`], since `S` is
/// itself a body-alphabet byte).
fn ssws_scheme_immediately_precedes(line: &str, start: usize) -> bool {
    let bytes = line.as_bytes();
    let mut pos = start;
    while pos > 0 && matches!(bytes[pos - 1], b' ' | b'\t') {
        pos -= 1;
    }
    if pos == start || pos < SSWS_SCHEME.len() {
        return false;
    }
    let scheme_start = pos - SSWS_SCHEME.len();
    text::starts_with_ci(line, scheme_start, SSWS_SCHEME)
        && (scheme_start == 0 || !is_body_byte(bytes[scheme_start - 1]))
}

/// Detects an Okta management API token: a literal `00` immediately followed
/// by an exact 40-byte [`is_body_byte`] body, on a line that either carries
/// an immediately-preceding `SSWS` scheme (`Confidence::High`) or
/// [`CONTEXT_KEYWORD`] (`Confidence::Medium`).
pub(super) struct OktaApiTokenDetector;

impl Detector for OktaApiTokenDetector {
    fn id(&self) -> &'static str {
        "okta-api-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            let has_keyword = line_has_context_keyword(line);

            let bytes = line.as_bytes();
            let literal = TOKEN_PREFIX.as_bytes();
            let ends = pattern::run_ends(bytes, is_body_byte);
            let mut pos = 0usize;
            while pos + literal.len() <= bytes.len() {
                if &bytes[pos..pos + literal.len()] != literal {
                    pos += 1;
                    continue;
                }
                let body_start = pos + literal.len();
                let body_end = ends[body_start];
                let shape_ok = body_end - body_start == BODY_LEN
                    && pattern::boundary_ok(bytes, pos, body_end, BOUNDARY)
                    && !text::is_repeated_character_filler(&line[body_start..body_end]);
                let gate = if !shape_ok {
                    None
                } else if ssws_scheme_immediately_precedes(line, pos) {
                    Some((Confidence::High, "ssws-scheme-adjacency"))
                } else if has_keyword {
                    Some((Confidence::Medium, "okta-keyword-cooccurrence"))
                } else {
                    None
                };
                if let Some((confidence, signal)) = gate
                    && let Some(range) = ByteRange::new(line_start + pos, line_start + body_end)
                {
                    candidates.push(
                        Candidate::new("okta_api_token", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([signal]),
                    );
                }
                pos += literal.len();
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNTHETICREVOKEDTOKENA0123456789abcdefgh";
    const DASH_UNDERSCORE_BODY: &str = "SYNTHETIC-REVOKED_TOKEN-0123456789abcdef";
    const _: () = assert!(BODY.len() == BODY_LEN);
    const _: () = assert!(DASH_UNDERSCORE_BODY.len() == BODY_LEN);

    fn token() -> String {
        format!("{TOKEN_PREFIX}{BODY}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        OktaApiTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_token_alongside_an_ssws_scheme_at_high_confidence() {
        for input in [
            format!("Authorization: SSWS {}", token()),
            format!("authorization: ssws {}", token()),
            format!("Authorization:SSWS  {}", token()),
            format!("Authorization: Ssws\t{}", token()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "okta_api_token");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            let start = input.rfind(&token()).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token().len()).unwrap()
            );
        }
    }

    #[test]
    fn detects_the_token_named_by_an_okta_keyword_at_medium_confidence() {
        for input in [
            format!("OKTA_API_TOKEN={}", token()),
            format!("okta.api_token: {}", token()),
            format!("# Okta management API token: {}", token()),
            format!("{{\"oktaApiToken\": \"{}\"}}", token()),
            format!("okta_api_token: {}", token()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "okta_api_token");
            assert_eq!(candidates[0].confidence(), Confidence::Medium);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        }
    }

    #[test]
    fn accepts_a_body_containing_dashes_and_underscores() {
        let value = format!("{TOKEN_PREFIX}{DASH_UNDERSCORE_BODY}");
        let input = format!("okta {value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
    }

    #[test]
    fn rejects_a_bare_value_with_no_context() {
        assert!(detect(&token()).is_empty());
    }

    #[test]
    fn rejects_context_on_a_different_line() {
        let input = format!("# okta\n{}\n", token());
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn rejects_an_ssws_scheme_glued_to_the_token_with_no_separating_space() {
        assert!(detect(&format!("okta SSWS{}", token())).is_empty());
    }

    #[test]
    fn matches_the_keyword_and_scheme_case_insensitively() {
        assert_eq!(detect(&format!("OKTA {}", token())).len(), 1);
        assert_eq!(detect(&format!("ssws {}", token())).len(), 1);
    }

    #[test]
    fn rejects_a_body_one_byte_short_of_the_required_length() {
        let short = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("okta {TOKEN_PREFIX}{short}")).is_empty());
    }

    #[test]
    fn rejects_a_body_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{BODY}0");
        assert!(detect(&format!("okta {TOKEN_PREFIX}{long}")).is_empty());
    }

    #[test]
    fn rejects_a_wrong_prefix() {
        assert!(detect(&format!("okta 01{BODY}")).is_empty());
    }

    #[test]
    fn rejects_a_masked_repeated_character_body() {
        assert!(detect(&format!("okta {TOKEN_PREFIX}{}", "a".repeat(BODY_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("okta OKTA_API_TOKEN=${OKTA_API_TOKEN}").is_empty());
    }

    #[test]
    fn rejects_a_tenant_domain() {
        assert!(detect("okta https://dev-12345.okta.com/oauth2/default").is_empty());
    }

    #[test]
    fn rejects_a_shorter_id_shaped_value_even_with_ssws_context() {
        // Okta's own entity identifiers (user, group, application) are
        // shorter than this grammar's exact 42-byte token; a short,
        // similarly `00`-prefixed id never satisfies the body-length
        // requirement, with or without an `SSWS` scheme nearby.
        assert!(detect("Authorization: SSWS 00u1a2B3c4D5e6F7g8H9").is_empty());
    }

    #[test]
    fn rejects_a_token_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("okta x{value}")).is_empty());
        assert!(detect(&format!("okta {value}x")).is_empty());
    }

    #[test]
    fn does_not_span_a_dot_delimited_jwt_even_with_context() {
        // A JWT is dot-delimited three-segment base64url text with no `00`
        // + 40-byte run of its own here; the existing JWT detector, not
        // this one, is the one that claims it, per the issue's own
        // instruction to reuse existing JWT detection for JWTs.
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   dGhpc2lzYXNpZ25hdHVyZQ";
        assert!(detect(&format!("Authorization: SSWS {jwt}")).is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nokta {}\r\n", token());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&token()).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token().len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("okta {}", token());
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("okta {} {}", token(), token());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::Medium)
        );
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{} ", token()).repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
