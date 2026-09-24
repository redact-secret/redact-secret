//! Mailgun private API key and HTTP webhook signing key detection.
//!
//! ## Grammar (frozen before implementation, per issue #314)
//!
//! Mailgun's own current documentation never states the private API key's
//! character alphabet or length in prose. The "Keys" API reference
//! (`documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/keys/post-v1-keys`,
//! observed 2026-09-23) shows only an illustrative placeholder value,
//! `"secret": "api-key-be-careful"`, which is documentation-example prose,
//! not a format contract -- the same category of gap [`super::mailchimp`]'s
//! own module doc already treats a silent provider page as. With the
//! provider's prose silent on the private API key itself, the reviewed
//! grammar for that credential rests on the two external tools the issue
//! names, consulted only as external behavioral references per `AGENTS.md`;
//! no code from either project is reproduced here:
//!
//! - gitleaks 8.30.1's `mailgun-private-api-token` rule requires a
//!   `mailgun` keyword within 50 bytes before an assignment operator, then
//!   `(key-[a-f0-9]{32})` -- a literal `key-` and a 32-byte lowercase-hex
//!   body.
//! - trufflehog 3.97.4's `mailgun` detector's "Key-MailGun Token" pattern
//!   matches `\b(key-[a-z0-9]{32})\b` anywhere, with no keyword requirement
//!   -- the same literal and length, but the full lowercase alphanumeric
//!   body alphabet rather than gitleaks' hex-only claim.
//!
//! Both tools agree on the literal `key-` prefix and the 32-byte body
//! length. They disagree on the body alphabet, and gitleaks' hex-only
//! reading is contradicted by an independently observed real key value
//! (`key-x3ifab7xngqxep7923iuab251q5vhox0`, from a third-party engineering
//! blog documenting Mailgun webhook verification) whose 32-byte body
//! includes non-hex letters (`g`, `n`, `q`, `u`, `v`) -- so, per the "adopt
//! the more specific, evidence-backed shape" reasoning [`super::mailchimp`]'s
//! own module doc already applies, the body alphabet is
//! [`pattern::is_lower_alnum`] (`[a-z0-9]`), trufflehog's broader reading,
//! not gitleaks' narrower hex-only class.
//!
//! Both external tools separately describe a distinct "signing key" shape:
//! gitleaks' `mailgun-signing-key` rule matches
//! `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}` and trufflehog's "Hex `MailGun`
//! Token" pattern matches `\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b` --
//! both a dash-segmented 32-8-8 hex triplet, structurally unlike the `key-`
//! prefixed shape above. Mailgun's own **current** API reference directly
//! contradicts this for the credential its account-level endpoint actually
//! names a signing key: the request and response examples on both
//! `.../account-management/get-v5-accounts-http_signing_key` and
//! `.../account-management/post-v5-accounts-http_signing_key` (observed
//! 2026-09-23) show the identical example value,
//! `"http_signing_key": "key-55c5c5c5c55f55ca5cd5f55d5c555c55"` -- the same
//! `key-` + 32-byte-body shape as the private API key above, not the 32-8-8
//! triplet. Per `AGENTS.md`'s instruction to freeze the grammar against
//! **current** provider documentation, this current, authoritative,
//! provider-hosted example overrides both external tools' now-outdated
//! triplet reading for the credential Mailgun's own API currently calls a
//! signing key. The 32-8-8 triplet is therefore treated as a known
//! unsupported legacy variant (see "Consequences and known gaps" below),
//! not a second grammar to implement.
//!
//! Because the current, provider-documented private API key and HTTP
//! webhook signing key shapes are structurally identical (`key-` followed
//! by a 32-byte [`pattern::is_lower_alnum`] body), this module implements
//! one grammar and one finding type for both, rather than inventing an
//! unfounded structural split the provider's own current interface does not
//! support. A same-line keyword requirement (below) still applies equally
//! to both, since neither credential's shape alone names Mailgun.
//!
//! Unlike Postman's `PMAK-` prefix, `key-` is a short, generic English word
//! plus a dash -- not a brand-specific token -- so, mirroring
//! [`super::mailchimp`]'s own reasoning for its unprefixed shape, this
//! detector requires a case-insensitive `mailgun` substring
//! ([`CONTEXT_KEYWORD`]) anywhere on the same line. This also matches
//! gitleaks' own independent choice to gate its `key-[a-f0-9]{32}` rule
//! behind the same keyword despite the literal prefix, corroborating that
//! the prefix alone is not considered specific enough in practice. `Medium`
//! confidence, `Provider` specificity, confidence-gated (not in
//! `ALWAYS_REDACT_TYPES`) -- there is no paired-identifier signal available
//! here the way [`super::twilio`]'s Account SID/API Key SID give its own
//! bare formats a `High`-confidence tier, so this format never rises above
//! `Medium`, the same reasoning [`super::mailchimp`]'s own module doc
//! documents for the same class of gap.
//!
//! A candidate whose body is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded, the same masked-
//! placeholder precedent [`super::mailchimp`], [`super::new_relic`], and
//! [`super::twilio`] already establish. A match is never a slice of a wider
//! `[A-Za-z0-9_-]` identifier ([`BOUNDARY`]); on the left this specifically
//! excludes a `key-` substring embedded in a longer identifier such as
//! gitleaks' own `pubkey-[a-f0-9]{32}` "Mailgun public validation key" rule
//! (`b` immediately precedes `key-` there and is itself alphanumeric, so the
//! left-boundary check rejects it) -- the exact "public validation
//! identifiers/keys" exclusion the issue's own scope section requires,
//! reached structurally rather than by a special case.
//!
//! ## The prefix-less triplet (issue #701)
//!
//! Three sources describe a prefix-less `<32 hex>-<8 hex>-<8 hex>` value as
//! Mailgun's newer private API key: a Mailgun-repository contributor (2019),
//! customer reports (2018) and trufflehog#3870 (2025). Both pinned tools
//! also match it: gitleaks' `mailgun-signing-key` and trufflehog's "Hex
//! MailGun Token". Mailgun's docs state no shape for any key and show a key
//! `id` shaped 8-8 hex. No issued key has been observed, so whether a fresh
//! private key or signing key uses this shape stays recorded uncertainty.
//! Missing a real key costs more than a rare false alarm, so this detector
//! reports the triplet too, under the same `mailgun_api_key` type and the
//! same same-line `mailgun` keyword gate: [`pattern::is_lower_hex`]
//! segments of exactly 32, 8 and 8 bytes joined by `-`, not a slice of a
//! wider identifier, not one repeated character, and not assigned to an
//! identifier-named key (`MAILGUN_KEY_ID=`). It reports medium confidence,
//! and high under a Mailgun-named key.
//!
//! ## Scope
//!
//! Per the issue's stated boundary ("Public validation identifiers/keys and
//! domain/message IDs require explicit policy separation; avoid equating
//! every key-* string with a Mailgun private key"):
//!
//! - `pubkey-<32 bytes>` (Mailgun's public validation key, per gitleaks'
//!   own dedicated `mailgun-pub-key` rule) is out of scope and is excluded
//!   structurally by [`BOUNDARY`], as described above.
//! - A Mailgun domain or message id (documented as an opaque identifier
//!   unrelated to the `key-` shape) never satisfies this grammar and is not
//!   classified.
//! - No Mandrill-, Mailchimp-, or Mailjet-specific grammar is given here:
//!   each is a separate product from Mailgun, not named by this issue, and
//!   out of scope.
//!
//! ## Consequences and known gaps
//!
//! - The legacy 72-byte `[A-Za-z0-9-]{72}` shape (trufflehog's "Original
//!   `MailGun` Token") is a known unsupported variant: it appears in no
//!   Mailgun documentation or recent report. The 32-8-8 triplet, once
//!   treated the same way, is detected since issue #701 (see above).
//! - A key with no `mailgun` keyword anywhere on its own line goes
//!   undetected -- for example a JSON response field named only
//!   `http_signing_key` with no `mailgun` substring nearby. This is the
//!   same accepted tradeoff [`super::mailchimp`]'s own module doc already
//!   carries, and matches gitleaks' own independent choice to accept the
//!   same gap for the same literal-prefixed shape.
//! - A benign `key-<32 lowercase-alphanumeric bytes>` value that is not a
//!   Mailgun credential, sharing a line with the word "mailgun" by
//!   coincidence, would false positive; this is the same class of risk
//!   every other keyword-gated format detector in this registry already
//!   accepts.

use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const KEY_LITERAL: &str = "key-";
const BODY_LEN: usize = 32;

/// The prefix-less triplet's segment widths: `<32>-<8>-<8>` lowercase hex
/// (issue #701).
const TRIPLET_SEGMENTS: [usize; 3] = [32, 8, 8];
/// `32 + 1 + 8 + 1 + 8`.
const TRIPLET_LEN: usize = 50;

/// Mailgun's own product name, case-insensitively, the same substring
/// gitleaks' independent `mailgun-private-api-token` and
/// `mailgun-signing-key` rules key their own keyword gate on, for a
/// same-line comment such as `# Mailgun API key: <value>`.
const CONTEXT_KEYWORD: &str = "mailgun";

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, the same
/// boundary rule [`super::mailchimp`] and [`super::postman`] use for their
/// own shapes; on the left this is what structurally excludes gitleaks'
/// `pubkey-` "public validation key" shape (see the module doc).
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line). Mirrors
/// [`super::mailchimp`]'s own `lines` helper, which documents why "line" is
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

/// `true` when `run` is exactly the `<32>-<8>-<8>` lowercase-hex triplet and
/// is not one repeated hex character.
fn is_triplet(run: &[u8]) -> bool {
    if run.len() != TRIPLET_LEN {
        return false;
    }
    let mut offset = 0usize;
    for (index, width) in TRIPLET_SEGMENTS.iter().enumerate() {
        if index > 0 {
            if run[offset] != b'-' {
                return false;
            }
            offset += 1;
        }
        if !run[offset..offset + width]
            .iter()
            .copied()
            .all(pattern::is_lower_hex)
        {
            return false;
        }
        offset += width;
    }
    let first = run[0];
    run.iter().any(|&byte| byte != b'-' && byte != first)
}

/// The confidence and context signal for a value starting at `start` of a
/// keyword-bearing `line`.
fn context_confidence(line: &str, start: usize) -> (Confidence, &'static str) {
    if text::is_provider_named_assignment(line, start, &[CONTEXT_KEYWORD]) {
        (Confidence::High, "mailgun-named-assignment")
    } else {
        (Confidence::Medium, "mailgun-keyword-cooccurrence")
    }
}

/// Detects a Mailgun private API key or HTTP webhook signing key on a line
/// that also carries [`CONTEXT_KEYWORD`]: a literal `key-` immediately
/// followed by an exact 32-byte [`pattern::is_lower_alnum`] body, or the
/// prefix-less `<32>-<8>-<8>` lowercase-hex triplet (issue #701).
pub(super) struct MailgunApiKeyDetector;

impl Detector for MailgunApiKeyDetector {
    fn id(&self) -> &'static str {
        "mailgun-api-key"
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
            let literal = KEY_LITERAL.as_bytes();
            let ends = pattern::run_ends(bytes, pattern::is_lower_alnum);
            let mut pos = 0usize;
            while pos + literal.len() <= bytes.len() {
                if &bytes[pos..pos + literal.len()] != literal {
                    pos += 1;
                    continue;
                }
                let body_start = pos + literal.len();
                let body_end = ends[body_start];
                if body_end - body_start == BODY_LEN
                    && pattern::boundary_ok(bytes, pos, body_end, BOUNDARY)
                    && !text::is_repeated_character_filler(&line[body_start..body_end])
                    && let Some(range) = ByteRange::new(line_start + pos, line_start + body_end)
                {
                    let (confidence, context_signal) = context_confidence(line, pos);
                    candidates.push(
                        Candidate::new("mailgun_api_key", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([context_signal, "documented-key-prefix"]),
                    );
                }
                pos += literal.len();
            }

            let hex_or_dash = pattern::run_ends(bytes, pattern::is_hex_or_dash);
            let mut start = 0usize;
            while start < bytes.len() {
                if !pattern::is_hex_or_dash(bytes[start]) {
                    start += 1;
                    continue;
                }
                let end = hex_or_dash[start];
                if is_triplet(&bytes[start..end])
                    && pattern::boundary_ok(bytes, start, end, BOUNDARY)
                    && !text::is_non_credential_assignment(line, start)
                    && let Some(range) = ByteRange::new(line_start + start, line_start + end)
                {
                    let (confidence, context_signal) = context_confidence(line, start);
                    candidates.push(
                        Candidate::new("mailgun_api_key", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([context_signal, "hex-triplet-shape"]),
                    );
                }
                start = end;
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "abcdefghijklmnopqrstuvwxyz012345";
    const _: () = assert!(BODY.len() == BODY_LEN);

    fn key() -> String {
        format!("{KEY_LITERAL}{BODY}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        MailgunApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    /// Locally constructed synthetic triplet; never issued by Mailgun.
    const TRIPLET: &str = concat!("0123456789abcdef0123456789abcdef", "-01234567", "-89abcdef");
    const _: () = assert!(TRIPLET.len() == TRIPLET_LEN);

    #[test]
    fn detects_the_prefix_less_triplet_alongside_a_mailgun_keyword() {
        for (input, confidence) in [
            (format!("MAILGUN_API_KEY={TRIPLET}"), Confidence::High),
            (format!("mailgun private key {TRIPLET}"), Confidence::Medium),
            (
                format!("{{\"mailgunSigningKey\": \"{TRIPLET}\"}}"),
                Confidence::High,
            ),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "mailgun_api_key");
            assert_eq!(candidates[0].confidence(), confidence, "{input}");
            let start = input.find(TRIPLET).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + TRIPLET.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_triplet_near_misses() {
        let upper = TRIPLET.to_ascii_uppercase();
        let short = TRIPLET[1..].to_owned();
        let long = format!("{TRIPLET}0");
        let shifted = format!("{}-{}", &TRIPLET[..31], &TRIPLET[32..]);
        let filler = format!("{}-{}-{}", "0".repeat(32), "0".repeat(8), "0".repeat(8));
        for value in [upper, short, long, shifted, filler] {
            let input = format!("mailgun {value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
        assert!(detect(TRIPLET).is_empty());
        assert!(detect(&format!("MAILGUN_KEY_ID={TRIPLET}")).is_empty());
        assert!(detect(&format!("mailgun x-{TRIPLET}")).is_empty());
    }

    #[test]
    fn detects_the_key_alongside_a_mailgun_keyword() {
        for input in [
            format!("MAILGUN_API_KEY={}", key()),
            format!("mailgun.api_key: {}", key()),
            format!("# Mailgun private API key: {}", key()),
            format!("{{\"mailgunApiKey\": \"{}\"}}", key()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "mailgun_api_key");
            let expected = if input.starts_with('#') {
                Confidence::Medium
            } else {
                Confidence::High
            };
            assert_eq!(candidates[0].confidence(), expected, "{input}");
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            let start = input.rfind(&key()).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + key().len()).unwrap()
            );
        }
    }

    #[test]
    fn detects_a_webhook_signing_key_named_field_alongside_the_keyword() {
        let input = format!("mailgun http_signing_key={}", key());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "mailgun_api_key");
    }

    #[test]
    fn rejects_a_bare_value_with_no_context() {
        assert!(detect(&key()).is_empty());
    }

    #[test]
    fn rejects_context_on_a_different_line() {
        let input = format!("# mailgun\n{}\n", key());
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn matches_the_keyword_case_insensitively() {
        let input = format!("MailGun {}", key());
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_body_one_byte_short_of_the_required_length() {
        let short = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("mailgun {KEY_LITERAL}{short}")).is_empty());
    }

    #[test]
    fn rejects_a_body_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{BODY}0");
        assert!(detect(&format!("mailgun {KEY_LITERAL}{long}")).is_empty());
    }

    #[test]
    fn rejects_an_uppercase_body() {
        let upper = BODY.to_ascii_uppercase();
        assert!(detect(&format!("mailgun {KEY_LITERAL}{upper}")).is_empty());
    }

    #[test]
    fn rejects_a_masked_repeated_character_body() {
        assert!(detect(&format!("mailgun {KEY_LITERAL}{}", "0".repeat(BODY_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("mailgun MAILGUN_API_KEY=${MAILGUN_API_KEY}").is_empty());
    }

    #[test]
    fn rejects_the_public_validation_key_shape() {
        // gitleaks' own `pubkey-<32 bytes>` "Mailgun public validation key"
        // shape is out of scope per the issue; the `b` immediately before
        // `key-` is alphanumeric, so the left-boundary check rejects it.
        assert!(detect(&format!("mailgun pubkey-{BODY}")).is_empty());
    }

    #[test]
    fn rejects_a_key_embedded_in_a_wider_identifier() {
        let value = key();
        assert!(detect(&format!("mailgun x{value}")).is_empty());
        assert!(detect(&format!("mailgun {value}x")).is_empty());
        assert!(detect(&format!("mailgun {value}-1")).is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nmailgun {}\r\n", key());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&key()).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key().len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("mailgun {}", key());
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("mailgun {} {}", key(), key());
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
        let input = format!("{} ", key()).repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
