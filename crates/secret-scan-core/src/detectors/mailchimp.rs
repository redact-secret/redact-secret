//! Mailchimp Marketing API key detection.
//!
//! Mailchimp's own documentation
//! (`mailchimp.com/developer/marketing/docs/fundamentals/`, observed
//! 2026-09-23) states the key format only through a worked example: "if your
//! API key is `0123456789abcdef0123456789abcde-us6`, then the data center
//! subdomain is `us6`". The page never states an exact character count or
//! alphabet in prose, and the example body itself (31 hex bytes, one short
//! of the length below) is documentation-example noise, not a stated
//! contract -- the same category of gap `super::postman`'s own module doc
//! treats a silent or inconsistent provider page as. With the provider's
//! prose silent, the reviewed grammar rests on the two external tools the
//! issue names, consulted only as external behavioral references per
//! `AGENTS.md`; no code from either project is reproduced here:
//!
//! - gitleaks 8.30.1's `mailchimp-api-key` rule requires a `mailchimp`
//!   keyword within 50 bytes before an assignment operator, then
//!   `([a-f0-9]{32}-us\d\d)` -- a 32-byte hex body, a literal `-us`, and
//!   **exactly two** digits.
//! - trufflehog 3.97.4's `mailchimp` detector matches
//!   `[0-9a-f]{32}-us[0-9]{1,2}` anywhere, with no keyword requirement (its
//!   `-us` keyword is only a chunk pre-filter, not part of the matched
//!   grammar) and **one or two** digits.
//!
//! Both tools agree on the 32-byte lowercase-hex body and the literal `-us`
//! separator. They disagree on the digit count, and gitleaks' own
//! two-digit-only reading is contradicted by the provider's own worked
//! example above (`-us6`, one digit) -- so, per the "adopt the more
//! specific, evidence-backed shape" reasoning `super::postman`'s own module
//! doc already applies (there in the other direction, toward the narrower
//! tool), here the *broader* shape is the one the provider's own example
//! corroborates: trufflehog's one-or-two-digit range. Digit count is
//! therefore [`MIN_DATACENTER_DIGITS`]..=[`MAX_DATACENTER_DIGITS`], not
//! gitleaks' fixed two.
//!
//! ## Grammar (frozen per issue #313, revised by #697, #698 and #699)
//!
//! A bare run of exactly [`KEY_HEX_LEN`] [`is_key_hex`] (`[0-9A-Fa-f]`)
//! bytes, immediately followed by the literal `-us`, then a run of
//! [`MIN_DATACENTER_DIGITS`] to [`MAX_DATACENTER_DIGITS`] ASCII digits
//! (greedily consumed, so a four-digit run never matches a three-digit
//! prefix of itself), bounded on both sides by a byte outside
//! [`pattern::is_alnum_dash`] -- wider than the match alphabet on the left so
//! an adjacent letter or a joining dash still rejects a truncated slice of a
//! longer identifier, and excluding a trailing dash on the right so a value
//! embedded in a longer dash-joined slug is not misread as standalone,
//! mirroring [`super::postman`]'s own `is_alnum_dash` boundary choice for
//! its own dash-containing shape.
//!
//! Unlike Postman's `PMAK-` prefix, neither the bare 32-byte hex body nor
//! its generic-looking `-us<N>` datacenter suffix names Mailchimp on its own
//! -- the same class of ambiguity `super::new_relic`'s License Key format
//! documents for its own bare hex value, and gitleaks' independent choice to
//! gate its rule on a same-line `mailchimp` keyword is corroborating
//! evidence that the shape alone is not considered specific enough in
//! practice. Per the issue's own "ambiguous unprefixed values require
//! reliable context" instruction, this detector originally required a
//! case-insensitive `mailchimp` substring ([`CONTEXT_KEYWORD`]) anywhere on
//! the same line (see "Keyword-free shape" below for the #931 revision) --
//! the same "same line" scope [`super::new_relic`] and [`super::twilio`]
//! already use for their own bare-hex formats, for the same
//! incremental-consistency reason documented there. `Provider` specificity,
//! confidence-gated (not in `ALWAYS_REDACT_TYPES`): `Medium` for a keyword
//! anywhere on the line, and `High` when the value is assigned to a key that
//! names Mailchimp (`decision-redact-provider-named-credential-assignments`,
//! issue #702). Since issue #936 the complete shape outside a hostname or
//! path is `High` with or without a keyword (see "Confidence" below).
//!
//! ## Unresolved provider facts (issues #697, #698, #699)
//!
//! No issued key has been observed and Mailchimp's prose states none of the
//! following, so each stays recorded uncertainty. The grammar takes the
//! reading that misses fewer real keys, except where a scored benchmark
//! twin pins the narrower reading.
//!
//! - **Case (#697).** The tools disagree: gitleaks, betterleaks and Nosey
//!   Parker match case-insensitively, trufflehog lowercase only. 2 of 115
//!   public-code candidates carried `A-F`. The body accepts `A-F` and
//!   `a-f`. An uppercase key is no longer missed, and a 32-byte uppercase
//!   hex run followed by `-us<N>` on a Mailchimp line is not plausibly
//!   anything else.
//! - **Datacenter digits (#698).** trufflehog accepts 1–2 digits, gitleaks
//!   exactly 2, and Nosey Parker 1–3. Public code shows 35 one-digit and 80
//!   two-digit suffixes, and none with three. The suffix accepts 1–3 digits,
//!   so a key from a future `us100`+ datacenter is not missed whole. Four or
//!   more digits still reject.
//! - **Body length (#699).** The fundamentals page's one worked example has
//!   a 31-byte body. Every scanner rule, a 2009 Mailchimp staff post and 111
//!   of 115 public-code candidates use 32. The example is read as a
//!   documentation typo, not a grammar. The body stays exactly 32 bytes;
//!   the benchmark's scored 31-byte twins
//!   (`mailchimp-api-key-*-datacenter-*-twin`) also assert that a 31-byte
//!   body stays silent.
//!
//! A candidate whose hex body is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded: the alphabet
//! contains characters (`0`, ...) a masked placeholder commonly repeats, and
//! this format has no structural marker of its own strong enough to keep a
//! value like `mailchimp 00000000000000000000000000000000-us1` from
//! matching the bare alphabet otherwise, the same precedent
//! [`super::new_relic`] and [`super::twilio`] already establish.
//!
//! ## Scope
//!
//! Per the issue's stated boundary ("Exclude audience/list/campaign IDs,
//! ordinary hex hashes, public URLs, and suffix-only strings"):
//!
//! - A Mailchimp audience/list/campaign id (a short alphanumeric id,
//!   documented as far shorter than 32 bytes) never satisfies the exact
//!   32-byte hex body and is not classified.
//! - A bare 32-byte hex value with no `-us<N>` suffix -- even alongside a
//!   `mailchimp` keyword -- is not classified: the suffix is part of the
//!   documented shape itself, not an optional decoration, so a value
//!   missing it is an intentional false negative, not a fuzzy match against
//!   a shorter shape (the same "no code from either project" class of
//!   discipline `super::postman`'s own module doc applies to its own
//!   internal-dash post-check).
//! - A bare `-us<N>` suffix with no preceding hex body ("suffix-only") is
//!   never classified: the grammar always anchors on the 32-byte hex run
//!   first.
//! - No Mandrill-specific grammar is given here: Mandrill's transactional
//!   email API is a separate product from Mailchimp Marketing, not named by
//!   this issue, and out of scope.
//!
//! ## Keyword-free shape (issue #931)
//!
//! The #313 gate missed complete keys whose Mailchimp context was on another
//! line (a `requests` Basic-auth tuple under a `usNN.api.mailchimp.com`
//! URL, an `Authorization: apikey` header under its `Host:` line) or absent
//! (a key pasted into support-ticket prose). The gate is relaxed only for
//! the **complete** shape -- exactly 32 hex bytes, the literal `-us`, and a
//! 1-3 digit datacenter, whole between boundaries -- because that suffix is
//! the one part of the grammar the bare hex body lacks: a hash, a UUID
//! without dashes or a hex id carries no `-us<N>` of its own, and
//! trufflehog 3.97.4 already matches this shape with no keyword. Without a
//! keyword, a match that is a DNS label (`<hex>-us1.example.test`) or a URL
//! path segment (`/<hex>-us1`) is an identifier position and is not
//! reported.
//!
//! ## Confidence (issue #936)
//!
//! #931 reported the keyword-free shape at [`Confidence::Medium`], so the
//! confidence-gated default policy only warned and the key stayed in the
//! sanitized output. Under the security-first default (redact over warn),
//! the complete shape outside an identifier position is
//! [`Confidence::High`] (`mailchimp-suffix-shape`) whether or not a
//! `mailchimp` keyword shares its line: a keyword cannot make the same
//! value less of a key. A Mailchimp-named key stays high
//! (`mailchimp-named-assignment`). Only a DNS-label or URL-path match that
//! a same-line keyword keeps reporting stays [`Confidence::Medium`]
//! (`mailchimp-keyword-cooccurrence`, warn).
//!
//! FN removed: complete keys with no same-line keyword (#931), now
//! redacted (#936). FP added: a non-secret 32-hex value that happens to be
//! followed by `-us<1-3 digits>` outside a hostname or path (a
//! region-sharded resource id in prose or a log field) is redacted.
//!
//! ## Consequences and known gaps
//!
//! - A bare 32-hex body with no `-us<N>` suffix is never reported, with or
//!   without a keyword.
//! - A benign 32-byte hex value immediately followed by a
//!   coincidental `-us<N>` (for example a region-sharded resource id) that
//!   happens to share a line with the word "mailchimp" would false
//!   positive; this is the same class of risk every other keyword-gated
//!   bare-format detector in this registry already accepts.

use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::prefilter::Literals;
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const KEY_HEX_LEN: usize = 32;
const DATACENTER_LITERAL: &str = "-us";
const MIN_DATACENTER_DIGITS: usize = 1;
const MAX_DATACENTER_DIGITS: usize = 3;

/// Mailchimp's own product name, case-insensitively, the same substring
/// gitleaks' independent `mailchimp-api-key` rule keys its own keyword gate
/// on, for a same-line comment such as `# Mailchimp API key: <value>`.
const CONTEXT_KEYWORD: &str = "mailchimp";

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, the same
/// boundary rule [`super::postman`] uses for its own dash-containing shape.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// `[0-9A-Fa-f]`: the body alphabet, case-insensitive since issue #697 (see
/// the module doc's unresolved provider facts).
fn is_key_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// `true` when [`CONTEXT_KEYWORD`] occurs (case-insensitively) anywhere in
/// `line`.
fn line_has_context_keyword(line: &str) -> bool {
    text::contains_ci(line, CONTEXT_KEYWORD)
}

/// Returns the end offset (relative to `bytes`) of a valid
/// `-us<MIN_DATACENTER_DIGITS..=MAX_DATACENTER_DIGITS digits>` datacenter
/// suffix starting at `hex_end`, or `None` if the literal is absent or the
/// digit run is the wrong length. The digit run is consumed greedily, so a
/// three-digit run (`-us123`) never matches as a two-digit suffix followed
/// by a stray digit.
fn match_datacenter_suffix(bytes: &[u8], hex_end: usize) -> Option<usize> {
    let literal = DATACENTER_LITERAL.as_bytes();
    let literal_end = hex_end + literal.len();
    if literal_end > bytes.len() || &bytes[hex_end..literal_end] != literal {
        return None;
    }
    let mut digits_end = literal_end;
    while digits_end < bytes.len() && bytes[digits_end].is_ascii_digit() {
        digits_end += 1;
    }
    let digit_count = digits_end - literal_end;
    (MIN_DATACENTER_DIGITS..=MAX_DATACENTER_DIGITS)
        .contains(&digit_count)
        .then_some(digits_end)
}

/// `true` when a keyword-free match at `bytes[start..end]` sits in a
/// structure that holds an identifier, not a key (issue #931): a DNS label
/// (the suffix is followed by `.` and an alphanumeric byte,
/// `<hex>-us1.example.test`) or a URL path segment (a `/` right before it,
/// `/objects/<hex>-us1`). A same-line `mailchimp` keyword overrides this,
/// as before.
fn is_non_credential_structure(bytes: &[u8], start: usize, end: usize) -> bool {
    let dns_label =
        bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_alphanumeric);
    let path_segment = start > 0 && bytes[start - 1] == b'/';
    dns_label || path_segment
}

/// Detects a Mailchimp Marketing API key: a bare 32-byte hex run immediately
/// followed by a `-us<1-3 digits>` datacenter suffix. The complete shape
/// alone is a high finding (issues #931, #936); a same-line
/// [`CONTEXT_KEYWORD`] only keeps a DNS-label or URL-path match reported, at
/// medium.
pub(super) struct MailchimpMarketingApiKeyDetector;

impl Detector for MailchimpMarketingApiKeyDetector {
    fn id(&self) -> &'static str {
        "mailchimp-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        text::for_each_long_run_line(input, |line_start, line_end| {
            let line = &input[line_start..line_end];
            let has_keyword = line_has_context_keyword(line);

            let bytes = line.as_bytes();
            let mut start = 0usize;
            while start < bytes.len() {
                if !is_key_hex(bytes[start]) {
                    start += 1;
                    continue;
                }
                let hex_end = pattern::run_end(bytes, start, is_key_hex);
                if hex_end - start == KEY_HEX_LEN
                    && let Some(full_end) = match_datacenter_suffix(bytes, hex_end)
                    && pattern::boundary_ok(bytes, start, full_end, BOUNDARY)
                    && !text::is_repeated_character_filler(&line[start..hex_end])
                    && (has_keyword || !is_non_credential_structure(bytes, start, full_end))
                    && let Some(range) = ByteRange::new(line_start + start, line_start + full_end)
                {
                    let identifier_position = is_non_credential_structure(bytes, start, full_end);
                    let (confidence, context_signal) = if has_keyword
                        && text::is_provider_named_assignment(line, start, &[CONTEXT_KEYWORD])
                    {
                        (Confidence::High, "mailchimp-named-assignment")
                    } else if !identifier_position {
                        // Issue #936: the complete shape outside a hostname
                        // or path is the key, keyword or not.
                        (Confidence::High, "mailchimp-suffix-shape")
                    } else {
                        (Confidence::Medium, "mailchimp-keyword-cooccurrence")
                    };
                    candidates.push(
                        Candidate::built_in("mailchimp_api_key", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([context_signal, "documented-datacenter-suffix"]),
                    );
                }
                start = hex_end;
            }
        });
        Ok(candidates)
    }
}

/// The literals one of which every `mailchimp-api-key` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
///
/// The keyword gate is case-insensitive and cannot be declared; the
/// datacenter suffix every candidate ends in can.
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&[DATACENTER_LITERAL])];

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "0123456789abcdef0123456789abcdef";
    const _: () = assert!(KEY_HEX.len() == KEY_HEX_LEN);

    fn key() -> String {
        format!("{KEY_HEX}-us6")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        MailchimpMarketingApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_key_alongside_a_mailchimp_keyword() {
        for input in [
            format!("MAILCHIMP_API_KEY={}", key()),
            format!("mailchimp.api_key: {}", key()),
            format!("# Mailchimp API key: {}", key()),
            format!("{{\"mailchimpApiKey\": \"{}\"}}", key()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "mailchimp_api_key");
            // Issue #936: a keyword elsewhere on the line no longer lowers
            // the complete shape to medium.
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            let start = input.rfind(&key()).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + key().len()).unwrap()
            );
        }
    }

    #[test]
    fn accepts_a_two_digit_datacenter_suffix() {
        let value = format!("{KEY_HEX}-us21");
        let input = format!("mailchimp {value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn reports_the_complete_shape_with_no_keyword_at_high() {
        // Issue #931: the complete `-us<dc>` shape alone is evidence; issue
        // #936: it is high, so the default policy redacts it.
        for input in [
            key(),
            format!("# mailchimp\n{}\n", key()),
            format!("auth=(\"anystring\", \"{}\"),", key()),
            format!("> Authorization: apikey {}", key()),
            format!("The key in the runbook is {}. Revoked?", key()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let range = candidates[0].range();
            assert_eq!(&input[range.start()..range.end()], key());
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert!(
                candidates[0]
                    .signals()
                    .iter()
                    .any(|signal| signal == "mailchimp-suffix-shape"),
                "{input}"
            );
        }
    }

    #[test]
    fn keyword_free_benign_twins_stay_silent() {
        for input in [
            // Hex, a dashless and a dashed UUID with no `-us<N>` suffix.
            KEY_HEX.to_owned(),
            "0123abcd-89ab-cdef-0123-456789abcdef".to_owned(),
            format!("request_id={KEY_HEX}"),
            // `-us` region labels that are not a 1-3 digit datacenter.
            format!("{KEY_HEX}-us-east-1"),
            format!("bucket {KEY_HEX}-us"),
            format!("{KEY_HEX}-us1234"),
            // The shape as a DNS label or a URL path segment.
            format!("https://{}.cdn.example.test/a.png", key()),
            format!("GET /v1/objects/{} HTTP/1.1", key()),
            // A wider identifier and a 31-byte body.
            format!("x{}", key()),
            format!("{}-us6", &KEY_HEX[1..]),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
        // A same-line keyword still overrides the structural exclusions, at
        // medium only (issue #936): the position is an identifier's.
        for input in [
            format!("mailchimp https://{}.cdn.example.test", key()),
            format!("mailchimp GET /v1/objects/{}", key()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::Medium, "{input}");
        }
    }

    #[test]
    fn matches_the_keyword_case_insensitively() {
        let input = format!("MailChimp {}", key());
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_bare_hex_body_with_no_datacenter_suffix() {
        assert!(detect(&format!("mailchimp {KEY_HEX}")).is_empty());
    }

    #[test]
    fn rejects_a_suffix_with_no_preceding_hex_body() {
        assert!(detect("mailchimp -us6").is_empty());
    }

    #[test]
    fn rejects_a_wrong_datacenter_literal() {
        assert!(detect(&format!("mailchimp {KEY_HEX}-eu6")).is_empty());
    }

    #[test]
    fn accepts_a_three_digit_datacenter_suffix() {
        let value = format!("{KEY_HEX}-us123");
        let input = format!("mailchimp {value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_four_digit_datacenter_suffix() {
        assert!(detect(&format!("mailchimp {KEY_HEX}-us1234")).is_empty());
    }

    #[test]
    fn rejects_a_hex_body_one_byte_short_of_the_required_length() {
        let short = &KEY_HEX[..KEY_HEX_LEN - 1];
        assert!(detect(&format!("mailchimp {short}-us6")).is_empty());
    }

    #[test]
    fn rejects_a_hex_body_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{KEY_HEX}0");
        assert!(detect(&format!("mailchimp {long}-us6")).is_empty());
    }

    #[test]
    fn accepts_an_uppercase_or_mixed_case_hex_body() {
        let upper = KEY_HEX.to_ascii_uppercase();
        let mixed = format!("{}{}", &KEY_HEX[..16], &upper[16..]);
        for body in [upper, mixed] {
            let value = format!("{body}-us6");
            let input = format!("mailchimp {value}");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.rfind(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_a_non_hex_letter_in_the_body() {
        let body = format!("{}z{}", &KEY_HEX[..16], &KEY_HEX[17..]);
        assert!(detect(&format!("mailchimp {body}-us6")).is_empty());
    }

    #[test]
    fn rejects_a_masked_repeated_character_body() {
        assert!(detect(&format!("mailchimp {}-us1", "0".repeat(KEY_HEX_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("mailchimp MAILCHIMP_API_KEY=${MAILCHIMP_API_KEY}").is_empty());
    }

    #[test]
    fn rejects_an_audience_id_reference() {
        // A Mailchimp audience/list id is documented as a short
        // alphanumeric id, far shorter than the 32-byte key body.
        assert!(detect("mailchimp list_id: a1b2c3d4e5").is_empty());
    }

    #[test]
    fn rejects_a_key_embedded_in_a_wider_identifier() {
        let value = key();
        assert!(detect(&format!("mailchimp x{value}")).is_empty());
        assert!(detect(&format!("mailchimp {value}x")).is_empty());
        assert!(detect(&format!("mailchimp {value}-1")).is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nmailchimp {}\r\n", key());
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
        let input = format!("mailchimp {}", key());
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("mailchimp {} {}", key(), key());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::High)
        );
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        // Since #931 every complete shape is reported; the line is still
        // scanned once.
        let input = format!("{} ", key()).repeat(10_000);
        assert_eq!(detect(&input).len(), 10_000);
        let near_misses = format!("{KEY_HEX}-us ").repeat(10_000);
        assert!(detect(&near_misses).is_empty());
    }
}
