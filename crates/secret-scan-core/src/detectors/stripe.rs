//! Stripe credential detection: API keys and webhook signing secrets.
//!
//! Stripe states that webhook signing secrets "aren't API keys"
//! (<https://docs.stripe.com/keys>), so issue #729 splits `whsec_` out of
//! the key family's `stripe_credential` finding type into its own
//! `stripe_webhook_signing_secret`. Both stay under the one `stripe-token`
//! detector id, the same "one detector, many declared types" shape
//! [`super::github`] uses. The `sk_`/`rk_`/`sk_org_` key shapes keep their
//! table in [`super::additional_providers::STRIPE`]; only the `whsec_`
//! grammar lives here.
//!
//! Frozen `whsec_` contract (`docs/audits/evidence/726/README.md`):
//! `whsec_` followed by at least 32 bytes of `[A-Za-z0-9+/]` and up to two
//! terminal `=` padding bytes. Stripe documents the prefix and where the
//! secret is configured, never a body length or alphabet; the 32-byte floor
//! is the API reference example, and `+`, `/` and `=` are admitted because
//! Stripe's own CLI scrubber (`\bwhsec_[a-zA-Z0-9+/]+=*`) does, while its
//! canary sanitizer does not, so no fixture may assert silence on them.
//!
//! Detection is deliberately bare: Svix and Standard Webhooks also issue
//! `whsec_` values, but those are webhook signing secrets too, so a bare hit
//! is still a secret to redact. Attributing a value to Stripe specifically
//! is a scoring concept in the benchmark, not a detector gate.

use crate::detectors::additional_providers::STRIPE;
use crate::detectors::pattern;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const WEBHOOK_PREFIX: &str = "whsec_";
const WEBHOOK_TYPE: &str = "stripe_webhook_signing_secret";
const WEBHOOK_SIGNALS: [&str; 2] = ["stripe-documented-prefix", "webhook-base64-body"];
/// The provider's only full-length example body (API reference,
/// `webhook_endpoints` object).
const WEBHOOK_BODY_MIN: usize = 32;
const WEBHOOK_MAX_PADDING: usize = 2;
/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, the same
/// boundary the key shapes use.
const BOUNDARY: pattern::Alphabet = pattern::is_alnum_dash;

fn is_base64_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

pub(super) struct StripeTokenDetector;

impl Detector for StripeTokenDetector {
    fn id(&self) -> &str {
        STRIPE.id()
    }

    fn detect(
        &self,
        input: &str,
        context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = STRIPE.detect(input, context)?;
        for (start, end) in scan_webhook(input) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new(WEBHOOK_TYPE, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(WEBHOOK_SIGNALS),
            );
        }
        candidates.sort_by_key(|candidate| candidate.range().start());
        Ok(candidates)
    }
}

/// Every boundary-delimited `whsec_` value, left to right. A failed attempt
/// advances one byte; a shape-complete attempt advances past the whole value
/// whether or not the boundary check keeps it, so a wider identifier that
/// embeds the prefix never yields a second, shorter reading.
fn scan_webhook(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let body_ends = pattern::run_ends(bytes, is_base64_body);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(WEBHOOK_PREFIX.as_bytes()) {
            start += 1;
            continue;
        }
        let body_start = start + WEBHOOK_PREFIX.len();
        let body_end = body_ends[body_start];
        if body_end - body_start < WEBHOOK_BODY_MIN {
            start += 1;
            continue;
        }
        let padding = bytes[body_end..]
            .iter()
            .take(WEBHOOK_MAX_PADDING)
            .take_while(|&&byte| byte == b'=')
            .count();
        let end = body_end + padding;
        if pattern::boundary_ok(bytes, start, end, BOUNDARY) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNTHETICREVOKEDWEBHOOKSECRET012";
    const _: () = assert!(BODY.len() == WEBHOOK_BODY_MIN);

    fn detect(input: &str) -> Vec<Candidate> {
        StripeTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn ranges(input: &str) -> Vec<(usize, usize)> {
        detect(input)
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect()
    }

    #[test]
    fn detects_a_webhook_secret_with_its_own_type_and_metadata() {
        let input = format!("whsec_{BODY}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), WEBHOOK_TYPE);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn applies_the_thirty_two_byte_floor() {
        let one_short = format!("whsec_{}", &BODY[..WEBHOOK_BODY_MIN - 1]);
        assert!(ranges(&one_short).is_empty());
        let longer = format!("whsec_{BODY}0123456789");
        assert_eq!(ranges(&longer), vec![(0, longer.len())]);
    }

    #[test]
    fn admits_base64_symbols_and_up_to_two_padding_bytes() {
        for tail in ["+", "/", "+/+/", "=", "=="] {
            let input = format!("whsec_{BODY}{tail}");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{tail}");
        }
        let symbolic = format!("whsec_{}+{}/", &BODY[..16], &BODY[16..]);
        assert_eq!(ranges(&symbolic), vec![(0, symbolic.len())]);
    }

    #[test]
    fn a_third_padding_byte_is_left_outside_the_match() {
        let input = format!("whsec_{BODY}===");
        assert_eq!(ranges(&input), vec![(0, input.len() - 1)]);
    }

    #[test]
    fn rejects_a_value_embedded_in_a_wider_identifier() {
        for input in [
            format!("legacywhsec_{BODY}"),
            format!("_whsec_{BODY}"),
            format!("whsec_{BODY}_backup"),
            format!("whsec_{BODY}-1"),
        ] {
            assert!(ranges(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_separator_near_misses_masks_and_references() {
        for input in [
            format!("whsec{BODY}"),
            format!("whsec-{BODY}"),
            format!("wh_sec_{BODY}"),
            "whsec_********************************".to_string(),
            "whsec_${STRIPE_WEBHOOK_SECRET}".to_string(),
            "whsec_...".to_string(),
        ] {
            assert!(ranges(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn public_identifiers_and_signature_digests_stay_clean() {
        for input in [
            "we_1SYNTHETICENDPOINTID",
            "evt_1SYNTHETICEVENTIDENTIFIER",
            "pk_live_SYNTHETICREVOKEDPUBLISHABLE",
            "t=1700000000,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd",
        ] {
            assert!(ranges(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn key_and_webhook_shapes_stay_distinct_and_ordered_in_one_input() {
        let input = format!("whsec_{BODY}\nsk_live_SYNTHETICREVOKEDSYNTHETIC");
        let candidates = detect(&input);
        let types: Vec<&str> = candidates.iter().map(Candidate::type_name).collect();
        assert_eq!(types, vec![WEBHOOK_TYPE, "stripe_credential"]);
        let reversed = format!("sk_live_SYNTHETICREVOKEDSYNTHETIC\nwhsec_{BODY}");
        let candidates = detect(&reversed);
        let types: Vec<&str> = candidates.iter().map(Candidate::type_name).collect();
        assert_eq!(types, vec!["stripe_credential", WEBHOOK_TYPE]);
    }

    #[test]
    fn reports_each_rolling_secret_once() {
        let input = format!("whsec_{BODY} whsec_{BODY}");
        let second = 6 + BODY.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![(0, 6 + BODY.len()), (second, second + 6 + BODY.len())]
        );
    }
}
