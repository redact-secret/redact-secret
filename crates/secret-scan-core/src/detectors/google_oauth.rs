//! Google OAuth client secret detection (issue #1029, #1012 handoff
//! [`docs/audits/evidence/1012/google-oauth2-credential.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1012/google-oauth2-credential.md)).
//!
//! Google publishes no grammar for OAuth client secrets. Google's own
//! osv-scalibr rule `gcpoauth2client` (`@google.com` authors) is
//! `\bGOCSPX-[a-zA-Z0-9_-]{28}`, narrowed to exactly 28 by a Google engineer
//! on 2025-12-03; noseyparker (2023) and `CredSweeper` (2023) give the same
//! width with a `[A-Za-z0-9_-]` right boundary. Three dated references from
//! three owners in two classes: READY-T2 (T1 if ruling R2 is applied to the
//! osv-scalibr rule).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `GOCSPX-` | T2 (T1 under R2) |
//! | Body | exactly 28 `[A-Za-z0-9_-]` (35 in total) | T2 |
//! | Boundary | no `[A-Za-z0-9_-]` byte on either side | T2 |
//!
//! A body of any other width is rejected whole, never truncated. The access
//! token `ya29.` and the refresh token `1//` stay unclaimed (BLOCKED in
//! #1012), and so do client secrets issued before the prefix, outside the
//! `client_secret` name `generic-token` already reads. `google` is not added
//! to `generic-token`'s dedicated-provider deferral list: the unprefixed
//! legacy secrets would go silent under `GOOGLE_*` names. A padded
//! `GOCSPX-` placeholder of exactly 28 body bytes is claimed (the #867
//! precedent).

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "GOCSPX-";
const BODY_LEN: usize = 28;
const SIGNALS: [&str; 2] = ["google-oauth-client-secret-prefix", "exact-length-suffix"];

pub(super) const GOOGLE_OAUTH_CLIENT_SECRET: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "google-oauth-client-secret",
        "google_oauth_client_secret",
        &[PrefixShape::exact(
            PREFIX,
            BODY_LEN,
            pattern::is_alnum_dash,
            &SIGNALS,
        )],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic `[A-Za-z0-9_-]` filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn secret(len: usize) -> String {
        format!("{PREFIX}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        GOOGLE_OAUTH_CLIENT_SECRET
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn claims_exactly_28_body_bytes_at_the_value_span() {
        let value = secret(BODY_LEN);
        for input in [
            value.clone(),
            format!("GOOGLE_CLIENT_SECRET={value}\n"),
            format!("{{\"installed\": {{\"client_secret\": \"{value}\"}}}}"),
            format!("the secret is {value}."),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&value).unwrap();
            assert_eq!(candidates[0].type_name(), "google_oauth_client_secret");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn claims_the_inventory_trigger() {
        let trigger = format!("{PREFIX}{}", "SyntheticRevokedGoogleClient");
        assert_eq!(detect(&trigger).len(), 1);
    }

    #[test]
    fn rejects_one_property_twins_whole() {
        let value = secret(BODY_LEN);
        let body = &value[PREFIX.len()..];
        for input in [
            secret(27),
            secret(29),
            format!("gocspx-{body}"),
            format!("GOCSPX_{body}"),
            format!("GOCSPX-{}.{}", &body[..10], &body[11..]),
            format!("x{value}"),
            format!("-{value}"),
            format!("{value}_"),
            format!("{value}-"),
            format!("{value}a"),
            "GOCSPX-...".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }
}
