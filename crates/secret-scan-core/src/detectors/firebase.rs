//! Firebase Cloud Messaging (FCM) legacy server key detection.
//!
//! Issue #520 (B3a, under Epic #501) scopes Firebase to "server keys,
//! service-account credentials, privileged tokens" as the genuinely secret
//! material, explicitly excluding the public Web SDK client config
//! (`apiKey`, `authDomain`, `projectId`, `appId`, `messagingSenderId`, ...)
//! from that target set. This module covers the one Firebase-specific
//! secret format with a documented lexical shape: the legacy FCM HTTP/XMPP
//! "server key". The other two named categories are already covered
//! elsewhere and are not duplicated here:
//!
//! - **Service-account credentials**: a Firebase Admin SDK service-account
//!   JSON export is a Google Cloud service-account key -- the same
//!   structural PEM-delimiter match [`super::private_key`] already finds,
//!   with no Firebase-specific code path (see issue #519's audit,
//!   `docs/audits/evidence/519/README.md`, Family 2, which reaches the
//!   identical conclusion for Google's own service-account exports).
//! - **The `AIza`-prefixed key issued for Firebase/Gemini/Cloud use** is
//!   the same shape [`super::additional_providers`]'s `google-api-key`
//!   detector already matches (see issue #519's audit, Family 3). Public
//!   client-config discrimination for that shape is handled at the pipeline
//!   level (`crate::pipeline::is_within_firebase_client_config_context`),
//!   not here, because it is a cross-cutting exemption over an existing
//!   detector's candidates, the same mechanism already used for vendor
//!   placeholder literals (`crate::pipeline::KNOWN_VENDOR_PLACEHOLDER_LITERALS`).
//!
//! ## Server key grammar
//!
//! The legacy FCM server key (Firebase console: Project settings -> Cloud
//! Messaging -> "Server key", used with the now-deprecated HTTP v0/XMPP
//! send APIs) begins with the literal `AAAA`, per two independent
//! non-tool sources describing real-world exposed keys: a 2024 Firebase
//! Cloud Messaging deprecation discussion thread on the B4X developer forum
//! (`www.b4x.com/android/forum/threads/firebase-cloud-messaging-disable-
//! server-keys-and-legacy-http-protocol-on-june-20-2024.148656/`, observed
//! 2026-09-20, quoting an example key beginning `AAAAHMbG..`) and an
//! independent security-research writeup on FCM takeovers
//! (`abss0x7tbh.github.io/posts/fcm-takeover/`, observed 2026-09-20).
//! Neither Google's current documentation nor gitleaks 8.30.1 nor
//! trufflehog 3.97.4 publishes a rule for this shape: trufflehog's own
//! `proto/detector_type.proto` (observed 2026-09-20) reserves both
//! `Firebase = 33` and `FirebaseCloudMessaging = 102` explicitly marked
//! `// Not yet implemented`, confirming the family is recognized but
//! unshipped by that tool, not merely unsearched here.
//!
//! The one tool source for the body's exact two-segment length is
//! `projectdiscovery/nuclei-templates`'s `http/exposures/tokens/
//! firebase-fcm-server-key-disclosure.yaml` template (observed 2026-09-20),
//! whose detection regex is `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` --
//! read here as the literal `AAAA`, then exactly 7 bytes of
//! `[A-Za-z0-9_-]`, then a literal `:`, then exactly 140 bytes of
//! `[A-Za-z0-9_-]`, for 152 bytes total. This is single-tool evidence for
//! the exact widths (T2, the same evidence tier this crate already accepts
//! for `docker-token`'s and `linear-token`'s exact-width segments -- see
//! `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-
//! provider-families.md`), corroborated only for the `AAAA` prefix itself
//! by the two non-tool sources above, not for the full width. A shorter or
//! longer segment, a missing or misplaced separator, or a body/checksum run
//! embedded in a wider identifier is an intentional false negative rather
//! than a fuzzy match, the same tradeoff [`super::grafana`]'s
//! `GrafanaServiceAccountTokenDetector` makes for its own hand-parsed
//! two-segment shape (which this detector's matching logic mirrors).
//!
//! ## Current operational status
//!
//! Google phased out the legacy FCM HTTP/XMPP send APIs this key
//! authenticates during 2024 (the B4X thread above cites a June 20, 2024
//! shutoff, later moved to July 22, 2024); the FCM HTTP v1 API requires an
//! OAuth 2.0 access token from a service account instead. A leaked legacy
//! server key found today is very likely already non-functional against
//! Google's send endpoint. It is still detected: the same key frequently
//! remains embedded in old client bundles, `firebase-messaging-sw.js`
//! service worker files, and `manifest.json` files (the exact three
//! locations `nuclei-templates`' own scan template checks) years after the
//! send API it authenticated was retired, and this crate does not
//! special-case a format's detection on its issuer's current operational
//! status -- the same posture GitHub's still-fully-supported classic
//! `ghp_`/`gho_` prefix scheme takes despite fine-grained PATs being
//! GitHub's now-preferred format (issue #517).
//!
//! ## Action
//!
//! The finding is `Specificity::Provider` and listed in
//! `policy::ALWAYS_REDACT_TYPES`: the fixed prefix, exact two-segment
//! length, and colon separator are specific enough on their own, the same
//! tradeoff every other fixed-prefix provider grammar in this crate makes.

use crate::detectors::pattern::{self, is_alnum_dash};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &[u8] = b"AAAA";
const BODY_LEN: usize = 7;
const SEPARATOR: u8 = b':';
const TAIL_LEN: usize = 140;

/// Requires the exact `AAAA<7 alnum-dash>:<140 alnum-dash>` shape. A shorter
/// or longer segment, a missing or misplaced separator, or a body/tail run
/// embedded in a wider identifier is an intentional false negative rather
/// than a fuzzy match.
pub(super) struct FirebaseServerKeyDetector;

impl Detector for FirebaseServerKeyDetector {
    fn id(&self) -> &'static str {
        "firebase-server-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let alnum_dash_ends = pattern::run_ends(bytes, is_alnum_dash);
        let mut candidates = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start..].starts_with(PREFIX) {
                start += 1;
                continue;
            }

            let Some(end) = match_at(bytes, &alnum_dash_ends, start) else {
                start += 1;
                continue;
            };

            if pattern::boundary_ok(bytes, start, end, is_alnum_dash)
                && let Some(range) = ByteRange::new(start, end)
            {
                candidates.push(
                    Candidate::new("firebase_server_key", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["firebase-documented-prefix", "two-segment-exact-length"]),
                );
            }
            start = end;
        }
        Ok(candidates)
    }
}

/// Attempts an `AAAA<7 alnum-dash>:<140 alnum-dash>` match anchored exactly
/// at `start`, where `bytes[start..]` is already known to begin with
/// [`PREFIX`]. Returns the exclusive end offset on success; the caller
/// still applies the boundary check.
fn match_at(bytes: &[u8], alnum_dash_ends: &[usize], start: usize) -> Option<usize> {
    let body_start = start + PREFIX.len();
    if alnum_dash_ends[body_start] < body_start + BODY_LEN {
        return None;
    }
    let separator = body_start + BODY_LEN;
    if bytes.get(separator) != Some(&SEPARATOR) {
        return None;
    }

    let tail_start = separator + 1;
    if alnum_dash_ends[tail_start] < tail_start + TAIL_LEN {
        return None;
    }

    Some(tail_start + TAIL_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNREV0";
    const TAIL: &str = "SYNTHETICREVOKEDFIREBASEFCMLEGACYSERVERKEYFIXTUREPADDING0123456789SYNTHETICREVOKEDFIREBASEFCMLEGACYSERVERKEYFIXTUREPADDING0123456789ABCDWXYZ";

    fn token() -> String {
        format!("AAAA{BODY}:{TAIL}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        FirebaseServerKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn fixture_segments_are_exactly_documented_length() {
        assert_eq!(BODY.len(), BODY_LEN);
        assert_eq!(TAIL.len(), TAIL_LEN);
    }

    #[test]
    fn detects_a_synthetic_key_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "firebase_server_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_key_bare_in_env_and_service_worker_contexts() {
        let value = token();
        for input in [
            value.clone(),
            format!("FCM_SERVER_KEY={value}"),
            format!("\"serverKey\": \"{value}\""),
            format!("const SERVER_KEY = '{value}';"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = token();
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn rejects_a_truncated_body_segment() {
        let short_body = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("AAAA{short_body}:{TAIL}")).is_empty());
    }

    #[test]
    fn rejects_a_truncated_tail_segment() {
        let short_tail = &TAIL[..TAIL_LEN - 1];
        assert!(detect(&format!("AAAA{BODY}:{short_tail}")).is_empty());
    }

    #[test]
    fn rejects_a_body_segment_longer_than_documented() {
        assert!(detect(&format!("AAAA{BODY}A:{TAIL}")).is_empty());
    }

    #[test]
    fn rejects_a_tail_segment_longer_than_documented() {
        assert!(detect(&format!("AAAA{BODY}:{TAIL}A")).is_empty());
    }

    #[test]
    fn rejects_a_malformed_separator() {
        assert!(detect(&format!("AAAA{BODY}.{TAIL}")).is_empty());
        assert!(detect(&format!("AAA-{BODY}:{TAIL}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_alone() {
        assert!(detect("AAAA").is_empty());
        assert!(detect(&format!("AAAA{BODY}")).is_empty());
        assert!(detect(&format!("AAAA{BODY}:")).is_empty());
    }

    #[test]
    fn rejects_the_body_or_tail_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        let masked_tail = "*".repeat(TAIL_LEN);
        assert!(detect(&format!("AAAA{BODY}:{masked_tail}")).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("${FCM_SERVER_KEY}").is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = token();
        assert_eq!(detect(&value), detect(&value));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        // Every occurrence has a body one byte short of the documented
        // length, so none matches; the scan must still stay linear instead
        // of rescanning from each failed prefix position.
        let short_body = &BODY[..BODY_LEN - 1];
        let input = format!("AAAA{short_body}:{TAIL} ").repeat(2_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
