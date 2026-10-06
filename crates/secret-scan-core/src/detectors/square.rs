//! Square access token and OAuth application secret detection (issue #1107,
//! handoff [`docs/audits/evidence/1014/square.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/square.md)).
//!
//! A Square access token (`SQUARE_ACCESS_TOKEN`, sent as `Authorization:
//! Bearer`) acts for a merchant or the developer's own account, and the OAuth
//! application secret (`client_secret`) lets an integration exchange
//! authorization codes and renew or revoke seller tokens. The grammar is T1
//! under rulings R4 and R5 from the provider's documentation examples,
//! corroborated by third-party scanner rules (T2):
//!
//! | Form | Grammar | Finding type |
//! | --- | --- | --- |
//! | Access token | `EAAA` + exactly 60 `[A-Za-z0-9_-]` (64 in total) | `square_access_token` |
//! | Production application secret | `sq0csp-` + 43 or 44 `[A-Za-z0-9_-]` | `square_oauth_application_secret` |
//! | Sandbox application secret | `sandbox-sq0csb-` + exactly 43 `[A-Za-z0-9_-]` | `square_oauth_application_secret` |
//!
//! ## Length disclaimer (ruling Q8, open)
//!
//! Square's own page says not to use token length for validation, and its
//! examples disagree with themselves: an access token of 64 characters
//! (`EAAA` + 60) in one place and a 63-character `EAAl` form in the
//! `ObtainToken` reference, and an application secret of 43 characters in the
//! walkthrough and 44 in the reference and its generated SDK fixture. Whether
//! R5 may still support an exact-width grammar when the provider disclaims
//! length is ruling Q8 on #1014, which is open; this follows its
//! recommendation (yes): the stable widths are claimed (`EAAA` + 60, which four
//! independent scanner and request sources also use, and the 43 or 44 union of
//! the two provider widths for `sq0csp-`) and every conflicting shape is left
//! unclaimed and is a bounded false negative:
//!
//! - the `EAAl` + 59 (63 total) access token and the `EQAA` + 60 refresh
//!   token, one provider example each and not independent of their generated
//!   SDK fixture;
//! - `EAAA` of any width other than 60, and `sq0csp-` of any width other than
//!   43 or 44;
//! - `sandbox-sq0csb-` of any width other than 43 (one docs example).
//!
//! The issuance check (structure only) that would settle the widths is a
//! benchmarks-side item and is pending.
//!
//! ## Exclusions and boundaries
//!
//! JWT-format access tokens (`eyJ...`) stay with `jwt`. The `sq0atp-` legacy
//! token (scanner rules only), the `sq0cgb-` authorization code and the public
//! application ids (`sq0idp-`, `sq0ids-`, `sq0idb-`, `sandbox-sq0idb-`) are
//! unclaimed. The boundary is `[A-Za-z0-9_-]` on both sides, so a longer run (a
//! Meta `EAAA...` Graph token is far longer, a Base64 blob is glued to its
//! neighbours) cannot match; the match is case-sensitive, so a lowercase Docker
//! digest does not match. A `+`, `=` or `/` inside the body ends the run under
//! the width, which trufflehog's class would accept and Square's own example
//! does not.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const ACCESS_TOKEN: &str = "square_access_token";
const APPLICATION_SECRET: &str = "square_oauth_application_secret";
const SIGNALS: [&str; 2] = ["square-docs-prefix", "square-docs-shape"];
const SECRET_WIDTHS: &[usize] = &[43, 44];

pub(super) const SQUARE: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "square-token",
    &[
        PrefixShape::exact("EAAA", 60, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::one_of("sq0csp-", SECRET_WIDTHS, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("sandbox-sq0csb-", 43, pattern::is_alnum_dash, &SIGNALS),
    ],
    &[ACCESS_TOKEN, APPLICATION_SECRET, APPLICATION_SECRET],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    /// Synthetic filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(B64URL[(i * 7 + seed * 13 + i / 5) % B64URL.len()]))
            .collect()
    }

    fn key(prefix: &str, len: usize) -> String {
        format!("{prefix}{}", filler(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        SQUARE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn stable_widths_are_claimed_with_exact_spans() {
        for (key, type_name) in [
            (key("EAAA", 60), ACCESS_TOKEN),
            (key("sq0csp-", 43), APPLICATION_SECRET),
            (key("sq0csp-", 44), APPLICATION_SECRET),
            (key("sandbox-sq0csb-", 43), APPLICATION_SECRET),
        ] {
            for input in [
                key.clone(),
                format!("SQUARE_ACCESS_TOKEN={key}"),
                format!("Authorization: Bearer {key}"),
                format!("\u{d0a4}\u{1f511} \"{key}\"."),
            ] {
                assert_single(&input, &key, type_name);
            }
        }
    }

    #[test]
    fn conflicting_widths_and_shapes_are_unclaimed() {
        for input in [
            key("EAAA", 59),
            key("EAAA", 61),
            key("EAAl", 59),
            key("EQAA", 60),
            key("EAAB", 60),
            key("eaaa", 60),
            key("sq0csp-", 42),
            key("sq0csp-", 45),
            key("sandbox-sq0csb-", 42),
            key("sandbox-sq0csb-", 44),
            key("sq0idp-", 22),
            key("sq0atp-", 22),
            format!("xEAAA{}", filler(60, 1)),
            format!("{}_", key("EAAA", 60)),
            format!("{}-x", key("sq0csp-", 43)),
            format!("{}0", key("sq0csp-", 44)),
            format!("EAAA{}+{}", filler(30, 2), filler(29, 3)),
            format!("EAAA{}={}", filler(30, 2), filler(29, 3)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repetition_stays_linear_and_exact() {
        assert!(detect(&"EAAA".repeat(10_000)).is_empty());
        assert!(detect(&"sq0csp-".repeat(10_000)).is_empty());
        let token = key("EAAA", 60);
        assert_eq!(detect(&format!("{token} ").repeat(200)).len(), 200);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
