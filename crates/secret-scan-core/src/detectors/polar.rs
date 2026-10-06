//! Polar organization access token and API credential detection (issue
//! #1020, handoff [`docs/audits/evidence/1014/polar.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/polar.md)).
//!
//! Every fact is T1 under rulings R1 and R9, from the provider's server code
//! (`polarsource/polar`, re-checked 2026-09-29). `kit/crypto.py` has
//! generated 37 characters of `[A-Za-z0-9]` plus a zero-padded 6-character
//! base62 CRC32 since 2025-01-02; before that it returned
//! `secrets.token_urlsafe()`, 43 unpadded URL-safe Base64 bytes with no
//! checksum. The organization access token service was added after the
//! checksum era began, so only it has the narrower body.
//!
//! | Prefix | Body | Finding type |
//! | --- | --- | --- |
//! | `polar_oat_` | exactly 43 `[A-Za-z0-9]` | `polar_organization_access_token` |
//! | `polar_pat_`, `polar_at_u_`, `polar_at_o_`, `polar_rt_u_`, `polar_rt_o_`, `polar_cs_`, `polar_crt_` | exactly 43 `[A-Za-z0-9_-]` (union of both eras) | `polar_api_credential` |
//!
//! ## Checksum
//!
//! The `polar_oat_` CRC32 is never used to reject a shape-valid match:
//! security comes first, so a failed checksum is not an intentional false
//! negative. Ruling Q1 of the #1014 handoff index stays open for the
//! maintainer. It must never apply to the other roles in any case, because
//! an era-1 body is all-alphanumeric about a quarter of the time and has no
//! checksum.
//!
//! ## Exclusions and boundaries
//!
//! `polar_ci_` OAuth client ids are public by design (ruling Q5), and
//! `polar_c_`/`polar_cl_` checkout client secrets are handed to the browser;
//! neither is a prefix here. Session and single-use tokens are out of this
//! contract. A Polar webhook secret uses Stripe's `whsec_` prefix and stays
//! with `stripe-token`. Boundary `[A-Za-z0-9_-]`: a 42- or 44-byte body, a
//! `-` or `_` in a `polar_oat_` body, and a glued value are intentional
//! false negatives, never a truncated match.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 43;
const SIGNALS: [&str; 2] = ["polar-generator-prefix", "polar-generator-length"];
const ORGANIZATION: &str = "polar_organization_access_token";
const API: &str = "polar_api_credential";

pub(super) const POLAR: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "polar-token",
    &[
        PrefixShape::exact("polar_oat_", BODY_LEN, pattern::is_alnum, &SIGNALS),
        PrefixShape::exact("polar_pat_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_at_u_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_at_o_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_rt_u_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_rt_o_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_cs_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("polar_crt_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
    ],
    &[ORGANIZATION, API, API, API, API, API, API, API],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const API_PREFIXES: [&str; 7] = [
        "polar_pat_",
        "polar_at_u_",
        "polar_at_o_",
        "polar_rt_u_",
        "polar_rt_o_",
        "polar_cs_",
        "polar_crt_",
    ];

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn detect(input: &str) -> Vec<Candidate> {
        POLAR
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("POLAR_ACCESS_TOKEN={token}"),
            format!("export POLAR_ACCESS_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("polar = Polar(access_token=\"{token}\")"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn every_role_is_detected_in_every_context() {
        let oat = format!("polar_oat_{}", filler(ALNUM, BODY_LEN, 1));
        for input in contexts(&oat) {
            assert_single(&input, &oat, ORGANIZATION);
        }
        for (seed, prefix) in API_PREFIXES.iter().enumerate() {
            // An era-1 body carries `-` and `_`; an era-2 body is alphanumeric.
            for body in [
                filler(URL_SAFE, BODY_LEN, seed),
                filler(ALNUM, BODY_LEN, seed),
            ] {
                let token = format!("{prefix}{body}");
                for input in contexts(&token) {
                    assert_single(&input, &token, API);
                }
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = filler(ALNUM, BODY_LEN, 2);
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        let oat = format!("polar_oat_{body}");
        for input in [
            format!("polar_oat_{}", &body[..42]),
            format!("polar_oat_{body}A"),
            format!("polar_pat_{}", &body[..42]),
            format!("polar_pat_{body}A"),
            format!("polar_oat_{dashed}"),
            format!("polar_oat_{underscored}"),
            format!("polar_at_{body}"),
            format!("POLAR_OAT_{body}"),
            format!("x{oat}"),
            format!("_{oat}"),
            format!("{oat}_"),
            format!("{oat}-x"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn public_and_out_of_contract_siblings_are_not_claimed() {
        let body = filler(ALNUM, BODY_LEN, 3);
        for prefix in [
            "polar_ci_",
            "polar_c_",
            "polar_cl_",
            "polar_us_",
            "polar_cst_",
            "polar_ac_",
            "whsec_",
        ] {
            let input = format!("{prefix}{body}");
            assert!(detect(&input).is_empty(), "{input}");
        }
        for input in [
            "POLAR_ACCESS_TOKEN=polar_oat_xxxxxxxx",
            "POLAR_ACCESS_TOKEN=${POLAR_ACCESS_TOKEN}",
            "polar_access_token_id = 42",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let oat = format!("polar_oat_{}", filler(ALNUM, BODY_LEN, 4));
        assert_eq!(detect(&format!("{oat} {oat}")).len(), 2);
        assert!(detect(&oat.repeat(200)).is_empty());
        assert!(detect(&"polar_oat_".repeat(2_000)).is_empty());
    }
}
