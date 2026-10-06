//! Trigger.dev secret API key and personal access token detection (issue
//! #904, handoff [`docs/audits/evidence/860/trigger-dev.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/trigger-dev.md)).
//!
//! | Shape | Finding type | Evidence |
//! | --- | --- | --- |
//! | `tr_<env>_sk_` + exactly 24 `[0-9A-Za-z]` (additional key) | `trigger_dev_secret_api_key` | published SDK regex + generator (T1) |
//! | `tr_<env>_` + exactly 24 `[0-9A-Za-z]` (root key) | `trigger_dev_secret_api_key` | generator (T1 under R1) + docs prefix |
//! | `tr_<env>_` + exactly 20 `[0-9A-Za-z]` (legacy root, ≤ v4.0.0) | `trigger_dev_secret_api_key` | generator at tag (T1 under R1) |
//! | `tr_pat_` + exactly 40 `[1-9a-km-z]` | `trigger_dev_personal_access_token` | generator (T1 under R1) + docs prefix |
//!
//! `<env>` is one of the provider's four `EnvSlug` values: `dev`, `stg`,
//! `prod`, `preview`. Root and additional keys are one finding type: the
//! provider documents both as the environment's secret key with the same
//! scope. The personal access token acts for a user across projects, so it
//! is its own type (the GitHub one-type-per-family precedent).
//!
//! ## Exclusions and overlaps
//!
//! The public `pk_<env>_` key is public by design and never claimed;
//! `tr_oat_` (no known generator), `tr_uat_` and public access tokens (JWTs,
//! kept by `jwt`), `tr_proj_` refs and any other env slug are unclaimed.
//! Longest prefix wins at a shared position, so `tr_prod_sk_` is tried
//! before `tr_prod_`; the root alphabet excludes `_`, so an additional key is
//! never read as a root key, and `tr_prod_sk_` + 21 matches neither shape.
//! `tr_<env>_sk_` contains `sk_`, but the byte before it is `_`, which the
//! Stripe and `ElevenLabs` leading boundaries reject; the body also never
//! carries Stripe's `live_`/`test_` segment or `ElevenLabs`' 48 hex.
//!
//! Boundary `[A-Za-z0-9_-]`: an embedded, over-long or glued value is an
//! intentional false negative.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const KEY_LEN: usize = 24;
const LEGACY_ROOT_LEN: usize = 20;
const PAT_LEN: usize = 40;
const ROOT_LENS: [usize; 2] = [KEY_LEN, LEGACY_ROOT_LEN];

const SECRET_KEY: &str = "trigger_dev_secret_api_key";
const PAT: &str = "trigger_dev_personal_access_token";

/// `[A-Za-z0-9_-]`: the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// `[1-9a-km-z]`: the personal-access-token generator alphabet (lowercase,
/// no `0`, no `l`).
fn is_pat_char(byte: u8) -> bool {
    matches!(byte, b'1'..=b'9' | b'a'..=b'k' | b'm'..=b'z')
}

const SIGNALS: [&str; 2] = [
    "trigger-dev-documented-prefix",
    "trigger-dev-generator-length",
];

pub(super) const TRIGGER_DEV: TypedKnownFormatProviderDetector =
    TypedKnownFormatProviderDetector::new(
        "trigger-dev-token",
        &[
            PrefixShape::exact("tr_dev_sk_", KEY_LEN, pattern::is_alnum, &SIGNALS),
            PrefixShape::exact("tr_stg_sk_", KEY_LEN, pattern::is_alnum, &SIGNALS),
            PrefixShape::exact("tr_prod_sk_", KEY_LEN, pattern::is_alnum, &SIGNALS),
            PrefixShape::exact("tr_preview_sk_", KEY_LEN, pattern::is_alnum, &SIGNALS),
            PrefixShape::one_of("tr_dev_", &ROOT_LENS, pattern::is_alnum, &SIGNALS),
            PrefixShape::one_of("tr_stg_", &ROOT_LENS, pattern::is_alnum, &SIGNALS),
            PrefixShape::one_of("tr_prod_", &ROOT_LENS, pattern::is_alnum, &SIGNALS),
            PrefixShape::one_of("tr_preview_", &ROOT_LENS, pattern::is_alnum, &SIGNALS),
            PrefixShape::exact("tr_pat_", PAT_LEN, is_pat_char, &SIGNALS),
        ],
        &[
            SECRET_KEY, SECRET_KEY, SECRET_KEY, SECRET_KEY, SECRET_KEY, SECRET_KEY, SECRET_KEY,
            SECRET_KEY, PAT,
        ],
        is_token_char,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const ENVS: [&str; 4] = ["dev", "stg", "prod", "preview"];

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const PAT_ALPHABET: &[u8] = b"123456789abcdefghijkmnopqrstuvwxyz";

    fn additional(env: &str) -> String {
        format!("tr_{env}_sk_{}", filler(ALNUM, KEY_LEN, 1))
    }

    fn root(env: &str, len: usize) -> String {
        format!("tr_{env}_{}", filler(ALNUM, len, 2))
    }

    fn pat() -> String {
        format!("tr_pat_{}", filler(PAT_ALPHABET, PAT_LEN, 3))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        TRIGGER_DEV
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
            format!("TRIGGER_SECRET_KEY={token}"),
            format!("export TRIGGER_SECRET_KEY=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("configure({{ secretKey: \"{token}\" }});"),
            format!("Here is my key {token} can you debug this?"),
            format!("env:\n  TRIGGER_SECRET_KEY: {token}\n"),
            format!("The key is {token}."),
        ]
    }

    #[test]
    fn every_env_and_width_is_detected_in_every_context() {
        for env in ENVS {
            for token in [
                additional(env),
                root(env, KEY_LEN),
                root(env, LEGACY_ROOT_LEN),
            ] {
                for input in contexts(&token) {
                    assert_single(&input, &token, SECRET_KEY);
                }
            }
        }
        let token = pat();
        for input in contexts(&token) {
            assert_single(&input, &token, PAT);
        }
        assert_eq!(TRIGGER_DEV.id(), "trigger-dev-token");
    }

    #[test]
    fn width_twins_are_rejected() {
        let mut twins = Vec::new();
        for env in ENVS {
            for len in [23, 25] {
                twins.push(format!("tr_{env}_sk_{}", filler(ALNUM, len, 1)));
            }
            for len in [19, 21, 22, 23, 25] {
                twins.push(root(env, len));
            }
            // An additional key with a short body matches neither shape.
            twins.push(format!("tr_{env}_sk_{}", filler(ALNUM, 21, 1)));
        }
        for len in [39, 41] {
            twins.push(format!("tr_pat_{}", filler(PAT_ALPHABET, len, 3)));
        }
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn alphabet_twins_are_rejected() {
        let mut twins = Vec::new();
        for byte in ["-", "_", "."] {
            let mut value = additional("prod");
            value.replace_range(18..19, byte);
            twins.push(value);
            let mut value = root("dev", KEY_LEN);
            value.replace_range(15..16, byte);
            twins.push(value);
        }
        for byte in ["0", "l", "A"] {
            let mut value = pat();
            value.replace_range(20..21, byte);
            twins.push(value);
        }
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn unknown_envs_and_case_changes_are_rejected() {
        let body = filler(ALNUM, KEY_LEN, 2);
        for prefix in [
            "tr_test_",
            "tr_staging_",
            "tr_production_",
            "TR_PROD_",
            "tr_Prod_",
            "tr-prod-",
            "tr_prod-",
            "tr_oat_",
            "tr_proj_",
        ] {
            let input = format!("{prefix}{body}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn glued_values_are_rejected() {
        for token in [additional("dev"), root("prod", KEY_LEN), pat()] {
            for input in [
                format!("s{token}"),
                format!("x{token}"),
                format!("_{token}"),
                format!("-{token}"),
                format!("{token}a"),
                format!("{token}_x"),
                format!("{token}-1"),
            ] {
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn public_keys_placeholders_and_identifiers_are_not_claimed() {
        let public = filler(ALNUM, LEGACY_ROOT_LEN, 4);
        for input in [
            format!("pk_dev_{public}"),
            format!("TRIGGER_PUBLIC_KEY=pk_prod_{public}"),
            "TRIGGER_SECRET_KEY=tr_dev_sk_xxxxxxxxxx".to_owned(),
            "TRIGGER_SECRET_KEY=tr_dev_...".to_owned(),
            "project: tr_proj_abcdefghijklmnop".to_owned(),
            "if (tr_dev_mode) { start(); }".to_owned(),
            "const tr_prod_config_loaded_from_disk = true;".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn an_exact_width_placeholder_is_a_known_false_positive() {
        let input = format!("TRIGGER_SECRET_KEY=tr_dev_sk_{}", "x".repeat(KEY_LEN));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = additional("prod");
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(300)).is_empty());
    }
}
