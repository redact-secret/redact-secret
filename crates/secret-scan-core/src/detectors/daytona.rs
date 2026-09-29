//! Daytona API key detection (issue #970, handoff
//! `docs/audits/evidence/860/daytona.md`).
//!
//! The provider's key generator is `dtn_` followed by
//! `crypto.randomBytes(32).toString('hex')` (`daytonaio/daytona`
//! `apps/api/src/common/utils/api-key.ts`, last public at v0.190.0,
//! 2026-06-23). Core development moved to a private codebase after that, so
//! the contract is T1 as of v0.190.0 under ruling R9 (a provider generator
//! counts as T1 as of its date until a newer provider source contradicts it).
//! The same generator also mints region proxy, SSH-gateway and runner keys,
//! which are lexically identical.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `dtn_` | T1 (provider docs and code) |
//! | Body | exactly 64 `[0-9a-f]` | T1 as of v0.190.0 (provider generator, R9) |
//!
//! The boundary is `[A-Za-z0-9_-]` on both sides. The body alphabet is
//! lowercase hex only, so an uppercase hex byte or a non-hex letter inside
//! the run leaves fewer than 64 body bytes and rejects the match, and a byte
//! of the wider boundary alphabet after the 64th (a 65th hex digit, an
//! uppercase letter, `_`, `-`) rejects it too: a body is never truncated.
//! Without the prefix the body is a SHA-256 digest (including Daytona's own
//! stored key hash), so the prefix is load-bearing and a bare 64-hex string
//! stays unclaimed.
//!
//! Left unclaimed: `dtn_secret_<random>` Secrets placeholders (`s` is not
//! hex), `dtn_artifact_` markers, `dtn_***`/`dtn_...` and short `OpenAPI`
//! placeholders, unprefixed self-provisioned runner keys, legacy self-hosted
//! base64-UUID keys, and `DAYTONA_JWT_TOKEN` (a JWT, which the `jwt`
//! detector keeps). `daytona` is not added to `generic-token`'s
//! dedicated-provider deferral list.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "dtn_";
const BODY_LEN: usize = 64;
const SIGNALS: [&str; 2] = ["daytona-documented-prefix", "daytona-generator-length"];

pub(super) const DAYTONA_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "daytona-api-key",
    "daytona_api_key",
    &[PrefixShape::exact(
        PREFIX,
        BODY_LEN,
        pattern::is_lower_hex,
        &SIGNALS,
    )],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic lowercase-hex filler, never provider-issued.
    fn body(len: usize) -> String {
        "5e7c0ded".repeat(len.div_ceil(8))[..len].to_owned()
    }

    fn key(len: usize) -> String {
        format!("{PREFIX}{}", body(len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        DAYTONA_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "daytona_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(key: &str) -> Vec<String> {
        vec![
            key.to_owned(),
            format!("DAYTONA_API_KEY={key}"),
            format!("export DAYTONA_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("daytona = Daytona(DaytonaConfig(api_key=\"{key}\"))"),
            format!("variable \"daytona_api_key\" {{ default = \"{key}\" }}"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn the_exact_shape_is_detected_in_every_context() {
        let key = key(BODY_LEN);
        assert_eq!(key.len(), 68);
        for input in contexts(&key) {
            assert_single(&input, &key);
        }
        assert_eq!(DAYTONA_API_KEY.id(), "daytona-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(BODY_LEN);
        for input in [
            key(BODY_LEN - 1),
            key(BODY_LEN + 1),
            // One uppercase hex byte, and one non-hex letter, in the body.
            format!("{PREFIX}{}A{}", &value[..30], &value[31..]),
            format!("{PREFIX}{}g{}", &value[..30], &value[31..]),
            // ... and after a full-length run.
            format!("{PREFIX}{value}A"),
            format!("{PREFIX}{value}g"),
            format!("DTN_{value}"),
            format!("dtn-{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("{PREFIX}{value}_"),
            format!("{PREFIX}{value}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_daytona_text_is_not_claimed() {
        let digest = body(BODY_LEN);
        for input in [
            "DAYTONA_API_KEY=dtn_***".to_owned(),
            "DAYTONA_API_KEY=dtn_...".to_owned(),
            "DAYTONA_API_KEY=dtn_1234567890".to_owned(),
            "secret: dtn_secret_SyntheticRevokedPlaceholder".to_owned(),
            "stdout marker dtn_artifact_SyntheticRevokedMarker".to_owned(),
            format!("sha256: {digest}"),
            format!("DAYTONA_RUNNER_KEY={digest}"),
            "the prefix is dtn_".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key(BODY_LEN);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&format!("{key}_{key}")).is_empty());
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
        assert!(detect(&format!("{PREFIX}{}", body(20_000))).is_empty());
    }
}
