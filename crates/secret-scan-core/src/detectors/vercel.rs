//! Vercel credential detection, one finding type per credential class
//! (issue #1036, research #1013, evidence
//! [`docs/audits/evidence/1013/vercel.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1013/vercel.md); taxonomy #858).
//!
//! Every `vcp_`, `vci_`, `vca_`, `vcr_` and `vck_` value is matched exactly as
//! before #1036: the prefix plus at least 20 `[A-Za-z0-9_-]`, maximal run,
//! boundary `[A-Za-z0-9_-]`. Spans and the always-redact action are therefore
//! unchanged for every input. Only the finding type of a match is refined:
//!
//! | Matched value | Finding type | Contract |
//! | --- | --- | --- |
//! | `vcp_` + exactly 56 `[A-Za-z0-9]` (60) | `vercel_personal_access_token` | T2 |
//! | `vca_` + exactly 56 `[A-Za-z0-9]` (60) | `vercel_app_access_token` | T2 (one provider value) |
//! | `vcr_` + exactly 56 `[A-Za-z0-9]` (60) | `vercel_app_refresh_token` | T2 (shared body) |
//! | any other match, all five prefixes | `vercel_token` | none claimed |
//!
//! The typed bodies are exactly 56 alphanumerics: no `_` or `-` (every
//! provider example and `CredSweeper`; the provider maskers and Kingfisher
//! that admit `_`/`-` are maskers or carry no provider value), and no checksum
//! is required (the CRC-32/base62 tail is provider-backed on one `vca_` value
//! only, and the CLI `vcp_` example fails it). A `vcp_`/`vca_`/`vcr_` match
//! with any other body (shorter, longer, or with `_` or `-`) falls back to the
//! unqualified `vercel_token`, so nothing redacted before #1036 becomes
//! unredacted (security-first). Because the run is maximal, a typed value
//! glued to a wider identifier (`..._backup`, `...-1`, a 57th byte) is
//! reported whole as `vercel_token`, never truncated to the typed 60 bytes.
//!
//! `vci_` and `vck_` are pending maintainer ruling Q-VC: no provider source
//! writes `vci_` with the underscore, and no full-length provider `vck_`
//! value exists. They always report `vercel_token`, which claims no grammar.
//! The interim shape's alphabet equals its boundary, so a glued `..._backup`
//! is absorbed into the match (the same-alphabet defect `RunLength::AtLeast`
//! documents); it is kept so no redaction is lost.
//!
//! All five share one detector id, `vercel-token`, the one-detector,
//! several-types model of `github-token` (#517) and #774. `dpl_` deployment
//! ids, every other `vc?_` letter and the legacy unprefixed 24-character form
//! stay unclaimed.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The exact body width of the three typed classes.
pub(super) const TYPED_BODY_LEN: usize = 56;

/// The pre-#1036 floor every prefix keeps.
const FLOOR: usize = 20;
/// Every marker (`vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`) is four bytes.
const PREFIX_LEN: usize = 4;

const TYPED_SIGNALS: [&str; 2] = ["vercel-documented-prefix", "corroborated-exact-length"];

/// Unchanged from the pre-#1036 aggregate detector.
const AGGREGATE_SIGNALS: [&str; 2] = ["vercel-documented-prefix", "opaque-suffix"];

/// The unqualified compatibility type.
const AGGREGATE_TYPE: &str = "vercel_token";

/// The contract-typed prefixes and their finding types.
const TYPED: [(&str, &str); 3] = [
    ("vcp_", "vercel_personal_access_token"),
    ("vca_", "vercel_app_access_token"),
    ("vcr_", "vercel_app_refresh_token"),
];

/// The pre-#1036 shape table, unchanged: it decides every span.
const SHAPES: [PrefixShape<'static>; 5] = [
    PrefixShape::at_least("vcp_", FLOOR, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
    PrefixShape::at_least("vci_", FLOOR, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
    PrefixShape::at_least("vca_", FLOOR, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
    PrefixShape::at_least("vcr_", FLOOR, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
    PrefixShape::at_least("vck_", FLOOR, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
];

/// The `vercel-token` detector.
pub(super) struct VercelDetector;

pub(super) const VERCEL: VercelDetector = VercelDetector;

// Method syntax keeps the registry and prefilter tables in `super` uniform
// with every other table-driven detector (`VERCEL.detector_id()`).
#[allow(clippy::unused_self)]
impl VercelDetector {
    /// [`Detector::id`], usable in a `const`.
    pub(super) const fn detector_id(&self) -> &'static str {
        "vercel-token"
    }

    /// The shape table; every candidate starts with one of its prefixes, so
    /// they are this detector's prefilter literals.
    pub(super) const fn shapes(&self) -> &'static [PrefixShape<'static>] {
        &SHAPES
    }
}

/// The contract type of a matched `value`, if it is a typed class at exactly
/// its contract width and alphabet.
fn typed_class(value: &[u8]) -> Option<&'static str> {
    let (prefix, type_name) = TYPED
        .iter()
        .find(|(prefix, _)| value.starts_with(prefix.as_bytes()))?;
    let body = &value[prefix.len()..];
    (body.len() == TYPED_BODY_LEN && body.iter().copied().all(pattern::is_alnum))
        .then_some(*type_name)
}

impl Detector for VercelDetector {
    fn id(&self) -> &str {
        self.detector_id()
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        for (start, end, signals) in
            pattern::scan_prefixed_shapes(input, &SHAPES, pattern::is_alnum_dash)
        {
            // Issue #1042: a body that is one repeated character
            // (`vcp_` + a run of `x`) is a documentation placeholder, as the
            // #1013 evidence records; a random body never is (#934).
            if super::text::is_repeated_character_filler(&input[start + PREFIX_LEN..end]) {
                continue;
            }
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            let candidate = match typed_class(&bytes[start..end]) {
                Some(type_name) => Candidate::built_in(type_name, Confidence::High, range)
                    .with_signals(TYPED_SIGNALS.iter().copied()),
                None => Candidate::built_in(AGGREGATE_TYPE, Confidence::High, range)
                    .with_signals(signals.iter().copied()),
            };
            candidates.push(candidate.with_specificity(Specificity::Provider));
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERIM: [&str; 2] = ["vci_", "vck_"];

    /// Low-entropy synthetic filler: a fixed stem, then `0` padding. Never
    /// derived from an issued credential.
    fn body(len: usize) -> String {
        const STEM: &[u8] = b"SyntheticRevokedVercelFixture";
        (0..len)
            .map(|i| char::from(*STEM.get(i).unwrap_or(&b'0')))
            .collect()
    }

    fn detect(input: &str) -> Vec<Candidate> {
        VERCEL
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("VERCEL_TOKEN={token}"),
            format!("export VERCEL_TOKEN=\"{token}\""),
            format!("vercel deploy --token {token}"),
            format!("curl -H \"Authorization: Bearer {token}\" https://api.vercel.com/v2/user"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"access_token\": \"{token}\", \"token_type\": \"Bearer\"}}"),
            format!("vercel:\n  token: {token}\n"),
            format!("client = Vercel(bearer_token=\"{token}\")"),
            format!("Here is my token {token} can you debug this?"),
            format!("Rotate ({token}), then redeploy."),
            format!("# \u{1f511} caf\u{e9}\r\n{token}\r\n"),
        ]
    }

    /// Exactly one candidate in `input`, of `type_name`, at `token`'s span.
    fn assert_sole(input: &str, token: &str, type_name: &str) {
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

    #[test]
    fn typed_classes_are_detected_at_their_exact_span_in_every_context() {
        for (prefix, type_name) in TYPED {
            let token = format!("{prefix}{}", body(TYPED_BODY_LEN));
            assert_eq!(token.len(), 60);
            for input in contexts(&token) {
                assert_sole(&input, &token, type_name);
            }
        }
        assert_eq!(VERCEL.id(), "vercel-token");
    }

    #[test]
    fn interim_prefixes_keep_the_aggregate_type_and_the_pre_split_shape() {
        for prefix in INTERIM {
            for len in [FLOOR, 29, TYPED_BODY_LEN, 200] {
                let token = format!("{prefix}{}", body(len));
                for input in contexts(&token) {
                    assert_sole(&input, &token, "vercel_token");
                }
            }
            let token = format!("{prefix}SYNTHETIC_REVOKED-KEY_VALUE");
            assert_sole(&token, &token, "vercel_token");
            assert!(detect(&format!("{prefix}{}", body(FLOOR - 1))).is_empty());
            assert!(detect(&format!("{prefix}SYNTH!ETIC_REVOKED_SYNTHETIC")).is_empty());
        }
    }

    /// Security-first fallback: a typed-prefix value off the exact contract is
    /// still reported, whole, as `vercel_token`, exactly as before #1036.
    #[test]
    fn off_contract_typed_values_fall_back_to_vercel_token_whole() {
        let valid = body(TYPED_BODY_LEN);
        for (prefix, _) in TYPED {
            let mut values = vec![
                format!("{prefix}{}", body(TYPED_BODY_LEN - 1)),
                format!("{prefix}{}", body(TYPED_BODY_LEN + 1)),
                format!("{prefix}{}", body(FLOOR)),
                format!("{prefix}{}", body(200)),
                format!("{prefix}{}_{}", &valid[..28], &valid[28..]),
                format!("{prefix}{}-{}", &valid[..28], &valid[28..]),
                format!("{prefix}{valid}_backup"),
                format!("{prefix}{valid}-1"),
                format!("{prefix}{valid}a"),
            ];
            for separator in ["_", "-"] {
                let mut replaced = valid.clone();
                replaced.replace_range(30..31, separator);
                values.push(format!("{prefix}{replaced}"));
            }
            for value in values {
                for input in contexts(&value) {
                    assert_sole(&input, &value, "vercel_token");
                }
            }
            // A separator outside the alphabet ends the run: the leading 30
            // bytes still clear the floor, as before.
            let cut = format!("{prefix}{}", &valid[..30]);
            for separator in [".", "!", " "] {
                let input = format!("{cut}{separator}{}", &valid[31..]);
                assert_sole(&input, &cut, "vercel_token");
            }
            assert!(detect(&format!("{prefix}{}", body(FLOOR - 1))).is_empty());
        }
    }

    #[test]
    fn marker_twins_and_leading_glue_are_rejected() {
        let valid = body(TYPED_BODY_LEN);
        for (prefix, _) in TYPED {
            let token = format!("{prefix}{valid}");
            for input in [
                format!("{}{valid}", prefix.to_ascii_uppercase()),
                format!("{}{valid}", prefix.replace('_', "-")),
                format!("{}{valid}", &prefix[..3]),
                format!("x{token}"),
                format!("legacy{token}"),
                format!("_{token}"),
                format!("-{token}"),
                format!("7{token}"),
            ] {
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn classes_are_isolated_from_each_other() {
        let value = body(TYPED_BODY_LEN);
        let lines: Vec<String> = TYPED
            .iter()
            .map(|(prefix, _)| format!("{prefix}{value}"))
            .chain(INTERIM.iter().map(|prefix| format!("{prefix}{value}")))
            .collect();
        let input = lines.join("\n");
        let candidates = detect(&input);
        let types: Vec<&str> = candidates.iter().map(Candidate::type_name).collect();
        assert_eq!(
            types,
            [
                "vercel_personal_access_token",
                "vercel_app_access_token",
                "vercel_app_refresh_token",
                "vercel_token",
                "vercel_token",
            ]
        );
        let mut offset = 0;
        for (candidate, line) in candidates.iter().zip(&lines) {
            assert_eq!(
                candidate.range(),
                ByteRange::new(offset, offset + line.len()).unwrap()
            );
            offset += line.len() + 1;
        }
    }

    #[test]
    fn benign_siblings_are_not_claimed() {
        let value = body(TYPED_BODY_LEN);
        for input in [
            "deployment: dpl_8sFjq2K3nQeR7xYtLmWzAbCdEfGh".to_owned(),
            format!("vcx_{value}"),
            format!("vcs_{value}"),
            format!("vc_{value}"),
            "vcp_<YOUR_VERCEL_TOKEN>".to_owned(),
            format!("vcp_{}", "*".repeat(TYPED_BODY_LEN)),
            "vcp_${VERCEL_TOKEN}".to_owned(),
            "vcp_...".to_owned(),
            "Personal access tokens begin with the prefix vcp_ and app tokens with vca_."
                .to_owned(),
            "prj_SyntheticRevokedVercelProjectId000".to_owned(),
            "team_SyntheticRevokedVercelTeamId0000".to_owned(),
            format!("VERCEL_TOKEN={}", body(24)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_one_character_filler_body_is_a_placeholder() {
        for prefix in ["vcp_", "vci_", "vca_", "vcr_", "vck_"] {
            for len in [FLOOR, 24, TYPED_BODY_LEN] {
                assert!(detect(&format!("{prefix}{}", "x".repeat(len))).is_empty());
                assert!(detect(&format!("{prefix}{}", "0".repeat(len))).is_empty());
            }
            let twin = format!("{prefix}{}y", "x".repeat(FLOOR));
            assert_eq!(detect(&twin).len(), 1, "{twin}");
        }
    }

    #[test]
    fn a_repeated_value_is_reported_once_per_occurrence() {
        for (prefix, type_name) in TYPED {
            let token = format!("{prefix}{}", body(TYPED_BODY_LEN));
            let candidates = detect(&format!("{token} {token}"));
            assert_eq!(candidates.len(), 2);
            assert!(candidates.iter().all(|c| c.type_name() == type_name));
        }
    }

    /// A long `[A-Za-z0-9_-]` run after a prefix is one aggregate match, as
    /// before #1036, and the scan stays linear.
    #[test]
    fn a_long_run_is_one_aggregate_match() {
        // A two-character body: a one-character one is a placeholder (#1042).
        for input in ["vcp_".repeat(4096), format!("vcp_{}", "AB".repeat(50_000))] {
            assert_sole(&input, &input, "vercel_token");
        }
    }

    /// The pre-#1036 aggregate detector, verbatim, as an oracle.
    const PRE_SPLIT: crate::detectors::additional_providers::KnownFormatProviderDetector =
        crate::detectors::additional_providers::KnownFormatProviderDetector::new(
            "vercel-token",
            "vercel_token",
            &[
                PrefixShape::at_least("vcp_", 20, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
                PrefixShape::at_least("vci_", 20, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
                PrefixShape::at_least("vca_", 20, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
                PrefixShape::at_least("vcr_", 20, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
                PrefixShape::at_least("vck_", 20, pattern::is_alnum_dash, &AGGREGATE_SIGNALS),
            ],
            pattern::is_alnum_dash,
        );

    /// Nothing redacted before #1036 becomes unredacted: every span, count,
    /// confidence and specificity equals the pre-split detector's; only the
    /// type of an exact-contract typed value differs.
    #[test]
    fn every_span_equals_the_pre_split_detector() {
        let valid = body(TYPED_BODY_LEN);
        let mut values = Vec::new();
        for prefix in ["vcp_", "vci_", "vca_", "vcr_", "vck_", "VCP_", "vcx_"] {
            for len in [0, 19, 20, 21, 55, 56, 57, 60, 200] {
                values.push(format!("{prefix}{}", body(len)));
            }
            for glue in ["_", "-", ".", "!", " ", "a", "_backup", "-1"] {
                values.push(format!("{prefix}{}{glue}{}", &valid[..28], &valid[28..]));
                values.push(format!("{prefix}{valid}{glue}"));
                values.push(format!("{glue}{prefix}{valid}"));
            }
        }
        values.push("vcp_".repeat(64));
        for value in values {
            for input in contexts(&value) {
                let old = PRE_SPLIT
                    .detect(&input, &DetectorContext::new(input.len()))
                    .unwrap();
                let new = detect(&input);
                assert_eq!(old.len(), new.len(), "{input}");
                for (old, new) in old.iter().zip(&new) {
                    assert_eq!(old.range(), new.range(), "{input}");
                    assert_eq!(old.confidence(), new.confidence(), "{input}");
                    assert_eq!(
                        old.effective_specificity(),
                        new.effective_specificity(),
                        "{input}"
                    );
                    let typed =
                        typed_class(&input.as_bytes()[new.range().start()..new.range().end()]);
                    assert_eq!(new.type_name(), typed.unwrap_or("vercel_token"), "{input}");
                }
            }
        }
    }
}
