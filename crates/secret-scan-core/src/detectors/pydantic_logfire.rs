//! Pydantic Logfire token detection (issue #1106, handoff
//! [`docs/audits/evidence/1014/pydantic-logfire.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/pydantic-logfire.md)).
//!
//! Logfire write tokens (`LOGFIRE_TOKEN`), read tokens and organization or
//! project API keys (`LOGFIRE_READ_TOKEN`, `LOGFIRE_API_KEY`) and the Pydantic
//! AI Gateway key (`PYDANTIC_AI_GATEWAY_API_KEY`) share one
//! `pylf_v<n>_<region>_` namespace that no text feature splits, so they are
//! one detector and one finding type. The lexical grammar is T1 under rulings
//! R1 and R2: the `pydantic/logfire` SDK parser (`auth.py`,
//! `^pylf_v<digits>_<[a-z]+ region>_`, an optional lowercase-hex 8-4-4-4-12
//! organization id followed by `_`, then `[a-zA-Z0-9]+`), the `pydantic-ai`
//! gateway parser (`[a-zA-Z0-9-_]+`, whose `-` and `_` are the organization
//! id's) and the provider's own scrubber, which redacts any `pylf_v\d+_`.
//!
//! | Part | Grammar |
//! | --- | --- |
//! | Prefix | `pylf_v` + 1 to 3 digits + `_` + `[a-z]{2,16}` region + `_` |
//! | Organization id | optional 8-4-4-4-12 hex (either case) + `_` |
//! | Body | `[A-Za-z0-9]{20,}` |
//!
//! ## Floor and region cap (ruling Q7, open)
//!
//! The provider regex has no body bound. Every observed body is exactly 44
//! `[A-Za-z0-9]` bytes (provider fixtures and a third-party scanner rule), but
//! 44 is not provider-stated, so no exact width is claimed. The floor of 20 is
//! a narrowing policy below every observed token that removes the placeholders
//! in provider tests and docs (`..._xxx`, `..._token1`, `..._fake`); the
//! region cap of 16 is a policy cap on a class the provider leaves open
//! (`us`, `eu`, `ap`, `stagingus` are the observed regions). Neither widens
//! the provider grammar. Whether a policy floor may serve as the T1 floor is
//! ruling Q7 on the #1014 index, which is open; this follows its
//! recommendation (yes). If it is refused the floor falls back to `{1,}`,
//! a one-constant change that also removes the near-miss fixtures below 20.
//! The provider scrubber also redacts the bare prefix, a stronger posture
//! than this detector takes.
//!
//! ## Boundaries
//!
//! The whole `[A-Za-z0-9_-]` run after `pylf_v` is read and rejected, never
//! truncated, unless it has exactly the grammar above, so an uppercase region,
//! a missing digit or region, an organization id with a wrong group width, a
//! body under 20 and a `_` or `-` glued after the body are all false
//! negatives. A byte of `[A-Za-z0-9_-]` before `pylf_v` rejects the match.
//! Legacy tokens with no `pylf_` prefix, non-UUID dash or underscore bodies
//! and `pylf_v3`/`pylf_v4` 80-byte shapes that only a scanner fixture shows
//! stay unclaimed.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "pydantic-logfire-token";
const TYPE: &str = "pydantic_logfire_token";

const PREFIX: &str = "pylf_v";
const VERSION_MAX: usize = 3;
const REGION_MIN: usize = 2;
const REGION_MAX: usize = 16;
const BODY_MIN: usize = 20;
/// Version digit, `_`, region, `_` and the body floor: the least a run after
/// the prefix can be.
const RUN_MIN: usize = 1 + 1 + REGION_MIN + 1 + BODY_MIN;
const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
/// The organization id and the `_` that follows it.
const UUID_LEN: usize = 36 + 1;

const SIGNALS: [&str; 1] = ["pydantic-logfire-documented-prefix"];
const SIGNALS_WITH_ORG: [&str; 2] = [
    "pydantic-logfire-documented-prefix",
    "pydantic-logfire-org-id",
];

/// One shape for the prefix literal (and the shared prefilter, issue #983);
/// [`has_grammar`] decides the whole run.
pub(super) const SHAPES: &[PrefixShape<'static>] =
    &[
        PrefixShape::at_least(PREFIX, RUN_MIN, pattern::is_alnum_dash, &SIGNALS)
            .with_post_check(has_grammar),
    ];

/// Splits the run after the prefix into `(has_org_id, body)` when it is
/// `<digits>_<region>_[<uuid>_]<body>`.
fn parse(run: &[u8]) -> Option<(bool, &[u8])> {
    let digits = run.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 || digits > VERSION_MAX || run.get(digits) != Some(&b'_') {
        return None;
    }
    let after_version = &run[digits + 1..];
    let region = after_version
        .iter()
        .take_while(|byte| byte.is_ascii_lowercase())
        .count();
    if !(REGION_MIN..=REGION_MAX).contains(&region) || after_version.get(region) != Some(&b'_') {
        return None;
    }
    let rest = &after_version[region + 1..];
    let has_org = is_org_id(rest);
    let body = if has_org { &rest[UUID_LEN..] } else { rest };
    (body.len() >= BODY_MIN && body.iter().all(u8::is_ascii_alphanumeric))
        .then_some((has_org, body))
}

/// Whether `rest` begins with a hex 8-4-4-4-12 organization id and its `_`.
fn is_org_id(rest: &[u8]) -> bool {
    if rest.len() < UUID_LEN || rest[UUID_LEN - 1] != b'_' {
        return false;
    }
    let mut at = 0;
    for (index, group) in UUID_GROUPS.iter().enumerate() {
        if index > 0 {
            if rest[at] != b'-' {
                return false;
            }
            at += 1;
        }
        if !rest[at..at + group].iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        at += group;
    }
    true
}

fn has_grammar(bytes: &[u8], start: usize, end: usize) -> bool {
    parse(&bytes[start + PREFIX.len()..end]).is_some()
}

/// Recognizes `pylf_v<n>_<region>_[<org id>_]<body>`.
pub(super) struct LogfireDetector;

pub(super) const LOGFIRE: LogfireDetector = LogfireDetector;

impl Detector for LogfireDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        for (start, end, _signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            let signals: &[&str] =
                if parse(&bytes[start + PREFIX.len()..end]).is_some_and(|(org, _)| org) {
                    &SIGNALS_WITH_ORG
                } else {
                    &SIGNALS
                };
            candidates.push(
                Candidate::built_in(TYPE, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &[u8] = b"0123456789abcdef";

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn uuid(seed: usize) -> String {
        UUID_GROUPS
            .iter()
            .enumerate()
            .map(|(i, &len)| filler(HEX, len, seed + i))
            .collect::<Vec<_>>()
            .join("-")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        LOGFIRE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), TYPE);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn v1_and_v2_forms_are_detected_with_exact_spans() {
        let body = filler(ALNUM, 44, 1);
        let org = uuid(2);
        for token in [
            format!("pylf_v1_us_{body}"),
            format!("pylf_v1_eu_{}", &body[..20]),
            format!("pylf_v1_stagingus_{body}"),
            format!("pylf_v2_ap_{org}_{body}"),
            format!("pylf_v2_us_{}_{body}", org.to_uppercase()),
            format!("pylf_v12_{}_{body}", "a".repeat(16)),
        ] {
            for input in [
                token.clone(),
                format!("LOGFIRE_TOKEN={token}"),
                format!("Authorization: Bearer {token}"),
                format!("\u{d0a4}\u{1f511} \"{token}\"."),
            ] {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = filler(ALNUM, 44, 3);
        let mut bad_org = uuid(4);
        bad_org.replace_range(8..9, "_");
        for input in [
            format!("pylf_v1_us_{}", &body[..19]),
            format!("pylf_v_us_{body}"),
            format!("pylf_v1__{body}"),
            format!("pylf_v1_US_{body}"),
            format!("pylf_v1_u_{body}"),
            format!("pylf_v1_{}_{body}", "a".repeat(17)),
            format!("pylf_v1234_us_{body}"),
            format!("PYLF_v1_us_{body}"),
            format!("pylf_v2_us_{bad_org}_{body}"),
            format!("pylf_v2_us_{}_{}", uuid(5), &body[..19]),
            format!("pylf_v1_us_{body}_"),
            format!("pylf_v1_us_{body}-x"),
            format!("pylf_v1_us_{}-{}", &body[..22], &body[22..]),
            format!("xpylf_v1_us_{body}"),
            format!("_pylf_v1_us_{body}"),
            format!("-pylf_v1_us_{body}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn placeholders_and_masks_are_unclaimed() {
        for input in [
            "pylf_v1_us_...",
            "pylf_v1_us_xxx",
            "pylf_v1_us_token1",
            "pylf_v1_us_0kYhc****",
            "pylf_v\\d+_",
            "LOGFIRE_TOKEN=${LOGFIRE_TOKEN}",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repetition_stays_linear_and_exact() {
        assert!(detect(&"pylf_v".repeat(10_000)).is_empty());
        let token = format!("pylf_v1_us_{}", filler(ALNUM, 44, 6));
        assert_eq!(detect(&format!("{token} ").repeat(200)).len(), 200);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
