//! Amazon Bedrock API key detection (issues #864, #778, #779).
//!
//! ## Decision: two families, one module
//!
//! Amazon Bedrock has two bearer-token types that share the
//! `AWS_BEARER_TOKEN_BEDROCK` variable and the `Authorization: Bearer`
//! header but differ in origin, lifetime and lexical shape, so they are two
//! detectors and two finding types, matching the two support-matrix
//! families the benchmarks side tracks:
//!
//! | detector | type | shape |
//! | --- | --- | --- |
//! | `aws-bedrock-long-term-api-key` | `aws_bedrock_long_term_api_key` | `ABSK` + standard Base64 |
//! | `aws-bedrock-short-term-api-key` | `aws_bedrock_short_term_api_key` | `bedrock-api-key-` + fixed 133-byte Base64 head + standard Base64 |
//!
//! A long-term key is issued by AWS (an IAM service-specific credential,
//! logged in `CloudTrail`, valid until a chosen expiry). A short-term key is
//! minted client-side by the AWS token generators as a Base64-encoded
//! `SigV4`-presigned URL and lives at most 12 hours. Neither replaces
//! `aws_access_key_id`: an `AKIA`/`ASIA` id is plain text and never carries
//! either prefix, and a short-term key hides its embedded `ASIA` id inside
//! Base64.
//!
//! ## Evidence and tier (maintainer ruling 2026-09-27, #778, #779)
//!
//! - **Long-term prefix and alphabet, T1.** Accepted on the AWS Security
//!   Blog ("Securing Amazon Bedrock API keys", 2025-10-17), a
//!   provider-authored scan pattern: `ABSK` and the standard-Base64
//!   alphabet with `={0,2}` padding. Total length and IAM user-name
//!   variants other than `BedrockAPIKey-` stay T2/unspecified; the blog is
//!   accepted as provider evidence for the prefix and alphabet only, not a
//!   format specification. See `docs/audits/evidence/864/README.md`.
//! - **Short-term prefix, head and alphabet, T1.** Accepted on the
//!   AWS-authored token generators `aws-bedrock-token-generator-python`
//!   (`token_generator.py`: `AUTH_PREFIX = "bedrock-api-key-"`,
//!   `TOKEN_VERSION = "&Version=1"`, Base64 of a SigV4-presigned
//!   `https://bedrock.amazonaws.com/?Action=CallWithBearerToken` URL), the
//!   JS (`src/token.ts`) and Java (`BedrockTokenGenerator.java`)
//!   generators, plus the AWS Security Blog pattern (whose printed body
//!   class is malformed; the intended class is `[A-Za-z0-9+/]`): the
//!   `bedrock-api-key-` prefix, the fixed 133-character Base64 head, and
//!   the standard padded-Base64 alphabet. Total length (not documented;
//!   "over 1000 characters" is vendor-blog only) and the session-token part
//!   of the body stay T2/unspecified.
//! - **Short-term 133-byte head.** The 99 bytes
//!   `bedrock.amazonaws.com/?Action=CallWithBearerToken&X-Amz-Algorithm=`
//!   `AWS4-HMAC-SHA256&X-Amz-Credential` encode to 132 stable Base64
//!   characters, and the 133rd is fixed by the following `=`
//!   (`X-Amz-Credential=`). The head follows from the generator code and
//!   is the same one the blog prints. A test re-derives it.
//! - **Lengths, T2.** No AWS source states a length. The long-term body
//!   bounds are the tolerance the peer scanners use (gitleaks and
//!   git-secrets: 109 to 269 Base64 characters after `ABSK`; one vendor
//!   measures 132 total). The short-term tail floor is a lax lower bound
//!   below any token the generator can construct (about 496 total with an
//!   empty session token), not a measured length. There is no upper bound:
//!   a session token makes the key longer.
//!
//! ## Grammar
//!
//! - Long term: `ABSK`, then 109 to 269 standard-Base64 bytes
//!   (`[A-Za-z0-9+/]`), then up to two `=`. The `QmVkcm9ja0FQSUtleS` head
//!   (`BedrockAPIKey`, a console-created key) is not required: it only adds
//!   a signal, because keys for other IAM user names exist.
//! - Short term: `bedrock-api-key-`, the exact 133-byte head, then at least
//!   64 more standard-Base64 bytes, then up to two `=`.
//! - A key is never a slice of a wider token: the byte before it must not be
//!   `[A-Za-z0-9+/_-]` (`=` is allowed, so `NAME=ABSK…` matches), and the
//!   byte after the padding must not be `[A-Za-z0-9+/=_-]`. A URL-safe body
//!   (`-`, `_`), a mid-body `=`, three `=`, a wrong-case prefix, or a glued
//!   Base64 neighbour therefore reject instead of truncating.
//! - Findings are always redacted, high confidence, provider specificity.
//!
//! ## Trade-offs
//!
//! - **False negatives.** A long-term key outside 109 to 269 body bytes
//!   (a future longer key) is missed, not truncated. A short-term key with a
//!   changed head (a new query-parameter order or `Version`) is missed. Keys
//!   that other AWS products issue under other prefixes are out of scope.
//! - **False positives.** A long Base64 blob that begins with `ABSK` by
//!   chance; a doc placeholder (`ABSK...`, `ABSK<your-key>`) is too short or
//!   holds non-Base64 bytes and is not reported.
//! - **Excluded.** The decoded public alias `BedrockAPIKey-xxxx-at-<account>`,
//!   `ServiceSpecificCredentialId`, IAM ARNs and user names, and
//!   `AKIA`/`ASIA` ids are never matched here.
//! - **Cost.** One first-byte filter, then prefix comparison, then one
//!   forward pass over the Base64 run of a candidate. A candidate must pass
//!   the leading boundary first, so an `ABSKABSK…` run is scanned once.
//!   Nothing allocates per byte, and no state crosses a line, so
//!   incremental and WASM scanning pay the same linear cost as the other
//!   prefixed families.

use crate::detectors::pattern;
use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const LONG_TERM_PREFIX: &str = "ABSK";
const SHORT_TERM_PREFIX: &str = "bedrock-api-key-";

/// Minimum and maximum Base64 bytes after `ABSK` (T2 tolerance).
const LONG_TERM_BODY_MIN: usize = 109;
const LONG_TERM_BODY_MAX: usize = 269;

/// The 133 Base64 characters every short-term key starts with after its
/// prefix: `bedrock.amazonaws.com/?Action=CallWithBearerToken&X-Amz-Algorithm`
/// `=AWS4-HMAC-SHA256&X-Amz-Credential=`, encoded. A test re-derives it.
const SHORT_TERM_HEAD: &str = "YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbiZYLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsP";

/// Minimum Base64 bytes after the head (T2, deliberately lax).
const SHORT_TERM_TAIL_MIN: usize = 64;

/// The Base64 of `BedrockAPIKey`, the head of a console-created long-term
/// key's decoded alias. Signal only, never required.
const CONSOLE_ALIAS_HEAD: &str = "QmVkcm9ja0FQSUtleS";

const LONG_TERM_SIGNALS: [&str; 2] = ["aws-bedrock-long-term-prefix", "base64-body"];
const LONG_TERM_CONSOLE_SIGNALS: [&str; 3] = [
    "aws-bedrock-long-term-prefix",
    "base64-body",
    "console-alias-head",
];
const SHORT_TERM_SIGNALS: [&str; 3] = [
    "aws-bedrock-short-term-prefix",
    "fixed-presigned-url-head",
    "base64-body",
];

/// A byte a key must not be glued to on its left.
fn is_left_glue(byte: u8) -> bool {
    pattern::is_base64_body(byte) || byte == b'_' || byte == b'-'
}

/// A byte a key must not be glued to on its right (after its padding).
fn is_right_glue(byte: u8) -> bool {
    is_left_glue(byte) || byte == b'='
}

/// One match: the whole key including padding, and the Base64 body's start.
struct Match {
    start: usize,
    end: usize,
    body_start: usize,
}

/// Length of the maximal standard-Base64 run starting at `from`.
fn base64_run(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .take_while(|&&byte| pattern::is_base64_body(byte))
        .count()
}

/// Consumes up to two `=` at `end` and applies the right boundary. `None`
/// when a third `=` or a glued identifier byte follows.
fn finish(bytes: &[u8], mut end: usize) -> Option<usize> {
    let mut padding = 0;
    while padding < 2 && bytes.get(end) == Some(&b'=') {
        end += 1;
        padding += 1;
    }
    match bytes.get(end) {
        Some(&byte) if is_right_glue(byte) => None,
        _ => Some(end),
    }
}

/// Finds every key: `prefix`, an optional exact `head`, then a Base64 run
/// whose length after the head is `min_tail..=max_tail`.
fn scan(input: &str, prefix: &str, head: &str, min_tail: usize, max_tail: usize) -> Vec<Match> {
    let bytes = input.as_bytes();
    let prefix = prefix.as_bytes();
    let mut matches = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let Some(offset) = bytes[at..].iter().position(|&byte| byte == prefix[0]) else {
            break;
        };
        let start = at + offset;
        at = start + 1;
        if !bytes[start..].starts_with(prefix) {
            continue;
        }
        if start > 0 && is_left_glue(bytes[start - 1]) {
            continue;
        }
        let body_start = start + prefix.len();
        let run = base64_run(bytes, body_start);
        if run < head.len() + min_tail
            || run > head.len() + max_tail
            || !bytes[body_start..].starts_with(head.as_bytes())
        {
            continue;
        }
        let Some(end) = finish(bytes, body_start + run) else {
            continue;
        };
        matches.push(Match {
            start,
            end,
            body_start,
        });
        at = end;
    }
    matches
}

fn candidates(
    type_name: &'static str,
    matches: Vec<Match>,
    signals: impl Fn(&Match) -> &'static [&'static str],
) -> Vec<Candidate> {
    matches
        .into_iter()
        .filter_map(|found| {
            let range = ByteRange::new(found.start, found.end)?;
            Some(
                Candidate::new(type_name, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals(&found).iter().copied()),
            )
        })
        .collect()
}

/// Detects a long-term Amazon Bedrock API key; see the module doc.
pub(super) struct AwsBedrockLongTermApiKeyDetector;

impl Detector for AwsBedrockLongTermApiKeyDetector {
    fn id(&self) -> &'static str {
        "aws-bedrock-long-term-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let matches = scan(
            input,
            LONG_TERM_PREFIX,
            "",
            LONG_TERM_BODY_MIN,
            LONG_TERM_BODY_MAX,
        );
        Ok(candidates(
            "aws_bedrock_long_term_api_key",
            matches,
            |found| {
                if input[found.body_start..].starts_with(CONSOLE_ALIAS_HEAD) {
                    &LONG_TERM_CONSOLE_SIGNALS
                } else {
                    &LONG_TERM_SIGNALS
                }
            },
        ))
    }
}

/// Detects a short-term Amazon Bedrock API key; see the module doc.
pub(super) struct AwsBedrockShortTermApiKeyDetector;

impl Detector for AwsBedrockShortTermApiKeyDetector {
    fn id(&self) -> &'static str {
        "aws-bedrock-short-term-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let matches = scan(
            input,
            SHORT_TERM_PREFIX,
            SHORT_TERM_HEAD,
            SHORT_TERM_TAIL_MIN,
            usize::MAX - SHORT_TERM_HEAD.len(),
        );
        Ok(candidates(
            "aws_bedrock_short_term_api_key",
            matches,
            |_| &SHORT_TERM_SIGNALS,
        ))
    }
}

/// The literals one of which every long-term Bedrock key candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const LONG_TERM_REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&[LONG_TERM_PREFIX])];

/// The literals one of which every short-term Bedrock key candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const SHORT_TERM_REQUIRED_LITERALS: &[Literals] =
    &[Literals::Strs(&[SHORT_TERM_PREFIX])];

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Independently written standard Base64 encoder (padded).
    fn base64(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Deterministic synthetic Base64 filler of exactly `len` characters that
    /// uses every alphabet character, including `+` and `/`. Never derived
    /// from a real key.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % 64]))
            .collect()
    }

    fn long_key(body_len: usize) -> String {
        format!("{LONG_TERM_PREFIX}{}", filler(body_len, 1))
    }

    fn short_key(tail_len: usize) -> String {
        format!(
            "{SHORT_TERM_PREFIX}{SHORT_TERM_HEAD}{}",
            filler(tail_len, 2)
        )
    }

    fn detect_long(input: &str) -> Vec<Candidate> {
        AwsBedrockLongTermApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_short(input: &str) -> Vec<Candidate> {
        AwsBedrockShortTermApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_one(found: &[Candidate], type_name: &str, input: &str, key: &str) {
        assert_eq!(found.len(), 1, "{input}");
        assert_eq!(found[0].type_name(), type_name);
        assert_eq!(found[0].confidence(), Confidence::High);
        assert_eq!(found[0].effective_specificity(), Specificity::Provider);
        let start = input.find(key).unwrap();
        assert_eq!(
            found[0].range(),
            ByteRange::new(start, start + key.len()).unwrap()
        );
    }

    #[test]
    fn short_term_head_is_the_encoded_presigned_url_head() {
        let plain = b"bedrock.amazonaws.com/?Action=CallWithBearerToken\
&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=";
        assert_eq!(base64(plain).as_bytes()[..133], *SHORT_TERM_HEAD.as_bytes());
        assert_eq!(SHORT_TERM_HEAD.len(), 133);
        assert_eq!(&base64(b"BedrockAPIKey-")[..18], CONSOLE_ALIAS_HEAD);
    }

    #[test]
    fn long_term_bare_and_boundary_lengths() {
        for len in [LONG_TERM_BODY_MIN, 128, 132, LONG_TERM_BODY_MAX] {
            let key = long_key(len);
            assert_one(
                &detect_long(&key),
                "aws_bedrock_long_term_api_key",
                &key,
                &key,
            );
        }
    }

    #[test]
    fn long_term_rejects_lengths_outside_the_band() {
        assert!(detect_long(&long_key(LONG_TERM_BODY_MIN - 1)).is_empty());
        assert!(detect_long(&long_key(LONG_TERM_BODY_MAX + 1)).is_empty());
    }

    #[test]
    fn long_term_includes_padding_in_the_span() {
        for pad in ["", "=", "=="] {
            let key = format!("{}{pad}", long_key(130));
            let input = format!("k={key}\n");
            assert_one(
                &detect_long(&input),
                "aws_bedrock_long_term_api_key",
                &input,
                &key,
            );
        }
    }

    #[test]
    fn long_term_contexts_have_exact_spans() {
        let key = long_key(128);
        let contexts = [
            key.clone(),
            format!("AWS_BEARER_TOKEN_BEDROCK={key}"),
            format!("export AWS_BEARER_TOKEN_BEDROCK={key}"),
            format!("export AWS_BEARER_TOKEN_BEDROCK=\"{key}\""),
            format!("AWS_BEARER_TOKEN_BEDROCK: {key}"),
            format!("AWS_BEARER_TOKEN_BEDROCK: '{key}'"),
            format!("{{\"AWS_BEARER_TOKEN_BEDROCK\": \"{key}\"}}"),
            format!("Authorization: Bearer {key}"),
            format!("curl -H \"Authorization: Bearer {key}\" https://example.invalid/"),
            format!("os.environ[\"AWS_BEARER_TOKEN_BEDROCK\"] = \"{key}\""),
            format!("client = Client(api_key=\"{key}\")"),
            format!("{{\"tool\":\"set_env\",\"arguments\":{{\"value\":\"{key}\"}}}}"),
            format!("```\n{key}\n```"),
            format!("({key}), [{key}] <{key}>."),
        ];
        for input in contexts {
            let found = detect_long(&input);
            assert!(!found.is_empty(), "{input}");
            for candidate in &found {
                let range = candidate.range();
                assert_eq!(&input[range.start()..range.end()], key);
            }
        }
    }

    #[test]
    fn long_term_twins_are_rejected() {
        let key = long_key(128);
        let body = &key[4..];
        // wrong prefix, case, glued neighbours
        assert!(detect_long(&format!("ABSX{body}")).is_empty());
        assert!(detect_long(&format!("absk{body}")).is_empty());
        assert!(detect_long(&format!("Q{key}")).is_empty());
        assert!(detect_long(&format!("-{key}")).is_empty());
        assert!(detect_long(&format!("{}Q", long_key(LONG_TERM_BODY_MAX))).is_empty());
        assert!(detect_long(&format!("{key}_x")).is_empty());
        // wrong alphabet: URL-safe characters mid-body or at the end
        let mut url_safe = key.clone();
        url_safe.replace_range(60..61, "-");
        assert!(detect_long(&url_safe).is_empty());
        url_safe.replace_range(60..61, "_");
        assert!(detect_long(&url_safe).is_empty());
        // padding faults: mid-body `=`, three `=`
        let mut mid = key.clone();
        mid.replace_range(60..61, "=");
        assert!(detect_long(&mid).is_empty());
        assert!(detect_long(&format!("{key}===")).is_empty());
    }

    #[test]
    fn long_term_placeholders_and_lookalikes_are_not_reported() {
        assert!(detect_long("ABSK...").is_empty());
        assert!(detect_long("AWS_BEARER_TOKEN_BEDROCK=ABSK<your-key>").is_empty());
        assert!(detect_long("AWS_BEARER_TOKEN_BEDROCK=").is_empty());
        assert!(detect_long("AWS_BEARER_TOKEN_BEDROCK=${AWS_BEARER_TOKEN_BEDROCK}").is_empty());
        assert!(detect_long(&format!("Q{}", filler(200, 3))).is_empty());
        // public alias, ids, ARNs: not the key
        assert!(detect_long("BedrockAPIKey-abcd-at-000000000000").is_empty());
        assert!(detect_long("arn:aws:iam::000000000000:user/BedrockAPIKey-abcd").is_empty());
    }

    #[test]
    fn long_term_console_head_adds_a_signal_only() {
        let with_head = format!("{LONG_TERM_PREFIX}{CONSOLE_ALIAS_HEAD}{}", filler(110, 4));
        let found = detect_long(&with_head);
        assert_eq!(found.len(), 1);
        assert!(found[0].signals().iter().any(|s| s == "console-alias-head"));
        let without = detect_long(&long_key(128));
        assert_eq!(without.len(), 1);
        assert!(
            !without[0]
                .signals()
                .iter()
                .any(|s| s == "console-alias-head")
        );
    }

    #[test]
    fn long_term_two_keys_and_no_akia_collision() {
        let key = long_key(128);
        let input = format!("{key} {key}");
        assert_eq!(detect_long(&input).len(), 2);
        let akia = format!("AKIA{}", "SYNTHETICEXAMPLE");
        assert!(detect_long(&akia).is_empty());
        assert!(detect_short(&akia).is_empty());
        // An AKIA id does not become a Bedrock key and vice versa.
        let aws = crate::detectors::aws::AwsAccessKeyDetector;
        assert!(
            aws.detect(&key, &DetectorContext::new(key.len()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn short_term_detects_across_contexts() {
        let key = short_key(400);
        let contexts = [
            key.clone(),
            format!("AWS_BEARER_TOKEN_BEDROCK={key}"),
            format!("export AWS_BEARER_TOKEN_BEDROCK={key}"),
            format!("AWS_BEARER_TOKEN_BEDROCK: {key}"),
            format!("{{\"AWS_BEARER_TOKEN_BEDROCK\": \"{key}\"}}"),
            format!("Authorization: Bearer {key}"),
            format!("os.environ[\"AWS_BEARER_TOKEN_BEDROCK\"] = \"{key}\""),
            format!("{{\"tool\":\"call\",\"arguments\":{{\"api_key\":\"{key}\"}}}}"),
        ];
        for input in contexts {
            let found = detect_short(&input);
            assert_eq!(found.len(), 1, "{input}");
            let range = found[0].range();
            assert_eq!(&input[range.start()..range.end()], key);
            assert_eq!(found[0].type_name(), "aws_bedrock_short_term_api_key");
        }
    }

    #[test]
    fn short_term_padding_and_length_are_unbounded_above() {
        for pad in ["", "=", "=="] {
            let key = format!("{}{pad}", short_key(1500));
            let input = format!("t={key}\n");
            assert_one(
                &detect_short(&input),
                "aws_bedrock_short_term_api_key",
                &input,
                &key,
            );
        }
        assert_eq!(detect_short(&short_key(SHORT_TERM_TAIL_MIN)).len(), 1);
        assert!(detect_short(&short_key(SHORT_TERM_TAIL_MIN - 1)).is_empty());
    }

    #[test]
    fn short_term_twins_are_rejected() {
        let tail = filler(400, 2);
        // truncated head, at every length short of 133
        for cut in [1, 28, 100, 132] {
            let head = &SHORT_TERM_HEAD[..cut];
            assert!(detect_short(&format!("{SHORT_TERM_PREFIX}{head}{tail}")).is_empty());
        }
        // one character off inside the head
        let mut bad = SHORT_TERM_HEAD.to_owned();
        bad.replace_range(40..41, "Z");
        assert!(detect_short(&format!("{SHORT_TERM_PREFIX}{bad}{tail}")).is_empty());
        // prefix only, wrong prefix, wrong case
        assert!(detect_short(SHORT_TERM_PREFIX).is_empty());
        assert!(detect_short(&format!("bedrock-api-token-{SHORT_TERM_HEAD}{tail}")).is_empty());
        assert!(detect_short(&format!("Bedrock-Api-Key-{SHORT_TERM_HEAD}{tail}")).is_empty());
        // the head alone (a constant) with nothing after it
        assert!(detect_short(&format!("{SHORT_TERM_PREFIX}{SHORT_TERM_HEAD}")).is_empty());
        // wrong alphabet in the tail
        let key = short_key(400);
        let mut url_safe = key.clone();
        let cut = key.len() - 100;
        url_safe.replace_range(cut..=cut, "-");
        assert!(detect_short(&url_safe).is_empty());
        url_safe.replace_range(cut..=cut, "_");
        assert!(detect_short(&url_safe).is_empty());
        // padding faults and glued neighbours
        assert!(detect_short(&format!("{key}===")).is_empty());
        assert!(detect_short(&format!("x{key}")).is_empty());
        assert!(detect_short(&format!("{key}-more")).is_empty());
    }

    #[test]
    fn short_term_placeholders_are_not_reported() {
        assert!(detect_short("bedrock-api-key-YOUR_KEY_HERE").is_empty());
        assert!(detect_short("<your-bedrock-api-key>").is_empty());
        assert!(detect_short("Authorization: Bearer ${AWS_BEARER_TOKEN_BEDROCK}").is_empty());
    }

    #[test]
    fn the_two_shapes_do_not_claim_each_other() {
        assert!(detect_long(&short_key(400)).is_empty());
        assert!(detect_short(&long_key(128)).is_empty());
    }

    #[test]
    fn adversarial_repetition_is_linear_and_quiet() {
        let dense = "ABSK".repeat(20_000);
        assert!(detect_long(&dense).is_empty());
        let dense = SHORT_TERM_PREFIX.repeat(5_000);
        assert!(detect_short(&dense).is_empty());
    }

    #[test]
    fn multibyte_neighbours_do_not_split_offsets() {
        let key = long_key(128);
        let input = format!("caf\u{e9}{key}\u{e9}");
        assert_one(
            &detect_long(&input),
            "aws_bedrock_long_term_api_key",
            &input,
            &key,
        );
    }
}
