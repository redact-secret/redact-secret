//! Issue #1014 second-wave provider families (#1102 Xata, #1103 Sourcegraph,
//! #1104 Unkey, #1105 Buildkite) through the public API with the full
//! default registry.
//!
//! Every key is built at run time from a literal prefix plus a seeded
//! low-entropy synthetic filler, so no realistic key literal is committed.
//! The filler was never derived from an issued credential.
//!
//! Each family checks, against the whole built-in registry rather than its
//! own detector alone:
//!
//! - every probe context (bare in prose, env, `export`, Bearer, `X-API-Key`,
//!   JSON `token`/`api_key`, SDK keyword argument, chat sentence, YAML,
//!   fenced block, sentence punctuation, a multibyte lead) yields exactly one
//!   finding, of the provider type, at exactly the key's UTF-8 byte span,
//!   redacted;
//! - one-property twins yield no finding of the provider's detector;
//! - benign siblings stay unclaimed by the provider's detector;
//! - a repetition line stays bounded and exact;
//! - the whole input, every two-chunk UTF-8 byte partition and a per-line
//!   incremental session agree on text, spans, detector and type.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Deterministic low-entropy synthetic filler over `alphabet`.
fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The probe contexts plus a few host forms, including a multibyte lead so a
/// byte offset differs from a character offset.
fn contexts(key: &str) -> Vec<String> {
    vec![
        key.to_owned(),
        format!("PROVIDER_TOKEN={key}\n"),
        format!("export PROVIDER_TOKEN=\"{key}\"\n"),
        format!("Authorization: Bearer {key}\n"),
        format!("X-API-Key: {key}\n"),
        format!("{{\"token\": \"{key}\"}}"),
        format!("{{\"api_key\": \"{key}\"}}"),
        format!("client = Client(api_key=\"{key}\")\n"),
        format!("Here is my key {key} can you debug why it fails?"),
        format!("config:\n  token: {key}\n"),
        format!("```\n{key}\n```"),
        format!("The key is {key}."),
        format!("\u{d0a4}\u{d0a4}\u{1f511} 키: {key}\n"),
    ]
}

fn detector_findings<'a>(findings: &'a [Finding], detector: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == detector)
        .collect()
}

/// Exactly one finding in `input`: `detector`/`type_name` at the key's span,
/// redacted, and the key gone from the output.
fn assert_sole_finding_in(input: &str, detector: &str, type_name: &str, key: &str) {
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{type_name}: {input}: {findings:?}");
    let finding = &findings[0];
    let start = input.find(key).unwrap();
    assert_eq!(finding.detector(), detector, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + key.len()),
        "{input}"
    );
    assert!(!text.contains(key), "{input}");
}

fn assert_sole_provider_finding(detector: &str, type_name: &str, key: &str) {
    for input in contexts(key) {
        assert_sole_finding_in(&input, detector, type_name, key);
    }
}

fn assert_unclaimed(detector: &str, input: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        detector_findings(&findings, detector).is_empty(),
        "{detector} claimed {input}: {findings:?}"
    );
}

fn assert_twins_unclaimed(detector: &str, twins: &[String]) {
    for twin in twins {
        for input in contexts(twin) {
            assert_unclaimed(detector, &input);
        }
    }
}

/// `count` space-separated copies of `key` yield exactly `count` findings of
/// `detector` and nothing else, and no copy survives redaction.
fn assert_repetition_line(detector: &str, key: &str, count: usize) {
    let line = format!("{key} ").repeat(count);
    let (text, findings) = whole_input(&line);
    assert_eq!(detector_findings(&findings, detector).len(), count);
    assert_eq!(findings.len(), count, "{findings:?}");
    assert!(!text.contains(key));
}

/// The whole input, every two-chunk UTF-8 byte partition and a per-line
/// incremental session produce the same text and the same findings.
fn assert_parity(input: &str) {
    let (expected_text, expected) = whole_input(input);
    assert!(!expected.is_empty(), "{input}");
    let same = |label: &str, text: String, findings: &[Finding]| {
        assert_eq!(text, expected_text, "{label}");
        assert_eq!(findings.len(), expected.len(), "{label}: {findings:?}");
        for (got, want) in findings.iter().zip(&expected) {
            assert_eq!(got.range(), want.range(), "{label}");
            assert_eq!(got.detector(), want.detector(), "{label}");
            assert_eq!(got.type_name(), want.type_name(), "{label}");
            assert_eq!(got.action(), want.action(), "{label}");
        }
    };
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        same(&format!("{pieces:?}"), session.text(), &session.findings());
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    same("per line", session.text(), &session.findings());
}

/// A three-line input: a multibyte comment, the key on its own line, and the
/// key behind a Bearer scheme.
fn parity_input(key: &str) -> String {
    format!("# \u{d0a4}\u{1f511} 키\n{key}\nAuthorization: Bearer {key}\n")
}

mod xata {
    use super::*;

    pub(super) const DETECTOR: &str = "xata-api-key";
    const USER: &str = "xata_user_api_key";
    const ORGANIZATION: &str = "xata_organization_api_key";

    pub(super) fn key(prefix: &str, len: usize, seed: usize) -> String {
        format!("{prefix}{}", filler(ALNUM, len, seed))
    }

    #[test]
    fn both_roles_win_every_context_as_the_sole_finding() {
        for (prefix, type_name) in [("xau_", USER), ("xao_", ORGANIZATION)] {
            for len in [32, 33, 34, 36] {
                assert_sole_provider_finding(DETECTOR, type_name, &key(prefix, len, len));
            }
        }
        let key = key("xau_", 33, 1);
        for input in [
            format!("XATA_API_KEY={key}\n"),
            format!("# .env\nXATA_API_KEY={key}\nXATA_BRANCH=main\n"),
            format!(
                "{{\"mcpServers\":{{\"xata\":{{\"command\":\"xata-mcp\",\"env\":{{\"XATA_API_KEY\":\"{key}\"}}}}}}}}\n"
            ),
            format!("curl -H 'Authorization: Bearer {key}' https://api.xata.example/v1\n"),
        ] {
            assert_sole_finding_in(&input, DETECTOR, USER, &key);
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 33, 2);
        let base = format!("xau_{body}");
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("xau_{}", &body[..31]),
                format!("xao_{}", &body[..31]),
                format!("xau_{}", filler(ALNUM, 37, 3)),
                format!("xao_{}", filler(ALNUM, 37, 3)),
                format!("xau_{dashed}"),
                format!("xau_{underscored}"),
                format!("XAU_{body}"),
                format!("xat_{body}"),
                format!("xau-{body}"),
                format!("maxau_{body}"),
                format!("x{base}"),
                format!("_{base}"),
                format!("{base}_"),
                format!("{base}-x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "xau_test xau_redacted xau_some_key xau_test123\n".to_owned(),
            "XATA_API_KEY=${XATA_API_KEY}\n".to_owned(),
            format!("XATA_API_KEY=xau_{}\n", "*".repeat(33)),
            "xau_snake_case_identifier_name_that_is_long\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"xau_".repeat(10_000));
        assert_unclaimed(DETECTOR, &key("xau_", 33, 4).repeat(200));
        assert_repetition_line(DETECTOR, &key("xao_", 34, 4), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&key("xau_", 33, 5)));
        assert_parity(&parity_input(&key("xao_", 36, 6)));
    }
}

mod sourcegraph {
    use super::*;

    pub(super) const DETECTOR: &str = "sourcegraph-token";
    const TYPE: &str = "sourcegraph_access_token";
    const LOWER_HEX: &[u8] = b"0123456789abcdef";

    fn hex(seed: usize) -> String {
        filler(LOWER_HEX, 40, seed)
    }

    pub(super) fn forms(seed: usize) -> Vec<String> {
        vec![
            format!("sgp_{}", hex(seed)),
            format!("sgp_local_{}", hex(seed + 1)),
            format!("sgp_{}_{}", filler(LOWER_HEX, 16, seed + 2), hex(seed + 3)),
            format!("sgp_{}", hex(seed + 4).to_uppercase()),
            format!("sgp_{}_{}", filler(ALNUM, 32, seed + 5), hex(seed + 6)),
        ]
    }

    #[test]
    fn every_form_wins_every_context_as_the_sole_finding() {
        for token in forms(1) {
            assert_sole_provider_finding(DETECTOR, TYPE, &token);
        }
        let token = &forms(2)[1];
        for input in [
            format!("SRC_ACCESS_TOKEN={token}\n"),
            format!(
                "# .env\nSRC_ENDPOINT=https://sourcegraph.example.test\nSRC_ACCESS_TOKEN={token}\n"
            ),
            format!("Authorization: token {token}\n"),
            format!("src login -endpoint https://sourcegraph.example.test -token {token}\n"),
            format!(
                "{{\"mcpServers\":{{\"sourcegraph\":{{\"env\":{{\"SRC_ACCESS_TOKEN\":\"{token}\"}}}}}}}}\n"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, TYPE, token);
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = hex(3);
        let base = format!("sgp_{body}");
        let mut non_hex = body.clone();
        non_hex.replace_range(39..40, "g");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("sgp_{}", &body[..39]),
                format!("sgp_{body}a"),
                format!("sgp_local_{}", &body[..39]),
                format!("sgp_local_{body}0"),
                format!("sgp_{non_hex}"),
                format!("sgp_local{body}"),
                format!("sgp__{body}"),
                format!("sgp_{}_{body}", filler(ALNUM, 33, 4)),
                format!("SGP_{body}"),
                format!("sgp-{body}"),
                format!("xsgp_{body}"),
                format!("_{base}"),
                format!("{base}-x"),
                format!("{base}_tail"),
            ],
        );
    }

    #[test]
    fn excluded_shapes_and_benign_text_are_unclaimed() {
        let sha = hex(5);
        for input in [
            format!("commit {sha}\n"),
            format!("sgph_{sha}\n"),
            format!("sgph_local_{sha}\n"),
            format!("sgd_{}\n", filler(LOWER_HEX, 64, 6)),
            format!("slk_{sha}\n"),
            format!("sgp_{}\n", "x".repeat(40)),
            "SRC_ACCESS_TOKEN=${SRC_ACCESS_TOKEN}\n".to_owned(),
            "SRC_ACCESS_TOKEN=sgp_xxxxxxxx\n".to_owned(),
            "the sgp_token word alone\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_bare_40_hex_value_is_never_a_finding_of_any_detector_without_context() {
        let (_, findings) = whole_input(&format!("see commit {}\n", hex(7)));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"sgp_".repeat(10_000));
        assert_unclaimed(DETECTOR, &format!("sgp_{}", "a_".repeat(5_000)));
        assert_unclaimed(DETECTOR, &format!("sgp_{}", hex(8)).repeat(200));
        assert_repetition_line(DETECTOR, &format!("sgp_local_{}", hex(8)), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        for token in forms(9) {
            assert_parity(&parity_input(&token));
        }
    }
}

mod unkey {
    use super::*;

    pub(super) const DETECTOR: &str = "unkey-root-key";
    const TYPE: &str = "unkey_root_key";
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    fn b58(len: usize, seed: usize) -> String {
        filler(BASE58, len, seed)
    }

    pub(super) fn v1(seed: usize) -> String {
        format!("unkey_{}unkeyv1{}", b58(8, seed), b58(42, seed + 1))
    }

    pub(super) fn dashboard(seed: usize) -> String {
        format!("unkey_3Z{}", b58(22, seed))
    }

    #[test]
    fn both_forms_win_every_context_as_the_sole_finding() {
        let (v1, dashboard) = (v1(1), dashboard(2));
        assert_eq!((v1.len(), dashboard.len()), (63, 30));
        assert_sole_provider_finding(DETECTOR, TYPE, &v1);
        assert_sole_provider_finding(DETECTOR, TYPE, &dashboard);
        // A version 1 head that begins 3Z is still one 63-byte key.
        let head_3z = format!("unkey_3Z{}unkeyv1{}", b58(6, 3), b58(42, 4));
        assert_sole_provider_finding(DETECTOR, TYPE, &head_3z);
        for key in [&v1, &dashboard] {
            for input in [
                format!("UNKEY_ROOT_KEY={key}\n"),
                format!("# .env\nUNKEY_ROOT_KEY={key}\nUNKEY_API_ID=api_3ZsyntheticRevokedApiId\n"),
                format!("const unkey = new Unkey({{ rootKey: \"{key}\" }});\n"),
                format!(
                    "curl -H 'Authorization: Bearer {key}' https://api.unkey.example/v2/keys.createKey\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let head = b58(8, 5);
        let tail = b58(42, 6);
        let key = v1(7);
        let dash = dashboard(8);
        let swap = |text: &str, offset: usize, byte: &str| {
            let mut copy = text.to_owned();
            copy.replace_range(offset..=offset, byte);
            copy
        };
        let mut twins = vec![
            format!("unkey_{head}unkeyv1{}", &tail[..41]),
            format!("unkey_{head}unkeyv1{tail}A"),
            format!("unkey_{head}unkeyv2{tail}"),
            format!("unkey_{head}Unkeyv1{tail}"),
            format!("unkey_{}unkeyv1{tail}A", &head[..7]),
            format!("unkey_3Y{}", b58(22, 9)),
            format!("unkey_3Z{}", b58(21, 10)),
            format!("unkey_3Z{}", b58(23, 11)),
            format!("UNKEY_{}", &key[6..]),
            format!("unkey-{}", &key[6..]),
            format!("x{key}"),
            format!("_{key}"),
            format!("my_{key}"),
            format!("{key}_x"),
            format!("{dash}-x"),
        ];
        for offset in [6, 13, 40, 62] {
            for bad in ["0", "O", "I", "l", "_"] {
                twins.push(swap(&key, offset, bad));
            }
        }
        for offset in [8, 20, 29] {
            for bad in ["0", "O", "I", "l"] {
                twins.push(swap(&dash, offset, bad));
            }
        }
        assert_twins_unclaimed(DETECTOR, &twins);
    }

    #[test]
    fn customer_prefixed_version_1_keys_are_a_bounded_false_negative_until_ruling_q10() {
        for prefix in ["acme", "my_product", "a", "sixteen_chars_pfx"] {
            let key = format!("{prefix}_{}unkeyv1{}", b58(8, 12), b58(42, 13));
            assert_twins_unclaimed(DETECTOR, std::slice::from_ref(&key));
        }
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "unkey_root_key unkey_mutations unkey_api_id\n".to_owned(),
            "key_3ZsyntheticRevokedKeyId api_3ZsyntheticRevokedApiId\n".to_owned(),
            "UNKEY_ROOT_KEY=unkey_xxxxxxxxxxxxxxxxxxxxxxxx\n".to_owned(),
            "UNKEY_ROOT_KEY=${UNKEY_ROOT_KEY}\n".to_owned(),
            "unkey_abcdefghijkmnopqrstuvwxy\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"unkey_".repeat(10_000));
        assert_unclaimed(DETECTOR, &v1(14).repeat(100));
        assert_repetition_line(DETECTOR, &v1(14), 200);
        assert_repetition_line(DETECTOR, &dashboard(15), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&v1(16)));
        assert_parity(&parity_input(&dashboard(17)));
    }
}
