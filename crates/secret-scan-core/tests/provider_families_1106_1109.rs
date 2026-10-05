//! Issue #1014 third-wave provider families (#1106 Pydantic Logfire, #1107
//! Square, #1108 Mapbox, #1109 Fly) through the public API with the full
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
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const LOWER_HEX: &[u8] = b"0123456789abcdef";

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

mod pydantic_logfire {
    use super::*;

    pub(super) const DETECTOR: &str = "pydantic-logfire-token";
    const TYPE: &str = "pydantic_logfire_token";

    fn org(seed: usize) -> String {
        [8, 4, 4, 4, 12]
            .iter()
            .enumerate()
            .map(|(i, &len)| filler(LOWER_HEX, len, seed + i))
            .collect::<Vec<_>>()
            .join("-")
    }

    pub(super) fn v1(region: &str, len: usize, seed: usize) -> String {
        format!("pylf_v1_{region}_{}", filler(ALNUM, len, seed))
    }

    pub(super) fn v2(region: &str, len: usize, seed: usize) -> String {
        format!(
            "pylf_v2_{region}_{}_{}",
            org(seed),
            filler(ALNUM, len, seed + 7)
        )
    }

    #[test]
    fn every_role_and_region_wins_every_context_as_the_sole_finding() {
        for region in ["us", "eu", "ap", "stagingus"] {
            assert_sole_provider_finding(DETECTOR, TYPE, &v1(region, 44, 1));
        }
        assert_sole_provider_finding(DETECTOR, TYPE, &v2("us", 44, 2));
        assert_sole_provider_finding(
            DETECTOR,
            TYPE,
            &v2("eu", 44, 3).replace(&org(3), &org(3).to_uppercase()),
        );
        let write = v1("us", 44, 4);
        for input in [
            format!("LOGFIRE_TOKEN={write}\n"),
            format!("LOGFIRE_READ_TOKEN={write}\n"),
            format!("LOGFIRE_API_KEY={write}\n"),
            format!("PYDANTIC_AI_GATEWAY_API_KEY={write}\n"),
            format!("logfire.configure(token=\"{write}\")\n"),
            format!(
                "curl -H 'Authorization: Bearer {write}' https://logfire-us.example/v1/traces\n"
            ),
            format!(
                "{{\"mcpServers\":{{\"logfire\":{{\"env\":{{\"LOGFIRE_READ_TOKEN\":\"{write}\"}}}}}}}}\n"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, TYPE, &write);
        }
    }

    #[test]
    fn the_body_floor_is_20_and_there_is_no_cap() {
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 20, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 21, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 80, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v2("us", 20, 6));
        assert_twins_unclaimed(
            DETECTOR,
            &[v1("us", 19, 5), v1("us", 1, 5), v2("us", 19, 6)],
        );
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 44, 7);
        let mut wrong_group = org(8);
        wrong_group.replace_range(0..1, "");
        let mut dashed = body.clone();
        dashed.replace_range(22..23, "-");
        let mut underscored = body.clone();
        underscored.replace_range(22..23, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("pylf_v_us_{body}"),
                format!("pylf_v1__{body}"),
                format!("pylf_v1_US_{body}"),
                format!("pylf_v1_u_{body}"),
                format!("pylf_v1_{}_{body}", "a".repeat(17)),
                format!("pylf_v1234_us_{body}"),
                format!("PYLF_v1_us_{body}"),
                format!("pylf_v1-us_{body}"),
                format!("pylf_v1_us-{body}"),
                format!("pylf_v2_us_{wrong_group}_{body}"),
                format!("pylf_v1_us_{dashed}"),
                format!("pylf_v1_us_{underscored}"),
                format!("xpylf_v1_us_{body}"),
                format!("_pylf_v1_us_{body}"),
                format!("-pylf_v1_us_{body}"),
                format!("pylf_v1_us_{body}_"),
                format!("pylf_v1_us_{body}-x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "pylf_v1_us_... pylf_v1_us_xxx pylf_v1_us_token1 pylf_v1_us_fake\n".to_owned(),
            "the masked pylf_v1_us_0kYhc**** form\n".to_owned(),
            "default scrubbing pattern pylf_v\\d+_ in config text\n".to_owned(),
            "LOGFIRE_TOKEN=${LOGFIRE_TOKEN}\n".to_owned(),
            "https://logfire-us.pydantic.dev/\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"pylf_v".repeat(10_000));
        assert_unclaimed(DETECTOR, &"pylf_v1_us_".repeat(5_000));
        assert_unclaimed(DETECTOR, &v1("us", 44, 9).repeat(200));
        assert_repetition_line(DETECTOR, &v1("us", 44, 9), 200);
        assert_repetition_line(DETECTOR, &v2("eu", 44, 10), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&v1("us", 44, 11)));
        assert_parity(&parity_input(&v2("eu", 30, 12)));
    }
}

mod square {
    use super::*;

    pub(super) const DETECTOR: &str = "square-token";
    const ACCESS: &str = "square_access_token";
    const SECRET: &str = "square_oauth_application_secret";

    pub(super) fn token(prefix: &str, len: usize, seed: usize) -> String {
        format!("{prefix}{}", filler(B64URL, len, seed))
    }

    #[test]
    fn every_stable_form_wins_every_context_as_the_sole_finding() {
        assert_sole_provider_finding(DETECTOR, ACCESS, &token("EAAA", 60, 1));
        assert_sole_provider_finding(DETECTOR, SECRET, &token("sq0csp-", 43, 2));
        assert_sole_provider_finding(DETECTOR, SECRET, &token("sq0csp-", 44, 3));
        assert_sole_provider_finding(DETECTOR, SECRET, &token("sandbox-sq0csb-", 43, 4));
        // The body alphabet includes `-` and `_`.
        let access = token("EAAA", 60, 5);
        assert!(access.contains('-') || access.contains('_'));
        for input in [
            format!("SQUARE_ACCESS_TOKEN={access}\n"),
            format!("const client = new Client({{ accessToken: \"{access}\" }});\n"),
            format!(
                "curl -H 'Authorization: Bearer {access}' https://connect.example.test/v2/payments\n"
            ),
            format!(
                "{{\"mcpServers\":{{\"square\":{{\"env\":{{\"SQUARE_ACCESS_TOKEN\":\"{access}\"}}}}}}}}\n"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, ACCESS, &access);
        }
        let secret = token("sq0csp-", 44, 6);
        for input in [
            format!("client_secret={secret}\n"),
            format!(
                "{{\"client_id\": \"sq0idp-{}\", \"client_secret\": \"{secret}\"}}\n",
                filler(B64URL, 22, 7)
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, SECRET, &secret);
        }
    }

    /// Ruling Q8 on #1014 is open: the provider disclaims length validation and
    /// its own examples disagree (64 vs 63 characters, 43 vs 44), so the stable
    /// widths are claimed and every conflicting shape is a bounded false
    /// negative of this detector (it stays with generic context).
    #[test]
    fn conflicting_widths_and_shapes_are_a_bounded_false_negative_until_ruling_q8() {
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token("EAAA", 59, 8),
                token("EAAA", 61, 9),
                // The 63-character access token and the 64-character refresh
                // token of the `ObtainToken` reference.
                token("EAAl", 59, 10),
                token("EQAA", 60, 11),
                token("EAAB", 60, 12),
                token("sq0csp-", 42, 13),
                token("sq0csp-", 45, 14),
                token("sandbox-sq0csb-", 42, 15),
                token("sandbox-sq0csb-", 44, 16),
            ],
        );
    }

    #[test]
    fn twins_are_unclaimed() {
        let access = token("EAAA", 60, 17);
        let secret = token("sq0csp-", 43, 18);
        let body = filler(B64URL, 60, 19);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("eaaa{body}"),
                format!("EAAA{}+{}", &body[..30], &body[31..]),
                format!("EAAA{}={}", &body[..30], &body[31..]),
                format!("EAAA{}/{}", &body[..30], &body[31..]),
                format!("SQ0CSP-{}", filler(B64URL, 43, 20)),
                format!("sq0csp_{}", filler(B64URL, 43, 20)),
                token("sq0idp-", 22, 21),
                token("sq0ids-", 22, 21),
                token("sq0idb-", 22, 21),
                token("sandbox-sq0idb-", 22, 21),
                token("sq0atp-", 22, 22),
                token("sq0cgb-", 22, 23),
                token("sandbox-sq0csp-", 43, 24),
                format!("x{access}"),
                format!("_{access}"),
                format!("-{access}"),
                format!("{access}_"),
                format!("{access}-x"),
                format!("{access}0"),
                format!("x{secret}"),
                format!("{secret}_x"),
                format!("{secret}-x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_and_lookalikes_are_unclaimed() {
        let digest = filler(LOWER_HEX, 64, 25);
        let padding = format!("iVBORw0KGgoAAAANSUhEUgAAAEAAAAB{}\n", "A".repeat(80));
        for input in [
            format!("sha256:eaaa{}\n", &digest[..60]),
            format!("sha256:{digest}\n"),
            padding,
            format!("EAAAAAAA{}\n", "A".repeat(100)),
            "EAAA-your-access-token sq0csp-xxxxxxxx\n".to_owned(),
            "SQUARE_ACCESS_TOKEN=${SQUARE_ACCESS_TOKEN}\n".to_owned(),
            format!("SQUARE_ACCESS_TOKEN=EAAA{}\n", "*".repeat(60)),
            "the sq0csp- prefix and the EAAA prefix\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_jwt_format_square_token_stays_with_the_jwt_detector() {
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            filler(B64URL, 30, 26),
            filler(B64URL, 60, 27),
            filler(B64URL, 43, 28)
        );
        let (_, findings) = whole_input(&format!("SQUARE_ACCESS_TOKEN={jwt}\n"));
        assert!(detector_findings(&findings, DETECTOR).is_empty());
        assert_sole_finding_in(&format!("x {jwt}\n"), "jwt", "jwt", &jwt);
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"EAAA".repeat(10_000));
        assert_unclaimed(DETECTOR, &"sq0csp-".repeat(10_000));
        assert_unclaimed(DETECTOR, &"sandbox-sq0csb-".repeat(5_000));
        assert_unclaimed(DETECTOR, &token("EAAA", 60, 29).repeat(200));
        assert_repetition_line(DETECTOR, &token("EAAA", 60, 29), 200);
        assert_repetition_line(DETECTOR, &token("sq0csp-", 44, 30), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&token("EAAA", 60, 31)));
        assert_parity(&parity_input(&token("sq0csp-", 43, 32)));
        assert_parity(&parity_input(&token("sandbox-sq0csb-", 43, 33)));
    }
}

mod mapbox {
    use super::*;

    pub(super) const DETECTOR: &str = "mapbox-token";
    const TYPE: &str = "mapbox_secret_access_token";

    pub(super) fn token(
        header: &str,
        payload_tail: usize,
        signature: usize,
        seed: usize,
    ) -> String {
        format!(
            "{header}.eyJ{}.{}",
            filler(B64URL, payload_tail, seed),
            filler(B64URL, signature, seed + 1)
        )
    }

    fn jwt(seed: usize) -> String {
        format!(
            "eyJ{}.eyJ{}.{}",
            filler(B64URL, 30, seed),
            filler(B64URL, 60, seed + 1),
            filler(B64URL, 43, seed + 2)
        )
    }

    #[test]
    fn secret_tokens_win_every_context_as_the_sole_finding_at_every_payload_width() {
        for (seed, payload_tail) in [20, 21, 55, 60, 100, 250].into_iter().enumerate() {
            assert_sole_provider_finding(DETECTOR, TYPE, &token("sk", payload_tail, 22, seed));
        }
        let token = token("sk", 60, 22, 7);
        assert!(token.contains('-') || token.contains('_'));
        for input in [
            format!("MAPBOX_SECRET_TOKEN={token}\n"),
            format!("SK_MAPBOX={token}\n"),
            format!("MAPBOX_DOWNLOADS_TOKEN={token}\n"),
            format!("//api.mapbox.example/downloads/v2/:_authToken={token}\n"),
            format!("systemProp.mapboxAccessToken={token}\n"),
            format!("{{\"token\": \"{token}\"}}\n"),
            format!(
                "curl -H 'Authorization: Bearer {token}' https://api.mapbox.example/styles/v1\n"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, TYPE, &token);
        }
    }

    /// The `jwt` detector cannot start inside `sk.eyJ...`: the byte before the
    /// payload's `eyJ` is a `.`, which it treats as part of a wider token. The
    /// provider type is the only finding, whole-input and incremental, and the
    /// same JWT without an `sk.` header stays a plain `jwt` finding.
    #[test]
    fn a_secret_token_is_one_provider_span_with_no_jwt_finding() {
        let token = token("sk", 60, 22, 8);
        for input in [
            format!("{token}\n"),
            format!("Authorization: Bearer {token}\n"),
            format!("MAPBOX_SECRET_TOKEN={token}\n"),
            format!("# \u{d0a4}\u{1f511} 키\n{token}\n"),
        ] {
            let (_, findings) = whole_input(&input);
            assert!(
                findings.iter().all(|f| f.detector() != "jwt"),
                "{input}: {findings:?}"
            );
            assert_sole_finding_in(&input, DETECTOR, TYPE, &token);
            assert_parity(&input);
            let lines: Vec<&str> = input.split_inclusive('\n').collect();
            let session = run(&lines);
            assert!(
                session.findings().iter().all(|f| f.detector() != "jwt"),
                "{input}"
            );
        }
        // A signature that itself starts with `eyJ` and is followed by more
        // base64url segments is still claimed only up to its 22 bytes, with no
        // `jwt` finding over any of it.
        let tricky = format!(
            "sk.eyJ{}.eyJ{}.{}",
            filler(B64URL, 30, 9),
            filler(B64URL, 19, 10),
            filler(B64URL, 20, 11)
        );
        let claimed = &tricky[..tricky.len() - 21];
        let (_, findings) = whole_input(&tricky);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].detector(), DETECTOR);
        assert_eq!(
            (findings[0].range().start(), findings[0].range().end()),
            (0, claimed.len())
        );
        assert_parity(&format!("{tricky}\n"));
        // The same JWT without a header is a plain `jwt` finding, and a
        // two-segment `eyJ...` value is neither.
        let bare = jwt(12);
        assert_sole_finding_in(&format!("x {bare}\n"), "jwt", "jwt", &bare);
        assert_parity(&format!("x {bare}\n"));
        let two_segments = format!("eyJ{}.{}", filler(B64URL, 60, 13), filler(B64URL, 22, 14));
        let (_, findings) = whole_input(&format!("x {two_segments}\n"));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_secret_token_glued_to_a_jwt_shape_is_not_claimed_as_a_fourth_segment() {
        let (_, findings) = whole_input(&format!("sk.{}\n", jwt(15)));
        assert!(
            detector_findings(&findings, DETECTOR).is_empty(),
            "{findings:?}"
        );
    }

    #[test]
    fn public_and_temporary_tokens_are_never_claimed() {
        // `pk.` is public by design; `tk.` stays unclaimed until ruling Q9 on
        // #1014 (a bounded false negative of this detector).
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token("pk", 60, 22, 16),
                token("tk", 60, 22, 17),
                token("pk", 20, 22, 18),
            ],
        );
    }

    #[test]
    fn the_payload_floor_is_20_and_the_signature_is_exactly_22() {
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token("sk", 19, 22, 19),
                token("sk", 1, 22, 19),
                token("sk", 60, 21, 20),
                token("sk", 60, 23, 20),
                token("sk", 60, 0, 20),
            ],
        );
    }

    #[test]
    fn twins_are_unclaimed() {
        let payload = filler(B64URL, 60, 21);
        let signature = filler(B64URL, 22, 22);
        let base = token("sk", 60, 22, 21);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token("SK", 60, 22, 21),
                format!("sk_eyJ{payload}.{signature}"),
                format!("sk-eyJ{payload}.{signature}"),
                format!("sk.eyI{payload}.{signature}"),
                format!("sk.abc{payload}.{signature}"),
                format!("sk.eyJ{payload}{signature}"),
                format!("sk.eyJ{payload}"),
                format!("sk.eyJ{payload}.{signature}_"),
                format!("sk.eyJ{payload}.{signature}-x"),
                format!("sk.eyJ{payload}..{signature}"),
                format!("task.eyJ{payload}.{signature}"),
                format!("desk.eyJ{payload}.{signature}"),
                format!("x{base}"),
                format!("_{base}"),
                format!("-{base}"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            format!("{}\n", jwt(23)),
            format!("MAPBOX_ACCESS_TOKEN={}\n", token("pk", 60, 22, 24)),
            "mapbox://styles/user/ckabc123 user.abc123 mapbox.mapbox-streets-v8\n".to_owned(),
            "an sk. prefix and a task.list\n".to_owned(),
            "MAPBOX_SECRET_TOKEN=${MAPBOX_SECRET_TOKEN}\n".to_owned(),
            "MAPBOX_SECRET_TOKEN=sk.eyJ****.****\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"sk.eyJ".repeat(10_000));
        assert_unclaimed(DETECTOR, &format!("sk.eyJ{}", filler(B64URL, 100_000, 25)));
        assert_unclaimed(DETECTOR, &token("sk", 60, 22, 26).repeat(100));
        assert_repetition_line(DETECTOR, &token("sk", 60, 22, 26), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&token("sk", 60, 22, 27)));
        assert_parity(&parity_input(&token("sk", 20, 22, 28)));
    }
}
