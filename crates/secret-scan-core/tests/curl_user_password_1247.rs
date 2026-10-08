//! The password of a `curl` credential argument
//! (redact-secret#1247,
//! `decision-read-the-curl-user-password-argument-as-a-contextual-secret`),
//! driven through the public default pipeline and the incremental session.
//!
//! Every value is synthetic and assembled at run time from a deterministic
//! filler; no `-u user:value` text is committed (the flag is joined at run
//! time).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, DefaultPolicy, DetectorRegistry, scan};
use support::{
    as_chunks, assert_clean, assert_value, assert_values_with, char_boundary_partitions,
    findings_with_parity, run, single_byte_partition, whole_input,
};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A deterministic synthetic value of `len` bytes.
fn value(len: usize, seed: usize) -> String {
    let chars: Vec<char> = ALNUM.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 11 + index * index * 3) % chars.len()])
        .collect()
}

fn user_flag() -> String {
    ["-", "u"].concat()
}

const HOST: &str = "https://api.example.test/v1/items";

/// Asserts that the incremental session, split at every character boundary,
/// in one-character chunks and in one-byte chunks, equals the whole input.
fn assert_every_partition(input: &str) {
    let (text, findings) = whole_input(input);
    for parts in char_boundary_partitions(input) {
        let session = run(&parts);
        assert_eq!(
            session.text(),
            text,
            "{input:?}: split at {}",
            parts[0].len()
        );
        assert_eq!(
            session.findings(),
            findings,
            "{input:?}: split at {}",
            parts[0].len()
        );
    }
    let bytes = single_byte_partition(input);
    let session = run(&as_chunks(&bytes));
    assert_eq!(session.text(), text, "{input:?}: 1-byte text");
    assert_eq!(session.findings(), findings, "{input:?}: 1-byte findings");
}

#[test]
fn every_spelling_reads_the_password_only() {
    let secret = value(20, 1);
    let u = user_flag();
    // The short option that closes a cluster of argument-less ones.
    let short = "u".to_owned();
    for command in [
        format!("curl {u} svc:{secret} {HOST}\n"),
        format!("curl -U svc:{secret} {HOST}\n"),
        format!("curl --user svc:{secret} {HOST}\n"),
        format!("curl --user=svc:{secret} {HOST}\n"),
        format!("curl --proxy-user svc:{secret} {HOST}\n"),
        format!("curl --proxy-user=svc:{secret} {HOST}\n"),
        format!("curl {u}svc:{secret} {HOST}\n"),
        format!("curl -sSfLk{short} svc:{secret} {HOST}\n"),
        format!("curl -sS{short}svc:{secret} {HOST}\n"),
        format!("curl --digest {u} svc:{secret} {HOST}\n"),
        format!("curl {u} svc:{secret} --digest {HOST}\n"),
        format!("curl {HOST} -X GET -H 'Accept: a/b' {u} svc:{secret}\n"),
        format!("curl {u} :{secret} {HOST}\n"),
        format!("curl {u} 'svc:{secret}' {HOST}\n"),
        format!("curl {u} \"svc:{secret}\" {HOST}\n"),
        format!("curl --user=\"svc:{secret}\" {HOST}\n"),
        format!("curl {u} svc:\"{secret}\" {HOST}\n"),
        format!("curl {u} \"svc\":{secret} {HOST}\n"),
        format!("curl {u} svc:{secret}"),
        format!("curl\t{u}\tsvc:{secret}\t{HOST}\r\n"),
    ] {
        assert_value(&command, &secret);
    }
}

#[test]
fn options_that_only_look_like_the_credential_flag_are_not_read() {
    let secret = value(20, 2);
    let u = user_flag();
    for command in [
        format!("curl --user-agent \"svc/1.0:{secret}\" {HOST}\n"),
        format!("curl -A \"svc/1.0:{secret}\" {HOST}\n"),
        format!("curl -T ./report:{secret}.txt {HOST}/upload\n"),
        format!("curl -H \"X-User: svc:{secret}\" {HOST}\n"),
        format!("curl -d \"u=svc:{secret}\" {HOST}\n"),
        format!("curl --us svc:{secret} {HOST}\n"),
        format!("curl --users svc:{secret} {HOST}\n"),
        format!("curl -x{u} svc:{secret} {HOST}\n"),
        format!("curl -{u}x svc:{secret} {HOST}\n"),
        format!("curl \"{u}\" svc:{secret} {HOST}\n"),
        // The password slot is a separate word, not part of the argument.
        format!("curl {u} svc : {secret} {HOST}\n"),
        format!("curl {u} svc {HOST}\n"),
    ] {
        // `-ux` is the attached spelling with the user `x`, which has no
        // colon in `-ux` itself: the next word is an ordinary argument.
        assert_clean(&command);
    }
}

#[test]
fn the_command_word_is_curl_and_nothing_longer() {
    let secret = value(20, 3);
    let u = user_flag();
    for prefix in [
        "",
        "sudo ",
        "time ",
        "LC_ALL=C ",
        "env -i ",
        "$(",
        "`",
        "( ",
        "{ ",
        "@",
        "bash -c \"",
        "sh -c '",
        "X=",
        "echo hi; ",
        "echo hi && ",
        "echo hi | ",
    ] {
        assert_value(&format!("{prefix}curl {u} svc:{secret} {HOST}\n"), &secret);
    }
    for word in [
        "/usr/bin/curl",
        "./curl",
        "C:\\tools\\curl",
        "curl.exe",
        "/opt/curl/bin/curl.exe",
    ] {
        assert_value(&format!("{word} {u} svc:{secret} {HOST}\n"), &secret);
    }
    for word in [
        "mycurl",
        "libcurl",
        "curl-config",
        "curlimages/curl:8.10.1",
        "curl_cli",
        "curls",
        "xcurl.exe",
        "curl.exe2",
        "-curl",
        "~curl",
        ".curlrc",
    ] {
        assert_clean(&format!("{word} {u} svc:{secret} {HOST}\n"));
    }
    // The path before `curl` is bounded.
    let long_path = format!("{}/curl", "d".repeat(300));
    assert_clean(&format!("{long_path} {u} svc:{secret} {HOST}\n"));
}

#[test]
fn a_credential_flag_of_another_command_is_not_curls() {
    let secret = value(20, 4);
    let u = user_flag();
    for command in [
        format!("curl -sS {HOST}; docker run {u} svc:{secret} alpine\n"),
        format!("curl -sS {HOST} && sudo {u} svc:{secret} psql\n"),
        format!("curl -sS {HOST} | docker run {u} svc:{secret} alpine\n"),
        format!("curl -sS {HOST} & docker run {u} svc:{secret} alpine\n"),
        format!("curl -sS {HOST}\ndocker run {u} svc:{secret} alpine\n"),
        format!("curl -sS {HOST}\r\ndocker run {u} svc:{secret} alpine\r\n"),
        format!("echo {u} svc:{secret} | curl -sS {HOST}\n"),
        format!("docker run {u} svc:{secret} curlimages/curl:8.10.1 --version\n"),
        format!("The `{u} svc:{secret}` flag of the wrapper takes a pair.\n"),
        format!("curl -sS {HOST} \\\n  -H 'a: b'\ndocker run {u} svc:{secret} alpine\n"),
    ] {
        assert_clean(&command);
    }
}

#[test]
fn a_backslash_continuation_keeps_the_command_open() {
    let secret = value(20, 5);
    let u = user_flag();
    for command in [
        format!("curl -X GET \\\n  -H 'Accept: a/b' \\\n  {u} svc:{secret} \\\n  {HOST}\n"),
        format!("curl -X GET \\\r\n  {u} svc:{secret} \\\r\n  {HOST}\r\n"),
        format!("curl \\\n{u} svc:{secret} {HOST}\n"),
        format!("curl {u} \\\n  svc:{secret} {HOST}\n"),
        format!("curl --user \\\r\n  svc:{secret} {HOST}\r\n"),
        format!("curl {u} svc:{secret}\\\n {HOST}\n"),
    ] {
        assert_value(&command, &secret);
        assert_every_partition(&command);
    }
    // A backslash that is itself escaped does not continue the line.
    assert_clean(&format!("curl -sS {HOST} \\\\\n{u} svc:{secret} {HOST}\n"));
    // A continuation ends where the next line does not continue.
    assert_clean(&format!("curl -sS \\\n  {HOST}\n{u} svc:{secret} {HOST}\n"));
}

#[test]
fn quoting_and_escapes_follow_the_word_grammar() {
    let secret = value(20, 6);
    let u = user_flag();
    let spaced = format!("{} {}", value(8, 7), value(8, 8));
    let with_double = format!("{}\"{}", value(8, 9), value(8, 10));
    let with_single = format!("{}'{}", value(8, 11), value(8, 12));
    let escaped = format!("!{}\\${}\\!", value(6, 13), value(6, 14));
    let colons = format!("{}:{}", value(6, 15), value(6, 16));
    let at = format!("{}@{}", value(6, 17), value(6, 18));
    let percent = format!("{}%zz{}", value(6, 19), value(6, 20));
    let slash = format!("{}/{}", value(6, 21), value(6, 22));
    assert_value(&format!("curl {u} 'svc:{spaced}' {HOST}\n"), &spaced);
    assert_value(&format!("curl {u} \"svc:{spaced}\" {HOST}\n"), &spaced);
    assert_value(
        &format!("curl {u} 'svc:{with_double}' {HOST}\n"),
        &with_double,
    );
    assert_value(
        &format!("curl {u} \"svc:{with_single}\" {HOST}\n"),
        &with_single,
    );
    assert_value(&format!("curl {u} svc:{escaped} {HOST}\n"), &escaped);
    assert_value(&format!("curl {u} svc:{colons} {HOST}\n"), &colons);
    assert_value(&format!("curl {u} svc:{at} {HOST}\n"), &at);
    assert_value(&format!("curl {u} svc:{percent} {HOST}\n"), &percent);
    assert_value(&format!("curl {u} svc:{slash} {HOST}\n"), &slash);
    // `)` is a password byte: the substitution's closing parenthesis is
    // included (accepted over-redaction).
    assert_value(
        &format!("X=$(curl -s {u} svc:{secret})\n"),
        &format!("{secret})"),
    );
    // An escaped separator inside a quote does not end the argument.
    let ampersand = format!("{}&{}", value(6, 23), value(6, 24));
    assert_value(&format!("curl {u} 'svc:{ampersand}' {HOST}\n"), &ampersand);
    assert_value(&format!("curl {u} svc:{ampersand} {HOST}\n"), &value(6, 23));
    // The user is never claimed, whatever its shape.
    let findings = findings_with_parity(&format!(
        "curl {u} agent@example.test/token:{secret} {HOST}\n"
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn an_argument_without_a_known_end_or_a_password_is_silent() {
    let secret = value(20, 25);
    let u = user_flag();
    for command in [
        // No colon, an empty password, only a colon.
        format!("curl {u} svc {HOST}\n"),
        format!("curl {u} svc: {HOST}\n"),
        format!("curl {u} : {HOST}\n"),
        format!("curl --negotiate {u} : {HOST}\n"),
        format!("curl {u} \":\" {HOST}\n"),
        format!("curl {u} 'svc:' {HOST}\n"),
        format!("curl {u} svc:\"\" {HOST}\n"),
        format!("curl --user= {HOST}\n"),
        // An unterminated quote, at the end of a line or of the input.
        format!("curl {u} \"svc:{secret}\n"),
        format!("curl {u} \"svc:{secret}"),
        format!("curl {u} 'svc:{secret}\nnext line'\n"),
        // The option is the last word.
        format!("curl {HOST} {u}\n"),
        format!("curl {HOST} {u}"),
        format!("curl {HOST} {u} ; svc:{secret}\n"),
        // A command held inside another quoted string needs a second pass.
        format!("bash -c \"curl {u} \\\"svc:{secret}\\\" {HOST}\"\n"),
        format!("bash -c 'curl {u} \\'svc:{secret}\\' {HOST}'\n"),
    ] {
        assert_clean(&command);
    }
}

#[test]
fn the_password_bound_is_4096_bytes() {
    let u = user_flag();
    let at_bound = value(4_096, 26);
    assert_value(&format!("curl {u} svc:{at_bound} {HOST}\n"), &at_bound);
    let over_bound = value(4_097, 27);
    assert_clean(&format!("curl {u} svc:{over_bound} {HOST}\n"));
    assert_clean(&format!("curl {u} 'svc:{over_bound}' {HOST}\n"));
}

/// The findings of the synchronous pipeline only: these inputs are lines
/// longer than a streaming session's default token limit.
fn whole_input_findings(input: &str) -> Vec<redact_secret::Finding> {
    whole_input(input).1
}

#[test]
fn the_window_is_bounded() {
    let secret = value(20, 28);
    let u = user_flag();
    // An option well inside the window is read; one past 8192 bytes of
    // arguments after the curl word is another command's.
    let near = format!(
        "curl -H 'a: {}' {u} svc:{secret} {HOST}\n",
        "x".repeat(8_000)
    );
    let findings = whole_input_findings(&near);
    let start = near.find(&secret).unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].range().start(), start);
    let far = format!(
        "curl -H 'a: {}' {u} svc:{secret} {HOST}\n",
        "x".repeat(8_300)
    );
    assert!(whole_input_findings(&far).is_empty());
    // An argument that reaches the end of the window has no known end.
    let reaching = format!("curl -H 'a: {}' {u} svc:{secret}\n", "x".repeat(8_160));
    assert!(whole_input_findings(&reaching).is_empty());
}

#[test]
fn references_masks_and_placeholders_are_silent_but_weak_literals_are_not() {
    let u = user_flag();
    for placeholder in [
        "${CURL_PASS}",
        "$CURL_PASS",
        "%CURL_PASS%",
        "$(cat /run/secrets/pw)",
        "`pass show svc/api`",
        "<password>",
        "<your password>",
        "********",
        "xxxxxxxxxxxx",
        "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
        "YOUR_PASSWORD_HERE",
        "replace_me",
        "changeme",
        "example",
        "password",
        "secret",
        "changeit",
        "mysecretpassword",
        "{{ secrets.SVC_PASS }}",
        "${{ secrets.SVC_PASS }}",
        "{api_token}",
    ] {
        let quoted = placeholder.contains(' ') || placeholder.contains('`');
        let argument = if quoted {
            format!("\"svc:{placeholder}\"")
        } else {
            format!("svc:{placeholder}")
        };
        assert_clean(&format!("curl {u} {argument} {HOST}\n"));
        assert_clean(&format!("curl {u} 'svc:{placeholder}' {HOST}\n"));
    }
    assert_clean(&format!("curl {u} \"$CURL_USER:$CURL_PASS\" {HOST}\n"));
    assert_clean(&format!(
        "curl {u} \"${{CURL_USER}}:${{CURL_PASS}}\" {HOST}\n"
    ));
    // A weak value is still the password slot.
    for weak in ["admin", "pass", "test1234", "hunter2"] {
        assert_value(&format!("curl {u} svc:{weak} {HOST}\n"), weak);
    }
    // A reference only as part of the value stays read.
    let tail = value(12, 29);
    assert_value(
        &format!("curl {u} svc:changeme{tail} {HOST}\n"),
        &format!("changeme{tail}"),
    );
}

#[test]
fn the_url_userinfo_keeps_its_own_finding() {
    let secret = value(20, 30);
    let url_password = value(20, 31);
    let u = user_flag();
    let input = format!("curl {u} svc:{secret} https://other:{url_password}@api.example.test/v1\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert_eq!(findings[0].type_name(), "contextual_secret");
    assert_eq!(findings[1].type_name(), "connection_string_password");
    let first = input.find(&secret).unwrap();
    assert_eq!(
        (findings[0].range().start(), findings[0].range().end()),
        (first, first + secret.len())
    );
    let second = input.find(&url_password).unwrap();
    assert_eq!(
        (findings[1].range().start(), findings[1].range().end()),
        (second, second + url_password.len())
    );
}

#[test]
fn the_zendesk_literal_and_the_flag_reader_make_one_finding() {
    let token = value(40, 32);
    let u = user_flag();
    let input = format!("curl {HOST} {u} agent@example.test/token:{token}\n");
    assert_value(&input, &token);
    let input = format!("curl {u} \"agent@example.test/token:{token}\" {HOST}\n");
    assert_value(&input, &token);
}

#[test]
fn two_commands_and_two_credentials_are_two_findings_in_order() {
    let first = value(20, 33);
    let second = value(20, 34);
    let u = user_flag();
    let input = format!("curl {u} a:{first} {HOST} && curl --user b:{second} {HOST}\n");
    assert_values_with(&input, &[&first, &second], Confidence::High, Action::Redact);
    assert_every_partition(&input);
    // Every curl word of a run of curl words reads the same credential once.
    let input = format!("curl curl curl {u} a:{first} {HOST}\n");
    assert_value(&input, &first);
}

#[test]
fn offsets_are_utf8_bytes_whatever_precedes_the_span() {
    let secret = value(20, 35);
    let u = user_flag();
    let input = format!(
        "# \u{c11c}\u{be44}\u{c2a4} \u{d638}\u{cd9c}\ncurl {u} \u{c0ac}\u{c6a9}\u{c790}:{secret} {HOST}\n"
    );
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1);
    let start = input.find(&secret).unwrap();
    assert_eq!(
        (findings[0].range().start(), findings[0].range().end()),
        (start, start + secret.len())
    );
    assert_ne!(start, input[..start].chars().count());
    assert_every_partition(&input);
    // A multibyte password is read to its end; an escaped multibyte byte
    // stays inside the span.
    let wide = format!("{}\u{e9}\u{c0ac}{}", value(6, 36), value(6, 37));
    assert_value(&format!("curl {u} svc:{wide} {HOST}\n"), &wide);
    let escaped = format!("{}\\\u{c0ac}{}", value(6, 38), value(6, 39));
    assert_value(&format!("curl {u} svc:{escaped} {HOST}\n"), &escaped);
}

#[test]
fn every_split_point_gives_the_whole_input_result() {
    let short = "u".to_owned();
    let secret = value(20, 40);
    let spaced = format!("{} {}", value(8, 41), value(8, 42));
    let u = user_flag();
    for input in [
        format!("curl {u} svc:{secret} {HOST}\n"),
        format!("  sudo /usr/bin/curl.exe -sSfLk{short} \"svc:{secret}\" {HOST}\r\n"),
        format!("curl --user='svc:{spaced}' {HOST}\ntail\n"),
        format!(
            "curl {HOST} \\\n  -H 'a: b' \\\r\n  --proxy-user svc:{secret} \\\n  -o out\nrest\n"
        ),
        format!("curl {u} svc:{secret}"),
        format!("curl {u} \"svc:{secret}\n{u} a:b\n"),
        format!("curl -sS {HOST}; docker run {u} svc:{secret} alpine\n"),
        format!("x=$(curl {u} svc:{secret})\n"),
        format!("curl {u} svc:{secret} \\\r"),
        format!("curl {u} svc:{secret} \\\r\n{HOST}\r"),
        format!("curl {u} svc:{secret} \\\rx {HOST}\n"),
    ] {
        assert_every_partition(&input);
    }
}

#[test]
fn a_held_command_is_released_at_its_end_and_never_retracted() {
    let secret = value(20, 43);
    let u = user_flag();
    let input = format!("curl \\\n  {u} svc:{secret} \\\n  {HOST}\nafter\n");
    let mut session = redact_secret::IncrementalSanitizer::new(support::generous_limits()).unwrap();
    let mut released = String::new();
    let mut findings = Vec::new();
    for (index, chunk) in input.split_inclusive('\n').enumerate() {
        let result = session.append(chunk).unwrap();
        released.push_str(result.text());
        findings.extend(result.findings().to_vec());
        match index {
            // The command continues: nothing of it is released yet.
            0 | 1 => assert!(released.is_empty(), "{index}: {released:?}"),
            // Its last line closes it: released whole, already redacted.
            2 => {
                assert!(released.contains("<SECRET_1>"), "{released:?}");
                assert!(!released.contains(&secret), "{released:?}");
            }
            _ => {}
        }
    }
    let result = session.finalize().unwrap();
    released.push_str(result.text());
    findings.extend(result.findings().to_vec());
    assert_eq!(findings.len(), 1);
    let (text, whole) = whole_input(&input);
    assert_eq!(released, text);
    assert_eq!(findings, whole);
}

#[test]
fn the_common_profile_reads_the_same_password() {
    let secret = value(20, 44);
    let u = user_flag();
    let registry = DetectorRegistry::with_common_built_in([]).unwrap();
    let input = format!("curl {u} svc:{secret} {HOST}\n");
    let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    let start = input.find(&secret).unwrap();
    assert_eq!(
        (findings[0].range().start(), findings[0].range().end()),
        (start, start + secret.len())
    );
    assert_eq!(findings[0].type_name(), "contextual_secret");
    assert_eq!(findings[0].confidence(), Confidence::High);
    assert_eq!(findings[0].action(), Action::Redact);
}

#[test]
fn a_run_of_curl_words_does_not_multiply_the_work() {
    // Many curl words share one window: the scan reads it once. The result
    // is the one credential, however many words precede it.
    let secret = value(20, 45);
    let u = user_flag();
    let words = "curl ".repeat(20_000);
    let input = format!("{words}{u} svc:{secret} {HOST}\n");
    let findings = whole_input_findings(&input);
    assert_eq!(findings.len(), 1, "{}", findings.len());
    let start = input.find(&secret).unwrap();
    assert_eq!(findings[0].range().start(), start);
    let quoted = "\"curl ".repeat(10_000);
    let input = format!("{quoted}{u} svc:{secret} {HOST}\n");
    assert!(whole_input_findings(&input).len() <= 1);
}

#[test]
fn generated_command_lines_give_the_whole_input_result_at_every_partition() {
    // Deterministic pseudo-random command lines built from the pieces the
    // reader reacts to; the secret is a run-time filler.
    let secret = value(16, 46);
    let u = user_flag();
    let pieces: Vec<String> = vec![
        "curl ".into(),
        "curl.exe ".into(),
        "/usr/bin/curl ".into(),
        format!("{u} svc:{secret} "),
        format!("--user=\"svc:{secret}\" "),
        format!("--proxy-user 'svc:{secret}' "),
        format!("-sSfLku svc:{secret} "),
        format!("{u} \"svc:{secret}"),
        "-H 'a: b' ".into(),
        "https://api.example.test/v1 ".into(),
        "\"".into(),
        "'".into(),
        "\\".into(),
        "\\\n".into(),
        "\\\r\n".into(),
        "\\\r".into(),
        "\r".into(),
        "\n".into(),
        "\r\n".into(),
        ";".into(),
        "&&".into(),
        "|".into(),
        " ".into(),
        "\t".into(),
        "$(".into(),
        ")".into(),
        "@".into(),
        "\u{e9}".into(),
        "\u{65e5}".into(),
        "docker run ".into(),
        "echo ".into(),
    ];
    let mut state: u64 = 0xC0DE_1247_0000_0001;
    let mut next = |bound: usize| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(state >> 33).unwrap() % bound
    };
    let mut read = 0usize;
    for round in 0..300 {
        let length = 1 + next(18);
        let mut input: String = (0..length)
            .map(|_| pieces[next(pieces.len())].as_str())
            .collect();
        if round % 2 == 0 {
            input.insert_str(0, "curl ");
        }
        if !whole_input(&input).1.is_empty() {
            read += 1;
        }
        assert_every_partition(&input);
    }
    assert!(read > 30, "the generator must exercise real reads: {read}");
}
