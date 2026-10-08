//! The Zendesk API-token credential string `{email}/token:{api_token}`
//! (redact-secret#1230, Group E `zendesk:api-token`), driven through the public
//! default pipeline.
//!
//! credential-evidence Case `zendesk-api-token-basic-credential-token-part`
//! flags the part after `/token:` of an email-address-and-token credential
//! string, the token only: the email, the `/token` separator and any quote are
//! outside the span. Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence};
use support::{assert_clean, assert_value, assert_values_with, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &str = "0123456789abcdef";

fn value(alphabet: &str, len: usize, seed: usize) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 11 + index * index * 3) % chars.len()])
        .collect()
}

fn shapes() -> Vec<String> {
    vec![
        value(HEX, 32, 1),
        value(ALNUM, 64, 2),
        value(&format!("{ALNUM}-_"), 40, 3),
        "qmxtvbnlkrwzpdsh".to_owned(),
        format!("{}-{}", value(ALNUM, 18, 4), value(ALNUM, 18, 5)),
        format!(
            "{}_{}.{}",
            value(ALNUM, 12, 6),
            value(ALNUM, 12, 7),
            value(ALNUM, 12, 8)
        ),
        value(ALNUM, 40, 9),
    ]
}

const EMAILS: &[&str] = &[
    "agent@example.test",
    "agent+support@example.test",
    "first.last@help.example.test",
    "AGENT@EXAMPLE.TEST",
    "a_b-c%d@sub.domain.example.org",
];

#[test]
fn the_token_after_the_separator_is_read_exactly_in_json_and_environment_values() {
    for email in EMAILS {
        for token in shapes() {
            // A JSON member, pretty-printed or compact, last or not.
            assert_value(
                &format!(
                    "{{\n  \"zendesk\": {{\n    \"credentials\": \"{email}/token:{token}\"\n  }}\n}}\n"
                ),
                &token,
            );
            assert_value(
                &format!(
                    "{{\"credentials\":\"{email}/token:{token}\",\"subdomain\":\"example\"}}\n"
                ),
                &token,
            );
            // An environment assignment: plain, quoted, exported, CRLF, end of input.
            assert_value(
                &format!("ZENDESK_BASIC_CREDENTIALS={email}/token:{token}\n"),
                &token,
            );
            assert_value(
                &format!("ZENDESK_BASIC_CREDENTIALS=\"{email}/token:{token}\"\n"),
                &token,
            );
            assert_value(
                &format!("export ZENDESK_AUTH='{email}/token:{token}'\r\n"),
                &token,
            );
            assert_value(
                &format!("ZENDESK_BASIC_CREDENTIALS={email}/token:{token}"),
                &token,
            );
            assert_value(
                &format!("ZENDESK_BASIC_CREDENTIALS={email}/token:{token}  \t\n"),
                &token,
            );
            // Not a named slot at all: the literal `/token:` is the anchor.
            assert_value(
                &format!("{{\"auth\": \"{email}/token:{token}\"}}\n"),
                &token,
            );
            assert_value(
                &format!("note: use {email}/token:{token} for the API\n"),
                &token,
            );
        }
    }
}

#[test]
fn context_does_not_move_the_span() {
    let token = value(ALNUM, 40, 20);
    assert_value(
        &format!("로그: 설정\nZENDESK_BASIC_CREDENTIALS=agent@example.test/token:{token}\n끝\n"),
        &token,
    );
    let big = "configuration line of ordinary words\n".repeat(2_000);
    assert_value(
        &format!("{big}ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:{token}\n"),
        &token,
    );
    // Two credential strings, and a same-shape public neighbour.
    let second = value(ALNUM, 40, 21);
    assert_values_with(
        &format!(
            "A=agent@example.test/token:{token}\nB=other@example.test/token:{second}\nsubdomain=example-subdomain\n"
        ),
        &[&token, &second],
        Confidence::High,
        Action::Redact,
    );
    // A neighbouring secret under its own name is a separate finding.
    let password = value(ALNUM, 40, 22);
    assert_values_with(
        &format!(
            "ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:{token}\npassword={password}\n"
        ),
        &[&token, &password],
        Confidence::High,
        Action::Redact,
    );
}

#[test]
fn the_token_wins_over_the_whole_string_reading_in_the_redacted_output() {
    let token = value(ALNUM, 40, 30);
    for input in [
        format!("ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:{token}\n"),
        format!("{{\"credentials\": \"agent@example.test/token:{token}\"}}\n"),
        format!("ZENDESK_API_TOKEN=agent@example.test/token:{token}\n"),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        let range = findings[0].range();
        let start = input.find(&token).unwrap();
        assert_eq!(
            (range.start(), range.end()),
            (start, start + token.len()),
            "{input:?}"
        );
        assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
        let (text, _) = support::whole_input(&input);
        assert!(!text.contains(&token), "{text:?}");
        // The email is an identifier the Case leaves outside the span.
        assert!(text.contains("agent@example.test/token:"), "{text:?}");
    }
}

#[test]
fn masked_references_templates_and_placeholder_tokens_are_silent() {
    for placeholder in [
        "********",
        "${ZENDESK_API_TOKEN}",
        "$ZENDESK_API_TOKEN",
        "{{ secrets.ZENDESK_API_TOKEN }}",
        "{api_token}",
        "<api_token>",
        "<your api token>",
        "YOUR_API_TOKEN",
        "xxxxxxxxxxxxxxxx",
        "",
    ] {
        for email in ["agent@example.test", "AGENT+x@help.example.test"] {
            assert_clean(&format!(
                "ZENDESK_BASIC_CREDENTIALS={email}/token:{placeholder}\n"
            ));
            assert_clean(&format!(
                "{{\"credentials\": \"{email}/token:{placeholder}\"}}\n"
            ));
        }
    }
    // Not an email on the left, no colon, no token, an email alone.
    assert_clean(
        "curl https://example-subdomain.zendesk.example.test/api/v2/users.json -u {email_address}/token:{api_token}\n",
    );
    assert_clean("ZENDESK_BASIC_CREDENTIALS=agent@example.test/token\n");
    assert_clean("ZENDESK_BASIC_CREDENTIALS=agent@example.test\n");
    assert_clean("{\"subdomain\": \"example-subdomain\", \"email\": \"agent@example.test\"}\n");
    assert_clean(
        "Zendesk calls the part after /token: the API token, and the part before it the email address.\n",
    );
}

#[test]
fn a_string_inside_an_enclosing_json_string_ends_at_its_escape() {
    // The credential string inside a JSON string, as a fixture file or a log
    // field holds it: the escaped line break or quote is not part of the token.
    let token = value(ALNUM, 40, 60);
    for tail in ["\\n\",\n", "\\\"}\\n\"\n", "\\\"\n"] {
        assert_value(
            &format!(
                "  \"text\": \"ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:{token}{tail}"
            ),
            &token,
        );
    }
    for tail in ["\\n\",\n", "\\\"\n"] {
        assert_clean(&format!(
            "  \"text\": \"ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:********{tail}"
        ));
    }
}

#[test]
fn a_left_side_that_is_not_an_email_address_is_not_read() {
    let token = value(ALNUM, 40, 40);
    for left in [
        "agent",
        "agent@",
        "@example.test",
        "agent@example",
        "agent@example.t",
    ] {
        let findings = findings_with_parity(&format!("NOTE_VALUE={left}/token:{token}\n"));
        assert!(findings.is_empty(), "{left}: {findings:?}");
    }
}

#[test]
fn the_basic_flag_form_is_one_finding_on_the_token() {
    // The `/token:` literal and the curl credential-argument reader (issue
    // #1247) read the same bytes: one finding, the token only. The flag is
    // joined at run time.
    let token = value(ALNUM, 40, 50);
    let flag = ["-", "u"].concat();
    for input in [
        format!(
            "curl https://example-subdomain.zendesk.example.test/api/v2/users.json {flag} \"agent@example.test/token:{token}\"\n"
        ),
        format!(
            "curl {flag} 'agent@example.test/token:{token}' https://example-subdomain.zendesk.example.test/api/v2/users.json\n"
        ),
    ] {
        assert_value(&input, &token);
    }
    // A plain username and password is the same carrier: the password only.
    assert_value(
        &format!(
            "curl {flag} agent:{token} https://example-subdomain.zendesk.example.test/api/v2/users.json\n"
        ),
        &token,
    );
}
