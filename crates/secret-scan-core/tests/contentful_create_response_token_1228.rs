//! The Contentful create-token response member `token` (redact-secret#1228,
//! Group C `contentful:cma-personal-access-token`), driven through the public
//! default pipeline.
//!
//! credential-evidence Case
//! `contentful-cma-personal-access-token-bearer-header-and-create-response-member`
//! flags the `token` member of the create-token response, whose documented
//! example carries `sys` (with `redactedValue`) and the request's `scopes`. A
//! bare `token` stays unmatched by the accepted rule (#1241), so the member is
//! read only as a quoted JSON member beside a `sys` or `scopes` member within
//! the sibling window. A response that is only `{"token": ...}` or only a `name`
//! beside it is not read: a recorded policy limit, not a vocabulary change.
//! Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence};
use support::{assert_clean, assert_value, assert_values_with};

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
        value(HEX, 64, 1),
        ["CFPAT", "-", value(ALNUM, 43, 2).as_str()].concat(),
        value(ALNUM, 40, 3),
        format!("{}-{}", value(ALNUM, 20, 4), value(ALNUM, 20, 5)),
        format!(
            "{}.{}_{}",
            value(ALNUM, 12, 6),
            value(ALNUM, 12, 7),
            value(ALNUM, 12, 8)
        ),
        value(ALNUM, 150, 9),
        value(ALNUM, 16, 10),
    ]
}

#[test]
fn the_token_member_is_read_beside_the_documented_siblings() {
    for token in shapes() {
        // Pretty, with sys and scopes, token last or first.
        assert_value(
            &format!(
                "{{\n  \"sys\": {{\n    \"type\": \"PersonalAccessToken\",\n    \"id\": \"x1\",\n    \"redactedValue\": \"0001\"\n  }},\n  \"name\": \"ci\",\n  \"scopes\": [\n    \"content_management_manage\"\n  ],\n  \"token\": \"{token}\"\n}}\n"
            ),
            &token,
        );
        assert_value(
            &format!(
                "{{\n  \"token\": \"{token}\",\n  \"scopes\": [\"content_management_read\"]\n}}\n"
            ),
            &token,
        );
        // Compact, CRLF and tabs, spaced colons.
        assert_value(
            &format!(
                "{{\"sys\":{{\"type\":\"PersonalAccessToken\"}},\"name\":\"ci\",\"token\":\"{token}\"}}\n"
            ),
            &token,
        );
        assert_value(
            &format!(
                "{{\r\n\t\"scopes\" : [\"content_management_manage\"],\r\n\t\"token\" : \"{token}\"\r\n}}\r\n"
            ),
            &token,
        );
        // In a raw HTTP response.
        assert_value(
            &format!(
                "HTTP/1.1 201 Created\ncontent-type: application/json\n\n{{\"scopes\":[\"content_management_manage\"],\"token\":\"{token}\"}}\n"
            ),
            &token,
        );
    }
}

#[test]
fn context_does_not_move_the_span_and_neighbours_stay_apart() {
    let token = value(ALNUM, 40, 20);
    assert_value(
        &format!("로그: 응답\n{{\n  \"scopes\": [\"a\"],\n  \"token\": \"{token}\"\n}}\n끝\n"),
        &token,
    );
    let big = "response line of ordinary words\n".repeat(2_000);
    assert_value(
        &format!("{big}{{\"scopes\":[\"a\"],\"token\":\"{token}\"}}\n"),
        &token,
    );
    let password = value(ALNUM, 40, 21);
    assert_values_with(
        &format!("{{\"scopes\":[\"a\"],\"token\":\"{token}\",\"password\":\"{password}\"}}\n"),
        &[&token, &password],
        Confidence::High,
        Action::Redact,
    );
}

#[test]
fn a_bare_token_member_stays_unmatched() {
    let token = value(ALNUM, 40, 30);
    for input in [
        // Alone: the policy limit; the evidence names no sibling for it.
        format!("{{\"token\":\"{token}\"}}\n"),
        format!("{{\n  \"token\": \"{token}\"\n}}\n"),
        // A name beside it is not a documented sibling.
        format!("{{\n  \"name\": \"SYNTHETIC-token-name\",\n  \"token\": \"{token}\"\n}}\n"),
        format!("{{\"csrf\":\"x\",\"token\":\"{token}\"}}\n"),
        // The other forms of a bare token.
        format!("token={token}\n"),
        format!("token: {token}\n"),
        format!("{{ \"scopes\": [\"a\"], token: \"{token}\" }}\n"),
        // A sibling too far away (more than five lines).
        format!(
            "{{\n  \"scopes\": [],\n{}  \"token\": \"{token}\"\n}}\n",
            "  \"n\": 1,\n".repeat(6)
        ),
        // Look-alike names.
        format!("{{\"scopes\":[\"a\"],\"tokens\":\"{token}\"}}\n"),
        format!("{{\"scopes\":[\"a\"],\"token_type\":\"{token}\"}}\n"),
        format!("{{\"scopes\":[\"a\"],\"tokenId\":\"{token}\"}}\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn placeholders_masks_references_and_the_redacted_value_member_are_silent() {
    for placeholder in [
        "********",
        "<token>",
        "{token}",
        "${CONTENTFUL_TOKEN}",
        "$TOKEN",
        "{{ token }}",
        "CFPAT-xxx",
        "CFPAT-123...789",
        "",
    ] {
        assert_clean(&format!(
            "{{\"scopes\":[\"a\"],\"token\":\"{placeholder}\"}}\n"
        ));
    }
    // The four-character `sys.redactedValue` is not the token: below the floor.
    assert_clean("{\n  \"sys\": {\n    \"redactedValue\": \"0001\"\n  }\n}\n");
}
