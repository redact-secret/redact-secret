//! The `token` parameter of an OAuth token revocation or introspection request
//! (redact-secret#1230, Group E `reddit:oauth-access-token`), driven through
//! the public default pipeline.
//!
//! credential-evidence Case `reddit-oauth-revoke-token-request-body-token-field`
//! flags the value of the `token` parameter of a `revoke_token` request body,
//! with or without `token_type_hint`. A bare `token` stays unmatched by the
//! accepted rule; it is read here only where the request names a revoke or
//! introspect endpoint (`/revoke`, `/revoke_token`, `/introspect`, RFC 7009 and
//! RFC 7662) within the request window, or carries `token_type_hint=`.
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
        value(ALNUM, 150, 9),
        value(ALNUM, 16, 10),
    ]
}

fn request(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\nHost: www.reddit.example.test\nContent-Type: application/x-www-form-urlencoded\n\n{body}"
    )
}

#[test]
fn the_form_body_of_a_revoke_request_is_read_without_a_hint() {
    for token in shapes() {
        for path in [
            "/api/v1/revoke_token",
            "/oauth2/revoke",
            "/revoke",
            "/oauth/introspect",
        ] {
            // First, middle and last parameter; LF, CRLF and end of input.
            assert_value(&request(path, &format!("token={token}\n")), &token);
            assert_value(&request(path, &format!("token={token}")), &token);
            assert_value(&request(path, &format!("a=b&token={token}&c=d\n")), &token);
            assert_value(&request(path, &format!("a=b&c=d&token={token}\n")), &token);
            assert_value(
                &format!("POST {path} HTTP/1.1\r\nHost: h.example.test\r\n\r\ntoken={token}\r\n"),
                &token,
            );
            // Percent-escaped neighbours.
            assert_value(
                &request(path, &format!("a=%2F%3D&token={token}&b=%20\n")),
                &token,
            );
        }
    }
}

#[test]
fn a_curl_request_names_its_endpoint_on_the_same_line() {
    for token in shapes() {
        for flag in ["-d", "--data", "--data-raw", "--data-urlencode"] {
            assert_value(
                &format!(
                    "curl -X POST https://www.reddit.example.test/api/v1/revoke_token {flag} token={token}\n"
                ),
                &token,
            );
            assert_value(
                &format!(
                    "curl -X POST https://www.reddit.example.test/api/v1/revoke_token {flag} \"token={token}\"\n"
                ),
                &token,
            );
            assert_value(
                &format!(
                    "curl -X POST https://www.reddit.example.test/api/v1/revoke_token {flag} 'token={token}' -H \"Accept: */*\"\n"
                ),
                &token,
            );
            // The flag before the URL, and the endpoint with a query.
            assert_value(
                &format!("curl {flag} token={token} https://www.reddit.example.test/revoke?x=1\n"),
                &token,
            );
        }
        // A continued curl command: the endpoint on the line above.
        assert_value(
            &format!(
                "curl -X POST https://www.reddit.example.test/api/v1/revoke_token \\\n  -d token={token} \\\n  -d token_type_hint=refresh_token\n"
            ),
            &token,
        );
    }
}

#[test]
fn the_token_type_hint_parameter_alone_names_the_request() {
    for token in shapes() {
        assert_value(
            &format!("token={token}&token_type_hint=refresh_token\n"),
            &token,
        );
        assert_value(
            &format!("token_type_hint=access_token&token={token}\n"),
            &token,
        );
        assert_value(
            &format!(
                "curl -d \"token={token}&token_type_hint=access_token\" https://api.example.test/anything\n"
            ),
            &token,
        );
        assert_value(
            &format!(
                "curl https://api.example.test/anything -d token={token} -d token_type_hint=refresh_token\n"
            ),
            &token,
        );
    }
}

#[test]
fn context_does_not_move_the_span() {
    let token = value(ALNUM, 40, 20);
    assert_value(
        &format!(
            "로그: 요청\n{}",
            request("/api/v1/revoke_token", &format!("token={token}\n끝\n"))
        ),
        &token,
    );
    let big = "request line of ordinary words\n".repeat(2_000);
    assert_value(
        &format!(
            "{big}{}",
            request("/api/v1/revoke_token", &format!("token={token}\n"))
        ),
        &token,
    );
    // A neighbouring secret under its own name is a separate finding; the
    // hint parameter is not.
    let password = value(ALNUM, 40, 21);
    assert_values_with(
        &request(
            "/api/v1/revoke_token",
            &format!("token={token}&token_type_hint=refresh_token&password={password}\n"),
        ),
        &[&token, &password],
        Confidence::High,
        Action::Redact,
    );
    // Two requests.
    let second = value(ALNUM, 40, 22);
    assert_values_with(
        &format!(
            "{}\n{}",
            request("/revoke", &format!("token={token}\n")),
            request("/revoke", &format!("token={second}\n"))
        ),
        &[&token, &second],
        Confidence::High,
        Action::Redact,
    );
}

#[test]
fn without_a_revoke_context_a_bare_token_stays_unmatched() {
    let token = value(ALNUM, 40, 30);
    for input in [
        format!("token={token}\n"),
        format!("GET /x?token={token} HTTP/1.1\n"),
        format!("POST /api/v1/other HTTP/1.1\nHost: h.example.test\n\ntoken={token}\n"),
        format!("curl -d token={token} https://api.example.test/other\n"),
        format!("TOKEN={token}\n"),
        format!("export TOKEN={token}\n"),
        format!("{{\"token\":\"{token}\"}}\n"),
        format!("token: {token}\n"),
        // A revoke request line far above (more than nine lines).
        format!(
            "POST /revoke HTTP/1.1\n{}token={token}\n",
            "X-Padding: 1\n".repeat(12)
        ),
        // `revoke` as part of a longer path segment is another endpoint.
        format!("POST /revoked HTTP/1.1\nHost: h\n\ntoken={token}\n"),
        format!("POST /revoke-all HTTP/1.1\nHost: h\n\ntoken={token}\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn the_revoke_context_does_not_widen_other_names() {
    let secret = value(ALNUM, 40, 40);
    let token = value(ALNUM, 40, 41);
    // Another name in the same request keeps its own reading; the JSON body
    // member `token` of a revoke request is not the form parameter.
    assert_value(
        &request(
            "/revoke",
            &format!("client_secret={secret}&token_type_hint=x\n"),
        ),
        &secret,
    );
    assert_clean(&request("/revoke", &format!("{{\"token\":\"{token}\"}}\n")));
    assert_clean(&request(
        "/revoke",
        &format!("token_type_hint=refresh_token&other={token}\n"),
    ));
}

#[test]
fn placeholders_masks_references_and_empty_values_are_silent() {
    for placeholder in [
        "${REDDIT_TOKEN}",
        "$TOKEN",
        "<token>",
        "{token}",
        "{{ token }}",
        "********",
        "TOKEN",
        "",
    ] {
        assert_clean(&request(
            "/api/v1/revoke_token",
            &format!("token={placeholder}\n"),
        ));
        assert_clean(&format!(
            "curl -X POST https://www.reddit.example.test/api/v1/revoke_token -d token={placeholder} -d token_type_hint=refresh_token\n"
        ));
    }
    assert_clean(
        "The token parameter of the revoke_token request carries the access or refresh token.\n",
    );
}
