//! The `HubSpot` private app access-token-info request member `tokenKey`
//! (redact-secret#1228, Group C `hubspot:private-app-access-token`), driven
//! through the public default pipeline.
//!
//! credential-evidence Case
//! `hubspot-private-app-access-token-bearer-header-and-token-key-member` flags the
//! value of the `tokenKey` member of the JSON body of an access-token-info
//! request by its position, not its shape. `tokenKey` is read only as a quoted
//! JSON member name (the carrier), never as a variable, a query parameter or a
//! YAML property. Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence};
use support::{assert_clean, assert_value, assert_values_with, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn value(alphabet: &str, len: usize, seed: usize) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 11 + index * index * 3) % chars.len()])
        .collect()
}

fn shapes() -> Vec<String> {
    vec![
        value(ALNUM, 40, 1),
        format!("{}-{}", value(ALNUM, 20, 2), value(ALNUM, 20, 3)),
        format!(
            "{}.{}_{}",
            value(ALNUM, 12, 4),
            value(ALNUM, 12, 5),
            value(ALNUM, 12, 6)
        ),
        value(ALNUM, 150, 7),
        value(ALNUM, 16, 8),
        // The UUID and prefixed layouts people expect are observed, not claimed.
        "3f2504e0-4f89-11d3-9a0c-0305e82c3301".to_owned(),
        ["pat", "-na1-", "0f2c4e6a-8b1d-4a3c-9e5f-7b9d1c3e5a7c"].concat(),
    ]
}

#[test]
fn the_member_is_read_in_every_documented_layout() {
    for token in shapes() {
        // A raw request with the JSON body, and curl --data.
        assert_value(
            &format!(
                "POST /oauth/v2/private-apps/get/access-token-info HTTP/1.1\nHost: api.example.test\nContent-Type: application/json\n\n{{\"tokenKey\":\"{token}\"}}\n"
            ),
            &token,
        );
        assert_value(
            &format!(
                "curl -X POST https://api.example.test/oauth/v2/private-apps/get/access-token-info -H \"Content-Type: application/json\" --data '{{\"tokenKey\":\"{token}\"}}'\n"
            ),
            &token,
        );
        // JSON layouts.
        assert_value(&format!("{{\"tokenKey\":\"{token}\"}}\n"), &token);
        assert_value(&format!("{{\"tokenKey\": \"{token}\"}}"), &token);
        assert_value(&format!("{{ \"tokenKey\" : \"{token}\" }}\n"), &token);
        assert_value(
            &format!("{{\r\n\t\"tokenKey\": \"{token}\"\r\n}}\r\n"),
            &token,
        );
        assert_value(&format!("{{\"a\":1,\"tokenKey\":\"{token}\"}}\n"), &token);
        assert_value(&format!("{{\"tokenKey\":\"{token}\",\"a\":1}}\n"), &token);
        // Serialized into another JSON string.
        assert_value(
            &format!("{{\"body\":\"{{\\\"tokenKey\\\":\\\"{token}\\\"}}\"}}\n"),
            &token,
        );
    }
}

#[test]
fn context_does_not_move_the_span() {
    let token = value(ALNUM, 40, 20);
    assert_value(
        &format!("로그: 요청 본문\n{{\"tokenKey\":\"{token}\"}}\n끝\n"),
        &token,
    );
    let big = "request line of ordinary words\n".repeat(2_000);
    assert_value(&format!("{big}{{\"tokenKey\":\"{token}\"}}\n"), &token);
    let second = value(ALNUM, 40, 21);
    assert_values_with(
        &format!("{{\"tokenKey\":\"{token}\"}}\n{{\"tokenKey\":\"{second}\"}}\n"),
        &[&token, &second],
        Confidence::High,
        Action::Redact,
    );
    let password = value(ALNUM, 40, 22);
    assert_values_with(
        &format!("{{\"tokenKey\":\"{token}\",\"password\":\"{password}\"}}\n"),
        &[&token, &password],
        Confidence::High,
        Action::Redact,
    );
}

#[test]
fn placeholders_masks_references_empty_values_and_prose_are_silent() {
    for placeholder in [
        "[YOUR_TOKEN]",
        "********",
        "<token>",
        "{token}",
        "${HUBSPOT_PRIVATE_APP_TOKEN}",
        "$TOKEN",
        "{{ secrets.HUBSPOT_TOKEN }}",
        "YOUR_TOKEN",
        "",
    ] {
        assert_clean(&format!("{{\"tokenKey\":\"{placeholder}\"}}\n"));
        assert_clean(&format!(
            "curl --data '{{\"tokenKey\":\"{placeholder}\"}}' https://api.example.test/x\n"
        ));
    }
    assert_clean(
        "Include your access token in the tokenKey field of the request body to view the token information.\n",
    );
}

#[test]
fn a_storage_key_name_is_not_a_token() {
    // `tokenKey` is also the name of the storage key an application saves a
    // token under; a value that is itself a credential name is a reference.
    for name in [
        "accessToken",
        "access_token",
        "auth-token-storage-key",
        "authorizationTokenStorageKey",
        "refreshToken",
        "jwt_token_key",
        "id_token",
    ] {
        assert_clean(&format!("{{\"tokenKey\":\"{name}\"}}\n"));
    }
}

#[test]
fn only_the_quoted_member_name_is_read() {
    let token = value(ALNUM, 40, 30);
    // A variable, a query parameter, a YAML property, an environment variable
    // and an unquoted object key are not the documented carrier: a stated
    // false negative.
    for input in [
        format!("const tokenKey = \"{token}\";\n"),
        format!("tokenKey={token}\n"),
        format!("GET /x?tokenKey={token} HTTP/1.1\n"),
        format!("tokenKey: {token}\n"),
        format!("TOKEN_KEY={token}\n"),
        format!("{{ tokenKey: \"{token}\" }}\n"),
        format!("client.configure(tokenKey=\"{token}\")\n"),
    ] {
        assert_clean(&input);
    }
    // Neighbouring member names are other fields.
    for name in [
        "tokenKeyId",
        "tokenKeys",
        "token_key_hint",
        "myTokenKey",
        "tokenId",
        "token",
    ] {
        assert_clean(&format!("{{\"{name}\":\"{token}\"}}\n"));
    }
    // The quoted member is read even with the other name in the object.
    let findings = findings_with_parity(&format!(
        "{{\"tokenId\":\"{token}\",\"tokenKey\":\"{token}\"}}\n"
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
}
