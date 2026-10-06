//! Pipe-joined composites whose halves are all placeholders, masks, empty or
//! references (redact-secret#1234, round-2 residual): `{your-app_id}|<secret>`
//! was reported as the 12-byte `{your-app_id`. Real-shaped values are assembled
//! at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{assert_clean, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn random(len: usize, seed: usize) -> String {
    let chars: Vec<char> = ALNUM.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 13 + index * index * 3) % chars.len()])
        .collect()
}

#[test]
fn a_composite_of_placeholder_halves_is_silent() {
    for second in [
        "{your-app_secret}",
        "<APP_SECRET>",
        "<your-app-secret>",
        "<your app secret>",
        "********",
        "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
        "${META_APP_SECRET}",
        "$META_APP_SECRET",
        "",
    ] {
        for carrier in [
            format!(
                "GET /v26.0/me?access_token={{your-app_id}}|{second} HTTP/1.1\nHost: h.example.test\n"
            ),
            format!(
                "curl -i -X GET \"https://graph.example.test/{{api-endpoint}}?access_token={{your-app_id}}|{second}\"\n"
            ),
            format!("GET /v26.0/me?access_token={{your-app_id}}|{second}&x=1 HTTP/1.1\n"),
            format!("로그: access_token={{your-app_id}}|{second}\n끝\n"),
            format!("client_secret={{your-app_id}}|{second}"),
        ] {
            assert_clean(&carrier);
        }
    }
}

#[test]
fn a_real_shaped_half_keeps_the_finding() {
    let secret = random(32, 1);
    for second in [
        secret.clone(),
        format!("<x>{secret}"),
        "**".to_owned() + &secret,
        format!("{{abc}}{secret}"),
    ] {
        let input = format!("GET /v26.0/me?access_token={{your-app_id}}|{second} HTTP/1.1\n");
        let findings = findings_with_parity(&input);
        assert!(!findings.is_empty(), "{input}");
    }
    // A real app id before a placeholder secret is not the brace composite.
    let findings = findings_with_parity(&format!(
        "GET /x?access_token={}|<APP_SECRET> HTTP/1.1\n",
        random(16, 2)
    ));
    assert!(!findings.is_empty());
    // The all-brace pair and a mask under three characters.
    assert_clean("GET /x?access_token={your-app_id}|{your-app_secret} HTTP/1.1\n");
    let findings = findings_with_parity("GET /x?access_token={your-app_id}|** HTTP/1.1\n");
    assert!(!findings.is_empty());
}
