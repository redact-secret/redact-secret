//! The `HubSpot` legacy and developer API key parameter `hapikey`
//! (redact-secret#1230, Group E `hubspot:legacy-api-key`), driven through the
//! public default pipeline.
//!
//! credential-evidence Case `hubspot-legacy-api-key-hapikey-query-parameter-value`
//! flags the value of the `hapikey` query parameter by its position, not its
//! shape, for both the retired account key and the current developer key.
//! Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

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
    let hex = |len: usize, seed: usize| value(HEX, len, seed);
    vec![
        hex(32, 1),
        // The UUID layout the account key is commonly written in (observed,
        // not claimed by the evidence).
        format!(
            "{}-{}-{}-{}-{}",
            hex(8, 2),
            hex(4, 3),
            hex(4, 4),
            hex(4, 5),
            hex(12, 6)
        ),
        value(ALNUM, 64, 7),
        value(&format!("{ALNUM}-_"), 40, 8),
        "qmxtvbnlkrwzpdsh".to_owned(),
        format!("{}-{}", value(ALNUM, 20, 9), value(ALNUM, 20, 10)),
        format!(
            "{}.{}_{}",
            value(ALNUM, 12, 11),
            value(ALNUM, 12, 12),
            value(ALNUM, 12, 13)
        ),
        value(ALNUM, 150, 14),
        value(ALNUM, 16, 15),
    ]
}

#[test]
fn the_query_parameter_is_read_in_every_carrier_layout() {
    for secret in shapes() {
        // A raw request line: first, middle, last, ended by a space.
        assert_value(
            &format!(
                "GET /contacts/v1/lists/all/contacts/all?hapikey={secret}&count=10 HTTP/1.1\nHost: api.hubspot.example.test\n"
            ),
            &secret,
        );
        assert_value(
            &format!(
                "GET /contacts/v1/lists/all/contacts/all?count=10&hapikey={secret} HTTP/1.1\nHost: api.hubspot.example.test\n"
            ),
            &secret,
        );
        assert_value(
            &format!("GET /x?a=1&hapikey={secret}&b=2 HTTP/1.1\r\nHost: h.example.test\r\n"),
            &secret,
        );
        // No HTTP version, end of input, trailing whitespace.
        assert_value(&format!("GET /x?hapikey={secret}"), &secret);
        assert_value(&format!("GET /x?count=1&hapikey={secret}  \t\n"), &secret);
        // curl: double, single and no quotes, with the developer key's appId.
        assert_value(
            &format!(
                "curl \"https://api.hubspot.example.test/contacts/v1/lists/all/contacts/all?hapikey={secret}\"\n"
            ),
            &secret,
        );
        assert_value(
            &format!(
                "curl 'https://api.hubspot.example.test/events?hapikey={secret}&appId=SYNTHETICAPPID0001'\n"
            ),
            &secret,
        );
        assert_value(
            &format!(
                "curl -X POST https://api.hubspot.example.test/events?appId=SYNTHETICAPPID0001&hapikey={secret}\n"
            ),
            &secret,
        );
        // A configuration URL inside a JSON string, last or not.
        assert_value(
            &format!(
                "{{\n  \"baseUrl\": \"https://api.hubspot.example.test/x?hapikey={secret}\"\n}}\n"
            ),
            &secret,
        );
        assert_value(
            &format!(
                "{{\"baseUrl\":\"https://api.hubspot.example.test/x?hapikey={secret}&portalId=1\",\"a\":1}}\n"
            ),
            &secret,
        );
        // Percent-escaped neighbours.
        assert_value(
            &format!("GET /x?q=a%20b&hapikey={secret}&r=%2F%3D HTTP/1.1\n"),
            &secret,
        );
    }
}

#[test]
fn the_name_is_read_as_a_member_a_variable_and_a_property() {
    let secret = value(HEX, 32, 21);
    // The upper-case environment variable and a user prefix.
    assert_value(&format!("HAPIKEY={secret}\n"), &secret);
    assert_value(&format!("export HAPIKEY=\"{secret}\"\n"), &secret);
    assert_value(&format!("HUBSPOT_HAPIKEY={secret}\n"), &secret);
    assert_value(&format!("MY_HUBSPOT_HAPIKEY='{secret}'\r\n"), &secret);
    // A JSON member, a YAML property and an assignment.
    assert_value(&format!("{{\"hapikey\":\"{secret}\"}}\n"), &secret);
    assert_value(&format!("hubspot:\n  hapikey: {secret}\n"), &secret);
    assert_value(&format!("hapikey = {secret}\n"), &secret);
}

#[test]
fn context_does_not_move_the_span_and_neighbours_stay_apart() {
    let secret = value(ALNUM, 40, 22);
    assert_value(
        &format!("로그: 요청 GET /x?hapikey={secret}&appId=1 HTTP/1.1\n끝\n"),
        &secret,
    );
    let big = "request line of ordinary words\n".repeat(2_000);
    assert_value(&format!("{big}GET /x?hapikey={secret} HTTP/1.1\n"), &secret);
    // Twice, with a same-shape public neighbour between.
    let second = value(ALNUM, 40, 23);
    assert_values_with(
        &format!(
            "GET /x?hapikey={secret}&appId=SYNTHETICAPPID0001 HTTP/1.1\nGET /y?hapikey={second} HTTP/1.1\n"
        ),
        &[&secret, &second],
        redact_secret::Confidence::High,
        redact_secret::Action::Redact,
    );
    // A neighbouring secret under its own name is a separate finding.
    let other = value(ALNUM, 40, 24);
    assert_values_with(
        &format!("GET /x?hapikey={secret}&password={other} HTTP/1.1\n"),
        &[&secret, &other],
        redact_secret::Confidence::High,
        redact_secret::Action::Redact,
    );
}

#[test]
fn placeholders_masks_references_empty_values_and_prose_are_silent() {
    for placeholder in [
        "{YOUR_DEVELOPER_API_KEY}",
        "{YOUR_API_KEY}",
        "<your-api-key>",
        "<YOUR_API_KEY>",
        "${HUBSPOT_API_KEY}",
        "$HUBSPOT_API_KEY",
        "SY************01",
        "************************************",
        "YOUR_API_KEY",
        "{{ hubspot_api_key }}",
    ] {
        assert_clean(&format!(
            "curl -X POST \"https://api.hubspot.example.test/events?hapikey={placeholder}\"\n"
        ));
        assert_clean(&format!("GET /x?count=10&hapikey={placeholder} HTTP/1.1\n"));
        assert_clean(&format!("HAPIKEY={placeholder}\n"));
    }
    assert_clean(
        "GET /contacts/v1/lists/all/contacts/all?count=10&hapikey= HTTP/1.1\nHost: api.hubspot.example.test\n",
    );
    assert_clean(
        "Older integrations pass the key in the hapikey query parameter of each request.\n",
    );
}

#[test]
fn only_the_whole_name_and_its_prefixed_form_are_read() {
    let secret = value(ALNUM, 40, 30);
    for name in [
        "hapikeyId",
        "hapikey_id",
        "hapikeyHint",
        "hapikeys",
        "hapikey_expires_at",
        "appId",
        "portalId",
        "app_id",
        "mask_hapikey_note",
    ] {
        assert_clean(&format!("GET /x?{name}={secret} HTTP/1.1\n"));
        assert_clean(&format!("{{\"{name}\":\"{secret}\"}}\n"));
    }
    // A prefix that says the value is not the secret keeps the existing rule.
    assert_clean("GET /x?publishable_hapikey=abcdefghij HTTP/1.1\n");
    assert_clean("GET /x?masked_hapikey=********** HTTP/1.1\n");
    // The public numeric ids stay silent.
    assert_clean("GET /x?portalId=12345678&appId=87654321 HTTP/1.1\n");
}
