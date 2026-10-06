//! The Elastic cross-cluster API key `encoded` member (redact-secret#1229,
//! Group D `elastic:cross-cluster-api-key`), driven through the public default
//! pipeline.
//!
//! credential-evidence Case `elastic-cross-cluster-api-key-create-response-members`
//! flags the `api_key` and `encoded` members of a create-cross-cluster-API-key
//! response (`encoded` is the base64 of `id:api_key`) and leaves `id` outside the
//! spans. `encoded` is read only beside an `api_key` member, never as a bare name.
//! Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence};
use support::{assert_clean, assert_values_with, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn random(len: usize, seed: usize) -> String {
    let chars: Vec<char> = ALNUM.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 13 + index * index * 3) % chars.len()])
        .collect()
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

struct Issued {
    id: String,
    api_key: String,
    encoded: String,
}

fn key(seed: usize, key_len: usize) -> Issued {
    let id = random(20, seed);
    let api_key = random(key_len, seed + 50);
    let encoded = base64(format!("{id}:{api_key}").as_bytes());
    Issued {
        id,
        api_key,
        encoded,
    }
}

fn assert_both(input: &str, key: &Issued) {
    assert_values_with(
        input,
        &[&key.api_key, &key.encoded],
        Confidence::High,
        Action::Redact,
    );
}

/// The two findings in the order the members appear.
fn assert_both_in_order(input: &str, first: &str, second: &str) {
    assert_values_with(input, &[first, second], Confidence::High, Action::Redact);
}

#[test]
fn the_response_members_are_read_in_every_documented_layout() {
    // Key lengths whose encoded form ends in no padding, `=` and `==`.
    for (seed, key_len) in [(1usize, 22usize), (2, 21), (3, 20), (4, 23)] {
        let k = key(seed, key_len);
        // Pretty JSON.
        assert_both(
            &format!(
                "{{\n  \"id\": \"{}\",\n  \"name\": \"synthetic-key\",\n  \"api_key\": \"{}\",\n  \"encoded\": \"{}\"\n}}\n",
                k.id, k.api_key, k.encoded
            ),
            &k,
        );
        // Compact JSON in a raw HTTP response, and as curl output.
        let compact = format!(
            "{{\"id\":\"{}\",\"name\":\"synthetic-key\",\"api_key\":\"{}\",\"encoded\":\"{}\"}}",
            k.id, k.api_key, k.encoded
        );
        assert_both(
            &format!("HTTP/1.1 200 OK\ncontent-type: application/json\n\n{compact}\n"),
            &k,
        );
        assert_both(
            &format!("$ curl -s -X POST \"https://cluster.example.test/create\"\n{compact}\n"),
            &k,
        );
        assert_both(&compact, &k);
        // CRLF and tabs, spaced colons.
        assert_both(
            &format!(
                "{{\r\n\t\"id\" : \"{}\",\r\n\t\"api_key\" : \"{}\",\r\n\t\"encoded\" : \"{}\"\r\n}}\r\n",
                k.id, k.api_key, k.encoded
            ),
            &k,
        );
        // `encoded` before `api_key`, an expiration member between, a nested array.
        assert_both_in_order(
            &format!(
                "{{\n  \"encoded\": \"{}\",\n  \"id\": \"{}\",\n  \"api_key\": \"{}\"\n}}\n",
                k.encoded, k.id, k.api_key
            ),
            &k.encoded,
            &k.api_key,
        );
        assert_both(
            &format!(
                "{{\n  \"id\": \"{}\",\n  \"name\": \"k\",\n  \"expiration\": 1893456000000,\n  \"api_key\": \"{}\",\n  \"encoded\": \"{}\"\n}}\n",
                k.id, k.api_key, k.encoded
            ),
            &k,
        );
        assert_both(
            &format!(
                "{{\n  \"keys\": [\n    {{\n      \"id\": \"{}\",\n      \"api_key\": \"{}\",\n      \"encoded\": \"{}\"\n    }}\n  ]\n}}\n",
                k.id, k.api_key, k.encoded
            ),
            &k,
        );
    }
}

#[test]
fn context_does_not_move_the_spans_and_the_id_stays_outside() {
    let k = key(5, 22);
    assert_both(
        &format!(
            "로그: 키 생성 결과\n{{\n  \"id\": \"{}\",\n  \"api_key\": \"{}\",\n  \"encoded\": \"{}\"\n}}\n끝\n",
            k.id, k.api_key, k.encoded
        ),
        &k,
    );
    let big = "response line of ordinary words\n".repeat(2_000);
    assert_both(
        &format!(
            "{big}{{\"id\":\"{}\",\"api_key\":\"{}\",\"encoded\":\"{}\"}}\n",
            k.id, k.api_key, k.encoded
        ),
        &k,
    );
    // The id has the shape of the api_key: it is still not a finding.
    let twin = Issued {
        id: k.api_key.clone().replacen(&k.api_key[..3], "xyz", 1),
        ..key(6, 22)
    };
    let input = format!(
        "{{\n  \"id\": \"{}\",\n  \"api_key\": \"{}\",\n  \"encoded\": \"{}\"\n}}\n",
        twin.id, twin.api_key, twin.encoded
    );
    assert_both(&input, &twin);
    // Two responses one after the other.
    let second = key(7, 22);
    assert_values_with(
        &format!(
            "{{\"id\":\"{}\",\"api_key\":\"{}\",\"encoded\":\"{}\"}}\n{{\"id\":\"{}\",\"api_key\":\"{}\",\"encoded\":\"{}\"}}\n",
            k.id, k.api_key, k.encoded, second.id, second.api_key, second.encoded
        ),
        &[&k.api_key, &k.encoded, &second.api_key, &second.encoded],
        Confidence::High,
        Action::Redact,
    );
}

#[test]
fn placeholders_masks_references_empty_members_and_prose_are_silent() {
    for (api_key, encoded) in [
        ("<API_KEY>", "<ENCODED_API_KEY>"),
        ("********", "********"),
        ("", ""),
        ("{{ outputs.api_key }}", "{{ outputs.encoded }}"),
        ("${API_KEY}", "${ENCODED}"),
        ("{api_key}", "{encoded_api_key}"),
    ] {
        assert_clean(&format!(
            "{{\n  \"name\": \"synthetic-cross-cluster-key\",\n  \"api_key\": \"{api_key}\",\n  \"encoded\": \"{encoded}\"\n}}\n"
        ));
    }
    assert_clean(
        "Copy the encoded member of the response to a safe place; it is needed for the local cluster configuration.\n",
    );
}

#[test]
fn encoded_is_not_a_name_without_its_api_key_sibling() {
    let k = key(8, 22);
    // Alone, a stated false negative: the member is not a vocabulary name.
    assert_clean(&format!("{{\"encoded\":\"{}\"}}\n", k.encoded));
    assert_clean(&format!(
        "{{\n  \"id\": \"{}\",\n  \"encoded\": \"{}\"\n}}\n",
        k.id, k.encoded
    ));
    // A bare assignment, a query parameter and a YAML property are not members.
    assert_clean(&format!("encoded={}\n", k.encoded));
    assert_clean(&format!("GET /x?encoded={} HTTP/1.1\n", k.encoded));
    assert_clean(&format!("encoded: {}\n", k.encoded));
    // A sibling too far away: more than five lines, or an unrelated member name.
    let filler = "  \"note\": \"x\",\n".repeat(7);
    assert_values_with(
        &format!(
            "{{\n  \"api_key\": \"{}\",\n{filler}  \"encoded\": \"{}\"\n}}\n",
            k.api_key, k.encoded
        ),
        &[&k.api_key],
        Confidence::High,
        Action::Redact,
    );
    for member in ["encoded_key", "encoded_url", "encodedValue", "urlencoded"] {
        assert_values_with(
            &format!(
                "{{\n  \"api_key\": \"{}\",\n  \"{member}\": \"{}\"\n}}\n",
                k.api_key, k.encoded
            ),
            &[&k.api_key],
            Confidence::High,
            Action::Redact,
        );
    }
}

#[test]
fn an_encoded_member_beside_an_api_key_in_the_same_object_only() {
    // Documented siblings of one object are read; a member of an object far
    // below another object's api_key is not (window of six lines).
    let k = key(9, 22);
    let other = key(10, 22);
    let gap = "  \"x\": 1,\n".repeat(6);
    let input = format!(
        "{{\n  \"api_key\": \"{}\"\n}}\n{gap}{{\n  \"encoded\": \"{}\"\n}}\n",
        other.api_key, k.encoded
    );
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn members_inside_an_enclosing_json_string_are_read() {
    // A response serialized into another JSON string, as a fixture file or a
    // log field holds it: the outer quote must not shift which member is which.
    let k = key(11, 22);
    assert_both(
        &format!(
            "  \"text\": \"{{\\\"id\\\":\\\"{}\\\",\\\"api_key\\\":\\\"{}\\\",\\\"encoded\\\":\\\"{}\\\"}}\\n\",\n",
            k.id, k.api_key, k.encoded
        ),
        &k,
    );
    assert_both(
        &format!(
            "{{\"body\":\"{{\\\"api_key\\\":\\\"{}\\\",\\\"encoded\\\":\\\"{}\\\"}}\"}}\n",
            k.api_key, k.encoded
        ),
        &k,
    );
}
