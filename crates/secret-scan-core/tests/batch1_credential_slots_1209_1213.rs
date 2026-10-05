//! Batch 1 credential slots (redact-secret#1209 to #1213), driven through the
//! public default pipeline.
//!
//! The independent oracle is the focused Batch 1 corpus of
//! redact-secret-benchmarks#717 (`benchmarks/batch1/corpus.mjs` at
//! `14271c7e85ad`). Every input here is re-authored from that corpus's layouts
//! with unmistakably synthetic values; the expected span of a positive is the
//! credential value itself (the encoded envelope for `Basic` and `ApiKey`),
//! computed as the UTF-8 byte offset of the value inside the input, and the
//! expected action is `redact`. Provider documentation establishes the slot
//! and role of each credential, never a universal byte shape, so no test
//! asserts a width, an alphabet or a provider type.
//!
//! * #1209 `X-Figma-Token`: detection was already measured as covered; the
//!   one measured false positive, the placeholder `YOUR_FIGMA_TOKEN`, is fixed.
//! * #1210 Asana `X-Hook-Secret`: no code, the validated behavior is pinned.
//! * #1211 Airtable `macSecretBase64`: a measured gap, one exact field name.
//! * #1212 `Authorization` / `Proxy-Authorization: ApiKey`: a measured gap.
//! * #1213 Canva `client_secret` and the `Basic` envelope: no code, pinned.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Whole-input findings, and the same text and findings under every two-chunk
/// UTF-8 byte partition and a line-per-chunk incremental session.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
        assert_eq!(session.findings(), expected, "{input:?}: {pieces:?}");
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    assert_eq!(session.text(), expected_text, "{input:?}: per line");
    assert_eq!(session.findings(), expected, "{input:?}: per line");
    expected
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

/// Exactly one `redact` finding of `type_name`, spanning exactly `value`
/// (found once in `input`) and nothing else: the carrier and the name stay
/// outside the span, and the sanitized text keeps them and drops the value.
fn assert_value(input: &str, value: &str, type_name: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

// ----------------------------------------------------- #1209 X-Figma-Token

const FIGMA_RAW: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGuQw5Rt0Yk";
const FIGMA_UNI: &str = "Hn4Vd8Ks2PxQ7mLb3ZcW9tRy6FjA1eGuTo5Ek0Ms7Nx";
const FIGMA_C1: &str = "Pw3Rn8Kd5VxL2mQb7ZcT9yHs4FjA1eGu";
const FIGMA_C2: &str = "Tz6Qm1Vd9KxP4nLb8RcW2yHs";
const FIGMA_MAP: &str = "Bd5Kx9Rn2VmP7qLc3ZtW8yHs4FjA6eGuQo1Ek0Ms";

#[test]
fn figma_header_value_is_redacted_in_every_supported_layout() {
    for (input, value) in [
        (
            format!(
                "GET /v1/files/FILE0 HTTP/1.1\r\nHost: api.example.test\r\nX-Figma-Token: {FIGMA_RAW}\r\nAccept: application/json\r\n\r\n"
            ),
            FIGMA_RAW,
        ),
        (
            format!(
                "// notiz: caf\u{e9} \u{1F680} Figma-Datei\nGET /v1/me HTTP/1.1\r\nHost: api.example.test\r\nX-Figma-Token: {FIGMA_UNI}\r\n\r\n"
            ),
            FIGMA_UNI,
        ),
        (
            format!(
                "curl -s -H 'X-Figma-Token: {FIGMA_C1}' https://api.example.test/v1/files/FILE0\n"
            ),
            FIGMA_C1,
        ),
        (
            format!(
                "curl -s -H \"X-Figma-Token: {FIGMA_C2}\" https://api.example.test/v1/files/FILE0\n"
            ),
            FIGMA_C2,
        ),
        (
            format!(
                "{{\"method\":\"GET\",\"url\":\"https://api.example.test/v1/files/FILE0\",\"headers\":{{\"Accept\":\"application/json\",\"X-Figma-Token\":\"{FIGMA_MAP}\"}}}}\n"
            ),
            FIGMA_MAP,
        ),
    ] {
        // A shared carrier names no credential subtype: the type is generic.
        assert_value(&input, value, "contextual_secret");
    }
}

#[test]
fn figma_header_value_stays_outside_the_header_name_and_the_unicode_prefix_offset_is_in_bytes() {
    let input = format!("// caf\u{e9} \u{1F680}\nX-Figma-Token: {FIGMA_UNI}\r\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let prefix = "// caf\u{e9} \u{1F680}\nX-Figma-Token: ";
    assert_eq!(findings[0].range().start(), prefix.len());
    assert_ne!(prefix.len(), prefix.chars().count());
    assert_eq!(findings[0].range().end(), prefix.len() + FIGMA_UNI.len());
}

#[test]
fn figma_placeholders_references_masks_and_lookalikes_stay_clean() {
    let id = "4829103847561029384";
    for input in [
        // The measured false positive: the instructional placeholder.
        "curl -H \"X-Figma-Token: YOUR_FIGMA_TOKEN\" https://api.example.test/v1/me\n",
        "X-Figma-Token: YOUR_FIGMA_TOKEN\r\n",
        "X-Figma-Token: your-figma-token\r\n",
        "X-Figma-Token: replace-with-your-figma-token\r\n",
        "{\"headers\":{\"X-Figma-Token\":\"YOUR_FIGMA_PERSONAL_ACCESS_TOKEN\"}}\n",
        "X-Figma-Token: <your-figma-token>\r\n",
        "curl -H \"X-Figma-Token: ${FIGMA_TOKEN}\" https://api.example.test/v1/me\n",
        "{\"headers\":{\"X-Figma-Token\":\"{{ secrets.figma_token }}\"}}\n",
        "X-Figma-Token: ****************\r\n",
        "X-Figma-Token: \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\r\n",
        // Public ids and a newline-separated value are not a header value.
        &format!("{{\"planId\":\"{id}\",\"user\":{{\"id\":\"{id}\",\"handle\":\"example\"}}}}\n"),
        &format!("X-Figma-Token:\r\n{FIGMA_RAW}\r\n"),
        // A bare `figd_` run is not part of this claim.
        &format!("Personal access tokens look like figd_{FIGMA_RAW} in the account settings.\n"),
    ] {
        assert_clean(input);
    }
}

#[test]
fn figma_name_lookalikes_with_a_suffix_stay_clean() {
    for input in [
        format!("X-Figma-Token-Id: {FIGMA_C1}\r\n"),
        format!("curl -H 'X-Figma-Token-Hint: {FIGMA_C1}' https://api.example.test/\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn the_figma_placeholder_exclusion_keeps_a_real_value_and_a_glued_placeholder() {
    // One word off the list, or a placeholder glued to random material, is
    // still a value a person could have pasted a credential into.
    for value in [
        format!("YOUR_FIGMA_TOKEN_{FIGMA_C1}"),
        format!("your-figma-token-{FIGMA_C2}"),
        FIGMA_C1.to_owned(),
    ] {
        assert_value(
            &format!("X-Figma-Token: {value}\r\n"),
            &value,
            "contextual_secret",
        );
    }
}

// ------------------------------------------------- #1210 Asana X-Hook-Secret

const HOOK_RAW: &str = "7f3a9c1e0b8d4a6fh2jkm5np0q1r3s9t";
const HOOK_RESP: &str = "c4e8a2b6d0f1k3m5n7p9a1c3e5g7i9k2m4o6q8s0";
const HOOK_UNI: &str = "9b1d3f5h7j9l1n3p5a7c9e1g3i5k7m9o0p2q";
const HOOK_C1: &str = "a1c3e5g7i9k1m3o5p7b9d1f3h5j7";
const HOOK_C2: &str = "e2g4i6k8m0o2q4b6d8f0h2j4l6n8p0a2c4e6g8i0k2m4";
const HOOK_MAP: &str = "d3f5h7j9l1n3p5b7d9f1h3j5l7n9p1a3";

#[test]
fn asana_hook_secret_header_value_is_redacted_in_every_supported_layout() {
    for (input, value) in [
        (
            format!(
                "POST /receive-webhook HTTP/1.1\r\nHost: hooks.example.test\r\nX-Hook-Secret: {HOOK_RAW}\r\nContent-Length: 0\r\n\r\n"
            ),
            HOOK_RAW,
        ),
        (
            format!("HTTP/1.1 200 OK\r\nX-Hook-Secret: {HOOK_RESP}\r\nContent-Length: 0\r\n\r\n"),
            HOOK_RESP,
        ),
        (
            format!(
                "# r\u{fc}ckruf \u{1F512}\nPOST /h HTTP/1.1\r\nX-Hook-Secret: {HOOK_UNI}\r\n\r\n"
            ),
            HOOK_UNI,
        ),
        (
            format!(
                "curl -X POST -H 'X-Hook-Secret: {HOOK_C1}' https://hooks.example.test/receive\n"
            ),
            HOOK_C1,
        ),
        (
            format!(
                "curl -X POST -H \"X-Hook-Secret: {HOOK_C2}\" https://hooks.example.test/receive\n"
            ),
            HOOK_C2,
        ),
        (
            format!(
                "{{\"headers\":{{\"Content-Type\":\"application/json\",\"X-Hook-Secret\":\"{HOOK_MAP}\"}},\"body\":{{}}}}\n"
            ),
            HOOK_MAP,
        ),
    ] {
        // No provider attribution is justified by the shared header carrier.
        assert_value(&input, value, "contextual_secret");
    }
}

#[test]
fn asana_hook_secret_value_offset_is_in_utf8_bytes() {
    let input =
        format!("# r\u{fc}ckruf \u{1F512}\nPOST /h HTTP/1.1\r\nX-Hook-Secret: {HOOK_UNI}\r\n\r\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let prefix = "# r\u{fc}ckruf \u{1F512}\nPOST /h HTTP/1.1\r\nX-Hook-Secret: ";
    assert_ne!(prefix.len(), prefix.chars().count());
    assert_eq!(findings[0].range().start(), prefix.len());
    assert_eq!(findings[0].range().end(), prefix.len() + HOOK_UNI.len());
}

#[test]
fn asana_signature_ids_lookalikes_placeholders_and_bare_strings_stay_clean() {
    let hmac = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    for input in [
        // An HMAC output is not the shared secret.
        format!("X-Hook-Signature: {hmac}\r\n"),
        format!("curl -H 'X-Hook-Signature: {hmac}' https://hooks.example.test/receive\n"),
        // Longer header names are different headers.
        "X-Hook-Secret-Id: 0f1e2d3c4b5a6978\r\n".to_owned(),
        format!("X-Hook-Secrets: {HOOK_RAW}\r\n"),
        "X-Hook-Secret: <hook-secret>\r\n".to_owned(),
        "curl -H \"X-Hook-Secret: ${HOOK_SECRET}\" https://hooks.example.test/receive\n".to_owned(),
        "X-Hook-Secret: ********\r\n".to_owned(),
        // A bare arbitrary string with no header around it.
        format!("The handshake finished with {HOOK_RAW} in the log.\n"),
    ] {
        assert_clean(&input);
    }
}

// ------------------------------------------- #1211 Airtable macSecretBase64

// 44-byte standard Base64 (32 bytes, one `=` pad) and a variant with `+`/`/`.
const MAC_JSON: &str = "q7L2m9Zp4TrW8vKc3NbY6hJd1FsA5eGuXo0Rt2Yk7Mw=";
const MAC_PRETTY: &str = "Hn4Vd8Ks2PxQ7mLb3ZcW9tRy6FjA1eGuTo5Ek0Ms7Nx=";
const MAC_YAML: &str = "Bd5Kx9Rn2VmP7qLc3ZtW8yHs4FjA6eGu+o1Ek0Ms7N/=";
const MAC_YAMLQ: &str = "Pw3Rn8Kd5VxL2mQb7ZcT9yHs4FjA1eGuXo6Rt0Yk2Mq=";
const MAC_SPACED: &str = "Tz6Qm1Vd9KxP4nLb8RcW2yHs5FjA7eGuYo3Ek0Ms1Nx=";
const MAC_ENV: &str = "Zc9Wn3Kd7VxL1mQb5PtR8yHs2FjA4eGuBo6Ek0Ms3Nq=";
const MAC_UNI: &str = "Lm8Qw2Vd6KxP9nTb4RcZ1yHs7FjA3eGuDo5Ek0Ms9Nx=";

#[test]
fn airtable_mac_secret_base64_value_is_redacted_in_every_supported_layout() {
    for (input, value) in [
        (
            format!(
                "{{\"id\":\"achSYNTHETICHOOK01\",\"macSecretBase64\":\"{MAC_JSON}\",\"expirationTime\":\"2026-10-19T00:00:00.000Z\"}}\n"
            ),
            MAC_JSON,
        ),
        (
            format!(
                "{{\n  \"macSecretBase64\": \"{MAC_PRETTY}\",\n  \"expirationTime\": \"2026-10-19T00:00:00.000Z\"\n}}\n"
            ),
            MAC_PRETTY,
        ),
        (
            format!(
                "webhook:\n  id: achSYNTHETICHOOK02\n  macSecretBase64: {MAC_YAML}\n  expirationTime: 2026-10-19\n"
            ),
            MAC_YAML,
        ),
        (
            format!("webhook:\n  macSecretBase64: \"{MAC_YAMLQ}\"\n"),
            MAC_YAMLQ,
        ),
        (format!("macSecretBase64 = \"{MAC_SPACED}\"\n"), MAC_SPACED),
        (
            format!("macSecretBase64={MAC_ENV}\nAIRTABLE_BASE=appSYNTHETICBASE01\n"),
            MAC_ENV,
        ),
        (
            format!("{{\"note\":\"caf\u{e9} \u{1F680}\",\"macSecretBase64\":\"{MAC_UNI}\"}}\n"),
            MAC_UNI,
        ),
    ] {
        // The whole encoded value, padding included; generic type.
        assert_value(&input, value, "contextual_secret");
    }
}

#[test]
fn airtable_value_offset_is_in_utf8_bytes_and_keeps_the_padding() {
    let prefix = "{\"note\":\"caf\u{e9} \u{1F680}\",\"macSecretBase64\":\"";
    let input = format!("{prefix}{MAC_UNI}\"}}\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_ne!(prefix.len(), prefix.chars().count());
    assert_eq!(findings[0].range().start(), prefix.len());
    assert_eq!(findings[0].range().end(), prefix.len() + MAC_UNI.len());
    assert!(MAC_UNI.ends_with('='));
}

#[test]
fn airtable_controls_stay_clean() {
    let hmac = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    for input in [
        // HMAC output in the notification header.
        format!("X-Airtable-Content-MAC: hmac-sha256={hmac}\r\n"),
        // Hook and base ids and adjacent public fields.
        "{\"id\":\"achSYNTHETICHOOK01\",\"baseId\":\"appSYNTHETICBASE01\",\"expirationTime\":\"2026-10-19T00:00:00.000Z\"}\n".to_owned(),
        // Another Base64 field: the vocabulary is exactly one name.
        format!("{{\"thumbnailBase64\":\"{MAC_JSON}\",\"name\":\"logo.png\"}}\n"),
        format!("{{\"imageBase64\":\"{MAC_JSON}\"}}\n"),
        // Field-name suffix and prefix lookalikes.
        "{\"macSecretBase64Length\":44,\"macSecretBase64Present\":true}\n".to_owned(),
        "{\"macSecretBase64Id\":\"SYNTHETICIDVALUE01\"}\n".to_owned(),
        format!("{{\"macSecretBase64Hash\":\"{MAC_JSON}\"}}\n"),
        format!("{{\"oldMacSecretBase64\":\"{MAC_JSON}\"}}\n"),
        // Placeholder, reference, masked.
        "macSecretBase64: <mac-secret-base64>\n".to_owned(),
        "macSecretBase64=${AIRTABLE_MAC_SECRET}\n".to_owned(),
        "{\"macSecretBase64\":\"****************************************\"}\n".to_owned(),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn airtable_hook_response_with_the_hmac_header_reports_only_the_secret() {
    let input = format!(
        "{{\"macSecretBase64\":\"{MAC_JSON}\"}}\nX-Airtable-Content-MAC: hmac-sha256=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0\n"
    );
    assert_value(&input, MAC_JSON, "contextual_secret");
}

// -------------------------------------- #1212 Authorization / Proxy: ApiKey

// Undecoded encoded values; the tests never decode them and claim no width.
const KEY_RAW: &str = "U1lOVEhFVElDLUlELTAwMDAxMDAwOlNZTlRIRVRJQy1LRVktMDAwMDEwMDA=";
const KEY_PROXY: &str = "U1lOVEhFVElDLUlELTAwMDAyMDAwOlNZTlRIRVRJQy1LRVktMDAwMDIwMDA=";
const KEY_UNI: &str = "U1lOVEhFVElDLUlELTAwMDAzMDAwOlNZTlRIRVRJQy1LRVktMDAwMDMwMDA=";
const KEY_C1: &str = "U1lOVEhFVElDLUlELTAwMDA0MDAwOlNZTlRIRVRJQy1LRVktMDAwMDQwMDA=";
const KEY_C2: &str = "U1lOVEhFVElDLUlELTAwMDA1MDAwOlNZTlRIRVRJQy1LRVktMDAwMDUwMDA=";
const KEY_C3: &str = "U1lOVEhFVElDLUlELTAwMDA2MDAwOlNZTlRIRVRJQy1LRVktMDAwMDYwMDA=";
const KEY_MAP: &str = "U1lOVEhFVElDLUlELTAwMDA3MDAwOlNZTlRIRVRJQy1LRVktMDAwMDcwMDA=";
const KEY_PMAP: &str = "U1lOVEhFVElDLUlELTAwMDA4MDAwOlNZTlRIRVRJQy1LRVktMDAwMDgwMDA=";

#[test]
fn apikey_authorization_value_is_redacted_in_every_supported_layout() {
    for (input, value) in [
        (
            format!(
                "GET /_security/_authenticate HTTP/1.1\r\nHost: es.example.test:9200\r\nAuthorization: ApiKey {KEY_RAW}\r\nAccept: application/json\r\n\r\n"
            ),
            KEY_RAW,
        ),
        (
            format!(
                "GET /_cluster/health HTTP/1.1\r\nHost: es.example.test:9200\r\nProxy-Authorization: ApiKey {KEY_PROXY}\r\n\r\n"
            ),
            KEY_PROXY,
        ),
        (
            format!(
                "# caf\u{e9} \u{1F680}\nGET / HTTP/1.1\r\nAuthorization: ApiKey {KEY_UNI}\r\n\r\n"
            ),
            KEY_UNI,
        ),
        (
            format!(
                "curl -s -H 'Authorization: ApiKey {KEY_C1}' https://es.example.test:9200/_cat/indices\n"
            ),
            KEY_C1,
        ),
        (
            format!(
                "curl -s -H \"Authorization: ApiKey {KEY_C2}\" https://es.example.test:9200/_cat/indices\n"
            ),
            KEY_C2,
        ),
        (
            format!(
                "curl -x http://proxy.example.test:3128 -H \"Proxy-Authorization: ApiKey {KEY_C3}\" https://es.example.test:9200/\n"
            ),
            KEY_C3,
        ),
        (
            format!(
                "{{\"headers\":{{\"Accept\":\"application/json\",\"Authorization\":\"ApiKey {KEY_MAP}\"}}}}\n"
            ),
            KEY_MAP,
        ),
        (
            format!("{{\"headers\":{{\"Proxy-Authorization\":\"ApiKey {KEY_PMAP}\"}}}}\n"),
            KEY_PMAP,
        ),
    ] {
        // Generic attribution: ApiKey is not unique to one provider, and the
        // encoded value is not decoded or split into id and key.
        assert_value(&input, value, "authorization_credential");
    }
}

#[test]
fn apikey_scheme_case_and_spacing_are_explicit() {
    // The scheme and header name are case-insensitive and a tab separates
    // the scheme from the value, as for `Basic`.
    for input in [
        format!("authorization: apikey {KEY_RAW}\r\n"),
        format!("AUTHORIZATION:ApiKey\t{KEY_RAW}\r\n"),
        format!("  Authorization :  APIKEY   {KEY_RAW}\r\n"),
    ] {
        assert_value(&input, KEY_RAW, "authorization_credential");
    }
}

#[test]
fn apikey_value_offset_is_in_utf8_bytes() {
    let prefix = "# caf\u{e9} \u{1F680}\nGET / HTTP/1.1\r\nAuthorization: ApiKey ";
    let input = format!("{prefix}{KEY_UNI}\r\n\r\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_ne!(prefix.len(), prefix.chars().count());
    assert_eq!(findings[0].range().start(), prefix.len());
    assert_eq!(findings[0].range().end(), prefix.len() + KEY_UNI.len());
}

#[test]
fn apikey_controls_stay_clean() {
    for input in [
        // Bare ApiKey prose with no header carrier.
        format!(
            "Send the key after the ApiKey scheme: ApiKey {KEY_RAW} is how the docs show it.\n"
        ),
        // Header-name prefix and suffix lookalikes.
        format!("X-Authorization: ApiKey {KEY_RAW}\r\n"),
        format!("Authorization-Info: ApiKey {KEY_RAW}\r\n"),
        format!("curl -H 'X-Proxy-Authorization: ApiKey {KEY_RAW}' https://es.example.test/\n"),
        // A newline between the scheme and the value.
        format!("Authorization: ApiKey\r\n{KEY_RAW}\r\n"),
        // Placeholders, references, masks.
        "Authorization: ApiKey <your-api-key>\r\n".to_owned(),
        "curl -H \"Authorization: ApiKey YOUR_API_KEY\" https://es.example.test:9200/\n".to_owned(),
        "curl -H \"Authorization: ApiKey ${ES_API_KEY}\" https://es.example.test:9200/\n"
            .to_owned(),
        "Authorization: ApiKey ****************************\r\n".to_owned(),
        // A key id alone (not claimed, not assumed benign): the id field has
        // no credential slot.
        "{\"id\":\"SYNTHETICKEYID000100\",\"name\":\"ingest-key\",\"expiration\":1791200000000}\n"
            .to_owned(),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn apikey_does_not_change_the_other_authorization_schemes() {
    // `Key` (fal), `Basic` and `Bearer` keep their own readings and types.
    let basic = format!("Authorization: Basic {KEY_RAW}\r\n");
    assert_value(&basic, KEY_RAW, "authorization_credential");
    let keyed = format!("Authorization: Key {KEY_RAW}\r\n");
    assert_value(&keyed, KEY_RAW, "authorization_credential");
    // `ApiKey` is one scheme word: a different word that starts with `Api`
    // is not it, and neither is the scheme glued to its value.
    assert_clean(&format!("Authorization: Apis {KEY_RAW}\r\n"));
    assert_clean(&format!("Authorization: ApiKey{KEY_RAW}\r\n"));
}

#[test]
fn apikey_values_overlap_with_a_provider_finding_resolves_to_one_finding() {
    // A Mailchimp key under the lowercase `apikey` scheme is one typed
    // provider finding over the same span, not two.
    let value = "0123456789abcdef0123456789abcdef-us6";
    let input = format!("Authorization: apikey {value}\r\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let start = input.find(value).unwrap();
    assert_eq!(findings[0].range().start(), start);
    assert_eq!(findings[0].range().end(), start + value.len());
    assert_eq!(findings[0].action(), Action::Redact);
}
