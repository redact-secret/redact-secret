//! Product dispositions for the credential-evidence `snapshot-2026.10.04.3`
//! failures that redact-secret#1203 collects outside #1199 to #1201 (the
//! 82 open root causes of redact-secret-benchmarks#698), driven through the
//! public default pipeline.
//!
//! The 82 root causes are 24 distinct base cases: every context.indent,
//! context.unicode-prefix and encoding.crlf variant and every metamorphic,
//! mutation and differential assertion of a base case replays with the same
//! findings, so a variant is never a separate defect. Published
//! `@redact-secret/core@0.1.0-beta.13` and the commit before this one return
//! the same findings as the beta.12 replay on all 24, so none is a beta.13
//! regression. Every input here is re-authored and synthetic; the evidence
//! case ids are pinned by name only. Three groups:
//!
//! * three in-contract false positives, fixed: the Terraform
//!   `(sensitive value)` marker, a provider-named placeholder for `exa`, and
//!   a PEM frame whose body is a placeholder name. Each has a benign
//!   input and a positive neighbour that must stay reported.
//! * contract behavior pinned as the scope decision of
//!   `decision-settle-the-open-structured-file-url-carrier-and-control-roots-of-1203`:
//!   no netrc, kubeconfig, session-cookie, SAS or signed-URL family, the
//!   bare `token` name stays unmatched, a Basic carrier is claimed without
//!   decoding, and an AWS access key id is redacted.
//! * expectations the evidence has to correct, pinned so a change of the
//!   contract is visible: the Twilio SID grammar, a `warn` on a low-entropy
//!   literal under a credential name, the escaped newline after a PEM
//!   footer, and the generic `x-api-key` header.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Whole-input findings, and the same result under every two-chunk byte
/// partition and a line-per-chunk partition.
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

fn span(input: &str, finding: &Finding) -> String {
    input[finding.range().start()..finding.range().end()].to_owned()
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

fn assert_one(input: &str, detector: &str, action: Action, spanned: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    assert_eq!(findings[0].detector(), detector, "{input:?}");
    assert_eq!(findings[0].action(), action, "{input:?}");
    assert_eq!(span(input, &findings[0]), spanned, "{input:?}");
}

/// Random-looking, unissued value with no provider marker.
const RANDOM: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGu";
const UUID: &str = "3f9a7c52-8d14-4e6b-b1a0-5c2d7e9f4a68";

// ------------------------------------------------------------ fixed (3)

#[test]
fn terraform_sensitive_marker_is_not_a_credential() {
    // Evidence case: authored-provider-neutral--terraform-apply-sensitive
    for input in [
        "password = (sensitive value)\n",
        "  ~ password                    = (sensitive value)\n",
        "      ~ tunnel1_preshared_key = (sensitive value)\n",
        "      + admin_password = (sensitive value)\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn terraform_sensitive_marker_does_not_hide_a_neighbouring_value() {
    // Positive neighbours: a real value, and the marker glued to material,
    // are not the exact marker and are reported as before.
    let real = format!("password = {RANDOM}\n");
    assert_one(&real, "generic-token", Action::Redact, RANDOM);

    let glued = format!("password = (sensitive value){RANDOM}\n");
    let findings = findings_with_parity(&glued);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Warn);

    let inside = format!("password = (sensitive value{RANDOM})\n");
    assert_eq!(findings_with_parity(&inside).len(), 1);
}

#[test]
fn exa_named_placeholders_are_excluded_like_other_listed_providers() {
    // Evidence case: exa--exa-api-key-your-key-here-placeholder
    for input in [
        "EXA_API_KEY=your_exa_api_key_here\n",
        "EXA_API_KEY=your-exa-api-key\n",
        "EXA_API_KEY=YOUR_EXA_API_KEY\n",
        "exa_api_key: replace-with-your-exa-key\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn exa_placeholder_exclusion_keeps_real_shaped_values() {
    // A placeholder glued to random material, and a real UUID key, stay
    // reported; a provider outside the closed list is still one word off.
    let glued = format!("EXA_API_KEY=your_exa_api_key_{RANDOM}\n");
    assert_eq!(findings_with_parity(&glued).len(), 1);

    let uuid = format!("EXA_API_KEY={UUID}\n");
    assert_one(&uuid, "generic-token", Action::Redact, UUID);

    assert_eq!(
        findings_with_parity("EXA_API_KEY=your_acmecloud_api_key_here\n").len(),
        1
    );
}

#[test]
fn pem_frame_with_a_placeholder_body_is_a_template() {
    // Evidence case: structured-credential-files-authored--documented-template-placeholders
    let template = concat!(
        "{\n",
        "  \"type\": \"service_account\",\n",
        "  \"private_key_id\": \"KEY_ID\",\n",
        "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nPRIVATE_KEY\\n-----END PRIVATE KEY-----\\n\",\n",
        "  \"client_email\": \"SERVICE_ACCOUNT_EMAIL\"\n",
        "}\n",
    );
    assert_clean(template);
    assert_clean(
        "{\"private_key\": \"-----BEGIN RSA PRIVATE KEY-----\\r\\nPRIVATE_KEY\\r\\n-----END RSA PRIVATE KEY-----\"}\n",
    );
}

#[test]
fn pem_frame_exclusion_keeps_a_real_or_off_list_body() {
    // A base64 body is key material: reported (and blocked as a private key).
    let body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVm";
    let real = format!(
        "{{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----\\n\"}}\n"
    );
    let findings = findings_with_parity(&real);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].detector(), "private-key");
    assert_eq!(findings[0].action(), Action::Block);

    // A name with a leftover word, or a random body, is not the template.
    for body in [RANDOM, "PRIVATE_KEY_9f2cQ7xLm4Rt", "PRIVATE KEY"] {
        let input = format!(
            "{{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----\\n\"}}\n"
        );
        assert!(!findings_with_parity(&input).is_empty(), "{body}");
    }
    // The frame must close: an unterminated frame is not a template.
    let open =
        "{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nPRIVATE_KEY\\nrest of the line\"}\n";
    assert!(!findings_with_parity(open).is_empty());
}

// -------------------------------------- scope: no declared family (13+)

#[test]
fn netrc_password_is_not_a_declared_family() {
    // Evidence cases: structured-credential-files-authored--netrc-single-line-entry,
    // --netrc-three-line-entry, --netrc-quoted-password-with-spaces,
    // --netrc-two-machines-and-default
    for input in [
        format!("machine registry.example.test login svc password {RANDOM}\n"),
        format!("machine registry.example.test\nlogin svc\npassword {RANDOM}\n"),
        format!("machine registry.example.test login \"svc user\" password \"{RANDOM} x\"\n"),
        format!(
            "machine a.example.test login a password {RANDOM}\nmachine b.example.test login b password {RANDOM}\ndefault login d password {RANDOM}\n"
        ),
    ] {
        assert_clean(&input);
    }
    // The same value under an assignment operator is claimed (contrast).
    assert_one(
        &format!("password: {RANDOM}\n"),
        "generic-token",
        Action::Redact,
        RANDOM,
    );
}

#[test]
fn kubeconfig_user_token_is_not_claimed_under_the_bare_token_name() {
    // Evidence cases: structured-credential-files-authored--kubeconfig-inline-bearer-token,
    // --kubeconfig-four-users-two-inline-secrets (the `token:` half)
    let kubeconfig = format!(
        "users:\n- name: alice\n  user:\n    token: {RANDOM}\n- name: carol\n  user:\n    username: carol\n    password: {RANDOM}\n"
    );
    let findings = findings_with_parity(&kubeconfig);
    // Only the `password:` value is claimed; the bare `token` name is not.
    assert_eq!(findings.len(), 1, "{findings:?}");
    let password_at = kubeconfig.rfind(RANDOM).unwrap();
    assert_eq!(findings[0].range().start(), password_at);
    assert_eq!(findings[0].action(), Action::Redact);
    // A prefixed token name is claimed (contrast).
    assert_one(
        &format!("    auth_token: {RANDOM}\n"),
        "generic-token",
        Action::Redact,
        RANDOM,
    );
}

#[test]
fn kubeconfig_base64_pem_client_key_is_an_encoded_carrier() {
    // Evidence case: structured-credential-files-authored--kubeconfig-client-key-data-encoded-pem
    // (decoding stays out of scope: decision-defer-encoded-input-decoding).
    // Joined at run time: base64 of a PEM frame, so no key-shaped text sits in the source.
    let encoded = [
        "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tClFV",
        "SkRSRVZHUjBoSlNrdE1UVTVQVUZGU1UxUlZWbGRZ",
        "V1Zvd01USXpORFUyTnpnNVlXSmpaR1ZtWjJocGFt",
        "dHNiVzV2Y0hGeWMzUjFkbmQ0ZVhvPQotLS0tLUVO",
        "RCBQUklWQVRFIEtFWS0tLS0tCg==",
    ]
    .concat();
    assert_clean(&format!("    client-key-data: {encoded}\n"));
}

#[test]
fn session_cookies_are_not_a_declared_family() {
    // Evidence cases: http-auth-carriers-authored--cookie-header-session-id-among-preferences,
    // --set-cookie-session-id-with-attributes
    assert_clean(&format!(
        "GET /v1/reports HTTP/1.1\nCookie: theme=dark; session_id={RANDOM}; locale=en-US\n"
    ));
    assert_clean(&format!(
        "HTTP/1.1 200 OK\nSet-Cookie: session_id={RANDOM}; Path=/; Secure; HttpOnly\n"
    ));
    // A credential-named cookie is an assignment and is claimed (contrast).
    let named = format!("Cookie: theme=dark; auth_token={RANDOM}; locale=en-US\n");
    let findings = findings_with_parity(&named);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(&named, &findings[0]), RANDOM);
}

#[test]
fn signed_urls_and_sas_tokens_are_not_declared_families() {
    // Evidence cases: url-credential-boundaries-authored--sas-token-in-config-line,
    // --s3-presigned-url-in-prose, --cloud-storage-signed-url-in-prose
    let hex64 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let sas = "blob_url = \"https://acct.blob.core.windows.net/exports/report.csv?sv=2022-11-02&se=2026-10-04T00%3A00%3A00Z&sr=b&sp=r&sig=c3ludGhldGljLW5vdC1hbi1pc3N1ZWQtc2lnbmF0dXJl\"\n";
    assert_clean(sas);

    let s3 = format!(
        "Download link: https://bucket.s3.us-east-1.amazonaws.com/report.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20261003T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature={hex64}\n"
    );
    assert_clean(&s3);

    let gcs = format!(
        "Link: https://storage.googleapis.com/bucket/report.csv?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Expires=900&X-Goog-Signature={hex64}\n"
    );
    assert_clean(&gcs);

    // Incidental, never a claim to cover the URL: an AWS access key id inside
    // `X-Amz-Credential` is claimed by its own family, and the signature that
    // makes the URL a bearer capability is left in the output.
    let with_credential = format!(
        "Download link: https://bucket.s3.us-east-1.amazonaws.com/report.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIASYNTHETICKEY0123%2F20261003%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature={hex64}\n"
    );
    let (sanitized, findings) = whole_input(&with_credential);
    assert!(
        findings
            .iter()
            .all(|finding| span(&with_credential, finding) != hex64),
        "{findings:?}"
    );
    assert!(sanitized.contains(hex64), "the signature is not claimed");
}

// -------------------- scope: carrier claimed without decoding (Basic)

#[test]
fn basic_carrier_is_claimed_without_decoding() {
    // Evidence cases: http-auth-carriers-authored--basic-empty-password,
    // --basic-rfc-published-example. The value is claimed as an
    // Authorization carrier; the product does not decode it, so "empty
    // password" and "published example" are not distinguished.
    for value in ["c3ZjLXJlcG9ydGluZzo=", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="] {
        let input = format!("GET /v1/reports HTTP/1.1\nAuthorization: Basic {value}\n");
        assert_one(&input, "generic-token", Action::Redact, value);
    }
    // The empty userinfo `:` itself is nothing to claim.
    assert_clean("GET /v1/reports HTTP/1.1\nAuthorization: Basic Og==\n");
}

#[test]
fn basic_token_cut_by_a_space_is_a_fragment() {
    // Evidence case: http-auth-carriers-authored--basic-token-split-by-space
    // (decision-define-fragmented-credentials-as-outside-the-raw-input-contract):
    // the first fragment is claimed incidentally, the rest stays in the output.
    let input = "Authorization: Basic c3ZjLXJlcG9y dGluZzpacDktc3ludGhldGljLUtkNFJtMg==\n";
    let (sanitized, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(input, &findings[0]), "c3ZjLXJlcG9y");
    assert!(sanitized.contains("dGluZzpacDktc3ludGhldGljLUtkNFJtMg=="));
}

// ------------------------- expectation corrections pinned for evidence

#[test]
fn twilio_sid_exclusion_is_the_documented_grammar_only() {
    // Evidence case: twilio-compound-credentials-authored--api-key-sid-alone
    // `SK` + 32 lowercase hex is the documented identifier (issue #746) and is
    // clean; the evidence input `SK` + 32 non-hex letters is not that shape.
    // Built at run time so no SID-shaped literal sits in the source.
    let sid = format!("SK{}", "0123456789abcdef".repeat(2));
    assert_clean(&format!("TWILIO_API_KEY={sid}\n"));
    let input = "TWILIO_API_KEY=SKSYNTHETICKEYSIDX0123456789abcdef\n";
    assert_one(
        input,
        "generic-token",
        Action::Redact,
        "SKSYNTHETICKEYSIDX0123456789abcdef",
    );
}

#[test]
fn a_literal_under_a_credential_name_warns_and_is_not_redacted() {
    // Evidence case: authored-provider-neutral--pytest-fake-fixtures
    // A low-entropy literal under a high-signal name is `medium`: reported,
    // action `warn`, text unchanged (contextual-detection.md, assignment rule).
    let input = "FAKE_TOKEN = \"test-token\"\nFAKE_SIGNING_SECRET = \"not-a-real-secret\"\n";
    let (sanitized, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Warn);
    assert_eq!(span(input, &findings[0]), "test-token");
    assert_eq!(sanitized, input);
}

#[test]
fn a_private_key_block_ends_at_its_footer_not_at_the_escaped_newline() {
    // Evidence cases: structured-credential-files-authored--service-account-key-file-minified-json,
    // --service-account-key-file-pretty-json. The escaped `\n` after the
    // footer is a line separator, as the raw newline after a raw PEM is, so it
    // stays in the output and the JSON stays valid.
    let body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVm";
    let footer = "-----END PRIVATE KEY-----";
    let input = format!(
        "{{\"private_key\":\"-----BEGIN PRIVATE KEY-----\\n{body}\\n{footer}\\n\",\"client_email\":\"svc@example.test\"}}\n"
    );
    let (sanitized, findings) = whole_input(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].detector(), "private-key");
    assert_eq!(findings[0].action(), Action::Block);
    assert!(span(&input, &findings[0]).ends_with(footer));
    assert!(
        sanitized.contains("\\n\",\"client_email\""),
        "{sanitized:?}"
    );
    assert!(!sanitized.contains(body));
}

#[test]
fn an_aws_access_key_id_is_redacted_beside_its_secret() {
    // Evidence case: structured-credential-files-authored--aws-credentials-file-two-profiles
    // Every secret span is exact; the two key ids are claimed by the
    // `aws-access-key` family, which the evidence does not list.
    // Pieces are joined at run time so no key-shaped literal sits in the source.
    let id_tail = "Q7LM2ZP9TRW4VKC8";
    let (id_a, id_b) = (["AKIA", id_tail].concat(), ["ASIA", id_tail].concat());
    let (secret_a, secret_b) = ([RANDOM, "Bt5Yw0Hk"].concat(), ["Bt5Yw0Hk", RANDOM].concat());
    let input = format!(
        "[default]\naws_access_key_id={id_a}\naws_secret_access_key={secret_a}\n\n[user1]\naws_access_key_id={id_b}\naws_secret_access_key={secret_b}\n"
    );
    let input = input.as_str();
    let (sanitized, findings) = whole_input(input);
    let spans: Vec<String> = findings.iter().map(|f| span(input, f)).collect();
    for expected in [&id_a, &secret_a, &id_b, &secret_b] {
        assert!(spans.iter().any(|s| s == expected), "{expected}: {spans:?}");
        assert!(!sanitized.contains(expected), "{expected}");
    }
}

#[test]
fn a_credential_named_header_on_any_host_is_claimed() {
    // Evidence case: exa--exa-api-key-other-host-twin. The Exa keyword gate
    // does not fire off its host; the generic `x-api-key` header assignment
    // claims a random value on every host.
    let input = format!("curl -s https://api.example.invalid/search -H \"x-api-key: {UUID}\"\n");
    assert_one(&input, "generic-token", Action::Redact, UUID);
}

// ---------------------------------------------- the case table is pinned

/// The 24 base cases behind the 82 open root causes, by evidence id, with
/// the disposition each is pinned under. A case that is added, removed or
/// re-dispositioned changes this table and the decision record together.
const CASES: &[(&str, &str)] = &[
    (
        "authored-provider-neutral--pytest-fake-fixtures",
        "warn-by-design",
    ),
    (
        "authored-provider-neutral--terraform-apply-sensitive",
        "fixed",
    ),
    ("exa--exa-api-key-other-host-twin", "expectation"),
    ("exa--exa-api-key-your-key-here-placeholder", "fixed"),
    (
        "http-auth-carriers-authored--basic-empty-password",
        "expectation",
    ),
    (
        "http-auth-carriers-authored--basic-rfc-published-example",
        "expectation",
    ),
    (
        "http-auth-carriers-authored--basic-token-split-by-space",
        "fragment",
    ),
    (
        "http-auth-carriers-authored--cookie-header-session-id-among-preferences",
        "unsupported",
    ),
    (
        "http-auth-carriers-authored--set-cookie-session-id-with-attributes",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--aws-credentials-file-two-profiles",
        "expectation",
    ),
    (
        "structured-credential-files-authored--documented-template-placeholders",
        "fixed",
    ),
    (
        "structured-credential-files-authored--kubeconfig-client-key-data-encoded-pem",
        "encoded",
    ),
    (
        "structured-credential-files-authored--kubeconfig-four-users-two-inline-secrets",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--kubeconfig-inline-bearer-token",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--netrc-quoted-password-with-spaces",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--netrc-single-line-entry",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--netrc-three-line-entry",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--netrc-two-machines-and-default",
        "unsupported",
    ),
    (
        "structured-credential-files-authored--service-account-key-file-minified-json",
        "expectation",
    ),
    (
        "structured-credential-files-authored--service-account-key-file-pretty-json",
        "expectation",
    ),
    (
        "twilio-compound-credentials-authored--api-key-sid-alone",
        "expectation",
    ),
    (
        "url-credential-boundaries-authored--cloud-storage-signed-url-in-prose",
        "unsupported",
    ),
    (
        "url-credential-boundaries-authored--s3-presigned-url-in-prose",
        "unsupported",
    ),
    (
        "url-credential-boundaries-authored--sas-token-in-config-line",
        "unsupported",
    ),
];

#[test]
fn the_case_table_has_one_row_per_base_case() {
    assert_eq!(CASES.len(), 24);
    let mut ids: Vec<&str> = CASES.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 24);
    let count = |kind: &str| CASES.iter().filter(|(_, d)| *d == kind).count();
    assert_eq!(count("fixed"), 3);
    assert_eq!(count("unsupported"), 11);
    assert_eq!(count("expectation"), 7);
    assert_eq!(count("fragment") + count("encoded"), 2);
    assert_eq!(count("warn-by-design"), 1);
}
