//! Product dispositions for the credential-evidence `snapshot-2026.10.04.4`
//! root causes that core had not classified (redact-secret#1205, follow-up to
//! #1203; the 57 open root causes of redact-secret-benchmarks#698 / PR #703),
//! driven through the public default pipeline.
//!
//! The 57 root causes are 24 distinct base cases: every context.indent,
//! context.unicode-prefix and encoding.crlf variant, every metamorphic or
//! mutation assertion and every peer occurrence of a base case replays with
//! the same findings, so a variant is never a separate defect. Published
//! `@redact-secret/core@0.1.0-beta.13` and `main` at 1e45cecf return the same
//! findings, sanitized output and UTF-8 byte ranges on all 24 (and on all 70
//! added cases), so none is a beta.13 regression. Every input here is
//! re-authored and synthetic; the evidence case ids are pinned by name only.
//!
//! * two in-contract false positives, fixed: the `${NAME:?message}`
//!   required-variable message, and a value that is the assigned name itself.
//!   Each has a benign input and a positive neighbour that stays reported.
//! * contract behavior pinned as the scope decision of
//!   `decision-settle-the-snapshot-2026-10-04-4-added-case-roots`: a token
//!   behind a percent-encoded delimiter (`%22`), a JSON `{"name", "value"}`
//!   pair and a parent-keyed `{"value"}` object, an HTTP session cookie, a
//!   credential split across array elements, and a backslash-escaped line
//!   break that ends a masked value.
//! * the fragment and base64/hex sendgrid cases already pinned by
//!   `evidence_snapshot_2026_10_04_3_1199_1200_1201.rs` stay in the table.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Whole-input findings, and the same result under every two-chunk UTF-8 byte
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
/// A unissued SendGrid-shaped key: `SG.` + 22 + `.` + 43.
const SENDGRID: &str = "SG.SYNTHETICGQLVARSA00000.NEVER-ISSUED-EXAMPLE-GQL-VARIABLES-A-000000";
/// 40 `[A-Za-z0-9/+]` with mixed case, under an AWS secret access key name.
const AWS_SECRET: &str = "SYNTHETICNBSOURCEARRAYNEVERISSUED000+/Ab";

// ------------------------------------------------------------ fixed (2)

#[test]
fn compose_required_variable_message_is_not_a_credential() {
    // Evidence case: docker-compose-resolution-authored--required-message
    for input in [
        "services:\n  web:\n    environment:\n      GITHUB_TOKEN: ${GITHUB_TOKEN:?GITHUB_TOKEN must be set}\n",
        "      SERVICE_API_KEY: ${SERVICE_API_KEY:?SERVICE_API_KEY is required}\n",
        "      SERVICE_API_KEY: \"${SERVICE_API_KEY:?SERVICE_API_KEY must be set}\"\n",
        "      SERVICE_API_KEY=${SERVICE_API_KEY:?SERVICE_API_KEY must be set}\n",
        "      SERVICE_API_KEY: ${SERVICE_API_KEY:?err}\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn compose_required_variable_exclusion_keeps_a_default_and_a_literal() {
    // A `:-` default is a literal a person can paste a credential into: it
    // stays reported, as the `default-literal` evidence case requires.
    let default = format!("      DB_PASSWORD: ${{DB_PASSWORD:-{RANDOM}}}\n");
    let findings = findings_with_parity(&default);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Redact);

    // The same message text as a plain value, with no `${` before the name.
    let plain = format!("      DB_PASSWORD: {RANDOM}\n");
    assert_one(&plain, "generic-token", Action::Redact, RANDOM);
    let colon = format!("DB_PASSWORD:?{RANDOM}\n");
    assert_eq!(findings_with_parity(&colon).len(), 1);
}

#[test]
fn a_value_that_is_its_own_assigned_name_is_a_reference() {
    // Evidence case:
    // jupyter-notebook-files-authored--same-value-in-source-stream-result-json-error-and-traceback
    // (the `{"aws_secret_access_key": aws_secret_access_key}` source line
    // beside the secret's own spans).
    for input in [
        "aws_secret_access_key = aws_secret_access_key\n",
        "x = {\"aws_secret_access_key\": aws_secret_access_key}\n",
        "x = {\"awsSecretAccessKey\": aws_secret_access_key}\n",
        "{\\\"aws_secret_access_key\\\": aws_secret_access_key}\n",
        "DB_PASSWORD=db_password\n",
    ] {
        assert_clean(input);
    }

    // The notebook line next to a real value: only the real value is found.
    let notebook = format!(
        "print(\\\"aws_secret_access_key=\\\" + aws_secret_access_key)\n\
         aws_secret_access_key = \"{AWS_SECRET}\"\n\
         x = {{\"aws_secret_access_key\": aws_secret_access_key}}\n"
    );
    let findings = findings_with_parity(&notebook);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(&notebook, &findings[0]), AWS_SECRET);
}

#[test]
fn self_reference_exclusion_keeps_other_identifiers_and_real_values() {
    // Another variable name, or the name with material glued to it, is not
    // the exact name and keeps the existing reading.
    assert_one(
        "aws_secret_access_key = other_secret_access_key\n",
        "generic-token",
        Action::Redact,
        "other_secret_access_key",
    );
    let glued = format!("aws_secret_access_key = aws_secret_access_key_{RANDOM}\n");
    assert_eq!(findings_with_parity(&glued).len(), 1);
    assert_one(
        &format!("aws_secret_access_key = \"{AWS_SECRET}\"\n"),
        "aws-secret-access-key",
        Action::Redact,
        AWS_SECRET,
    );
}

// ------------------------------- scope: carriers the contract does not read

#[test]
fn a_token_behind_a_percent_encoded_delimiter_is_an_encoded_carrier() {
    // Evidence case: graphql-requests-and-responses-authored--get-url-variables-value.
    // The key is contiguous, but the JSON quote around it is `%22`, so the
    // byte before it is the `2` of the escape. Percent-encoded input is not
    // decoded (`decision-defer-encoded-input-decoding`), and no family
    // treats `%XX` as a boundary.
    let url = format!(
        "GET /graphql?query=query%20Login&operationName=Login&variables=%7B%22apiKey%22%3A%22{SENDGRID}%22%7D HTTP/1.1\n"
    );
    assert_clean(&url);
    assert_clean(&format!("%22{SENDGRID}%22\n"));
    assert_clean(&format!("%3A%22ghp_{RANDOM}%22\n"));

    // The same key behind a raw delimiter is claimed, in a query parameter
    // and inside an escaped JSON string.
    assert_one(
        &format!("GET /graphql?apiKey={SENDGRID}&x=1 HTTP/1.1\n"),
        "sendgrid-token",
        Action::Redact,
        SENDGRID,
    );
    assert_one(
        &format!("{{\"variables\": \"{{\\\"apiKey\\\":\\\"{SENDGRID}\\\"}}\"}}\n"),
        "sendgrid-token",
        Action::Redact,
        SENDGRID,
    );
}

#[test]
fn a_json_name_value_pair_is_not_an_assignment() {
    // Evidence cases: har-exports-authored--bearer-token-in-postdata-params
    // and the `queryString` array of
    // har-exports-authored--bearer-token-in-url-and-querystring-array.
    // The name and the value are two members of one object. Only the YAML
    // `env` pairing of #1016 reads a sibling name, and only on adjacent
    // lines.
    let value = "synthetic.har.bearer-token_0123456789abd";
    for input in [
        format!("{{ \"name\": \"access_token\", \"value\": \"{value}\" }}\n"),
        format!(
            "[{{ \"name\": \"access_token\", \"value\": \"{value}\" }}, {{ \"name\": \"p\", \"value\": \"q\" }}]\n"
        ),
        format!("{{\n  \"name\": \"password\",\n  \"value\": \"{RANDOM}\"\n}}\n"),
    ] {
        assert_clean(&input);
    }

    // In the same HAR entry the `url` string carries the pair as a query
    // parameter, which is an assignment and is claimed exactly.
    let url = format!(
        "{{ \"url\": \"https://api.example.test/resource?access_token={value}&p=q\", \"queryString\": [{{ \"name\": \"access_token\", \"value\": \"{value}\" }}] }}\n"
    );
    let findings = findings_with_parity(&url);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Redact);
    assert_eq!(span(&url, &findings[0]), value);

    // The one-member form is an assignment.
    assert_one(
        &format!("{{ \"access_token\": \"{value}\" }}\n"),
        "generic-token",
        Action::Redact,
        value,
    );
}

#[test]
fn an_http_session_cookie_in_a_har_is_not_a_declared_family() {
    // Evidence case: har-exports-authored--session-cookie-in-headers-and-cookies-arrays.
    // `decision-settle-the-open-structured-file-url-carrier-and-control-roots-of-1203`
    // declares no session-cookie family; here the cookie is also a name/value
    // object pair.
    for input in [
        format!("{{ \"name\": \"Cookie\", \"value\": \"theme=dark; session_id={RANDOM}\" }}\n"),
        format!(
            "{{ \"name\": \"Set-Cookie\", \"value\": \"session_id={RANDOM}; Path=/; HttpOnly\" }}\n"
        ),
        format!("\"cookies\": [{{ \"name\": \"session_id\", \"value\": \"{RANDOM}\" }}]\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn a_value_under_a_credential_named_parent_object_is_not_an_assignment() {
    // Evidence case: hashicorp-terraform-authored--state-json-output-password-with-sensitive-true.
    // The credential name keys an object whose `value` member holds the
    // string; the `"sensitive": true` flag is a hint only a JSON reader can
    // use. The one-line `"password": "..."` of a resource is claimed.
    let output = format!(
        "{{\n  \"outputs\": {{\n    \"db_admin_password\": {{\n      \"value\": \"{RANDOM}\",\n      \"type\": \"string\",\n      \"sensitive\": true\n    }}\n  }}\n}}\n"
    );
    assert_clean(&output);

    let resource = format!("{{ \"values\": {{ \"password\": \"{RANDOM}\" }} }}\n");
    assert_one(&resource, "generic-token", Action::Redact, RANDOM);
}

#[test]
fn a_secret_split_across_notebook_array_elements_is_a_fragment() {
    // Evidence case: jupyter-notebook-files-authored--source-value-split-between-array-elements.
    // `decision-define-fragmented-credentials-as-outside-the-raw-input-contract`:
    // the literal is cut by the array's `",\n    "` element boundary.
    let (head, tail) = AWS_SECRET.split_at(17);
    let split = format!(
        "  \"source\": [\n    \"aws_secret_access_key = \\\"{head}\",\n    \"{tail}\\\"\\n\"\n  ]\n"
    );
    assert_clean(&split);

    let whole =
        format!("  \"source\": [\n    \"aws_secret_access_key = \\\"{AWS_SECRET}\\\"\\n\"\n  ]\n");
    assert_one(&whole, "aws-secret-access-key", Action::Redact, AWS_SECRET);
}

#[test]
fn a_masked_value_ended_by_an_escaped_line_break_is_warned_not_excluded() {
    // Evidence case: jupyter-notebook-files-authored--stdout-mask-where-source-has-environment-reference.
    // Backslash-escaped input is not decoded: the backslash and `n` of a
    // JSON-escaped line break are two value bytes, so the run is `****...\n`
    // and no longer a mask (`non_secret_values_993`). The finding is
    // `medium`, action `warn`, text unchanged.
    let mask = "*".repeat(40);
    let escaped = format!("\"text\": [\"aws_secret_access_key={mask}\\n\"]\n");
    let findings = findings_with_parity(&escaped);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].detector(), "generic-token");
    assert_eq!(findings[0].action(), Action::Warn);

    // The same mask ended by a real line break, or by the closing quote, is
    // excluded.
    assert_clean(&format!("aws_secret_access_key={mask}\n"));
    assert_clean(&format!("\"text\": [\"aws_secret_access_key={mask}\"]\n"));
}

// ---------------------------------------------- the case table is pinned

/// The 24 base cases behind the 57 open root causes, by evidence id, with the
/// disposition each is pinned under. A case that is added, removed or
/// re-dispositioned changes this table and the decision record together.
const CASES: &[(&str, &str)] = &[
    (
        "docker-compose-resolution-authored--required-message",
        "fixed",
    ),
    (
        "jupyter-notebook-files-authored--same-value-in-source-stream-result-json-error-and-traceback",
        "fixed",
    ),
    (
        "graphql-requests-and-responses-authored--get-url-variables-value",
        "encoded",
    ),
    (
        "har-exports-authored--bearer-token-in-postdata-params",
        "unsupported",
    ),
    (
        "har-exports-authored--bearer-token-in-url-and-querystring-array",
        "unsupported",
    ),
    (
        "har-exports-authored--session-cookie-in-headers-and-cookies-arrays",
        "unsupported",
    ),
    (
        "hashicorp-terraform-authored--state-json-output-password-with-sensitive-true",
        "unsupported",
    ),
    (
        "jupyter-notebook-files-authored--source-value-split-between-array-elements",
        "fragment",
    ),
    (
        "jupyter-notebook-files-authored--stdout-mask-where-source-has-environment-reference",
        "escaped-text",
    ),
    (
        "line-break-and-fragment-authored--key-split-across-javascript-added-literals",
        "fragment",
    ),
    (
        "line-break-and-fragment-authored--key-split-before-last-character-by-shell-continuation",
        "fragment",
    ),
    (
        "line-break-and-fragment-authored--key-split-by-backslash-crlf-continuation",
        "fragment",
    ),
    (
        "line-break-and-fragment-authored--key-split-by-unquoted-shell-continuation",
        "fragment",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-base64-standard-padded-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-base64-standard-padded-in-json",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-base64-standard-padded-three-layers-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-base64-url-safe-unpadded-of-base64-standard-padded-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-base64-url-safe-unpadded-of-hex-upper-of-base64-standard-padded-in-json",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-lower-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-lower-of-base64-standard-padded-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-lower-of-hex-lower-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-mixed-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-upper-in-env",
        "encoded",
    ),
    (
        "base64-hex-representation-projections--sendgrid-key-hex-upper-in-json",
        "encoded",
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
    assert_eq!(count("fixed"), 2);
    assert_eq!(count("unsupported"), 4);
    assert_eq!(count("fragment"), 5);
    assert_eq!(count("escaped-text"), 1);
    assert_eq!(count("encoded"), 12);
}
