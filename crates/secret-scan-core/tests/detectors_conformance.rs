//! Representative overlap cases from the shared conformance corpus
//! (`conformance/fixtures/synchronous-corpus.json`). Fixture ids are named in
//! each test so they can be cross-referenced against the corpus.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Action, ByteRange, Confidence, DefaultPolicy, DetectorRegistry, default_placeholder_formatter,
    run_detector_pipeline, scan, scan_and_redact,
};

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start, end).unwrap()
}

/// fixture: jwt-overlap-bearer / bearer-overlap-jwt
///
/// Registry order deterministically selects the structured JWT over the
/// broader Bearer candidate.
#[test]
fn structured_jwt_displaces_the_broader_bearer_candidate() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = "Authorization: Bearer eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";

    let findings = run_detector_pipeline(input, &registry).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector(), "jwt");
    assert_eq!(findings[0].type_name(), "jwt");
    assert_eq!(findings[0].confidence(), Confidence::High);
    assert_eq!(findings[0].range(), range(22, 101));
}

/// fixture: contextual-overlap-provider
///
/// A contextual candidate yields to a higher-specificity provider candidate
/// even though `generic-token` also proposes a (lower-specificity) span for
/// the same value.
#[test]
fn contextual_candidate_yields_to_a_higher_specificity_provider_candidate() {
    let input = "client_secret=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";
    let provider_range = range(14, input.len());

    let registry = DetectorRegistry::with_built_in([]).unwrap();

    let findings = run_detector_pipeline(input, &registry).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector(), "openai-token");
    assert_eq!(findings[0].type_name(), "openai_api_key");
    assert_eq!(findings[0].range(), provider_range);
}

/// fixture: contextual-overlap-nested-assignment
///
/// Two contextual assignment candidates overlap. The narrower inner value
/// wins the span-width tie breaker and the default policy redacts that exact
/// range.
#[test]
fn narrower_contextual_candidate_wins_and_redacts() {
    let input = "client_secret=\"SYNTHETIC_REVOKED_OUTER_MARKER; api_key=SYNTHETIC_REVOKED_CONTEXT_OVERLAP_1234\"";
    let registry = DetectorRegistry::with_built_in([]).unwrap();

    let result = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].detector(), "generic-token");
    assert_eq!(result.findings()[0].type_name(), "contextual_secret");
    assert_eq!(result.findings()[0].confidence(), Confidence::High);
    assert_eq!(result.findings()[0].range(), range(55, 93));
    assert_eq!(result.findings()[0].action(), Action::Redact);
    assert_eq!(
        result.text(),
        "client_secret=\"SYNTHETIC_REVOKED_OUTER_MARKER; api_key=<SECRET_1>\""
    );
}

/// fixture: authorization-overlap-contextual-assignment
///
/// The structural Token authorization candidate wins over the nested
/// contextual assignment candidate, and the default policy redacts the whole
/// authorization value selected by overlap resolution.
#[test]
fn authorization_candidate_wins_contextual_overlap_and_redacts() {
    let input = "Authorization: Token api_key=SYNTHETIC_REVOKED_AUTHORIZATION_OVERLAP_1234";
    let registry = DetectorRegistry::with_built_in([]).unwrap();

    let result = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].detector(), "generic-token");
    assert_eq!(result.findings()[0].type_name(), "authorization_credential");
    assert_eq!(result.findings()[0].confidence(), Confidence::High);
    assert_eq!(result.findings()[0].range(), range(21, 73));
    assert_eq!(result.findings()[0].action(), Action::Redact);
    assert_eq!(result.text(), "Authorization: Token <SECRET_1>");
}

/// fixture: bearer-overlap-contextual-assignment
///
/// The Bearer detector's structural candidate wins over the wider contextual
/// assignment candidate, and the default policy redacts exactly the winning
/// token range.
#[test]
fn bearer_candidate_wins_contextual_overlap_and_redacts() {
    let input = "auth = \"Bearer SYNTHETIC_REVOKED_BEARER_OVERLAP_1234\"";
    let registry = DetectorRegistry::with_built_in([]).unwrap();

    let result = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].detector(), "bearer-token");
    assert_eq!(result.findings()[0].type_name(), "bearer_token");
    assert_eq!(result.findings()[0].confidence(), Confidence::High);
    assert_eq!(result.findings()[0].range(), range(15, 52));
    assert_eq!(result.findings()[0].action(), Action::Redact);
    assert_eq!(result.text(), "auth = \"Bearer <SECRET_1>\"");
}

/// fixture: jwt-positive-structured, bearer-positive-scheme,
/// contextual-positive-assignment
///
/// The three built-in detectors run together without interfering with each
/// other's disjoint spans.
#[test]
fn disjoint_findings_from_every_built_in_detector_all_survive() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE\nBearer SYNTHETIC_REVOKED_BEARER_VALUE";

    let findings = run_detector_pipeline(input, &registry).unwrap();

    let mut by_detector: Vec<&str> = findings
        .iter()
        .map(redact_secret::DetectedFinding::detector)
        .collect();
    by_detector.sort_unstable();
    assert_eq!(by_detector, ["bearer-token", "generic-token"]);
}

// --- issue #107: deepened private-key and JWT grammar coverage ------------
//
// The corpus fixtures above prove *detection*: the right span, at the right
// confidence and specificity. The default policy's block/redact outcome is a
// separate decision layered on top (`src/policy.rs`), so it is asserted here
// explicitly, through the real built-in detectors and `DefaultPolicy`
// together, for the deepened grammar forms added alongside these tests.

/// fixture: private-key-positive-crlf-line-endings,
/// private-key-positive-openssh-multiline-body,
/// private-key-positive-dsa-label, private-key-positive-encrypted-label
///
/// Every accepted label and line-ending variant still blocks under the
/// default policy, not merely gets detected.
#[test]
fn every_deepened_private_key_grammar_variant_blocks_under_default_policy() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        "-----BEGIN PRIVATE KEY-----\r\nU1lOVEhFVElDX0NSTEZfVEVSTUlOQVRJT04=\r\n-----END PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nU1lOVEhFVElDX09QRU5TU0hf\nTVVMVElMSU5FX0JPRFlfVEVS\nTUlOQVRJT05fRVhBTVBMRQ==\n-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----\nU1lOVEhFVElDX0RTQV9SRVZPS0VE\n-----END DSA PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nU1lOVEhFVElDX0VOQ1JZUFRFRA==\n-----END ENCRYPTED PRIVATE KEY-----",
    ];

    for input in inputs {
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1, "{input}");
        assert_eq!(findings[0].type_name(), "private_key", "{input}");
        assert_eq!(findings[0].action(), Action::Block, "{input}");
    }
}

/// fixture: jwt-boundary-two-segments, jwt-boundary-four-segments,
/// jwt-boundary-standard-base64-alphabet, jwt-boundary-base64-padding,
/// jwt-negative-colon-delimiter, jwt-negative-payload-not-json-prefixed
///
/// Every structural near miss in segment count, alphabet, padding, and
/// delimiter produces no finding at all through the full built-in registry,
/// so there is no policy outcome and no overlap candidate left behind for
/// another detector to misclassify.
#[test]
fn structural_jwt_near_misses_produce_no_finding_through_the_full_registry() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA",
        "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE.EXTRA",
        "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNf+EFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE",
        "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA==.SYNTHETIC_REVOKED_SIGNATURE",
        "eyJTWU5USEVUSUNfSEVBREVS:eyJTWU5USEVUSUNfUEFZTE9BRA:SYNTHETIC_REVOKED_SIGNATURE",
        "eyJTWU5USEVUSUNfSEVBREVS.QUJDREVGR0hJSktMTU5PUA.SYNTHETIC_REVOKED_SIGNATURE",
    ];

    for input in inputs {
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings, Vec::new(), "{input}");
    }
}

/// fixture: jwt-overlap-bearer / bearer-overlap-jwt
///
/// Extends `structured_jwt_displaces_the_broader_bearer_candidate` (above)
/// through the default policy: the surviving JWT candidate redacts, and the
/// displaced Bearer candidate leaves no separate finding behind for the
/// policy to act on.
#[test]
fn structured_jwt_overlap_winner_redacts_under_default_policy() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = "Authorization: Bearer eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";

    let findings = scan(input, &registry, &DefaultPolicy).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].type_name(), "jwt");
    assert_eq!(findings[0].range(), range(22, 101));
    assert_eq!(findings[0].action(), Action::Redact);
}

// --- issue #108: deepened connection-string scheme and escaping coverage --
//
// `connection_string.rs`'s own unit tests and the corpus fixtures cited below
// prove *detection* for every previously-unresolved scheme
// (`postgresql`, `mysql`, `mariadb`, `mongodb+srv`, `rediss`, `amqp`,
// `amqps`). This asserts the always-redact policy outcome
// (`docs/coverage/detector-inventory.json`'s `connection_string_password`
// row) holds for a representative sample of them too, not merely detection.

/// fixture: connection-positive-postgresql, connection-positive-mariadb-percent-encoded,
/// connection-positive-mongodb-srv, connection-positive-rediss-fragment,
/// connection-positive-amqp-query, connection-positive-amqps
///
/// Every newly-evidenced scheme still redacts under the default policy, not
/// merely gets detected.
#[test]
fn every_newly_evidenced_scheme_redacts_under_default_policy() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        "postgresql://fixture:SYNTHETIC_REVOKED_DB_VALUE@db.example.test:5432/db",
        "mariadb://fixture:SYNTHETIC%3AREVOKED@db.example.test:3306/db",
        "mongodb+srv://fixture:SYNTHETIC_REVOKED_DB_VALUE@cluster0.example.mongodb.net/db",
        "rediss://:SYNTHETIC_REVOKED_DB_VALUE@cache.example.test:6380#primary",
        "amqp://fixture:SYNTHETIC_REVOKED_DB_VALUE@rabbit.example.test:5672?heartbeat=30",
        "amqps://fixture:SYNTHETIC_REVOKED_DB_VALUE@rabbit.example.test:5671/vh",
    ];

    for input in inputs {
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1, "{input}");
        assert_eq!(
            findings[0].type_name(),
            "connection_string_password",
            "{input}"
        );
        assert_eq!(findings[0].action(), Action::Redact, "{input}");
    }
}

/// fixture: connection-boundary-mongodb-unicode-host, connection-boundary-redis-unescaped-at,
/// connection-boundary-mariadb-unescaped-slash, connection-boundary-postgresql-malformed-ipv6
///
/// Every escaping/host-grammar boundary case produces no finding at all
/// through the full built-in registry, so there is no policy outcome and no
/// overlap candidate left behind for another detector to misclassify.
#[test]
fn connection_string_escaping_boundaries_produce_no_finding_through_the_full_registry() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        "mongodb://fixture:SYNTHETIC_REVOKED_DB_VALUE@café.example.test:27017/db",
        "redis://:pass@word@cache.example.test:6379/0",
        "mariadb://fixture:pa/ss@db.example.test/example",
        "postgresql://fixture:SYNTHETIC_REVOKED_DB_VALUE@[2001:db8::g]/example",
    ];

    for input in inputs {
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings, Vec::new(), "{input}");
    }
}

// --- issue #161: Azure Storage connection strings --------------------------
//
// `connection_string.rs`'s own unit tests and the corpus fixtures cited below
// prove *detection* for the Azure Storage `DefaultEndpointsProtocol=...;
// AccountKey=...` grammar, a distinct semicolon-delimited key=value form
// alongside this file's `scheme://` authorities. This asserts the
// always-redact policy outcome holds for it too, and that its declared
// boundary and near-miss cases produce no finding through the full registry.

const AZURE_ACCOUNT_NAME: &str = "fixturestorageaccount";
/// fixture: connection-positive-azure-https, connection-positive-azure-http,
/// connection-positive-azure-sovereign-suffix,
/// connection-boundary-azure-reordered-fields
///
/// Base64 decodes to
/// `SYNTHETIC-REVOKED-AZURE-STORAGE-ACCOUNT-KEY-FIXTURE-0000000000`.
const AZURE_ACCOUNT_KEY: &str =
    "U1lOVEhFVElDLVJFVk9LRUQtQVpVUkUtU1RPUkFHRS1BQ0NPVU5ULUtFWS1GSVhUVVJFLTAwMDAwMDAwMDA=";

/// fixture: connection-positive-azure-https, connection-positive-azure-http,
/// connection-positive-azure-sovereign-suffix,
/// connection-boundary-azure-reordered-fields
///
/// Every protocol variant, recognized `EndpointSuffix`, and field order
/// still redacts under the default policy, not merely gets detected.
#[test]
fn every_azure_storage_connection_string_variant_redacts_under_default_policy() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        format!(
            "DefaultEndpointsProtocol=https;AccountName={AZURE_ACCOUNT_NAME};AccountKey={AZURE_ACCOUNT_KEY};EndpointSuffix=core.windows.net"
        ),
        format!(
            "DefaultEndpointsProtocol=http;AccountName={AZURE_ACCOUNT_NAME};AccountKey={AZURE_ACCOUNT_KEY};EndpointSuffix=core.windows.net"
        ),
        format!(
            "DefaultEndpointsProtocol=https;AccountName={AZURE_ACCOUNT_NAME};AccountKey={AZURE_ACCOUNT_KEY};EndpointSuffix=core.usgovcloudapi.net"
        ),
        format!(
            "AccountName={AZURE_ACCOUNT_NAME};EndpointSuffix=core.windows.net;AccountKey={AZURE_ACCOUNT_KEY};DefaultEndpointsProtocol=https"
        ),
    ];

    for input in inputs {
        let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1, "{input}");
        assert_eq!(
            findings[0].type_name(),
            "connection_string_password",
            "{input}"
        );
        assert_eq!(findings[0].action(), Action::Redact, "{input}");
    }
}

/// fixture: connection-boundary-azure-missing-key-value,
/// connection-boundary-azure-malformed-base64,
/// connection-negative-azure-account-name-only,
/// connection-negative-azure-unrelated-semicolon-config
///
/// A present-but-empty `AccountKey`, a malformed base64 value, a connection
/// string missing the field entirely, and an unrelated semicolon-delimited
/// grammar (a SQL Server ADO.NET connection string) all produce no finding
/// at all through the full built-in registry.
#[test]
fn azure_storage_boundaries_and_near_misses_produce_no_finding_through_the_full_registry() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let inputs = [
        format!(
            "DefaultEndpointsProtocol=https;AccountName={AZURE_ACCOUNT_NAME};AccountKey=;EndpointSuffix=core.windows.net"
        ),
        format!(
            "DefaultEndpointsProtocol=https;AccountName={AZURE_ACCOUNT_NAME};AccountKey=not-a-valid-base64-key!!;EndpointSuffix=core.windows.net"
        ),
        format!(
            "DefaultEndpointsProtocol=https;AccountName={AZURE_ACCOUNT_NAME};EndpointSuffix=core.windows.net"
        ),
        "Server=tcp:fixture.database.windows.net,1433;Database=fixturedb;IntegratedSecurity=true;Encrypt=true;TrustServerCertificate=false;"
            .to_string(),
    ];

    for input in inputs {
        let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings, Vec::new(), "{input}");
    }
}
