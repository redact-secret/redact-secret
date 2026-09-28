//! Issue #911 through the public API with the full default registry: the
//! secret-*reference* shapes behind the untargeted benign-corpus finding
//! (benchmarks #378) produce no finding, and a random literal in the same
//! position is still redacted.
//!
//! Every input is independently re-authored for this test (not copied from
//! the benchmark fixtures), and every "literal" is synthetic filler built at
//! run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::Action;
use support::whole_input;

fn literal() -> String {
    (0..32)
        .map(|i| char::from(b"aZ3kQ9xL2mV7pR4tW8nB5cD1fG6hJ0sY"[(i * 11 + 3) % 32]))
        .collect()
}

/// `(benign file, the same file with a literal in the reference's place)`.
fn shapes() -> Vec<(&'static str, String, String)> {
    let v = literal();
    vec![
        (
            "helm existingSecret",
            "postgresql:\n  auth:\n    existingSecret: orders-db-credentials\n    secretKeys:\n      adminPasswordKey: admin-password\n".to_owned(),
            format!("postgresql:\n  auth:\n    webhookSecret: {v}\n"),
        ),
        (
            "external-secret secretKey",
            "spec:\n  target:\n    name: orders-env\n  data:\n    - secretKey: ORDERS_DB_PASSWORD\n      remoteRef:\n        key: prod/orders/db\n        property: password\n".to_owned(),
            format!("spec:\n  data:\n    - secretKey: {v}\n"),
        ),
        (
            "agent summary (Korean)",
            "- 주문 서비스 차트에서 `existingSecret: orders-db-credentials` 를 사용하도록 바꿨습니다.\n".to_owned(),
            format!("- 주문 서비스 설정에 `clientSecret: {v}` 를 넣었습니다.\n"),
        ),
        (
            "swift keychain identifiers",
            "enum VaultItem: String {\n    case sessionToken = \"com.example.orders.sessionToken\"\n    case signingSecret = \"com.example.orders.signingSecret\"\n    case adminPassword = \"com.example.orders.adminPassword\"\n}\n".to_owned(),
            format!("enum VaultItem: String {{\n    case sessionToken = \"{v}\"\n}}\n"),
        ),
        (
            "ansible vault lookup",
            "orders_api_token: \"{{ lookup('community.hashi_vault.hashi_vault', 'secret=kv/data/orders:api_token') }}\"\n".to_owned(),
            format!("orders_api_token: \"{{{{ lookup('community.hashi_vault.hashi_vault', 'secret={v}') }}}}\"\n"),
        ),
        (
            "lua secret lookup",
            "local secret = secrets:get(partner_id)\nreturn hmac(secret, body)\n".to_owned(),
            format!("local secret = \"{v}\"\nreturn hmac(secret, body)\n"),
        ),
        (
            "python constant kwarg",
            "def test_verify():\n    assert verify(body, signing_secret=TEST_SIGNING_SECRET)\n".to_owned(),
            format!("def test_verify():\n    assert verify(body, signing_secret=\"{v}\")\n"),
        ),
    ]
}

#[test]
fn reference_shapes_produce_no_finding() {
    for (label, benign, _) in shapes() {
        let (text, findings) = whole_input(&benign);
        assert!(findings.is_empty(), "{label}: {findings:?}");
        assert_eq!(text, benign, "{label}");
    }
}

#[test]
fn a_literal_in_the_same_position_is_still_redacted() {
    let v = literal();
    for (label, _, twin) in shapes() {
        let (text, findings) = whole_input(&twin);
        assert_eq!(findings.len(), 1, "{label}: {findings:?}");
        assert_eq!(findings[0].action(), Action::Redact, "{label}");
        assert!(!text.contains(&v), "{label}");
    }
}
