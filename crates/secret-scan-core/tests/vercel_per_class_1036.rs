//! Issue #1036: `vercel-token` reports one finding type per credential class,
//! through the public API with the full default registry.
//!
//! Every token is built at run time from a literal prefix plus a
//! low-entropy synthetic filler (a fixed stem, then `0` padding), so no
//! realistic token literal is committed. The filler was never derived from
//! an issued credential.
//!
//! - `vcp_`, `vca_` and `vcr_` + exactly 56 `[A-Za-z0-9]` yield exactly one
//!   finding of their own type, at exactly the token's span, redacted, in
//!   every host context, winning the overlap with `contextual_secret`,
//!   `bearer_token` and every other built-in;
//! - `vci_` and `vck_` keep the pre-split `vercel_token` shape and type;
//! - a `vcp_`/`vca_`/`vcr_` value off the exact contract (body 55/57, `_` or
//!   `-` in the body, a glued suffix) falls back to `vercel_token`, whole and
//!   redacted, in every context including bare and prose: security-first, no
//!   redaction present before #1036 is lost;
//! - marker twins, leading glue and benign siblings yield no `vercel-token`
//!   finding;
//! - classes never borrow each other's type;
//! - every two-chunk partition of a line matches the whole input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

const DETECTOR: &str = "vercel-token";

const TYPED: [(&str, &str); 3] = [
    ("vcp_", "vercel_personal_access_token"),
    ("vca_", "vercel_app_access_token"),
    ("vcr_", "vercel_app_refresh_token"),
];

const INTERIM: [&str; 2] = ["vci_", "vck_"];

/// Low-entropy synthetic filler.
fn body(len: usize) -> String {
    const STEM: &[u8] = b"SyntheticRevokedVercelFixture";
    (0..len)
        .map(|i| char::from(*STEM.get(i).unwrap_or(&b'0')))
        .collect()
}

fn token(prefix: &str) -> String {
    format!("{prefix}{}", body(56))
}

fn contexts(key: &str) -> Vec<String> {
    vec![
        key.to_owned(),
        format!("VERCEL_TOKEN={key}\n"),
        format!("export VERCEL_TOKEN=\"{key}\"\n"),
        format!("PROVIDER_TOKEN={key}\n"),
        format!("vercel deploy --prod --token {key}\n"),
        format!("vercel deploy --token={key}\n"),
        format!("Authorization: Bearer {key}\n"),
        format!("curl -H \"Authorization: Bearer {key}\" https://api.vercel.com/v2/user\n"),
        format!("X-API-Key: {key}\n"),
        format!("{{\"token\": \"{key}\"}}"),
        format!(
            "{{\"access_token\": \"{key}\", \"token_type\": \"Bearer\", \"expires_in\": 3600}}"
        ),
        format!("{{\"refresh_token\": \"{key}\"}}"),
        format!("{{\"api_key\": \"{key}\"}}"),
        format!("client = Vercel(bearer_token=\"{key}\")\n"),
        format!("const vercel = new Vercel({{ bearerToken: \"{key}\" }});\n"),
        format!("jobs:\n  deploy:\n    env:\n      VERCEL_TOKEN: {key}\n"),
        format!("config:\n  token: {key}\n"),
        format!("Here is my token {key} can you debug why it fails?"),
        format!("The token is {key}."),
        format!("Rotate ({key}), then redeploy."),
        format!("```\n{key}\n```"),
        format!("# \u{1f511} caf\u{e9}\r\n{key}\r\n"),
        format!("2026-09-29T00:00:00Z INFO deploy token={key} project=example\n"),
    ]
}

fn vercel_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == DETECTOR)
        .collect()
}

fn assert_sole_finding_in(input: &str, type_name: &str, key: &str) {
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{type_name}: {input}: {findings:?}");
    let finding = &findings[0];
    let start = input.find(key).unwrap();
    assert_eq!(finding.detector(), DETECTOR, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + key.len()),
        "{input}"
    );
    assert!(!text.contains(key), "{input}");
}

fn assert_unclaimed(input: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        vercel_findings(&findings).is_empty(),
        "{DETECTOR} claimed {input}: {findings:?}"
    );
}

#[test]
fn typed_classes_win_every_context_as_the_sole_finding() {
    for (prefix, type_name) in TYPED {
        let key = token(prefix);
        assert_eq!(key.len(), 60);
        for input in contexts(&key) {
            assert_sole_finding_in(&input, type_name, &key);
        }
    }
}

#[test]
fn interim_prefixes_keep_vercel_token_unchanged() {
    for prefix in INTERIM {
        for key in [
            format!("{prefix}{}", body(20)),
            format!("{prefix}{}", body(56)),
            format!("{prefix}SYNTHETIC_REVOKED-KEY_VALUE"),
        ] {
            for input in contexts(&key) {
                assert_sole_finding_in(&input, "vercel_token", &key);
            }
        }
    }
}

/// Security-first fallback: each one-property twin of a typed value is still
/// reported whole as `vercel_token` and redacted, exactly as before #1036.
#[test]
fn off_contract_typed_values_fall_back_to_vercel_token_in_every_context() {
    let valid = body(56);
    for (prefix, _) in TYPED {
        let mut underscore = valid.clone();
        underscore.replace_range(30..31, "_");
        let mut dash = valid.clone();
        dash.replace_range(30..31, "-");
        let fallbacks = [
            format!("{prefix}{}", body(55)),
            format!("{prefix}{}", body(57)),
            format!("{prefix}{}", body(20)),
            format!("{prefix}{underscore}"),
            format!("{prefix}{dash}"),
            format!("{prefix}{}_{}", &valid[..28], &valid[28..]),
            format!("{prefix}{}-{}", &valid[..28], &valid[28..]),
            format!("{prefix}{valid}_backup"),
            format!("{prefix}{valid}-1"),
        ];
        for value in fallbacks {
            for input in contexts(&value) {
                assert_sole_finding_in(&input, "vercel_token", &value);
            }
        }
    }
}

#[test]
fn marker_twins_and_leading_glue_are_unclaimed() {
    let valid = body(56);
    for (prefix, _) in TYPED {
        let twins = [
            format!("{}{valid}", prefix.to_ascii_uppercase()),
            format!("{}{valid}", prefix.replace('_', "-")),
            format!("x{prefix}{valid}"),
            format!("_{prefix}{valid}"),
            format!("{prefix}{}", body(19)),
        ];
        for twin in twins {
            for input in contexts(&twin) {
                assert_unclaimed(&input);
            }
        }
    }
}

#[test]
fn benign_siblings_are_unclaimed() {
    let value = body(56);
    for input in [
        "deployment: dpl_8sFjq2K3nQeR7xYtLmWzAbCdEfGh\n".to_owned(),
        "VERCEL_PROJECT_ID=prj_SyntheticRevokedVercelProjectId000\n".to_owned(),
        "VERCEL_ORG_ID=team_SyntheticRevokedVercelTeamId0000\n".to_owned(),
        format!("vcx_{value}"),
        format!("vc_{value}"),
        "VERCEL_TOKEN=vcp_<YOUR_VERCEL_TOKEN>\n".to_owned(),
        format!("VERCEL_TOKEN=vcp_{}\n", "*".repeat(56)),
        "VERCEL_TOKEN=vcp_${VERCEL_TOKEN}\n".to_owned(),
        "Personal access tokens begin with the prefix vcp_ and app tokens with vca_.".to_owned(),
        "Your key vck_....1234 was created.".to_owned(),
        format!("VERCEL_TOKEN={}\n", body(24)),
    ] {
        assert_unclaimed(&input);
    }
}

#[test]
fn classes_never_borrow_each_others_type() {
    let lines: Vec<String> = TYPED
        .iter()
        .map(|(prefix, _)| token(prefix))
        .chain(INTERIM.iter().map(|prefix| token(prefix)))
        .collect();
    let input = lines.join("\n");
    let (text, findings) = whole_input(&input);
    let got: Vec<(&str, usize, usize)> = findings
        .iter()
        .map(|f| (f.type_name(), f.range().start(), f.range().end()))
        .collect();
    let mut want = Vec::new();
    let mut offset = 0;
    for (line, type_name) in lines.iter().zip([
        "vercel_personal_access_token",
        "vercel_app_access_token",
        "vercel_app_refresh_token",
        "vercel_token",
        "vercel_token",
    ]) {
        want.push((type_name, offset, offset + line.len()));
        offset += line.len() + 1;
    }
    assert_eq!(got, want);
    for line in &lines {
        assert!(!text.contains(line.as_str()));
    }
}

#[test]
fn every_two_chunk_partition_matches_the_whole_input() {
    for (prefix, _) in TYPED {
        let key = token(prefix);
        for input in [
            format!("Authorization: Bearer {key}\n"),
            format!("VERCEL_TOKEN={key}\n"),
        ] {
            let (expected_text, expected) = whole_input(&input);
            assert_eq!(expected.len(), 1);
            for pieces in utf8_byte_partitions(&input) {
                let session = run(&as_chunks(&pieces));
                assert_eq!(session.text(), expected_text, "{pieces:?}");
                let findings = session.findings();
                assert_eq!(findings.len(), expected.len(), "{pieces:?}");
                for (got, want) in findings.iter().zip(&expected) {
                    assert_eq!(got.range(), want.range());
                    assert_eq!(got.detector(), want.detector());
                    assert_eq!(got.type_name(), want.type_name());
                }
            }
        }
    }
}
