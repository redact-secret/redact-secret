//! Issue #948 through the public API with the full default registry: a value
//! assigned to a provider-named high-signal credential name
//! (`OPENAI_API_KEY=`, `STRIPE_SECRET_KEY=`, `"githubToken":`) that the
//! provider's own detector declines is claimed by `generic-token` at the
//! generic floors, with the action a generic prefix (`MYAPP_API_KEY=`) gets.
//! An on-grammar value still resolves to exactly one typed provider finding,
//! because provider specificity outranks the contextual candidate in overlap
//! resolution.
//!
//! Every off-grammar value is synthetic filler built at run time; the
//! on-grammar values are the committed canonical corpus positives.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    Action, Confidence, DefaultPolicy, DetectorContext, DetectorRegistry, Finding, Specificity,
    scan,
};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// A copy of `DEDICATED_PROVIDER_SEGMENTS` and `DEDICATED_PROVIDER_PHRASES`
/// in `src/detectors/generic_token.rs`, the prefixes rule 2 of
/// `decision-redact-provider-named-credential-assignments` names. The unit
/// test `every_dedicated_provider_prefix_qualifies_for_high_signal_names`
/// covers the constants themselves; this copy drives the resolver sweep.
const RULE_TWO_PROVIDER_PREFIXES: &[&str] = &[
    "anthropic",
    "atlassian",
    "jira",
    "confluence",
    "cloudflare",
    "cf",
    "confluent",
    "databricks",
    "datadog",
    "dd",
    "digitalocean",
    "discord",
    "docker",
    "dockerhub",
    "fireworks",
    "github",
    "gh",
    "gitlab",
    "grafana",
    "groq",
    "heroku",
    "huggingface",
    "hf",
    "langfuse",
    "langsmith",
    "langchain",
    "linear",
    "mailchimp",
    "mailgun",
    "neon",
    "netlify",
    "newrelic",
    "notion",
    "npm",
    "okta",
    "openai",
    "openrouter",
    "perplexity",
    "pplx",
    "pinecone",
    "postman",
    "pulumi",
    "pypi",
    "replicate",
    "sendgrid",
    "sentry",
    "shopify",
    "slack",
    "stripe",
    "supabase",
    "telegram",
    "terraform",
    "travis",
    "travisci",
    "twilio",
    "vault",
    "vercel",
    "xai",
    "new_relic",
    "digital_ocean",
    "hugging_face",
];

/// A 32-byte mixed-case alphanumeric value that matches no provider grammar
/// (no provider prefix, no checksum): the shape the issue probed with.
fn off_grammar() -> String {
    (0..32)
        .map(|i| char::from(b"q7Wm2XbK9vRt4LcN8zPd3HsF6gJy5TkA"[(i * 13 + 5) % 32]))
        .collect()
}

/// Provider-named variables across providers, spelled the way each host
/// syntax spells them.
const PROVIDER_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_API_KEY",
    "STRIPE_SECRET_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_CLIENT_SECRET",
    "SLACK_BOT_TOKEN",
    "HUGGINGFACE_API_KEY",
    "HF_TOKEN",
    "MAILCHIMP_API_KEY",
    "DD_API_KEY",
    "NEW_RELIC_API_KEY",
    "SENDGRID_API_KEY",
];

/// `OPENAI_API_KEY` as `openaiApiKey`.
fn camel(name: &str) -> String {
    let mut out = String::new();
    for (index, part) in name.split('_').enumerate() {
        let lower = part.to_ascii_lowercase();
        if index == 0 {
            out.push_str(&lower);
        } else {
            let mut chars = lower.chars();
            if let Some(first) = chars.next() {
                out.push(first.to_ascii_uppercase());
                out.extend(chars);
            }
        }
    }
    out
}

/// The same assignment in the host syntaxes the issue lists: dotenv,
/// `export` with either quote, YAML, TOML, and a JSON camelCase key.
fn contexts(name: &str, value: &str) -> Vec<String> {
    let lower = name.to_ascii_lowercase();
    vec![
        format!("{name}={value}\n"),
        format!("export {name}=\"{value}\"\n"),
        format!("export {name}='{value}'\n"),
        format!("{lower}: {value}\n"),
        format!("{lower} = \"{value}\"\n"),
        format!("{{\"{}\": \"{value}\"}}", camel(name)),
    ]
}

fn value_range(input: &str, value: &str) -> (usize, usize) {
    let start = input.find(value).unwrap();
    (start, start + value.len())
}

/// `(detector, type, action, start, end)` per finding.
fn shape(findings: &[Finding]) -> Vec<(String, String, Action, usize, usize)> {
    findings
        .iter()
        .map(|finding| {
            (
                finding.detector().to_owned(),
                finding.type_name().to_owned(),
                finding.action(),
                finding.range().start(),
                finding.range().end(),
            )
        })
        .collect()
}

#[test]
fn an_off_grammar_value_under_a_provider_name_is_redacted_whole() {
    let value = off_grammar();
    for name in PROVIDER_NAMES {
        for input in contexts(name, &value) {
            let (text, findings) = whole_input(&input);
            assert_eq!(findings.len(), 1, "{input}: {findings:?}");
            let finding = &findings[0];
            assert_eq!(finding.detector(), "generic-token", "{input}");
            assert_eq!(finding.type_name(), "contextual_secret", "{input}");
            assert_eq!(finding.action(), Action::Redact, "{input}");
            assert_eq!(
                (finding.range().start(), finding.range().end()),
                value_range(&input, &value),
                "{input}"
            );
            assert!(!text.contains(&value), "{input}: value left in clear");
        }
    }
}

/// The fallback is the generic rule, not a new one: every value gets under
/// a provider name exactly what it gets under `MYAPP_<suffix>`, whether that
/// is redact, warn (a short or low-entropy value) or nothing.
#[test]
fn a_provider_name_gets_the_same_outcome_as_a_generic_prefix() {
    let values = [
        off_grammar(),
        // Below the high-confidence length of 16: medium, warn.
        "q7Wm2XbK9v".to_owned(),
    ];
    for value in &values {
        for (provider, generic) in [
            ("OPENAI_API_KEY", "MYAPP_API_KEY"),
            ("STRIPE_SECRET_KEY", "MYAPP_SECRET_KEY"),
            ("GITHUB_TOKEN", "MYAPP_TOKEN"),
            ("DD_API_KEY", "MYAPP_API_KEY"),
        ] {
            for (provider_input, generic_input) in contexts(provider, value)
                .into_iter()
                .zip(contexts(generic, value))
            {
                let (_, provider_findings) = whole_input(&provider_input);
                let (_, generic_findings) = whole_input(&generic_input);
                assert_eq!(provider_findings.len(), 1, "{provider_input}");
                let provider_actions: Vec<_> =
                    provider_findings.iter().map(Finding::action).collect();
                let generic_actions: Vec<_> =
                    generic_findings.iter().map(Finding::action).collect();
                assert_eq!(provider_actions, generic_actions, "{provider_input}");
                let expected = if value.len() < 16 {
                    Action::Warn
                } else {
                    Action::Redact
                };
                assert_eq!(provider_actions, [expected], "{provider_input}");
            }
        }
    }
}

/// Placeholders, references, templates and filler stay silent under a
/// provider name exactly as under a generic one, and so do masked-name
/// prefixes, identifier siblings, the #911 object-reference name
/// (`*_EXISTING_SECRET`) and the names the fallback leaves out (a
/// provider-prefixed ambiguous or request-scoped `_token` name).
#[test]
fn placeholder_reference_and_identifier_controls_stay_silent() {
    let value = off_grammar();
    let silent_values = [
        "your-openai-api-key",
        "YOUR_OPENAI_API_KEY",
        "<OPENAI_API_KEY>",
        "${OPENAI_API_KEY}",
        "$OPENAI_API_KEY",
        "{{ secrets.OPENAI_API_KEY }}",
        "$(cat /run/secrets/openai)",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ];
    for name in ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN"] {
        for silent in silent_values {
            for (input, generic) in contexts(name, silent)
                .into_iter()
                .zip(contexts("MYAPP_API_KEY", silent))
            {
                let (_, findings) = whole_input(&input);
                assert!(findings.is_empty(), "{input}: {findings:?}");
                let (_, generic_findings) = whole_input(&generic);
                assert!(
                    generic_findings.is_empty(),
                    "{generic}: {generic_findings:?}"
                );
            }
        }
    }
    for name in [
        "OPENAI_API_KEY_ID",
        "OPENAI_ORG_ID",
        "STRIPE_WEBHOOK_URL",
        "SLACK_CLIENT_ID",
        "GITHUB_CREDENTIALS",
        "GITHUB_CSRF_TOKEN",
        "STRIPE_EXISTING_SECRET",
    ] {
        for input in contexts(name, &value) {
            let (_, findings) = whole_input(&input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }
    // Issue #1018: a masking lead silences only a value that shows the
    // masking; the unmasked value is judged under the rest of the name.
    let masked = format!("{}{}", &value[..4], "*".repeat(value.len() - 4));
    for name in ["REDACTED_OPENAI_API_KEY", "MASKED_STRIPE_SECRET_KEY"] {
        for input in contexts(name, &masked) {
            let (_, findings) = whole_input(&input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
        let (_, findings) = whole_input(&format!("{name}={value}"));
        assert_eq!(findings.len(), 1, "{name}: {findings:?}");
    }
}

/// The strongest confidence of a provider-specificity candidate that a
/// built-in detector other than `generic-token` proposes overlapping
/// `start..end` of `input`, or `None` when there is none.
fn provider_candidate_confidence(
    registry: &DetectorRegistry,
    input: &str,
    start: usize,
    end: usize,
) -> Option<Confidence> {
    let context = DetectorContext::new(input.len());
    registry
        .detectors()
        .iter()
        .filter(|registered| registered.id() != "generic-token")
        .flat_map(|registered| registered.detector().detect(input, &context).unwrap())
        .filter(|candidate| {
            candidate.specificity() == Some(Specificity::Provider)
                && candidate.range().start() < end
                && start < candidate.range().end()
        })
        .map(|candidate| candidate.confidence())
        .max()
}

/// The rule-2 prefix a detector id names (`new-relic-license-key` ->
/// `new_relic`, `twilio-auth-token` -> `twilio`), or `None` for a family
/// with no provider prefix in rule 2 (`aws-access-key`).
fn own_prefix(detector: &str) -> Option<&'static str> {
    let normalized = detector.replace('-', "_");
    RULE_TWO_PROVIDER_PREFIXES
        .iter()
        .copied()
        .filter(|prefix| {
            normalized == *prefix
                || normalized.starts_with(&format!("{prefix}_"))
                || normalized.contains(&format!("_{prefix}_"))
        })
        .max_by_key(|prefix| prefix.len())
}

/// Every provider-type positive of the canonical corpus (a value the
/// assignment grammar reads whole) under every rule-2 provider prefix:
///
/// - the scan reports exactly one finding on the value, never a typed one
///   plus a contextual duplicate;
/// - a high-confidence provider candidate always keeps the value typed
///   (provider specificity outranks the contextual candidate);
/// - a medium provider candidate (a keyword-gated grammar under another
///   provider's name) yields to the high contextual candidate only because
///   it would warn where the contextual one redacts, which is what the same
///   value gets under `MYAPP_API_KEY`;
/// - with no provider candidate, `generic-token` reports the value;
/// - under the provider's own name the finding is always typed.
#[test]
fn an_on_grammar_value_stays_one_typed_provider_finding_under_every_provider_prefix() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let mut values: Vec<(String, String, String)> = support::synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.kind == "positive" && fixture.support == "supported")
        .filter_map(|fixture| {
            let [expected] = fixture.declared_expectations() else {
                return None;
            };
            if expected.specificity != "provider" || expected.detector == "generic-token" {
                return None;
            }
            let value = &fixture.input[expected.start..expected.end];
            // A contextual name only reads a single-line, quote-free value.
            if value.contains(['\n', '\r', ' ', '"', '\'']) || value.len() > 4096 {
                return None;
            }
            Some((
                value.to_owned(),
                expected.detector.clone(),
                expected.type_name.clone(),
            ))
        })
        .collect();
    values.sort();
    values.dedup();
    assert!(values.len() > 200, "{} provider positives", values.len());

    let (mut typed, mut stricter_contextual, mut fallback, mut own) = (0, 0, 0, 0);
    for (value, detector, type_name) in &values {
        for prefix in RULE_TWO_PROVIDER_PREFIXES {
            let input = format!("{}_API_KEY={value}\n", prefix.to_ascii_uppercase());
            let (start, end) = value_range(&input, value);
            let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
            let on_value: Vec<&Finding> = findings
                .iter()
                .filter(|finding| finding.range().start() < end && start < finding.range().end())
                .collect();
            assert_eq!(on_value.len(), 1, "{input}: {:?}", shape(&findings));
            let finding = on_value[0];
            match provider_candidate_confidence(&registry, &input, start, end) {
                Some(Confidence::High) => {
                    typed += 1;
                    assert_ne!(finding.detector(), "generic-token", "{input}");
                }
                Some(_) if finding.detector() == "generic-token" => {
                    stricter_contextual += 1;
                    assert_eq!(finding.action(), Action::Redact, "{input}");
                    let generic = format!("MYAPP_API_KEY={value}\n");
                    let (_, generic_findings) = whole_input(&generic);
                    assert_eq!(generic_findings.len(), 1, "{generic}");
                    assert_eq!(generic_findings[0].detector(), "generic-token", "{generic}");
                }
                Some(_) => typed += 1,
                None => {
                    fallback += 1;
                    assert_eq!(finding.detector(), "generic-token", "{input}");
                    assert_eq!(finding.type_name(), "contextual_secret", "{input}");
                }
            }
            if own_prefix(detector) == Some(*prefix) {
                own += 1;
                assert_ne!(finding.detector(), "generic-token", "{input}");
                if finding.detector() == detector {
                    assert_eq!(finding.type_name(), type_name, "{input}");
                    assert_eq!(
                        (finding.range().start(), finding.range().end()),
                        (start, end),
                        "{input}"
                    );
                }
            }
        }
    }
    assert!(
        typed > 0 && fallback > 0 && own > 100,
        "typed {typed}, stricter contextual {stricter_contextual}, fallback {fallback}, own {own}"
    );
}

/// The same inputs give the same text and findings whole and streamed at
/// every UTF-8 byte partition: `has_open_contextual_assignment` holds a
/// provider-named line open exactly as it holds a generic one.
#[test]
fn whole_input_and_incremental_sessions_agree() {
    let value = off_grammar();
    let mut inputs = Vec::new();
    for name in ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GH_TOKEN"] {
        inputs.extend(contexts(name, &value));
    }
    inputs.push(format!(
        "log line\nexport ANTHROPIC_API_KEY=\"{value}\" # rotated\nnext\n"
    ));
    for input in inputs {
        let (expected_text, expected) = whole_input(&input);
        assert_eq!(expected.len(), 1, "{input}");
        for pieces in utf8_byte_partitions(&input) {
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "{pieces:?}");
            assert_eq!(shape(&session.findings()), shape(&expected), "{pieces:?}");
        }
    }
}
