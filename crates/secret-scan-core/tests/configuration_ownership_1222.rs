//! The Rust recipes of `docs/guides/configuration-ownership.md` (issue #1222).
//!
//! The guide's Rust blocks are copied from the regions between the `docs:begin`
//! and `docs:end` markers below, so `cargo test` runs the exact code the guide
//! shows, and a test fails when the two drift. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const GUIDE: &str = include_str!("../../../docs/guides/configuration-ownership.md");
const SOURCE: &str = include_str!("configuration_ownership_1222.rs");

/// The text between `// docs:begin <name>` and `// docs:end <name>`, with the
/// four-space indentation of the function body removed.
fn region(name: &str) -> String {
    let begin = format!("// docs:begin {name}");
    let end = format!("// docs:end {name}");
    let start = SOURCE.find(&begin).unwrap();
    let start = start + SOURCE[start..].find('\n').unwrap() + 1;
    let stop = SOURCE.rfind(&end).unwrap();
    SOURCE[start..stop]
        .lines()
        .map(|line| line.strip_prefix("    ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_owned()
}

fn guide_contains(name: &str) {
    let code = region(name);
    assert!(
        GUIDE.contains(&code),
        "docs/guides/configuration-ownership.md no longer contains the {name} example verbatim"
    );
}

#[test]
fn shared_registries_keep_their_own_pii_selection() -> Result<(), Box<dyn std::error::Error>> {
    // docs:begin shared-registries
    use std::sync::Arc;
    use std::thread;

    use redact_secret::{BuiltInRegistry, DefaultPolicy, PiiSelection};

    const TEXT: &str = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n";

    // One immutable registry per configuration, built once and shared.
    let off = Arc::new(BuiltInRegistry::with_built_in()?);
    let global = Arc::new(BuiltInRegistry::with_built_in_and_pii(
        &PiiSelection::parse(&["pii:global"])?,
    )?);
    let network = Arc::new(BuiltInRegistry::with_built_in_and_pii(
        &PiiSelection::parse(&["pii:family:global:network-address"])?,
    )?);

    let counts: Vec<usize> = thread::scope(|scope| {
        [&off, &global, &network]
            .map(|registry| {
                let registry = Arc::clone(registry);
                scope.spawn(move || registry.scan(TEXT, &DefaultPolicy).unwrap().len())
            })
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    assert_eq!(counts, [0, 2, 1]);
    // docs:end shared-registries
    Ok(())
}

#[test]
fn a_policy_is_an_argument_of_each_call() -> Result<(), Box<dyn std::error::Error>> {
    // docs:begin policy-per-call
    use redact_secret::{
        BuiltInRegistry, ComparedPolicy, default_placeholder_formatter, load_action_policy,
    };

    let registry = BuiltInRegistry::with_built_in()?;
    let text = format!("API_KEY={}{}{}", "ghp", "_SYNTHETICREVOKED", "0".repeat(20));
    let keep_github = load_action_policy(
        br#"{"actionPolicyRevision":1,"base":"default","rules":[
            {"id":"keep-github","match":{"type":["github_token"]},"action":"warn"}]}"#,
    )?;

    // The policy is handed to the call; the registry holds no policy.
    let enforced = registry.scan_and_redact(&text, &keep_github, &default_placeholder_formatter)?;
    assert_eq!(enforced.text(), text);

    // Previewing a policy change runs detection once, under the same registry.
    let comparison = registry.compare_action_policies(
        &text,
        &[
            ComparedPolicy::Default,
            ComparedPolicy::ActionPolicy(&keep_github),
        ],
    )?;
    assert_eq!(comparison.changed_count(), 1);
    // docs:end policy-per-call
    Ok(())
}

#[test]
fn the_guide_shows_the_tested_code() {
    guide_contains("shared-registries");
    guide_contains("policy-per-call");
}
