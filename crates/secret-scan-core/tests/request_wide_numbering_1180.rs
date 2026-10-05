//! Request-wide placeholder numbering across several leaves (issue #1180).
//!
//! Every call numbers placeholders from 1, so a host that scans the string
//! leaves of one request needs request-wide unique numbers. The documented
//! recipe (`docs/guides/rust.md`, "Request-wide placeholder numbering") adds a
//! running offset to `PlaceholderContext::placeholder_index` inside a custom
//! formatter. This file runs that exact recipe against the real engine and
//! pins every claim the guide makes. Nothing here adds public API.
//!
//! Every input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::rc::Rc;

use redact_secret::{
    Action, DefaultPolicy, DetectorRegistry, Finding, FormatterFailure, IncrementalLimits,
    IncrementalSanitizer, PlaceholderContext, SecretScanError, SecretScanErrorCode,
    default_placeholder_formatter, scan_and_redact,
};

const TOKEN_A: &str = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const TOKEN_B: &str = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";
const WARN_LINE: &str = "password=hunter2xyz";
const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRURfQ09ORk9STUFOQ0U=\n-----END PRIVATE KEY-----";

/// One scanned leaf: where it sat in the request and the placeholder numbers
/// it consumed. No value, no placeholder text, no input.
#[derive(Debug, PartialEq, Eq)]
struct LeafReport {
    path: String,
    first: Option<usize>,
    last: Option<usize>,
}

/// The documented recipe: only an integer offset survives from leaf to leaf.
struct RequestNumbering {
    replaced_so_far: usize,
}

impl RequestNumbering {
    const fn new() -> Self {
        Self { replaced_so_far: 0 }
    }

    /// Redacts one leaf and advances the offset by the placeholders it used.
    /// On an error the offset is left alone and the host fails the request.
    fn redact_leaf(
        &mut self,
        registry: &DetectorRegistry,
        path: &str,
        leaf: &str,
    ) -> Result<(String, LeafReport), SecretScanError> {
        let base = self.replaced_so_far;
        let used = Cell::new(0_usize);
        let formatter = |_finding: &Finding,
                         context: &PlaceholderContext|
         -> Result<String, FormatterFailure> {
            used.set(context.placeholder_index());
            Ok(format!("<SECRET_{}>", base + context.placeholder_index()))
        };
        let result = scan_and_redact(leaf, registry, &DefaultPolicy, &formatter)?;
        self.replaced_so_far = base + used.get();
        let report = LeafReport {
            path: path.to_owned(),
            first: (used.get() > 0).then_some(base + 1),
            last: (used.get() > 0).then_some(base + used.get()),
        };
        Ok((result.text().to_owned(), report))
    }
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

#[test]
fn a_bare_call_restarts_at_one_which_is_why_a_request_needs_an_offset() {
    let registry = registry();
    for token in [TOKEN_A, TOKEN_B] {
        let result = scan_and_redact(
            &format!("token={token}"),
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        assert_eq!(result.text(), "token=<SECRET_1>");
    }
}

#[test]
fn leaves_of_one_request_are_numbered_uniquely_in_visit_order() {
    let registry = registry();
    let mut numbering = RequestNumbering::new();
    let leaves = [
        (
            "/messages/0/content",
            format!("first {TOKEN_A} and second {TOKEN_B}"),
        ),
        ("/messages/1/content", "nothing sensitive here".to_owned()),
        ("/messages/2/content", format!("again {TOKEN_A}")),
        ("/user", PRIVATE_KEY.to_owned()),
    ];

    let mut texts = Vec::new();
    let mut reports = Vec::new();
    for (path, leaf) in &leaves {
        let (text, report) = numbering.redact_leaf(&registry, path, leaf).unwrap();
        texts.push(text);
        reports.push(report);
    }

    // Several findings in one leaf take consecutive numbers; the leaf with no
    // finding consumes none; the third leaf resumes after the first leaf's two.
    assert_eq!(texts[0], "first <SECRET_1> and second <SECRET_2>");
    assert_eq!(texts[1], "nothing sensitive here");
    // The same value in a later leaf is a new occurrence and gets a new number.
    assert_eq!(texts[2], "again <SECRET_3>");
    // A `block` finding (private key) is replaced and numbered like `redact`.
    assert_eq!(texts[3], "<SECRET_4>");
    assert_eq!(numbering.replaced_so_far, 4);
    let report = |path: &str, first, last| LeafReport {
        path: path.to_owned(),
        first,
        last,
    };
    assert_eq!(
        reports,
        vec![
            report("/messages/0/content", Some(1), Some(2)),
            report("/messages/1/content", None, None),
            report("/messages/2/content", Some(3), Some(3)),
            report("/user", Some(4), Some(4)),
        ]
    );

    // A second request has its own offset and restarts at 1.
    let mut next_request = RequestNumbering::new();
    let (text, _) = next_request
        .redact_leaf(&registry, "/user", &format!("t {TOKEN_B}"))
        .unwrap();
    assert_eq!(text, "t <SECRET_1>");
}

#[test]
fn identical_values_in_one_leaf_are_numbered_per_occurrence() {
    let registry = registry();
    let mut numbering = RequestNumbering::new();
    let (text, _) = numbering
        .redact_leaf(&registry, "/a", &format!("x {TOKEN_A} y {TOKEN_A}"))
        .unwrap();
    assert_eq!(text, "x <SECRET_1> y <SECRET_2>");
    assert_eq!(numbering.replaced_so_far, 2);
}

#[test]
fn warn_consumes_no_number_and_block_does() {
    let registry = registry();
    let mut numbering = RequestNumbering::new();

    // The fixtures really carry the actions the guide names.
    let action_of = |input: &str| {
        scan_and_redact(
            input,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap()
        .findings()[0]
            .action()
    };
    assert_eq!(action_of(WARN_LINE), Action::Warn);
    assert_eq!(action_of(PRIVATE_KEY), Action::Block);
    assert_eq!(action_of(TOKEN_A), Action::Redact);

    // `warn` keeps the text and never calls the formatter, so the offset holds.
    let (warned, warned_report) = numbering.redact_leaf(&registry, "/a", WARN_LINE).unwrap();
    assert_eq!(warned, WARN_LINE);
    assert_eq!(warned_report.first, None);
    assert_eq!(numbering.replaced_so_far, 0);

    let (blocked, _) = numbering.redact_leaf(&registry, "/b", PRIVATE_KEY).unwrap();
    assert_eq!(blocked, "<SECRET_1>");

    // A later redacted leaf continues after the block, not after the warn.
    let (after, _) = numbering
        .redact_leaf(&registry, "/c", &format!("t {TOKEN_A}"))
        .unwrap();
    assert_eq!(after, "t <SECRET_2>");
}

#[test]
fn the_offset_equals_the_count_of_redact_and_block_findings() {
    // The recipe tracks the last `placeholder_index`; the same number is the
    // count of findings whose action is `redact` or `block`, so a host that
    // prefers to count findings gets an identical offset.
    let registry = registry();
    let leaf = format!("a {TOKEN_A} b {WARN_LINE} c {TOKEN_B}");
    let result = scan_and_redact(
        &leaf,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();
    let replaced = result
        .findings()
        .iter()
        .filter(|finding| matches!(finding.action(), Action::Redact | Action::Block))
        .count();
    let mut numbering = RequestNumbering::new();
    numbering.redact_leaf(&registry, "/leaf", &leaf).unwrap();
    assert_eq!(numbering.replaced_so_far, replaced);
    assert_eq!(replaced, 2);
}

#[test]
fn a_failing_leaf_is_an_error_with_no_partial_text_and_does_not_advance_the_offset() {
    let registry = registry();
    let failing = |_: &Finding, _: &PlaceholderContext| Err(FormatterFailure);
    let error =
        scan_and_redact(&format!("t {TOKEN_A}"), &registry, &DefaultPolicy, &failing).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::PlaceholderFailure);

    // The recipe adds nothing to that contract: an `Err` leaves `redact_leaf`
    // before the offset is written, and the host fails the whole request.
    let mut numbering = RequestNumbering::new();
    numbering
        .redact_leaf(&registry, "/a", &format!("t {TOKEN_A}"))
        .unwrap();
    assert_eq!(numbering.replaced_so_far, 1);
}

#[test]
fn the_same_recipe_numbers_an_incremental_session_per_leaf() {
    // Each streamed leaf is its own session whose `placeholder_index` counts
    // across that session's appends. The offset is read after `finalize`.
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let base = Rc::new(Cell::new(0_usize));
    let leaves = [
        (format!("first {TOKEN_A} then "), format!("{TOKEN_B} end")),
        ("clean ".to_owned(), "tail".to_owned()),
        (format!("again {TOKEN_A}"), String::new()),
    ];

    let mut texts = Vec::new();
    for (head, tail) in &leaves {
        let used = Rc::new(Cell::new(0_usize));
        let (leaf_base, leaf_used) = (base.get(), Rc::clone(&used));
        let formatter = move |_: &Finding, context: &PlaceholderContext| {
            leaf_used.set(context.placeholder_index());
            Ok(format!(
                "<SECRET_{}>",
                leaf_base + context.placeholder_index()
            ))
        };
        let mut session = IncrementalSanitizer::with_policy_and_formatter(
            limits,
            Box::new(DefaultPolicy),
            Box::new(formatter),
        )
        .unwrap();
        let mut text = session.append(head).unwrap().text().to_owned();
        text.push_str(session.append(tail).unwrap().text());
        text.push_str(session.finalize().unwrap().text());
        base.set(leaf_base + used.get());
        texts.push(text);
    }

    assert_eq!(texts[0], "first <SECRET_1> then <SECRET_2> end");
    assert_eq!(texts[1], "clean tail");
    assert_eq!(texts[2], "again <SECRET_3>");
}
