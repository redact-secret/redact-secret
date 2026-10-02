// Throwaway probe behind docs/audits/evidence/1072/README.md. Not part of any
// crate or build. To reproduce, put this file at `src/main.rs` of a scratch
// package that depends on the core by path:
//
//   [package] name = "probe" version = "0.0.0" edition = "2024"
//   [dependencies] redact-secret = { path = "<checkout>/crates/secret-scan-core" }
//   [workspace]
//
// and run `cargo run --release`. Every ruleset and input is synthetic.

use redact_secret::{
    DefaultPolicy, DetectorRegistry, WholeInputLimits, default_placeholder_formatter, load_ruleset,
    scan, scan_and_redact_with_limits,
};
use std::time::Instant;

const BASE: &str = "ruleset-revision: 1\ndetector: acme-token\nspecificity: contextual\nprefix: \"ACME_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n";

fn try_load(label: &str, text: &str) {
    match load_ruleset(text.as_bytes()) {
        Ok(d) => println!("{label}: OK ({} detectors)", d.len()),
        Err(e) => println!("{label}: ERR {} ({})", e.code().as_str(), e.class().as_str()),
    }
}

fn reg(rs: &str) -> DetectorRegistry {
    DetectorRegistry::with_built_in(load_ruleset(rs.as_bytes()).unwrap()).unwrap()
}

fn rs(prefix: &str, alphabet: &str, run: &str) -> String {
    format!(
        "ruleset-revision: 1\ndetector: probe-det\nspecificity: contextual\nprefix: \"{prefix}\"\nalphabet: {alphabet}\nrun: {run}\nvalidator: none\n"
    )
}

/// Minimum wall time over `reps` runs: the host is shared, so the minimum is
/// the least-disturbed sample.
fn best<T>(reps: u32, mut f: impl FnMut() -> T) -> (std::time::Duration, T) {
    let mut out = f();
    let mut min = std::time::Duration::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        out = f();
        min = min.min(t.elapsed());
    }
    (min, out)
}

fn grammar() {
    try_load("base", BASE);
    try_load("bom", &format!("\u{feff}{BASE}"));
    try_load("crlf", &BASE.replace('\n', "\r\n"));
    try_load("comment-no-colon", &format!("# note\n{BASE}"));
    try_load("comment-with-colon", &format!("# note: x\n{BASE}"));
    try_load("duplicate-prefix-field", &format!("{BASE}prefix: \"OTHER_\"\n"));
    try_load("duplicate-run-field", &format!("{BASE}run: exact 5\n"));
    try_load("revision-1.0", &BASE.replace("revision: 1", "revision: 1.0"));
    try_load("revision-quoted", &BASE.replace("revision: 1", "revision: \"1\""));
    try_load("block-before-revision", &format!("detector: x\n{BASE}"));
    try_load("concatenated-rulesets", &format!("{BASE}{BASE}"));
    try_load("concatenated-distinct-ids", &format!("{BASE}{}", BASE.replace("acme-token", "other-token")));
    try_load("upper-key", &BASE.replace("prefix:", "Prefix:"));
    try_load("tab-run", &BASE.replace("at-least 20", "at-least\t20"));
    try_load("run-extra-space", &BASE.replace("at-least 20", "at-least   20"));
    try_load("prefix-colon", &BASE.replace("\"ACME_\"", "\"ACME:\""));
    try_load("prefix-inner-quote", &BASE.replace("\"ACME_\"", "\"AC\"ME\""));
    try_load("prefix-backslash", &BASE.replace("\"ACME_\"", "\"AC\\nME\""));
    try_load("prefix-zwsp", &BASE.replace("\"ACME_\"", "\"AC\u{200b}ME_\""));
    try_load("prefix-nonascii", &BASE.replace("\"ACME_\"", "\"\u{e9}\u{e9}_\""));
    try_load("prefix-space", &BASE.replace("\"ACME_\"", "\"AC ME_\""));
    try_load("id-uppercase", &BASE.replace("acme-token", "Acme-Token"));
    try_load("id-underscore", &BASE.replace("acme-token", "acme_token"));
    try_load("id-64", &BASE.replace("acme-token", &"a".repeat(64)));
    try_load("id-65", &BASE.replace("acme-token", &"a".repeat(65)));
    try_load(
        "upper-alnum+trailing-lower-hex",
        &BASE
            .replace("alnum-dash", "upper-alnum")
            .replace("validator: none", "validator: trailing-lower-hex"),
    );
    try_load("exact-1", &BASE.replace("at-least 20", "exact 1"));
    try_load("run-4096", &BASE.replace("at-least 20", "at-least 4096"));
    try_load("run-4097", &BASE.replace("at-least 20", "at-least 4097"));
    try_load("run-leading-plus", &BASE.replace("at-least 20", "at-least +20"));
    try_load("run-leading-zero", &BASE.replace("at-least 20", "at-least 020"));
    try_load("names-only", "ruleset-revision: 1\nnames: ambiguous\nname: corp_passphrase\n");
    try_load("names-high", "ruleset-revision: 1\nnames: high-signal\nname: corp_passphrase\n");
    try_load("names-empty-block", "ruleset-revision: 1\nnames: ambiguous\n");
    try_load("only-revision", "ruleset-revision: 1\n");
    try_load("empty-bytes", "");
    println!(
        "invalid-utf8-bytes: {:?}",
        load_ruleset(&[0xff, 0xfe]).err().map(|e| e.class().as_str())
    );
    try_load("spec-provider", &BASE.replace("contextual", "provider"));
    try_load("spec-bogus", &BASE.replace("contextual", "bogus"));

    // Composition: two rulesets into one registry.
    let mut both = load_ruleset(BASE.as_bytes()).unwrap();
    both.extend(load_ruleset(BASE.replace("acme-token", "other-token").as_bytes()).unwrap());
    println!(
        "two-value-rulesets-registry: {:?}",
        DetectorRegistry::with_built_in(both).map(|r| r.len()).map_err(|e| e.code().as_str())
    );
    let mut both = load_ruleset(b"ruleset-revision: 1\nnames: ambiguous\nname: corp_a\n").unwrap();
    both.extend(load_ruleset(b"ruleset-revision: 1\nnames: ambiguous\nname: corp_b\n").unwrap());
    println!(
        "two-names-rulesets-registry: {:?}",
        DetectorRegistry::with_built_in(both).map(|r| r.len()).map_err(|e| e.code().as_str())
    );
    println!(
        "ruleset-in-common: {:?}",
        DetectorRegistry::with_common_built_in(load_ruleset(BASE.as_bytes()).unwrap())
            .map(|r| (r.len(), r.profile()))
            .map_err(|e| e.code().as_str())
    );
}

fn behavior() {
    // A prefix with a zero-width character loads but can never match.
    let r = reg(&rs("AC\u{200b}ME_", "alnum-dash", "at-least 8"));
    let f = scan("x ACME_abcdefghij y AC\u{200b}ME_abcdefghij", &r, &DefaultPolicy).unwrap();
    println!("zwsp-prefix findings: {}", f.len());

    // Default action of a ruleset detection.
    let r = reg(&rs("ACME_", "alnum-dash", "at-least 20"));
    let input = "token ACME_abcdefghijklmnopqrstuvwxyz end";
    let res = scan_and_redact_with_limits(
        input,
        &r,
        &DefaultPolicy,
        &default_placeholder_formatter,
        &WholeInputLimits::default(),
    )
    .unwrap();
    println!(
        "default-policy ruleset detection: action={:?} confidence={:?} type={} text_unchanged={}",
        res.findings()[0].action(),
        res.findings()[0].confidence(),
        res.findings()[0].type_name(),
        res.text() == input
    );

    // A ruleset prefix equal to a built-in prefix.
    let r = reg(&rs("ghp_", "alnum", "exact 36"));
    let f = scan("x ghp_SYNTHETICREVOKED00000000000000000000 y", &r, &DefaultPolicy).unwrap();
    println!(
        "builtin-prefix overlap: {:?}",
        f.iter()
            .map(|x| (x.detector().to_owned(), x.type_name().to_owned(), format!("{:?}", x.action())))
            .collect::<Vec<_>>()
    );

    // Duplicate fields: which value wins.
    let dup = format!("{BASE}prefix: \"OTHER_\"\n");
    let f = scan(
        "x OTHER_abcdefghijklmnopqrstuvwxyz ACME_abcdefghijklmnopqrstuvwxyz y",
        &reg(&dup),
        &DefaultPolicy,
    )
    .unwrap();
    println!("duplicate prefix: {} finding(s) at {:?}", f.len(), f.first().map(|x| x.range().start()));

    // Linearity: a 3-byte prefix over one long run, doubling the input.
    for (label, ruleset, unit) in [
        ("aaa/alnum/at-least 4096", rs("aaa", "alnum", "at-least 4096"), "a"),
        ("aaa/alnum/exact 4096", rs("aaa", "alnum", "exact 4096"), "a"),
        ("ab_/alnum-dash/at-least 4096 (periodic)", rs("ab_", "alnum-dash", "at-least 4096"), "ab_"),
    ] {
        let r = reg(&ruleset);
        for n in [1usize << 16, 1 << 18, 1 << 20, 1 << 22] {
            let input = unit.repeat(n / unit.len());
            let (t, f) = best(7, || scan(&input, &r, &DefaultPolicy).unwrap());
            println!("{label}: {n} bytes -> {t:?} min of 7 ({} findings)", f.len());
        }
    }

    // Load cost, 64 detectors (the maximum).
    let mut big = String::from("ruleset-revision: 1\n");
    for i in 0..64 {
        big.push_str(&format!(
            "detector: d-{i:02}\nspecificity: entropy\nprefix: \"a{i:02}\"\nalphabet: alnum\nrun: at-least 8\nvalidator: none\n"
        ));
    }
    let (t, n) = best(200, || load_ruleset(big.as_bytes()).unwrap().len());
    println!("parse+build 64 detectors: {t:?} min of 200 ({n})");
    let (t, n) = best(200, || {
        DetectorRegistry::with_built_in(load_ruleset(big.as_bytes()).unwrap()).unwrap().len()
    });
    println!("parse+build+registry, 64 detectors: {t:?} min of 200 ({n})");
    let (t, n) = best(200, || DetectorRegistry::with_built_in([]).unwrap().len());
    println!("registry, built-ins only: {t:?} min of 200 ({n})");

    // Scan cost: 64 three-byte prefixes against an input that hits all of them.
    let hostile = "a00a01a02a03a04a05a06a07a08a09a10a11a12a13a14a15 ".repeat(21_000);
    let plain = "The quick brown fox jumps over the lazy dog. ".repeat(23_000);
    for (name, ruleset) in [("no ruleset", None), ("64 detectors", Some(&big))] {
        let det = ruleset.map(|b| load_ruleset(b.as_bytes()).unwrap()).unwrap_or_default();
        let registry = DetectorRegistry::with_built_in(det).unwrap();
        for (iname, input) in [("hostile 1 MiB", &hostile), ("plain 1 MiB", &plain)] {
            let (t, found) = best(5, || scan(input, &registry, &DefaultPolicy).unwrap().len());
            println!("scan, {name}, {iname}: {t:?} min of 5, {found} findings");
        }
    }
}

fn main() {
    grammar();
    behavior();
}
