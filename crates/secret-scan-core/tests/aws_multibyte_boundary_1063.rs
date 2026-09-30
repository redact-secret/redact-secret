//! Issue #1063: `scan()` panicked in the AWS secret detector when a
//! multi-byte character (`é`, `日`, U+2028) sat right before a secret-name
//! identifier, because the identifier start was `rfind(..) + 1`, which is a
//! char boundary only after a one-byte character. A multi-byte separator now
//! scans exactly like the ASCII separator it stands in for, and `scan()`
//! never panics on generated Unicode before secret and token names.
//!
//! Every value is synthetic, built at run time, and was never issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{DefaultPolicy, DetectorRegistry, scan};

/// 40 synthetic alphanumeric chars with upper and lower case letters.
fn secret() -> String {
    "AbCdEfGh01".repeat(4)
}

/// `(type, matched text)` of every finding, in order.
fn outcome(input: &str) -> Vec<(String, String)> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy)
        .unwrap()
        .iter()
        .map(|finding| {
            let range = finding.range();
            (
                finding.type_name().to_string(),
                input[range.start()..range.end()].to_string(),
            )
        })
        .collect()
}

#[test]
fn a_multibyte_char_before_a_secret_name_does_not_panic_and_matches_ascii() {
    let s = secret();
    // A letter such as `é` or `日` joins the identifier, so its ASCII control
    // is a letter (`e`, `x`); U+2028 is a line break, so its control is `\n`.
    let cases = [
        ("\u{2028}", "\n", "aws_secret_access_key = "),
        ("é", "e", "secret: "),
        ("x\u{2028}", "x\n", "secret = "),
        ("日", "x", "secret="),
        ("é", "e", "aws_secret_access_key = "),
        ("日", "x", "AWS_SECRET_ACCESS_KEY="),
    ];
    for (wide, ascii, name) in cases {
        let with_wide = outcome(&format!("{wide}{name}{s}\n"));
        let with_ascii = outcome(&format!("{ascii}{name}{s}\n"));
        assert_eq!(with_wide, with_ascii, "{wide:?} {name:?}");
    }
    // The separator is not what hides the secret: the named form is found.
    let found = outcome(&format!("日aws_secret_access_key = {s}\n"));
    assert!(found.iter().any(|(_, text)| *text == s), "{found:?}");
}

/// A deterministic linear congruential generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next()).unwrap() % bound
    }
}

const UNICODE: &[char] = &[
    'é', '日', '\u{2028}', '\u{2029}', '\u{0085}', '\u{200B}', '\u{FEFF}', '\u{00A0}', '😀', 'ß',
    'İ', '\u{0301}', 'Ω', 'ｓ', '_', '.', '-', ' ', '\t', '\r', '\n', 'a', 'Z', '7',
];

const NAMES: &[&str] = &[
    "secret",
    "SECRET",
    "aws_secret_access_key",
    "AWS_SECRET_ACCESS_KEY",
    "client-secret",
    "aws.secret.key",
    "token",
    "api_key",
    "secret_key[0]",
];

const OPERATORS: &[&str] = &["=", ": ", " = ", ":=", "::", " : "];

#[test]
fn scan_never_panics_on_generated_unicode_before_secret_and_token_names() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let s = secret();
    for seed in 0..4u64 {
        let mut rng = Rng(0x1063_0000_5EED_0000 + seed);
        for _ in 0..400 {
            let lead: String = (0..rng.below(4))
                .map(|_| UNICODE[rng.below(UNICODE.len())])
                .collect();
            let name = NAMES[rng.below(NAMES.len())];
            let tail: String = (0..rng.below(3))
                .map(|_| UNICODE[rng.below(UNICODE.len())])
                .collect();
            let operator = OPERATORS[rng.below(OPERATORS.len())];
            let input = format!("{lead}{name}{tail}{operator}{s}\n");
            for finding in scan(&input, &registry, &DefaultPolicy).unwrap() {
                let range = finding.range();
                assert!(input.is_char_boundary(range.start()), "{input:?}");
                assert!(input.is_char_boundary(range.end()), "{input:?}");
            }
        }
    }
}
