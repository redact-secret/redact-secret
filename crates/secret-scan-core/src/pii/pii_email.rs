//! Conservative RFC 5322 / RFC 6531 email family contract v1.

use std::sync::OnceLock;

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

use super::{
    Alternative, ContextClass, ContextKind, ContextRequirement, ContextStrength, IdentityDomain,
    IdentityState, PiiFamily, SensitivityState, normalize_context, pii_context_table,
};
use crate::types::{ByteRange, Confidence, Obfuscation, Specificity};

const FAMILY_ID: &str = "pii:global:email";
const MAX_LOCAL_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 255;
const MAX_CANDIDATE_BYTES: usize = 254;
const MAX_ENCLOSING_PREFIX_BYTES: usize = MAX_DOMAIN_BYTES + 2;
const OCCURRENCE_EXCLUSIONS: &[&str] = &["en-example-label", "ko-example-label"];

pub(super) struct EmailFamily;

impl PiiFamily for EmailFamily {
    fn id(&self) -> &'static str {
        FAMILY_ID
    }

    fn context_requirement(&self) -> ContextRequirement {
        ContextRequirement::RequiredForSensitiveClassification
    }

    fn occurrence_exclusions(&self) -> &'static [&'static str] {
        OCCURRENCE_EXCLUSIONS
    }

    fn reject_invisible_normalization(&self) -> bool {
        true
    }

    fn detect(&self, input: &str) -> Vec<Alternative> {
        detect_email_candidates(input)
    }
}

fn detect_email_candidates(input: &str) -> Vec<Alternative> {
    detect_email_candidates_with(input, at_offsets(input), is_nfc)
}

/// Byte offsets of every `@`, found on bytes instead of decoded characters.
/// `@` is ASCII, so each offset is a character boundary (#1147). A
/// `match_indices` or probe-then-jump search is faster on sparse input but
/// 60% to 95% slower on `@`-dense input, so the plain byte walk is kept.
fn at_offsets(input: &str) -> impl Iterator<Item = usize> + '_ {
    input
        .as_bytes()
        .iter()
        .enumerate()
        .filter_map(|(offset, byte)| (*byte == b'@').then_some(offset))
}

/// The detector, parameterized by its `@` discovery and NFC predicate so a
/// test can run the pre-#1147 character walk and predicate as an oracle over
/// the same extraction code.
fn detect_email_candidates_with(
    input: &str,
    ats: impl Iterator<Item = usize>,
    is_nfc: impl Fn(&str) -> bool,
) -> Vec<Alternative> {
    let mut output = Vec::new();
    for at in ats {
        let Some(start) = scan_local_start(input, at) else {
            continue;
        };
        let Some(end) = scan_domain_end(input, at + 1) else {
            continue;
        };
        if start == at || end == at + 1 {
            continue;
        }
        let candidate = &input[start..end];
        if candidate.len() > MAX_CANDIDATE_BYTES
            || !valid_boundary(input, start, end)
            || unsupported_enclosing_syntax(input, start, at, end)
            || is_uri_userinfo(input, start, at)
        {
            continue;
        }
        let local = &input[start..at];
        let domain = &input[at + 1..end];
        if !valid_local(local) || !valid_domain(domain) || !is_nfc(candidate) {
            continue;
        }
        let start = match email_label_key_length(local) {
            Some(label) if valid_local(&local[label..]) => start + label,
            Some(_) => continue,
            None => start,
        };
        let sensitivity = if reserved_documentation_domain(domain) {
            SensitivityState::NonSensitive
        } else {
            SensitivityState::NotEstablished
        };
        let Some(range) = ByteRange::new(start, end) else {
            continue;
        };
        output.push(Alternative {
            family_id: FAMILY_ID,
            domain: IdentityDomain::Email,
            range,
            identity: IdentityState::Established,
            identity_confidence: Confidence::High,
            identity_specificity: Specificity::Structural,
            sensitivity,
            sensitivity_confidence: Confidence::High,
            sensitivity_specificity: Specificity::Contextual,
            obfuscation: Obfuscation::None,
            reject_invisible_normalization: true,
        });
    }
    output
}

/// Issue #926: RFC 5322 `atext` includes `=`, so in `email=local@domain` the
/// local-part scan runs back to the key. When the run before the first `=` is
/// a reviewed high-signal email field label of the context vocabulary (the
/// whole key or its last separator-delimited tokens, after the context-only
/// normalization: `email`, `customer_email`, `이메일`), that run and the `=`
/// are a label, not local part. Returns their byte length.
///
/// `atext` also includes `|`, so in a pipe-delimited record the scan runs
/// back over earlier fields (`id=7|email=local@domain`). A `|` starts a new
/// field, and the run from it to that field's first `=` is judged the same
/// way (issue #940). A field key may also end at a bare `|`
/// (`email|local@domain`, `|email|local@domain|`): when that key is a
/// reviewed label by the same rule, the `|` is a field boundary, not local
/// part (issue #943). The first field, from the left, whose key is a label
/// ends the label. Any other `=` or `|` stays local-part syntax, so
/// `|emailx|local@domain` and `|user|a|b@domain` keep the RFC reading.
fn email_label_key_length(local: &str) -> Option<usize> {
    std::iter::once(0)
        .chain(local.match_indices('|').map(|(index, _)| index + 1))
        .find_map(|field_start| {
            let field = &local[field_start..];
            let separator = field.find(['=', '|'])?;
            let key = &field[..separator];
            (!key.is_empty() && is_email_label_key(key)).then_some(field_start + separator + 1)
        })
}

fn is_email_label_key(key: &str) -> bool {
    let view = normalize_context(key);
    email_label_forms().iter().any(|form| {
        view == *form
            || view
                .strip_suffix(form.as_str())
                .is_some_and(|head| head.ends_with(' '))
    })
}

/// The context-only view of every form of a positive high-signal email
/// field label, normalized once per process instead of on every key.
fn email_label_forms() -> &'static [String] {
    static FORMS: OnceLock<Vec<String>> = OnceLock::new();
    FORMS.get_or_init(|| {
        pii_context_table::CONTEXT_ENTRIES
            .iter()
            .filter(|entry| {
                entry.kind == ContextKind::FieldLabel
                    && entry.class == ContextClass::Positive
                    && entry.strength == ContextStrength::HighSignal
                    && entry.domains.contains(&IdentityDomain::Email)
            })
            .flat_map(|entry| entry.forms.iter().map(|form| normalize_context(form)))
            .collect()
    })
}

/// [`is_email_label_key`] before issue #1058, which renormalized every form
/// on every call: the oracle for its test.
#[cfg(test)]
fn is_email_label_key_unshared(key: &str) -> bool {
    let view = normalize_context(key);
    pii_context_table::CONTEXT_ENTRIES
        .iter()
        .filter(|entry| {
            entry.kind == ContextKind::FieldLabel
                && entry.class == ContextClass::Positive
                && entry.strength == ContextStrength::HighSignal
                && entry.domains.contains(&IdentityDomain::Email)
        })
        .any(|entry| {
            entry.forms.iter().any(|form| {
                let form = normalize_context(form);
                view == form
                    || view
                        .strip_suffix(form.as_str())
                        .is_some_and(|head| head.ends_with(' '))
            })
        })
}

fn scan_local_start(input: &str, at: usize) -> Option<usize> {
    let mut bytes = 0usize;
    for (index, character) in input[..at].char_indices().rev() {
        if !is_local_character(character) && character != '.' {
            return Some(index + character.len_utf8());
        }
        bytes += character.len_utf8();
        if bytes > MAX_LOCAL_BYTES {
            return None;
        }
    }
    Some(0)
}

fn scan_domain_end(input: &str, start: usize) -> Option<usize> {
    let mut bytes = 0usize;
    for (offset, character) in input[start..].char_indices() {
        if !is_domain_character(character) && character != '.' {
            return Some(start + offset);
        }
        bytes += character.len_utf8();
        if bytes > MAX_DOMAIN_BYTES {
            return None;
        }
    }
    Some(input.len())
}

fn valid_boundary(input: &str, start: usize, end: usize) -> bool {
    let left = input[..start].chars().next_back();
    let right = input[end..].chars().next();
    left.is_none_or(|character| {
        !is_local_character(character)
            && character != '.'
            && character != '@'
            && !is_combining_mark(character)
            && !crate::normalize::is_invisible(character)
    }) && right.is_none_or(|character| {
        !is_domain_character(character)
            && !character.is_alphanumeric()
            && character != '.'
            && character != '@'
            && !is_combining_mark(character)
            && !crate::normalize::is_invisible(character)
    })
}

fn valid_local(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= MAX_LOCAL_BYTES
        && local
            .split('.')
            .all(|atom| !atom.is_empty() && atom.chars().all(is_local_character))
}

fn valid_domain(domain: &str) -> bool {
    let labels = domain.split('.').count();
    let reserved_single_label = ["example", "invalid", "localhost", "test"]
        .iter()
        .any(|reserved| domain.eq_ignore_ascii_case(reserved));
    domain.len() <= MAX_DOMAIN_BYTES
        && (labels >= 2 || reserved_single_label)
        && domain.split('.').all(|label| {
            label.len() <= 63
                && label.chars().next().is_some_and(is_domain_alphanumeric)
                && label
                    .chars()
                    .next_back()
                    .is_some_and(is_domain_alphanumeric)
                && label
                    .chars()
                    .all(|character| is_domain_alphanumeric(character) || character == '-')
        })
}

fn unsupported_enclosing_syntax(input: &str, start: usize, at: usize, end: usize) -> bool {
    let left = input[..start].chars().next_back();
    let right = input[end..].chars().next();
    if matches!(left, Some('<' | ')')) || matches!(right, Some('>' | '(')) {
        return true;
    }
    if left == Some(':') {
        let token_start = bounded_token_start(input, start);
        return input[token_start..at].contains('@');
    }
    false
}

fn is_local_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
        )
        || (!character.is_ascii() && character.is_alphanumeric())
}

fn is_domain_character(character: char) -> bool {
    is_domain_alphanumeric(character) || character == '-'
}

fn is_domain_alphanumeric(character: char) -> bool {
    character.is_ascii_alphanumeric()
}

/// ASCII is NFC by definition (every ASCII scalar is its own NFC form and
/// none composes with a neighbour), so the normalizer runs only for a
/// candidate that contains a non-ASCII local-part character (#1147).
fn is_nfc(value: &str) -> bool {
    value.is_ascii() || is_nfc_normalizing(value)
}

fn is_nfc_normalizing(value: &str) -> bool {
    value.nfc().eq(value.chars())
}

fn is_uri_userinfo(input: &str, start: usize, at: usize) -> bool {
    let token_start = bounded_token_start(input, start);
    input[token_start..at].contains("://")
}

fn bounded_token_start(input: &str, start: usize) -> usize {
    // One maximum-size source-route domain plus its leading `@` and trailing
    // `:`. Delimiters below isolate later, unrelated tokens.
    let mut floor = start.saturating_sub(MAX_ENCLOSING_PREFIX_BYTES);
    while floor < start && !input.is_char_boundary(floor) {
        floor += 1;
    }
    input[floor..start]
        .char_indices()
        .rev()
        .find(|(_, character)| {
            character.is_whitespace() || matches!(character, ',' | ';' | '<' | '>')
        })
        .map_or(floor, |(index, character)| {
            floor + index + character.len_utf8()
        })
}

fn reserved_documentation_domain(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    // `reserved` itself, or a subdomain `<label>.<reserved>`, ASCII
    // case-insensitively and without building a lowercased copy.
    let is_reserved = |reserved: &str| {
        let reserved = reserved.as_bytes();
        bytes.eq_ignore_ascii_case(reserved)
            || bytes.len() > reserved.len()
                && bytes[bytes.len() - reserved.len() - 1] == b'.'
                && bytes[bytes.len() - reserved.len()..].eq_ignore_ascii_case(reserved)
    };
    ["example.com", "example.net", "example.org"]
        .iter()
        .any(|reserved| is_reserved(reserved))
        || ["example", "invalid", "localhost", "test"]
            .iter()
            .any(|reserved| is_reserved(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(input: &str) -> Vec<Alternative> {
        detect_email_candidates(input)
    }

    #[test]
    fn shared_label_forms_classify_every_key_as_the_per_call_normalization_did() {
        let mut keys: Vec<String> = pii_context_table::CONTEXT_ENTRIES
            .iter()
            .flat_map(|entry| entry.forms.iter().map(|form| (*form).to_owned()))
            .collect();
        let mut variants = Vec::new();
        for key in &keys {
            for prefix in ["", "x", "x ", "x_", "x-", "\u{200b}", "고객 ", "e\u{301} "] {
                for suffix in ["", "s", " ", "\u{301}"] {
                    variants.push(format!("{prefix}{}{suffix}", key.to_ascii_uppercase()));
                    variants.push(format!("{prefix}{}{suffix}", key.replace(' ', "_")));
                    variants.push(format!("{prefix}{}{suffix}", key.replace(' ', "\u{200b}-")));
                }
            }
        }
        keys.extend(variants);
        keys.extend(["", " ", "mail", "emai", "e mail", "E\u{AD}MAIL"].map(str::to_owned));
        let mut labels = 0;
        for key in &keys {
            let expected = is_email_label_key_unshared(key);
            assert_eq!(is_email_label_key(key), expected, "{key:?}");
            labels += usize::from(expected);
        }
        assert!(labels > 100, "only {labels} keys were labels");
    }

    #[test]
    fn accepts_the_frozen_ascii_and_smtputf8_subset() {
        for input in [
            "fixture.876+tag@q7m9z2x4.synthetic",
            "고객876@x4z8v2n6.synthetic",
            "x@xn--bcher-kva.exampleish",
        ] {
            let found = candidates(input);
            assert_eq!(found.len(), 1, "{input:?}");
            assert_eq!(found[0].range, ByteRange::new(0, input.len()).unwrap());
            assert_eq!(found[0].sensitivity, SensitivityState::NotEstablished);
        }
    }

    #[test]
    fn whole_reserved_domains_are_identity_valid_but_non_sensitive() {
        for input in [
            "identity@example.com",
            "identity@sub.example.org",
            "identity@fixture.invalid",
            "identity@nested.test",
            "identity@test",
        ] {
            let found = candidates(input);
            assert_eq!(found.len(), 1, "{input:?}");
            assert_eq!(found[0].identity, IdentityState::Established);
            assert_eq!(found[0].sensitivity, SensitivityState::NonSensitive);
        }
        for input in [
            "identity@notexample.com",
            "identity@example.com.invalidated",
            "identity@test.exampleish",
        ] {
            assert_eq!(
                candidates(input)[0].sensitivity,
                SensitivityState::NotEstablished,
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_forms_lengths_boundaries_and_uri_userinfo() {
        assert!(is_uri_userinfo(
            "https://fixture876@q7m9z2x4.synthetic/path",
            6,
            18
        ));
        assert!(!is_uri_userinfo(
            "https://host/path, email: fixture876@q7m9z2x4.synthetic",
            26,
            36
        ));
        let multibyte_prefix = format!(
            "{}https://fixture876@q7m9z2x4.synthetic/path",
            "\u{1f642}".repeat(70)
        );
        assert!(candidates(&multibyte_prefix).is_empty());
        let unrelated_earlier_address = "first@a.synthetic,email:second@b.synthetic";
        let found = candidates(unrelated_earlier_address);
        assert!(found.iter().any(|candidate| {
            &unrelated_earlier_address[candidate.range.start()..candidate.range.end()]
                == "second@b.synthetic"
        }));
        let route_label = "r".repeat(63);
        let maximum_route_domain =
            format!("{route_label}.{route_label}.{route_label}.{route_label}");
        assert_eq!(maximum_route_domain.len(), MAX_DOMAIN_BYTES);
        let maximum_route = format!("@{maximum_route_domain}:fixture876@q7m9z2x4.synthetic");
        assert!(candidates(&maximum_route).is_empty());
        let overlong_local = format!("{}@q7m9z2x4.synthetic", "a".repeat(65));
        let overlong_label = format!("fixture876@{}.synthetic", "a".repeat(64));
        for input in [
            "a..b@q7m9z2x4.synthetic",
            ".a@q7m9z2x4.synthetic",
            "a.@q7m9z2x4.synthetic",
            "\"quoted\"@q7m9z2x4.synthetic",
            "a@[192.0.2.1]",
            "a@singlelabel",
            "a@-bad.synthetic",
            "a@bad-.synthetic",
            "https://fixture876@q7m9z2x4.synthetic/path",
            "a@q7m9z2x4.synthetic.",
            "<a@q7m9z2x4.synthetic>",
            "(comment)a@q7m9z2x4.synthetic",
            "a@q7m9z2x4.synthetic(comment)",
            "@route.synthetic:a@q7m9z2x4.synthetic",
            "a@b@q7m9z2x4.synthetic",
            "abc\u{200D}def@q7m9z2x4.synthetic",
            "a@q7m9z2x4.synthetic\u{200D}suffix",
            "a@q7m9z2x4.synthetic한글",
            "a@q7m9z2x4.syntheticé",
            "a@q7m9z2x4.synthetic\u{20DD}",
            "a@q7m9z2x4.synthetic\u{FE00}",
            overlong_local.as_str(),
            overlong_label.as_str(),
        ] {
            assert!(candidates(input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn a_reviewed_email_label_key_before_equals_is_not_local_part() {
        let ranges = |input: &str| {
            candidates(input)
                .iter()
                .map(|candidate| (candidate.range.start(), candidate.range.end()))
                .collect::<Vec<_>>()
        };
        let address = "fixture876-q7m9@x4z8v2n6.synthetic";
        for key in [
            "email",
            "EMAIL",
            "e-mail",
            "customer_email",
            "이메일",
            "고객_이메일",
        ] {
            let input = format!("{key}={address}");
            assert_eq!(ranges(&input), [(key.len() + 1, input.len())], "{input:?}");
        }
        // A later `=` inside the address stays local-part syntax.
        let input = format!("email=a=b{address}");
        assert_eq!(ranges(&input), [(6, input.len())]);
        // Keys that are not a whole reviewed label keep the joined candidate.
        for key in ["user", "emailx", "myemail", "user.email", "contact"] {
            let input = format!("{key}={address}");
            assert_eq!(ranges(&input), [(0, input.len())], "{input:?}");
        }
        // Issue #940: a `|` field delimiter ends the earlier fields of the key.
        for key in [
            "x|email",
            "a|b|email",
            "|email",
            "a|customer_email",
            "x|이메일",
        ] {
            let input = format!("{key}={address}");
            assert_eq!(ranges(&input), [(key.len() + 1, input.len())], "{input:?}");
        }
        // Issue #943: a reviewed label joined to the address by a bare `|`.
        for key in [
            "email",
            "|email",
            "id=7|email",
            "a|customer_email",
            "|이메일",
            "EMAIL",
        ] {
            let input = format!("{key}|{address}");
            assert_eq!(ranges(&input), [(key.len() + 1, input.len())], "{input:?}");
        }
        // The first label field wins even when a later field has an `=`.
        let input = format!("email|x={address}");
        assert_eq!(ranges(&input), [(6, input.len())]);
        for prefix in ["|emailx|", "|user|a|", "|email.x|", "|myemail|"] {
            let input = format!("{prefix}{address}");
            assert_eq!(ranges(&input), [(0, input.len())], "{input:?}");
        }
        for key in ["user|emailx", "user|user.email", "id=7|emailx"] {
            let input = format!("{key}={address}");
            assert_eq!(ranges(&input), [(0, input.len())], "{input:?}");
        }
        // A label followed by an invalid remainder yields no candidate.
        assert!(candidates("email=.a@x4z8v2n6.synthetic").is_empty());
        assert_eq!(
            candidates("email=identity@example.com")[0].sensitivity,
            SensitivityState::NonSensitive
        );
    }

    #[test]
    fn overlong_runs_stop_at_the_frozen_scan_bounds() {
        let overlong_local = format!("{}@x4z8v2n6.synthetic", "a".repeat(1_000_000));
        let overlong_domain = format!("fixture876@{}.synthetic", "a".repeat(1_000_000));
        assert!(candidates(&overlong_local).is_empty());
        assert!(candidates(&overlong_domain).is_empty());
    }
}

/// Differential test for #1086: `reserved_documentation_domain` compares the
/// domain in place instead of a lowercased copy.
#[cfg(test)]
mod case_insensitive_differential_tests {
    use super::*;
    use crate::test_rng::{BOUNDARY_PIECES, XorShift32};

    /// The implementation before #1086.
    fn old_reserved_documentation_domain(domain: &str) -> bool {
        let lowercase = domain.to_ascii_lowercase();
        ["example.com", "example.net", "example.org"]
            .iter()
            .any(|reserved| lowercase == *reserved || lowercase.ends_with(&format!(".{reserved}")))
            || ["example", "invalid", "localhost", "test"]
                .iter()
                .any(|reserved| {
                    lowercase == *reserved || lowercase.ends_with(&format!(".{reserved}"))
                })
    }

    #[test]
    fn reserved_domain_matches_the_lowercasing_implementation() {
        let words = [
            "example",
            "EXAMPLE",
            "Example",
            ".com",
            ".COM",
            ".net",
            ".org",
            ".Org",
            "invalid",
            "LOCALHOST",
            "localhost",
            "test",
            "TEST",
            "Test",
            ".",
            "mail",
            "a",
            "..",
            "-",
            "\u{212a}",
            "\u{e9}xample",
        ];
        let mut pieces: Vec<&str> = BOUNDARY_PIECES.to_vec();
        pieces.extend_from_slice(&words);
        let mut rng = XorShift32::new(0x1086_0005);
        let mut inputs: Vec<String> = vec![String::new(), ".".to_owned()];
        inputs.extend(words.iter().map(|word| (*word).to_owned()));
        for _ in 0..8000 {
            inputs.push(rng.text(&pieces, 5));
        }
        let mut hits = 0;
        for input in &inputs {
            let old = old_reserved_documentation_domain(input);
            assert_eq!(reserved_documentation_domain(input), old, "{input:?}");
            hits += usize::from(old);
        }
        assert!(hits > 20, "the generator must reach the positive cases");
    }
}

/// Issue #1147: the ASCII fast path of `is_nfc`, and the whole detector,
/// against the pre-change predicate (always normalize).
#[cfg(test)]
mod nfc_fast_path_tests {
    use super::*;
    use crate::test_rng::{BOUNDARY_PIECES, XorShift32};

    const PIECES: &[&str] = &[
        "a",
        "Z",
        "7",
        ".",
        "-",
        "_",
        "+",
        "@",
        "=",
        "|",
        " ",
        "\n",
        "<",
        ">",
        ":",
        "//",
        "mail.example",
        "example.com",
        "fixture",
        "xn--bcher-kva.test",
        "e\u{301}",
        "\u{e9}",
        "\u{ac00}",
        "\u{1100}\u{1161}",
        "\u{ffa1}",
        "\u{fb01}",
        "\u{212b}",
        "\u{1f600}",
        "\u{200b}",
        "\u{3a3}",
        "\u{2126}",
        "\u{1e9b}\u{323}",
        "고객",
        "\u{ff21}",
        "\u{0344}",
    ];

    /// The detector before #1147: the character walk for `@`, with a
    /// caller-supplied NFC predicate.
    fn old_detect(input: &str, is_nfc: impl Fn(&str) -> bool) -> Vec<Alternative> {
        let ats = input
            .char_indices()
            .filter_map(|(index, character)| (character == '@').then_some(index));
        detect_email_candidates_with(input, ats, is_nfc)
    }

    fn corpus() -> Vec<String> {
        let mut pieces: Vec<&str> = PIECES.to_vec();
        pieces.extend_from_slice(BOUNDARY_PIECES);
        let mut rng = XorShift32::new(0x1147_0001);
        let mut inputs: Vec<String> = vec![String::new(), "@".to_owned()];
        for _ in 0..6000 {
            inputs.push(rng.text(&pieces, 9));
        }
        // Well-formed candidates around a non-ASCII local part.
        for local in [
            "fixture",
            "fixture.876+tag",
            "e\u{301}x",
            "\u{e9}x",
            "고객876",
            "\u{fb01}x",
            "\u{212b}",
            "\u{1100}\u{1161}x",
            "x\u{323}\u{307}",
            "\u{1e9b}\u{323}",
        ] {
            for domain in ["q7m9z2x4.synthetic", "example.com", "a.b", "localhost"] {
                for (left, right) in [("", ""), (" ", " "), ("email=", ""), ("\u{301}", "")] {
                    inputs.push(format!("{left}{local}@{domain}{right}"));
                }
            }
        }
        // Long local parts at, below and above the 64-byte limit, and
        // candidates at the 254-byte limit.
        for len in [62usize, 63, 64, 65, 66] {
            inputs.push(format!("{}@q7m9z2x4.synthetic", "a".repeat(len)));
            inputs.push(format!("{}\u{e9}@q7m9z2x4.synthetic", "a".repeat(len - 2)));
            inputs.push(format!(
                "{}e\u{301}@q7m9z2x4.synthetic",
                "a".repeat(len - 3)
            ));
        }
        let label = "d".repeat(63);
        inputs.push(format!("u@{label}.{label}.{label}.{label}"));
        inputs.push(format!("u@{label}.{label}.{label}.{}", "d".repeat(60)));
        inputs.push(format!(
            "{}@{label}.{label}.{label}.{}",
            "a".repeat(64),
            "d".repeat(56)
        ));
        inputs
    }

    #[test]
    fn at_offsets_equal_the_character_walk() {
        for input in corpus() {
            let walked: Vec<usize> = input
                .char_indices()
                .filter_map(|(index, character)| (character == '@').then_some(index))
                .collect();
            let scanned: Vec<usize> = at_offsets(&input).collect();
            assert_eq!(scanned, walked, "{input:?}");
            assert!(scanned.iter().all(|at| input.is_char_boundary(*at)));
        }
    }

    #[test]
    fn is_nfc_equals_the_normalizing_predicate() {
        let (mut non_ascii, mut rejected) = (0, 0);
        for input in corpus() {
            assert_eq!(is_nfc(&input), is_nfc_normalizing(&input), "{input:?}");
            non_ascii += usize::from(!input.is_ascii());
            rejected += usize::from(!is_nfc_normalizing(&input));
        }
        assert!(non_ascii > 1000 && rejected > 100, "{non_ascii} {rejected}");
    }

    #[test]
    fn candidates_equal_the_always_normalizing_detector() {
        let (mut found, mut rejected_by_nfc) = (0usize, 0usize);
        for input in corpus() {
            let new = detect_email_candidates(&input);
            let old = old_detect(&input, is_nfc_normalizing);
            assert_eq!(format!("{new:?}"), format!("{old:?}"), "{input:?}");
            found += old.len();
            let accept_all = old_detect(&input, |_| true);
            rejected_by_nfc += accept_all.len() - old.len();
        }
        assert!(found > 50, "only {found} candidates");
        assert!(rejected_by_nfc > 20, "NFC rejection not exercised");
    }

    struct OldEmailFamily;

    impl PiiFamily for OldEmailFamily {
        fn id(&self) -> &'static str {
            FAMILY_ID
        }
        fn context_requirement(&self) -> ContextRequirement {
            EmailFamily.context_requirement()
        }
        fn occurrence_exclusions(&self) -> &'static [&'static str] {
            OCCURRENCE_EXCLUSIONS
        }
        fn reject_invisible_normalization(&self) -> bool {
            true
        }
        fn detect(&self, input: &str) -> Vec<Alternative> {
            old_detect(input, is_nfc_normalizing)
        }
    }

    fn registry(old: bool) -> crate::DetectorRegistry {
        let ids = ["pii:global:email"];
        let selectors = ["pii:family:global:email"];
        let selection =
            super::super::PiiSelection::parse_with_catalog(&selectors, &ids, &ids).unwrap();
        let family: Box<dyn PiiFamily> = if old {
            Box::new(OldEmailFamily)
        } else {
            Box::new(EmailFamily)
        };
        crate::DetectorRegistry::with_internal_test_detector(Box::new(
            super::super::PiiDomain::new(selection, vec![family]),
        ))
    }

    type Summary = (String, Vec<String>);

    fn summarize<'a>(findings: impl Iterator<Item = &'a crate::Finding>) -> Vec<String> {
        findings
            .map(|f| {
                format!(
                    "{:?}|{}|{}|{:?}|{:?}|{:?}",
                    f.id(),
                    f.type_name(),
                    f.detector(),
                    f.confidence(),
                    f.action(),
                    f.range()
                )
            })
            .collect()
    }

    fn whole(input: &str, old: bool) -> Summary {
        let result = crate::scan_and_redact(
            input,
            &registry(old),
            &crate::DefaultPolicy,
            &crate::default_placeholder_formatter,
        )
        .unwrap();
        (
            result.text().to_owned(),
            summarize(result.findings().iter()),
        )
    }

    fn incremental(input: &str, splits: &[usize], old: bool) -> Summary {
        let limits = crate::IncrementalLimits::new(4_096, 2_048, 512, 1_024).unwrap();
        let policy: Box<dyn crate::IncrementalPolicy> = Box::new(crate::DefaultPolicy);
        let formatter: Box<dyn crate::PlaceholderFormatter> =
            Box::new(crate::default_placeholder_formatter);
        let mut session =
            crate::IncrementalSanitizer::from_registry(registry(old), limits, policy, formatter);
        let mut text = String::new();
        let mut findings = Vec::new();
        let mut previous = 0;
        for &split in splits.iter().chain(std::iter::once(&input.len())) {
            let part = session.append(&input[previous..split]).unwrap();
            text.push_str(part.text());
            findings.extend(summarize(part.findings().iter()));
            previous = split;
        }
        let last = session.finalize().unwrap();
        text.push_str(last.text());
        findings.extend(summarize(last.findings().iter()));
        (text, findings)
    }

    #[test]
    fn whole_and_incremental_scans_equal_the_old_predicate() {
        let inputs = [
            "email: fixture.876+tag@q7m9z2x4.synthetic\nemail: \u{e9}x@q7m9z2x4.synthetic.",
            "email: e\u{301}x@q7m9z2x4.synthetic\nemail: \u{fb01}x@q7m9z2x4.synthetic\nemail: \u{ac00}@a.test",
            "email: 고객876@x4z8v2n6.synthetic\nemail: \u{1100}\u{1161}x@a.test\nemail: \u{212b}@a.test",
            "email=fixture@q7m9z2x4.synthetic\nemail: x\u{323}\u{307}@a.test\nemail: e\u{301}@a.test",
        ];
        let mut with_findings = 0;
        for input in inputs {
            let expected = whole(input, true);
            assert_eq!(whole(input, false), expected, "{input:?}");
            with_findings += usize::from(!expected.1.is_empty());
            let boundaries: Vec<usize> = input
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(input.len()))
                .collect();
            for &split in &boundaries {
                assert_eq!(
                    incremental(input, &[split], false),
                    incremental(input, &[split], true),
                    "{input:?} split {split}"
                );
            }
            let mut rng = XorShift32::new(0x1147_0002);
            for _ in 0..40 {
                let mut cuts: Vec<usize> = (0..3)
                    .map(|_| boundaries[rng.below(boundaries.len())])
                    .collect();
                cuts.sort_unstable();
                assert_eq!(
                    incremental(input, &cuts, false),
                    incremental(input, &cuts, true),
                    "{input:?} cuts {cuts:?}"
                );
            }
        }
        assert!(with_findings >= 4);
    }
}
