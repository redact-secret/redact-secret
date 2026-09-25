//! The strict exclusion grammar of the shadow scorer's `negative` group
//! (issue #770,
//! `decision-freeze-the-shadow-evidence-score-and-confidence-contract`
//! section 6).
//!
//! Negative evidence applies only when the **whole** candidate value is one
//! of the reviewed forms below. Each check anchors both ends of the value, so
//! a prefix, a suffix, a substring, or any fuzzy resemblance to a placeholder
//! or reference never matches. An attacker who wraps real material in
//! placeholder-looking text therefore gains nothing.
//!
//! The grammars are the `strict` set the benchmark calibration selected
//! (redact-secret-benchmarks#255, `docs/specs/calibration-experiments.md`
//! section 5), written from the benchmark's `negativeClass` definitions
//! (`docs/specs/candidate-features.md`). The benchmark's `dotted-reference`
//! class is deliberately absent: it also matches dotted credential grammars
//! such as JWT-like or `SG.`-style values.

/// A reviewed whole-value exclusion grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ExclusionGrammar {
    /// `{{` … `}}` with no brace inside.
    TemplateReference,
    /// `${NAME}`, `${NAME:-default}`, `${NAME-default}`, `$NAME` or `%NAME%`,
    /// `NAME` being `[A-Za-z_][A-Za-z0-9_]*`.
    EnvironmentReference,
    /// `$(` … `)` with no parenthesis inside, or `` ` `` … `` ` `` with no
    /// backtick inside.
    CommandSubstitution,
    /// `<` `[A-Za-z0-9_ .-]+` `>`.
    AnglePlaceholder,
    /// Three or more of one symbol from `* x X • # . - 0`.
    Mask,
    /// Words from the placeholder vocabulary only, at least one of them a
    /// marker word.
    PlaceholderVocabulary,
}

impl ExclusionGrammar {
    /// The benchmark's name for the grammar.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TemplateReference => "template-reference",
            Self::EnvironmentReference => "environment-reference",
            Self::CommandSubstitution => "command-substitution",
            Self::AnglePlaceholder => "angle-placeholder",
            Self::Mask => "mask",
            Self::PlaceholderVocabulary => "placeholder-vocabulary",
        }
    }
}

/// Words a placeholder may be built from.
pub(crate) const PLACEHOLDER_WORDS: [&str; 35] = [
    "a",
    "access",
    "an",
    "api",
    "auth",
    "change",
    "changeme",
    "client",
    "dummy",
    "example",
    "fake",
    "goes",
    "here",
    "id",
    "insert",
    "key",
    "me",
    "my",
    "nil",
    "none",
    "null",
    "password",
    "placeholder",
    "redacted",
    "replace",
    "replaceme",
    "sample",
    "secret",
    "tbd",
    "the",
    "todo",
    "token",
    "undefined",
    "value",
    "your",
];

/// Words of which a placeholder needs at least one.
pub(crate) const PLACEHOLDER_MARKERS: [&str; 18] = [
    "changeme",
    "dummy",
    "example",
    "fake",
    "here",
    "insert",
    "nil",
    "none",
    "null",
    "placeholder",
    "redacted",
    "replace",
    "replaceme",
    "sample",
    "tbd",
    "todo",
    "undefined",
    "your",
];

/// Symbols a mask may repeat.
pub(crate) const MASK_SYMBOLS: [char; 8] = ['*', 'x', 'X', '\u{2022}', '#', '.', '-', '0'];

/// The shortest mask.
pub(crate) const MIN_MASK_LEN: usize = 3;

/// The exclusion grammar the whole of `value` matches, if any, checked in
/// the benchmark's order.
#[must_use]
pub(crate) fn exclusion_grammar(value: &str) -> Option<ExclusionGrammar> {
    if is_template_reference(value) {
        Some(ExclusionGrammar::TemplateReference)
    } else if is_environment_reference(value) {
        Some(ExclusionGrammar::EnvironmentReference)
    } else if is_command_substitution(value) {
        Some(ExclusionGrammar::CommandSubstitution)
    } else if is_angle_placeholder(value) {
        Some(ExclusionGrammar::AnglePlaceholder)
    } else if is_mask(value) {
        Some(ExclusionGrammar::Mask)
    } else if is_placeholder_vocabulary(value) {
        Some(ExclusionGrammar::PlaceholderVocabulary)
    } else {
        None
    }
}

/// `value` is `open` + an interior without any of `forbidden` + `close`.
fn is_delimited(value: &str, open: &str, close: &str, forbidden: &[char]) -> bool {
    value.len() >= open.len() + close.len()
        && value
            .strip_prefix(open)
            .and_then(|rest| rest.strip_suffix(close))
            .is_some_and(|interior| !interior.contains(forbidden))
}

fn is_template_reference(value: &str) -> bool {
    is_delimited(value, "{{", "}}", &['{', '}'])
}

fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_environment_reference(value: &str) -> bool {
    if let Some(inner) = value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        // `NAME`, then optionally `:-default` or `-default` whose default
        // holds no closing brace.
        let name_end = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let (name, rest) = inner.split_at(name_end);
        let default_ok = rest.is_empty()
            || rest
                .strip_prefix(":-")
                .or_else(|| rest.strip_prefix('-'))
                .is_some_and(|default| !default.contains('}'));
        return is_name(name) && default_ok;
    }
    value.strip_prefix('$').is_some_and(is_name)
        || (value.len() >= 2
            && value
                .strip_prefix('%')
                .and_then(|rest| rest.strip_suffix('%'))
                .is_some_and(is_name))
}

fn is_command_substitution(value: &str) -> bool {
    is_delimited(value, "$(", ")", &['(', ')']) || is_delimited(value, "`", "`", &['`'])
}

fn is_angle_placeholder(value: &str) -> bool {
    value
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .is_some_and(|interior| {
            !interior.is_empty()
                && interior
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b' ' | b'.' | b'-'))
        })
}

fn is_mask(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    MASK_SYMBOLS.contains(&first)
        && chars.clone().all(|c| c == first)
        && chars.count() + 1 >= MIN_MASK_LEN
}

/// Word separators: `_`, `-`, `.` and whitespace.
fn is_word_separator(c: char) -> bool {
    matches!(c, '_' | '-' | '.') || c.is_whitespace()
}

fn is_placeholder_vocabulary(value: &str) -> bool {
    let lower = value.to_lowercase();
    let mut words = lower.split(is_word_separator).filter(|w| !w.is_empty());
    let mut any_word = false;
    let mut any_marker = false;
    let all_known = words.all(|word| {
        any_word = true;
        any_marker |= PLACEHOLDER_MARKERS.contains(&word);
        PLACEHOLDER_WORDS.contains(&word)
    });
    all_known && any_word && any_marker
}

#[cfg(test)]
mod tests {
    use super::ExclusionGrammar::*;
    use super::*;

    #[test]
    fn whole_value_forms_match_their_grammar() {
        for (value, grammar) in [
            ("{{ secrets.API_KEY }}", TemplateReference),
            ("{{}}", TemplateReference),
            ("${API_KEY}", EnvironmentReference),
            ("${API_KEY:-fallback}", EnvironmentReference),
            ("${API_KEY-fallback}", EnvironmentReference),
            ("$API_KEY", EnvironmentReference),
            ("%API_KEY%", EnvironmentReference),
            ("$(cat /run/secrets/api_key)", CommandSubstitution),
            ("`vault read -field=value kv/app`", CommandSubstitution),
            ("<your api key>", AnglePlaceholder),
            ("<API_KEY>", AnglePlaceholder),
            ("***", Mask),
            ("xxxxxxxxxxxxxxxx", Mask),
            ("\u{2022}\u{2022}\u{2022}\u{2022}", Mask),
            ("0000000000", Mask),
            ("your-api-key-here", PlaceholderVocabulary),
            ("CHANGEME", PlaceholderVocabulary),
            ("replace_me", PlaceholderVocabulary),
            ("example token", PlaceholderVocabulary),
        ] {
            assert_eq!(exclusion_grammar(value), Some(grammar), "{value:?}");
        }
    }

    /// Synthetic random-looking material an attacker controls.
    const MATERIAL: &str = "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa";

    #[test]
    fn prefix_suffix_and_substring_lookalikes_never_match() {
        let lookalikes = [
            // Placeholder vocabulary as a prefix, a suffix or a substring.
            format!("EXAMPLE{MATERIAL}"),
            format!("example_{MATERIAL}"),
            format!("{MATERIAL}_placeholder"),
            format!("your-{MATERIAL}-here"),
            format!("changeme{MATERIAL}"),
            // Delimiters on one side only, or real material after them.
            format!("{{{{ {MATERIAL}"),
            format!("{MATERIAL} }}}}"),
            format!("{{{{ x }}}}{MATERIAL}"),
            format!("{MATERIAL}{{{{ x }}}}"),
            format!("{{{{ a }}}} {{{{ {MATERIAL} }}}}x"),
            format!("${{API_KEY}}{MATERIAL}"),
            format!("$API_KEY-{MATERIAL}"),
            format!("{MATERIAL}$API_KEY"),
            format!("%API_KEY%{MATERIAL}"),
            format!("$(echo){MATERIAL}"),
            format!("`x`{MATERIAL}"),
            format!("<API_KEY>{MATERIAL}"),
            format!("{MATERIAL}<API_KEY>"),
            // A mask run only around real material.
            format!("****{MATERIAL}"),
            format!("{MATERIAL}xxxx"),
            format!("xxxx{MATERIAL}xxxx"),
            // Fuzzy resemblance: an edit away from a vocabulary word.
            "exampel-api-key".to_owned(),
            "your-api-keys".to_owned(),
            "placeholder1".to_owned(),
            // Vocabulary without a marker word.
            "api_secret_token".to_owned(),
            // Mask symbols that are not all the same, or too short.
            "xX".to_owned(),
            "*x*".to_owned(),
            "**".to_owned(),
            // Grammars the product deliberately does not treat as negative.
            "process.env.API_KEY".to_owned(),
            "secrets.TOKEN".to_owned(),
            "SG.Q7vK2mZp9LxR4tWb.8NcY3hJd6FsG1eUa".to_owned(),
            MATERIAL.to_owned(),
            String::new(),
        ];
        for value in &lookalikes {
            assert_eq!(exclusion_grammar(value), None, "{value:?}");
        }
    }

    #[test]
    fn inner_delimiters_and_malformed_names_do_not_match() {
        for value in [
            "{{ a }} }}",
            "{{ {a} }}",
            "${1ABC}",
            "${API KEY}",
            "${API_KEY:fallback}",
            "${API_KEY:-a}b}",
            "$",
            "$1ABC",
            "%%",
            "%API KEY%",
            "$(a(b))",
            "`a`b`",
            "<>",
            "<api/key>",
            "<a<b>",
        ] {
            assert_eq!(exclusion_grammar(value), None, "{value:?}");
        }
    }

    #[test]
    fn grammar_names_follow_the_benchmark_vocabulary() {
        let names = [
            TemplateReference,
            EnvironmentReference,
            CommandSubstitution,
            AnglePlaceholder,
            Mask,
            PlaceholderVocabulary,
        ]
        .map(ExclusionGrammar::as_str);
        assert_eq!(
            names,
            [
                "template-reference",
                "environment-reference",
                "command-substitution",
                "angle-placeholder",
                "mask",
                "placeholder-vocabulary"
            ]
        );
    }

    #[test]
    fn every_marker_is_a_placeholder_word() {
        for marker in PLACEHOLDER_MARKERS {
            assert!(PLACEHOLDER_WORDS.contains(&marker), "{marker}");
        }
    }
}
