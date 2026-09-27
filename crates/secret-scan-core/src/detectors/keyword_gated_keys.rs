//! Keyword-gated API keys for Mistral, Cohere, AI21 and Deepgram (issue #868).
//!
//! None of the four providers documents a prefix, length or alphabet for its
//! API key, and none of the provider SDKs validates one (`Mistral`,
//! `cohere.ClientV2`, `AI21Client` and `DeepgramClient` all accept any
//! string). The shapes below come only from scanner rules and maintainer
//! observation recorded in the research comments of issues #781, #782, #784
//! and #789, so this is **not** a T1 contract. It is a contextual,
//! unqualified, T2-at-best claim: a bare run of the right length is
//! indistinguishable from a hash, a session id or another vendor's key, so a
//! value is a finding only when provider context is adjacent to it.
//!
//! | Detector | Shape (scanner-inferred) | Provider keywords |
//! | --- | --- | --- |
//! | `mistral-api-key` | exactly 32 `[A-Za-z0-9]` | `mistral` |
//! | `cohere-api-key` | exactly 40 `[A-Za-z0-9]` | `cohere`, `CO_API_KEY` |
//! | `ai21-api-key` | exactly 32 `[A-Za-z0-9]` | `ai21` |
//! | `deepgram-api-key` | exactly 40 `[0-9a-z]` | `deepgram` |
//!
//! Deepgram's alphabet is the wider of the two scanner readings
//! (trufflehog `[0-9a-z]`, betterleaks `[a-f0-9]`); its own documentation
//! example (32 hex) contradicts both, and is read as a placeholder.
//!
//! Exa (#787) has no detector here: no source states any shape for its key
//! (only the key *id* is documented as a UUID), so any contract would be
//! invented. It stays with `generic-token`.
//!
//! ## Adjacency contract
//!
//! Context is read on the value's own line only (the incremental sanitizer's
//! processing unit), immediately before the value:
//!
//! 1. **Named assignment** (High): the value is assigned to a key whose
//!    normalized name carries the provider keyword and whose last segment is
//!    a credential word (`key`, `token`, `secret`, `apikey`, `credential`):
//!    `MISTRAL_API_KEY=`, `CO_API_KEY=`, `"deepgramApiKey":`.
//! 2. **SDK constructor** (High): the value is a keyword argument of a call
//!    whose callee name carries the provider keyword and whose key is a
//!    credential word (`Mistral(api_key="...")`,
//!    `cohere.ClientV2(api_key=...)`, `new CohereClient({ token: "..." })`),
//!    or the sole positional string (`DeepgramClient("...")`).
//! 3. **Keyword-adjacent key** (Medium): a credential-word key
//!    (`api_key:`) within 32 bytes after the provider keyword with only
//!    name-like bytes between them (`# Mistral API key: ...`).
//! 4. **Header** (Medium, Deepgram only): `Authorization: Token <value>` on a
//!    line that also names `deepgram` (`api.deepgram.com`). `Bearer` forms
//!    are already `bearer-token`'s.
//!
//! A key ending in an identifier or location segment (`_id`, `_url`,
//! `_org`, ...) never qualifies (`MISTRAL_KEY_ID=`, `DEEPGRAM_PROJECT_ID=`),
//! and a non-credential key (`Mistral(model="...")`) is not context at all.
//!
//! ## Trade-offs
//!
//! - False negatives: a constructor argument on a different line from the
//!   constructor, a value whose keyword is far from it, a key that differs
//!   from the inferred length or alphabet, and any provider key under a name
//!   with no keyword (`API_KEY=`). Under a provider-named assignment
//!   `generic-token` still redacts a wrong-length value; this detector only
//!   adds the typed, exact-length, constructor-aware claim.
//! - False positives: a 32/40-byte hash or id assigned to a keyword-named
//!   credential key. Filler runs and hash-labelled values are excluded.
//! - Overlap: the finding is `Provider` specificity, so overlap resolution
//!   keeps one finding for a span that `generic-token` also matches.
//!
//! Types are confidence-gated (not in `ALWAYS_REDACT_TYPES`), like Twilio.

use crate::detectors::generic_token::normalize_name;
use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// Last key-name segments that name the credential itself.
const CREDENTIAL_SEGMENTS: &[&str] = &["key", "token", "secret", "apikey", "credential"];

/// Longest gap between a provider keyword and the key that follows it, for
/// the keyword-adjacent (prose) form.
const KEYWORD_WINDOW: usize = 32;

/// Furthest an opening call parenthesis is searched for before a value, so
/// per-candidate work stays constant on a line packed with candidates.
const CALL_WINDOW: usize = 256;

/// Bytes of text before a value read for an `Authorization: Token` scheme.
const HEADER_WINDOW: usize = 48;

/// Static description of one keyword-gated provider key.
struct Spec {
    type_name: &'static str,
    len: usize,
    alphabet: Alphabet,
    /// Lowercase; matched as a substring of a normalized name or callee.
    keywords: &'static [&'static str],
    /// Lowercase normalized names matched only as whole `_` segments runs
    /// (`co_api_key`, so `pico_api_key` does not qualify).
    exact_names: &'static [&'static str],
    named_signal: &'static str,
    constructor_signal: &'static str,
    adjacent_signal: &'static str,
    /// Accepts an `Authorization: Token <value>` header on a keyword line.
    token_header: bool,
}

const MISTRAL: Spec = Spec {
    type_name: "mistral_api_key",
    len: 32,
    alphabet: pattern::is_alnum,
    keywords: &["mistral"],
    exact_names: &[],
    named_signal: "mistral-named-assignment",
    constructor_signal: "mistral-sdk-constructor",
    adjacent_signal: "mistral-keyword-adjacent",
    token_header: false,
};

const COHERE: Spec = Spec {
    type_name: "cohere_api_key",
    len: 40,
    alphabet: pattern::is_alnum,
    keywords: &["cohere"],
    exact_names: &["co_api_key"],
    named_signal: "cohere-named-assignment",
    constructor_signal: "cohere-sdk-constructor",
    adjacent_signal: "cohere-keyword-adjacent",
    token_header: false,
};

const AI21: Spec = Spec {
    type_name: "ai21_api_key",
    len: 32,
    alphabet: pattern::is_alnum,
    keywords: &["ai21"],
    exact_names: &[],
    named_signal: "ai21-named-assignment",
    constructor_signal: "ai21-sdk-constructor",
    adjacent_signal: "ai21-keyword-adjacent",
    token_header: false,
};

const DEEPGRAM: Spec = Spec {
    type_name: "deepgram_api_key",
    len: 40,
    alphabet: pattern::is_lower_alnum,
    keywords: &["deepgram"],
    exact_names: &[],
    named_signal: "deepgram-named-assignment",
    constructor_signal: "deepgram-sdk-constructor",
    adjacent_signal: "deepgram-keyword-adjacent",
    token_header: true,
};

/// `[A-Za-z0-9_-]`: a run is never a slice of a wider identifier.
fn is_boundary_byte(byte: u8) -> bool {
    pattern::is_alnum(byte) || matches!(byte, b'_' | b'-')
}

fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// Every non-overlapping, boundary-checked bare run of exactly `spec.len`
/// `spec.alphabet` bytes. A longer or shorter run is skipped whole.
fn scan_runs(line: &str, spec: &Spec) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let ends = pattern::run_ends(bytes, spec.alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !(spec.alphabet)(bytes[start]) {
            start += 1;
            continue;
        }
        let run_end = ends[start];
        if run_end - start == spec.len
            && pattern::boundary_ok(bytes, start, run_end, is_boundary_byte)
        {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

fn name_has_provider(spec: &Spec, normalized: &str) -> bool {
    spec.keywords
        .iter()
        .any(|keyword| normalized.contains(keyword))
        || spec.exact_names.iter().any(|name| {
            normalized == *name
                || normalized.starts_with(&format!("{name}_"))
                || normalized.ends_with(&format!("_{name}"))
                || normalized.contains(&format!("_{name}_"))
        })
}

fn is_credential_name(normalized: &str) -> bool {
    normalized
        .rsplit('_')
        .next()
        .is_some_and(|segment| CREDENTIAL_SEGMENTS.contains(&segment))
}

/// `true` when an unclosed call opens before `end` whose callee name carries
/// a provider keyword: `Mistral(`, `cohere.ClientV2(`, `new Exa({`.
fn inside_provider_call(line: &str, spec: &Spec, end: usize) -> bool {
    let bytes = line.as_bytes();
    let end = end.min(bytes.len());
    let floor = end.saturating_sub(CALL_WINDOW);
    let mut cursor = end;
    while cursor > floor {
        cursor -= 1;
        match bytes[cursor] {
            b')' => return false,
            b'(' => {
                let mut start = cursor;
                while start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric()
                        || matches!(bytes[start - 1], b'_' | b'.'))
                {
                    start -= 1;
                }
                let callee = line[start..cursor].to_ascii_lowercase();
                if spec.keywords.iter().any(|keyword| callee.contains(keyword)) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn contains_keyword_ci(window: &str, spec: &Spec) -> Option<usize> {
    let lowered = window.to_ascii_lowercase();
    spec.keywords
        .iter()
        .filter_map(|keyword| lowered.rfind(keyword).map(|at| at + keyword.len()))
        .max()
}

/// Classifies the context immediately before the value at `start`.
fn context(
    line: &str,
    spec: &Spec,
    start: usize,
    line_has_keyword: bool,
) -> Option<(Confidence, &'static str)> {
    let bytes = line.as_bytes();
    if let Some(key) = text::assignment_key(bytes, start) {
        let key_start = key.as_ptr() as usize - bytes.as_ptr() as usize;
        let normalized = normalize_name(std::str::from_utf8(key).ok()?);
        if !is_credential_name(&normalized) {
            return None;
        }
        if name_has_provider(spec, &normalized) {
            return Some((Confidence::High, spec.named_signal));
        }
        if inside_provider_call(line, spec, key_start) {
            return Some((Confidence::High, spec.constructor_signal));
        }
        let window =
            String::from_utf8_lossy(&bytes[key_start.saturating_sub(KEYWORD_WINDOW)..key_start])
                .into_owned();
        let keyword_end = contains_keyword_ci(&window, spec)?;
        let gap = window.get(keyword_end..)?;
        if gap
            .bytes()
            .all(|byte| !matches!(byte, b';' | b',' | b'=' | b')' | b'(' | b'{'))
        {
            return Some((Confidence::Medium, spec.adjacent_signal));
        }
        return None;
    }

    // No assignment key: a sole positional constructor argument, or an
    // `Authorization: Token` header.
    let mut cursor = start;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t' | b'"' | b'\'') {
        cursor -= 1;
    }
    if cursor > 0 && bytes[cursor - 1] == b'(' && inside_provider_call(line, spec, cursor) {
        return Some((Confidence::High, spec.constructor_signal));
    }
    if spec.token_header && cursor < start {
        let before = String::from_utf8_lossy(&bytes[cursor.saturating_sub(HEADER_WINDOW)..cursor])
            .to_ascii_lowercase();
        let scheme = before.trim_end();
        if let Some(head) = scheme.strip_suffix("token")
            && head.ends_with([' ', '\t', '"', '\''])
        {
            let head = head.trim_end_matches([' ', '\t', '"', '\'']);
            let header = head
                .strip_suffix(':')
                .or_else(|| head.strip_suffix('='))
                .map(|name| name.trim_end_matches([' ', '\t', '"', '\'']));
            if header.is_some_and(|name| name.ends_with("authorization")) && line_has_keyword {
                return Some((Confidence::Medium, "deepgram-token-header"));
            }
        }
    }
    None
}

/// `true` when `haystack` holds `needle` (lowercase ASCII, non-empty) under
/// ASCII case folding.
///
/// Scans for the needle's first byte (either case) with a straight-line
/// linear scan the compiler can auto-vectorize, and verifies the full needle
/// only at each candidate position. The provider keywords and name segments
/// this is called with are short (3-8 bytes) and rare in ordinary text, so
/// candidate positions are infrequent; measured against the four provider
/// keywords and `key` (the shortest `exact_names` segment) on the
/// `scale-logs-small-whole` performance workload, this is 1.3-3x faster than
/// a Boyer-Moore-Horspool shift-table scan (the shorter the needle, the
/// smaller a skip-based scan's average skip, so the branchy, data-dependent
/// table lookup stops paying for itself -- a plain byte scan a vectorizing
/// compiler already knows how to accelerate does not have that floor).
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let len = needle.len();
    if len == 0 {
        return true;
    }
    if haystack.len() < len {
        return false;
    }
    let first_lower = needle[0].to_ascii_lowercase();
    let first_upper = needle[0].to_ascii_uppercase();
    let last_start = haystack.len() - len;
    let mut at = 0;
    while at <= last_start {
        let Some(offset) = haystack[at..=last_start]
            .iter()
            .position(|&byte| byte == first_lower || byte == first_upper)
        else {
            return false;
        };
        let candidate = at + offset;
        if haystack[candidate..candidate + len].eq_ignore_ascii_case(needle) {
            return true;
        }
        at = candidate + 1;
    }
    false
}

/// `true` when `text` can hold a provider context for `spec`: a keyword, or
/// every `_` segment of an exact name (`co_api_key`), under ASCII case
/// folding.
///
/// Every context [`context`] accepts needs one of these on the value's own
/// line: a key whose normalized name contains a keyword or exact name, a call
/// whose callee contains a keyword, a keyword within [`KEYWORD_WINDOW`] bytes
/// before the key, or (Deepgram header) the keyword on the line.
/// [`normalize_name`] only lowercases, maps `.`/`-` to `_` and inserts `_`
/// before an uppercase letter, so a segment contiguous in the normalized name
/// is contiguous, modulo case, in the original. A text without any of them
/// therefore yields no candidate, and the run scan can be skipped.
fn may_have_provider_context(text: &str, spec: &Spec) -> bool {
    let bytes = text.as_bytes();
    spec.keywords
        .iter()
        .any(|keyword| contains_ascii_ci(bytes, keyword.as_bytes()))
        || spec.exact_names.iter().any(|name| {
            name.rsplit('_')
                .all(|segment| contains_ascii_ci(bytes, segment.as_bytes()))
        })
}

fn detect_spec(input: &str, spec: &Spec) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    if !may_have_provider_context(input, spec) {
        return candidates;
    }
    for (line_start, line_end) in lines(input) {
        let line = &input[line_start..line_end];
        if !may_have_provider_context(line, spec) {
            continue;
        }
        let runs = scan_runs(line, spec);
        if runs.is_empty() {
            continue;
        }
        let line_has_keyword = spec.token_header && contains_keyword_ci(line, spec).is_some();
        for (start, end) in runs {
            if text::is_repeated_character_filler(&line[start..end])
                || text::is_labelled_digest(line, start)
            {
                continue;
            }
            let Some((confidence, signal)) = context(line, spec, start, line_has_keyword) else {
                continue;
            };
            let Some(range) = ByteRange::new(line_start + start, line_start + end) else {
                continue;
            };
            candidates.push(
                Candidate::new(spec.type_name, confidence, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals([signal]),
            );
        }
    }
    candidates
}

macro_rules! keyword_gated_detector {
    ($struct_name:ident, $id:literal, $spec:expr) => {
        pub(super) struct $struct_name;

        impl Detector for $struct_name {
            fn id(&self) -> &'static str {
                $id
            }

            fn detect(
                &self,
                input: &str,
                _context: &DetectorContext,
            ) -> Result<Vec<Candidate>, DetectorFailure> {
                Ok(detect_spec(input, &$spec))
            }
        }
    };
}

keyword_gated_detector!(MistralApiKeyDetector, "mistral-api-key", MISTRAL);
keyword_gated_detector!(CohereApiKeyDetector, "cohere-api-key", COHERE);
keyword_gated_detector!(Ai21ApiKeyDetector, "ai21-api-key", AI21);
keyword_gated_detector!(DeepgramApiKeyDetector, "deepgram-api-key", DEEPGRAM);

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic bodies built at test time; none is or derives from a real key.
    fn body(len: usize, seed: &str) -> String {
        seed.chars().cycle().take(len).collect()
    }

    fn alnum32() -> String {
        body(32, "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9xC2")
    }

    fn alnum40() -> String {
        body(40, "zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fE")
    }

    fn lower40() -> String {
        body(40, "q7w3e9r1t5y8u2i4o6p0a")
    }

    fn run(spec: &Spec, input: &str) -> Vec<Candidate> {
        detect_spec(input, spec)
    }

    fn assert_exact(spec: &Spec, input: &str, value: &str, confidence: Confidence) {
        let found = run(spec, input);
        assert_eq!(found.len(), 1, "{input}");
        let range = found[0].range();
        assert_eq!(&input[range.start()..range.end()], value, "{input}");
        assert_eq!(found[0].confidence(), confidence, "{input}");
        assert_eq!(found[0].type_name(), spec.type_name);
    }

    #[test]
    fn fixture_lengths_are_the_inferred_lengths() {
        assert_eq!(alnum32().len(), 32);
        assert_eq!(alnum40().len(), 40);
        assert_eq!(lower40().len(), 40);
    }

    #[test]
    fn named_assignments_are_high_confidence_exact_spans() {
        let m = alnum32();
        let c = alnum40();
        let d = lower40();
        for input in [
            format!("MISTRAL_API_KEY={m}"),
            format!("export MISTRAL_API_KEY=\"{m}\""),
            format!("{{\"mistralApiKey\": \"{m}\"}}"),
            format!("mistral_api_key: {m}"),
        ] {
            assert_exact(&MISTRAL, &input, &m, Confidence::High);
        }
        for input in [
            format!("CO_API_KEY={c}"),
            format!("COHERE_API_KEY='{c}'"),
            format!("cohere.token: {c}"),
        ] {
            assert_exact(&COHERE, &input, &c, Confidence::High);
        }
        assert_exact(&AI21, &format!("AI21_API_KEY={m}"), &m, Confidence::High);
        for input in [
            format!("DEEPGRAM_API_KEY={d}"),
            format!("deepgram_api_key = \"{d}\""),
        ] {
            assert_exact(&DEEPGRAM, &input, &d, Confidence::High);
        }
    }

    #[test]
    fn sdk_constructor_arguments_are_high_confidence() {
        let m = alnum32();
        let c = alnum40();
        let d = lower40();
        assert_exact(
            &MISTRAL,
            &format!("client = Mistral(api_key=\"{m}\")"),
            &m,
            Confidence::High,
        );
        assert_exact(
            &MISTRAL,
            &format!("const c = new Mistral({{ apiKey: \"{m}\" }});"),
            &m,
            Confidence::High,
        );
        assert_exact(
            &COHERE,
            &format!("co = cohere.ClientV2(api_key=\"{c}\")"),
            &c,
            Confidence::High,
        );
        assert_exact(
            &COHERE,
            &format!("co = cohere.Client(\"{c}\")"),
            &c,
            Confidence::High,
        );
        assert_exact(
            &COHERE,
            &format!("new CohereClient({{ token: \"{c}\" }})"),
            &c,
            Confidence::High,
        );
        assert_exact(
            &AI21,
            &format!("AI21Client(api_key='{m}')"),
            &m,
            Confidence::High,
        );
        assert_exact(
            &DEEPGRAM,
            &format!("dg = DeepgramClient(api_key=\"{d}\")"),
            &d,
            Confidence::High,
        );
        assert_exact(
            &DEEPGRAM,
            &format!("dg = DeepgramClient(\"{d}\")"),
            &d,
            Confidence::High,
        );
    }

    #[test]
    fn a_keyword_adjacent_key_and_the_deepgram_token_header_are_medium() {
        let m = alnum32();
        let d = lower40();
        assert_exact(
            &MISTRAL,
            &format!("# Mistral API key: {m}"),
            &m,
            Confidence::Medium,
        );
        assert_exact(
            &DEEPGRAM,
            &format!("curl -H 'Authorization: Token {d}' https://api.deepgram.com/v1/projects"),
            &d,
            Confidence::Medium,
        );
        assert_exact(
            &DEEPGRAM,
            &format!(
                "headers = {{\"Authorization\": \"Token {d}\", \"host\": \"api.deepgram.com\"}}"
            ),
            &d,
            Confidence::Medium,
        );
    }

    #[test]
    fn bare_values_and_unrelated_keys_are_not_findings() {
        let m = alnum32();
        let c = alnum40();
        let d = lower40();
        for input in [
            m.clone(),
            format!("hash {m}"),
            format!("API_KEY={m}"),
            format!("OPENAI_API_KEY={m}"),
            format!("mistral is fine, id {m}"),
            format!("Client(api_key=\"{m}\")"),
            format!("Authorization: Token {m}"),
        ] {
            assert!(run(&MISTRAL, &input).is_empty(), "{input}");
            assert!(run(&AI21, &input).is_empty(), "{input}");
        }
        assert!(run(&COHERE, &c).is_empty());
        assert!(run(&COHERE, &format!("PICO_API_KEY={c}")).is_empty());
        assert!(run(&COHERE, &format!("cohere_api_key value {c}")).is_empty());
        assert!(run(&DEEPGRAM, &format!("Authorization: Token {d}")).is_empty());
        assert!(run(&DEEPGRAM, &format!("Authorization: Bearer {d} deepgram")).is_empty());
    }

    #[test]
    fn id_like_and_non_credential_siblings_are_not_findings() {
        let m = alnum32();
        let c = alnum40();
        let d = lower40();
        for input in [
            format!("MISTRAL_KEY_ID={m}"),
            format!("MISTRAL_MODEL={m}"),
            format!("Mistral(model=\"{m}\")"),
            format!("AI21_ORG_ID={m}"),
            format!("AI21_TEAM_ID={m}"),
        ] {
            assert!(run(&MISTRAL, &input).is_empty(), "{input}");
            assert!(run(&AI21, &input).is_empty(), "{input}");
        }
        assert!(run(&COHERE, &format!("COHERE_ORG_ID={c}")).is_empty());
        assert!(run(&COHERE, &format!("cohere.ClientV2(base_url=\"{c}\")")).is_empty());
        assert!(run(&DEEPGRAM, &format!("DEEPGRAM_PROJECT_ID={d}")).is_empty());
        assert!(run(&DEEPGRAM, &format!("DEEPGRAM_API_KEY_ID={d}")).is_empty());
    }

    #[test]
    fn placeholders_fillers_and_digests_are_not_findings() {
        let m = alnum32();
        for input in [
            "MISTRAL_API_KEY=your_api_key_here".to_owned(),
            "MISTRAL_API_KEY=<your-mistral-key>".to_owned(),
            "MISTRAL_API_KEY=${MISTRAL_API_KEY}".to_owned(),
            format!("MISTRAL_API_KEY={}", "x".repeat(32)),
            format!("MISTRAL_API_KEY={}", "0".repeat(32)),
            format!("MISTRAL_API_KEY=md5:{m}"),
            "Mistral(api_key=os.environ[\"MISTRAL_API_KEY\"])".to_owned(),
        ] {
            assert!(run(&MISTRAL, &input).is_empty(), "{input}");
        }
        assert!(run(&DEEPGRAM, &format!("DEEPGRAM_API_KEY={}", "a".repeat(40))).is_empty());
    }

    #[test]
    fn twins_with_the_wrong_length_or_alphabet_are_not_findings() {
        let m = alnum32();
        let c = alnum40();
        let d = lower40();
        for value in [
            body(31, &m),
            body(33, &m),
            format!("{}_{}", &m[..15], &m[16..]),
            format!("{}-{}", &m[..15], &m[16..]),
            format!("{m}{m}"),
        ] {
            let input = format!("MISTRAL_API_KEY={value}");
            assert!(run(&MISTRAL, &input).is_empty(), "{input}");
        }
        assert!(run(&COHERE, &format!("CO_API_KEY={}", body(39, &c))).is_empty());
        assert!(run(&COHERE, &format!("CO_API_KEY={}", body(41, &c))).is_empty());
        assert!(
            run(
                &DEEPGRAM,
                &format!("DEEPGRAM_API_KEY={}", d.to_ascii_uppercase())
            )
            .is_empty()
        );
        assert!(run(&DEEPGRAM, &format!("DEEPGRAM_API_KEY={}", body(39, &d))).is_empty());
        assert!(run(&AI21, &format!("AI21_API_KEY={}", body(40, &m))).is_empty());
    }

    #[test]
    fn a_value_is_not_reported_for_the_wrong_provider() {
        let m = alnum32();
        assert!(run(&AI21, &format!("MISTRAL_API_KEY={m}")).is_empty());
        assert!(run(&MISTRAL, &format!("AI21_API_KEY={m}")).is_empty());
        assert!(run(&MISTRAL, &format!("Cohere(api_key=\"{m}\")")).is_empty());
    }

    #[test]
    fn context_on_a_different_line_is_not_adjacent() {
        let m = alnum32();
        let input = format!("Mistral(\n    api_key=\"{m}\"\n)");
        assert!(run(&MISTRAL, &input).is_empty());
        let input = format!("MISTRAL_API_KEY=\n{m}");
        assert!(run(&MISTRAL, &input).is_empty());
    }

    #[test]
    fn every_value_on_a_line_is_judged_alone_and_scanning_is_deterministic() {
        let m = alnum32();
        let other = body(32, "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0");
        let input = format!("MISTRAL_API_KEY={m} SECOND={other}\r\nMISTRAL_API_KEY={other}");
        let first = run(&MISTRAL, &input);
        assert_eq!(first.len(), 2);
        assert_eq!(first, run(&MISTRAL, &input));
    }

    #[test]
    fn a_unicode_prefix_keeps_byte_offsets_exact() {
        let m = alnum32();
        let input = format!("한글 MISTRAL_API_KEY={m}");
        assert_exact(&MISTRAL, &input, &m, Confidence::High);
    }

    #[test]
    fn a_long_line_of_near_misses_stays_bounded() {
        let input = format!("MISTRAL_API_KEY={}", "a".repeat(200_000));
        assert!(run(&MISTRAL, &input).is_empty());
        let input = "Mistral(".repeat(20_000);
        assert!(run(&MISTRAL, &input).is_empty());
    }
}
