//! AWS access-key detection.
//!
//! Mirrors `src/detectors/aws.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::detectors::prefilter::Literals;
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 2] = ["AKIA", "ASIA"];

/// Restricts matches to the two documented AWS access-key prefixes and their
/// fixed length: `AKIA` (long-term IAM user keys) and `ASIA` (temporary STS
/// credentials, an identifier usable only with its secret and session
/// token), each + exactly 16 `[A-Z0-9]`, typed and actioned alike. The
/// `ASIA` contract is READY-T2 in issue #1012
/// (`docs/audits/evidence/1012/aws-sts-temporary-access-key.md`, #1027). This intentionally excludes other AWS identifiers such as
/// role and user IDs; unknown or future prefixes are false negatives until
/// explicitly added.
pub(super) struct AwsAccessKeyDetector;

impl Detector for AwsAccessKeyDetector {
    fn id(&self) -> &'static str {
        "aws-access-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &PREFIXES,
            RunLength::Exact(16),
            pattern::is_upper_alnum,
            pattern::is_alnum,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::built_in("aws_access_key_id", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["aws-prefix", "fixed-length"]),
            );
        }
        Ok(candidates)
    }
}

/// The literals one of which every `aws-access-key` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&PREFIXES)];

const SECRET_TYPE: &str = "aws_secret_access_key";
/// Base64 of 30 random bytes: exactly 40 characters, no padding.
const SECRET_LEN: usize = 40;
/// How far before a value the key name is read: a name, its quotes, an
/// operator and an `aws configure` `[****abcd]` hint fit well inside it.
const NAME_WINDOW: usize = 96;
/// A name or an access key ID is the context; one of these literals occurs
/// whenever a candidate is proposed, for the shared prefilter. A name is
/// accepted only when it spells `secret` as `secret`, `Secret` or `SECRET`,
/// so the declaration stays sound.
const SECRET_CONTEXT_LITERALS: [&str; 4] = ["AKIA", "ASIA", "ecret", "ECRET"];

/// `[A-Za-z0-9/+]`: the value class.
fn is_secret_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'+'
}

/// Every AWS access key ID in `input`, as start offsets, in order.
fn access_key_id_starts(input: &str) -> Vec<usize> {
    pattern::scan_prefixed_runs(
        input,
        &PREFIXES,
        RunLength::Exact(16),
        pattern::is_upper_alnum,
        pattern::is_alnum,
    )
    .into_iter()
    .map(|(start, _)| start)
    .collect()
}

/// The most words a `for <qualifier>` after the phrase may carry.
const MAX_QUALIFIER_WORDS: usize = 4;

/// `true` when lowercase `name` ends with the phrase `secret access key`
/// followed by `for` and one to [`MAX_QUALIFIER_WORDS`] words of ASCII
/// letters, digits, `_` or `-` (issue #1044): `the secret access key for
/// the staging user`, as a chat message or ticket writes it before `:`.
fn ends_with_qualified_phrase(name: &str) -> bool {
    const PHRASE: &str = "secret access key for ";
    // The last case-insensitive occurrence. The phrase has no border (it
    // starts with `s` and ends with a space), so occurrences never overlap.
    let mut last = None;
    let mut from = 0;
    while let Some(at) = text::find_ci(name.as_bytes(), from, PHRASE.as_bytes()) {
        last = Some(at);
        from = at + 1;
    }
    let Some(at) = last else {
        return false;
    };
    let qualifier = &name[at + PHRASE.len()..];
    let words: Vec<&str> = qualifier.split(' ').collect();
    (1..=MAX_QUALIFIER_WORDS).contains(&words.len())
        && words.iter().all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

/// `true` when `name` (the text before a value, already cut to the name
/// window) ends in an AWS secret access key name and an `=`/`:` operator:
/// an identifier whose compact form (lowercase, `_.-` removed) ends in
/// `secretaccesskey`, `awssecretkey` or `awssecret`, or the phrase
/// `secret access key` of the `aws configure` prompt and the console's CSV,
/// optionally followed by a `[...]` hint. Quotes and whitespace around the
/// name and operator are skipped.
fn ends_with_secret_name(prefix: &str) -> bool {
    let trim = |text: &str| -> usize { text.trim_end_matches([' ', '\t', '"', '\'', '\\']).len() };
    let mut end = trim(prefix);
    let Some(operator) = prefix[..end].chars().next_back() else {
        return false;
    };
    if operator != '=' && operator != ':' {
        return false;
    }
    end -= 1;
    if prefix[..end].ends_with(':') {
        end -= 1;
    }
    end = trim(&prefix[..end]);
    let mut name = &prefix[..end];
    if name.ends_with(']')
        && let Some(open) = name.rfind('[')
    {
        name = name[..open].trim_end_matches([' ', '\t']);
    }
    if !(name.contains("ecret") || name.contains("ECRET")) {
        return false;
    }
    if text::ends_with_ci(name, "secret access key") || ends_with_qualified_phrase(name) {
        return true;
    }
    // `at + len_utf8()`, not `at + 1`: the separator may be multi-byte.
    let identifier_start = name
        .char_indices()
        .rev()
        .find(|&(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')))
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let identifier = &name[identifier_start..];
    if !(identifier.contains("ecret") || identifier.contains("ECRET")) {
        return false;
    }
    compact_ends_with_ci(identifier, "secretaccesskey")
        || compact_ends_with_ci(identifier, "awssecretkey")
        || compact_ends_with_ci(identifier, "awssecret")
}

/// `true` when `identifier`, with every `_`, `.` and `-` byte removed, ends
/// with the lowercase ASCII `suffix`, case-insensitively.
fn compact_ends_with_ci(identifier: &str, suffix: &str) -> bool {
    let mut kept = identifier
        .bytes()
        .rev()
        .filter(|byte| !matches!(byte, b'_' | b'.' | b'-'));
    suffix.bytes().rev().all(|expected| {
        kept.next()
            .is_some_and(|byte| byte.to_ascii_lowercase() == expected)
    })
}

/// Every run on `input[line_start..line_end]` shaped like a secret access
/// key: exactly [`SECRET_LEN`] `[A-Za-z0-9/+]` (runs are maximal, so no such
/// byte is before or after it), not followed by `=` (Base64 padding: not a
/// 30-byte secret), with at least one uppercase and one lowercase letter.
fn secret_runs(
    input: &str,
    line_start: usize,
    line_end: usize,
) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut at = line_start;
    std::iter::from_fn(move || {
        while at < line_end {
            if !is_secret_byte(bytes[at]) {
                at += 1;
                continue;
            }
            let run_start = at;
            while at < line_end && is_secret_byte(bytes[at]) {
                at += 1;
            }
            let value = &bytes[run_start..at];
            if value.len() == SECRET_LEN
                && bytes.get(at) != Some(&b'=')
                && value.iter().any(u8::is_ascii_uppercase)
                && value.iter().any(u8::is_ascii_lowercase)
            {
                return Some((run_start, at));
            }
        }
        None
    })
}

/// `true` when an AWS secret access key name ([`ends_with_secret_name`]),
/// read back over at most [`NAME_WINDOW`] bytes of its line, is directly
/// before the run at `run_start`.
fn is_named(input: &str, line_start: usize, run_start: usize) -> bool {
    let mut window = run_start.saturating_sub(NAME_WINDOW).max(line_start);
    while !input.is_char_boundary(window) {
        window += 1;
    }
    ends_with_secret_name(&input[window..run_start])
}

/// The secret half of an AWS access key (issue #1028, #1012 READY-T2,
/// context-constrained; `docs/audits/evidence/1012/`
/// `aws-iam-user-secret-access-key.md`): exactly 40 `[A-Za-z0-9/+]` with no
/// `[A-Za-z0-9/+]` byte before it (a `=` there is an assignment operator),
/// no `[A-Za-z0-9/+=]` byte after it (ferret-scan's boundary), and at least
/// one uppercase and one lowercase letter, claimed only
///
/// - under an AWS secret access key name ([`ends_with_secret_name`]) read
///   back over at most [`NAME_WINDOW`] bytes on the value's line, or
/// - on the line of an `AKIA`/`ASIA` access key ID, or on the line directly
///   below or above one (issue #1044). The incremental session scans the
///   next unit below a copy of an ID line ([`carries_aws_access_key_id`],
///   issue #1040) and holds a line with an unclaimed run for one more line
///   ([`has_open_aws_secret_candidate_line`]), so streamed and whole-input
///   scans agree.
///
/// A bare 40-character run is not attributable: AWS's own detectors (Macie,
/// git-secrets, ferret-scan) require the same context. The mixed-case guard
/// keeps a 40-hex Git SHA and case-folded identifiers out; a random 30-byte
/// Base64 value lacks either case with probability about 1e-9. A 41-byte
/// temporary secret, a value with `=`, and an ID two lines away are
/// intentional false negatives here; `generic-token` still redacts every
/// width under a secret access key name.
pub(super) struct AwsSecretAccessKeyDetector;

impl Detector for AwsSecretAccessKeyDetector {
    fn id(&self) -> &'static str {
        "aws-secret-access-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        if !SECRET_CONTEXT_LITERALS
            .iter()
            .any(|literal| input.contains(literal))
        {
            return Ok(Vec::new());
        }
        let ids = access_key_id_starts(input);
        let lines: Vec<(usize, usize)> = text::lines(input).collect();
        let mut next_id = 0usize;
        let line_has_id: Vec<bool> = lines
            .iter()
            .map(|&(line_start, line_end)| {
                while next_id < ids.len() && ids[next_id] < line_start {
                    next_id += 1;
                }
                ids.get(next_id).is_some_and(|&id| id < line_end)
            })
            .collect();
        let mut candidates = Vec::new();
        for (index, &(line_start, line_end)) in lines.iter().enumerate() {
            // Issue #1044: the line directly above or below counts, as the
            // #1028 contract's "same or adjacent line" says.
            let adjacent = line_has_id[index]
                || (index > 0 && line_has_id[index - 1])
                || line_has_id.get(index + 1).copied().unwrap_or(false);
            for (run_start, run_end) in secret_runs(input, line_start, line_end) {
                let signal = if adjacent {
                    "aws-access-key-id-adjacent"
                } else if is_named(input, line_start, run_start) {
                    "aws-secret-access-key-name"
                } else {
                    continue;
                };
                if let Some(range) = ByteRange::new(run_start, run_end) {
                    candidates.push(
                        Candidate::built_in(SECRET_TYPE, Confidence::High, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals(["aws-secret-width", signal]),
                    );
                }
            }
        }
        Ok(candidates)
    }
}

/// Internal lookbehind check for the built-in incremental scanner: `true`
/// when `line` carries an AWS access key ID, so the session scans the next
/// unit below a copy of it, which [`AwsSecretAccessKeyDetector`] reads as
/// adjacent (issue #1028). The line itself is released when it closes: a
/// line is never held for the sake of the line below it (issue #1040).
pub(crate) fn carries_aws_access_key_id(line: &str) -> bool {
    !access_key_id_starts(line).is_empty()
}

/// Internal retention hint for the built-in incremental scanner (issue
/// #1044): `true` when the last complete line of `unit` holds a secret-shaped
/// run that nothing on its own line or the line above claims, so an access
/// key ID on the next line would claim it. That line must wait for exactly
/// one more line. `above_has_id` answers for the line above when `unit` is a
/// single line; it is asked only when needed.
///
/// A line that carries an ID is never held (issue #1040): a run on it is
/// already claimed, and the line below reads it through the session's copy.
/// A run claimed by a name on its line holds nothing either.
#[cfg(test)]
pub(crate) fn has_open_aws_secret_candidate_line(
    unit: &str,
    above_has_id: impl FnOnce() -> bool,
) -> bool {
    has_open_aws_secret_candidate_line_in(&super::lookback_tail(unit), above_has_id)
}

/// [`has_open_aws_secret_candidate_line`] over a [`super::lookback_tail`].
pub(crate) fn has_open_aws_secret_candidate_line_in(
    tail: &[&str],
    above_has_id: impl FnOnce() -> bool,
) -> bool {
    let tail = text::tail_lines(tail, 2);
    let Some(&last) = tail.last() else {
        return false;
    };
    if last.len() < SECRET_LEN || carries_aws_access_key_id(last) {
        return false;
    }
    if !secret_runs(last, 0, last.len()).any(|(run_start, _)| !is_named(last, 0, run_start)) {
        return false;
    }
    let above = match tail {
        [above, _] => carries_aws_access_key_id(above),
        _ => above_has_id(),
    };
    !above
}

/// The literals one of which every `aws-secret-access-key` candidate's
/// input contains, for the shared prefilter (`super::prefilter`).
pub(super) const SECRET_REQUIRED_LITERALS: &[Literals] =
    &[Literals::Strs(&SECRET_CONTEXT_LITERALS)];

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        AwsAccessKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn secrets(input: &str) -> Vec<(usize, usize)> {
        AwsSecretAccessKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
            .iter()
            .map(|candidate| {
                assert_eq!(candidate.type_name(), SECRET_TYPE);
                assert_eq!(candidate.confidence(), Confidence::High);
                assert_eq!(candidate.effective_specificity(), Specificity::Provider);
                (candidate.range().start(), candidate.range().end())
            })
            .collect()
    }

    const SECRET: &str = "SyntheticRevokedAwsSecretAccessKeyValue0";
    /// The inventory's reconciliation trigger, verbatim.
    const NAMED_SECRET: &str = "AWS_SECRET_ACCESS_KEY=SyntheticRevokedAwsSecretAccessKeyValue0";

    #[test]
    fn the_inventory_trigger_is_claimed() {
        assert_eq!(secrets(NAMED_SECRET), vec![(22, NAMED_SECRET.len())]);
    }

    fn span_of(input: &str) -> Vec<(usize, usize)> {
        let start = input.find(SECRET).unwrap();
        vec![(start, start + SECRET.len())]
    }

    #[test]
    fn a_secret_under_an_aws_secret_name_is_claimed() {
        assert_eq!(SECRET.len(), SECRET_LEN);
        for input in [
            format!("AWS_SECRET_ACCESS_KEY={SECRET}"),
            format!("aws_secret_access_key = {SECRET}\n"),
            format!("{{\"SecretAccessKey\": \"{SECRET}\"}}"),
            format!("secretAccessKey: '{SECRET}',"),
            format!("AWSSecretAccessKey={SECRET}"),
            format!("aws_secret_key: {SECRET}"),
            format!("MY_AWS_SECRET={SECRET}"),
            format!("AWS Secret Access Key [****abcd]: {SECRET}"),
            format!("Secret access key: {SECRET}"),
            format!("--aws-secret-access-key={SECRET}"),
            format!("Here is the secret access key for the staging user: {SECRET} please rotate"),
            format!("Secret access key for ci-deployer = {SECRET}"),
            format!("{{\\\"SecretAccessKey\\\":\\\"{SECRET}\\\"}}"),
        ] {
            assert_eq!(secrets(&input), span_of(&input), "{input}");
        }
    }

    #[test]
    fn a_secret_on_or_below_an_access_key_id_line_is_claimed() {
        let id = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let temporary = format!("ASIA{}", "SYNTHETIC0189TMP");
        for input in [
            format!("{id},{SECRET}"),
            format!("Access key ID,Secret access key\n{id},{SECRET}\n"),
            format!("{id}\n{SECRET}\n"),
            format!("{temporary}\r\n{SECRET}"),
            format!("{SECRET}\n{id}\n"),
            format!("value, then key id:\n{SECRET}\r\n{temporary}\r\n"),
            format!("Set-AWSCredential -AccessKey {id} -SecretKey {SECRET}"),
        ] {
            assert_eq!(secrets(&input), span_of(&input), "{input}");
        }
    }

    #[test]
    fn context_free_and_distant_values_are_not_claimed() {
        let id = format!("AKIA{}", "SYNTHETICEXAMPLE");
        for input in [
            SECRET.to_owned(),
            format!("token={SECRET}"),
            format!("secret={SECRET}"),
            format!("aws_access_key_id={SECRET}"),
            format!("{id}\n\n{SECRET}\n"),
            format!("{SECRET}\n\n{id}\n"),
            format!("Here is the secret access key for the staging user of the team: {SECRET}"),
            format!("the secret access key for: {SECRET}"),
            format!("secret access key is below\n{SECRET}"),
            format!("SeCrEtAccessKey={SECRET}"),
        ] {
            assert!(secrets(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn one_property_twins_are_not_claimed() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let upper = SECRET.to_ascii_uppercase();
        for value in [
            &SECRET[..39],
            &format!("{SECRET}A"),
            &format!("{}={}", &SECRET[..20], &SECRET[21..]),
            &format!("{}-{}", &SECRET[..20], &SECRET[21..]),
            &format!("{}_{}", &SECRET[..20], &SECRET[21..]),
            &format!("{SECRET}="),
            &format!("/{SECRET}"),
            hex,
            &upper,
        ] {
            let input = format!("AWS_SECRET_ACCESS_KEY={value}");
            assert!(secrets(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn the_hint_holds_only_a_line_whose_run_the_next_line_could_claim() {
        let id = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let no = || false;
        let yes = || true;
        assert!(has_open_aws_secret_candidate_line(
            &format!("{SECRET}\n"),
            no
        ));
        assert!(has_open_aws_secret_candidate_line(
            &format!("x\nnote {SECRET} end\r\n"),
            yes
        ));
        assert!(has_open_aws_secret_candidate_line(
            &format!("x\r{SECRET}\r"),
            yes
        ));
        // Claimed already: an ID on the line or above it, or a name.
        assert!(!has_open_aws_secret_candidate_line(
            &format!("{SECRET}\n"),
            yes
        ));
        assert!(!has_open_aws_secret_candidate_line(
            &format!("{id}\n{SECRET}\n"),
            no
        ));
        assert!(!has_open_aws_secret_candidate_line(
            &format!("{id} {SECRET}\n"),
            no
        ));
        assert!(!has_open_aws_secret_candidate_line(
            &format!("aws_secret_access_key = {SECRET}\n"),
            no
        ));
        // Not a run: the ID line itself, a SHA, a short or padded value.
        assert!(!has_open_aws_secret_candidate_line(&format!("{id}\n"), no));
        assert!(!has_open_aws_secret_candidate_line(
            "0123456789abcdef0123456789abcdef01234567\n",
            no
        ));
        assert!(!has_open_aws_secret_candidate_line(
            &format!("{}\n", &SECRET[..39]),
            no
        ));
        assert!(!has_open_aws_secret_candidate_line(
            &format!("{SECRET}=\n"),
            no
        ));
        assert!(!has_open_aws_secret_candidate_line("plain line\n", no));
    }

    #[test]
    fn the_lookbehind_check_reads_an_access_key_id_on_its_line() {
        let id = format!("ASIA{}", "SYNTHETIC0189TMP");
        assert!(carries_aws_access_key_id(&format!("{id}\n")));
        assert!(carries_aws_access_key_id(&format!(
            "aws_access_key_id = {id}\r\n"
        )));
        assert!(!carries_aws_access_key_id(&format!("{SECRET}\n")));
        assert!(!carries_aws_access_key_id(&format!(
            "AIDA{}\n",
            "SYNTHETIC0189TMP"
        )));
        assert!(!carries_aws_access_key_id("plain line\n"));
    }

    #[test]
    fn a_long_line_of_candidates_stays_linear() {
        let line = format!("{SECRET} ").repeat(10_000);
        assert!(secrets(&line).is_empty());
        let named = format!("aws_secret_access_key={SECRET} ").repeat(2_000);
        assert_eq!(secrets(&named).len(), 2_000);
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "aws_access_key_id");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_asia_prefix() {
        let input = format!("ASIA{}", "SYNTHETICEXAMPLE");
        assert_eq!(detect(&input).len(), 1);
    }

    /// Issue #1027 (#1012 READY-T2): `ASIA` + exactly 16 `[A-Z0-9]`, the
    /// same type, confidence and specificity as `AKIA`, with digits outside
    /// Base32 in the body.
    #[test]
    fn asia_mirrors_akia_and_rejects_its_one_property_twins() {
        let value = format!("ASIA{}", "SYNTHETIC0189EXA");
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "aws_access_key_id");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        for twin in [
            format!("ASIA{}", "SYNTHETIC0189EX"),
            format!("ASIA{}", "SYNTHETIC0189EXAM"),
            format!("ASIA{}", "SYNTHETIc0189EXA"),
            format!("ASIB{}", "SYNTHETIC0189EXA"),
            format!("x{value}"),
            format!("{value}9"),
        ] {
            assert!(detect(&twin).is_empty(), "{twin}");
        }
    }

    #[test]
    fn rejects_a_short_lookalike() {
        assert_eq!(detect("AKIASYNTHETICSHORT").len(), 0);
    }

    #[test]
    fn rejects_a_longer_alphanumeric_run() {
        assert_eq!(detect("AKIASYNTHETICEXAMPLEEXTRA").len(), 0);
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn rejects_an_embedded_lookalike() {
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        assert_eq!(detect(&format!("X{value}Y")).len(), 0);
    }

    #[test]
    fn rejects_a_user_id_prefix() {
        // AIDA (IAM user) is not a documented access-key prefix, like the
        // AROA (IAM role) case already covered by the corpus.
        assert_eq!(detect("AIDASYNTHETICEXAMPLE").len(), 0);
    }

    #[test]
    fn rejects_a_bare_account_id() {
        assert_eq!(
            detect("AWS account 123456789012 owns this resource.").len(),
            0
        );
    }

    #[test]
    fn rejects_an_iam_role_arn() {
        assert_eq!(
            detect("arn:aws:iam::123456789012:role/SyntheticExampleRole").len(),
            0
        );
    }

    #[test]
    fn rejects_an_s3_resource_arn() {
        assert_eq!(
            detect("arn:aws:s3:::synthetic-example-bucket-2026").len(),
            0
        );
    }

    #[test]
    fn rejects_an_ordinary_uppercase_identifier() {
        assert_eq!(detect("MAX_CONNECTIONS_ALLOWED_SYNTHETIC_EXAMPLE").len(), 0);
    }

    #[test]
    fn accepts_a_key_shaped_value_inside_a_comment_naming_example() {
        // The detector is pure grammar match with no context awareness, so a
        // comment naming the field "example" must not suppress a genuinely
        // key-shaped value; only the exact vendor-documented literal is
        // exempted (see pipeline.rs's KNOWN_VENDOR_PLACEHOLDER_LITERALS).
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("// example: {value} (rotate before deploying)");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "// example: ".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn accepts_a_value_adjacent_to_a_multibyte_unicode_character() {
        // "é" is 2 UTF-8 bytes; neither byte is ASCII-alnum, so both are
        // correctly treated as non-alnum boundary bytes rather than one of
        // them being mistaken for part of the run or splitting the offset.
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("caf\u{e9}{value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "caf\u{e9}".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }
}

/// Differential test for #1086: `ends_with_secret_name` compares the name in
/// place instead of a lowercased copy and a compacted lowercase copy.
#[cfg(test)]
mod case_insensitive_differential_tests {
    use super::*;
    use crate::test_rng::{BOUNDARY_PIECES, XorShift32};

    /// The implementation before #1086.
    fn old_ends_with_qualified_phrase(lower: &str) -> bool {
        let Some(at) = lower.rfind("secret access key for ") else {
            return false;
        };
        let qualifier = &lower[at + "secret access key for ".len()..];
        let words: Vec<&str> = qualifier.split(' ').collect();
        (1..=MAX_QUALIFIER_WORDS).contains(&words.len())
            && words.iter().all(|word| {
                !word.is_empty()
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
    }

    /// The implementation before #1086.
    fn old_ends_with_secret_name(prefix: &str) -> bool {
        let trim =
            |text: &str| -> usize { text.trim_end_matches([' ', '\t', '"', '\'', '\\']).len() };
        let mut end = trim(prefix);
        let Some(operator) = prefix[..end].chars().next_back() else {
            return false;
        };
        if operator != '=' && operator != ':' {
            return false;
        }
        end -= 1;
        if prefix[..end].ends_with(':') {
            end -= 1;
        }
        end = trim(&prefix[..end]);
        let mut name = &prefix[..end];
        if name.ends_with(']')
            && let Some(open) = name.rfind('[')
        {
            name = name[..open].trim_end_matches([' ', '\t']);
        }
        if !(name.contains("ecret") || name.contains("ECRET")) {
            return false;
        }
        let lower = name.to_ascii_lowercase();
        if lower.ends_with("secret access key") || old_ends_with_qualified_phrase(&lower) {
            return true;
        }
        let identifier_start = name
            .char_indices()
            .rev()
            .find(|&(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')))
            .map_or(0, |(at, ch)| at + ch.len_utf8());
        let identifier = &name[identifier_start..];
        if !(identifier.contains("ecret") || identifier.contains("ECRET")) {
            return false;
        }
        let compact: String = identifier
            .bytes()
            .filter(|byte| !matches!(byte, b'_' | b'.' | b'-'))
            .map(|byte| char::from(byte.to_ascii_lowercase()))
            .collect();
        compact.ends_with("secretaccesskey")
            || compact.ends_with("awssecretkey")
            || compact.ends_with("awssecret")
    }

    const WORDS: &[&str] = &[
        "secret access key",
        "Secret Access Key",
        "SECRET ACCESS KEY FOR ",
        "secret access key for ",
        "Secret Access Key For the staging user",
        "aws_secret_access_key",
        "AWS_SECRET_ACCESS_KEY",
        "AwsSecretKey",
        "aws.secret.key",
        "AWS-SECRET",
        "awsSecret",
        "SECRET",
        "secret",
        "ecret",
        "ECRET",
        "staging",
        "user",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "[hint]",
        "[",
        "]",
        " = ",
        ": ",
        ":=",
        "=",
        "\u{212a}",
        "\u{e9}",
        "\u{130}",
    ];

    #[test]
    fn secret_name_matches_the_lowercasing_implementation() {
        let mut pieces: Vec<&str> = BOUNDARY_PIECES.to_vec();
        pieces.extend_from_slice(WORDS);
        let mut rng = XorShift32::new(0x1086_0004);
        let mut inputs: Vec<String> = vec![String::new(), "=".to_owned(), ":".to_owned()];
        inputs.extend(WORDS.iter().map(|word| format!("{word}=")));
        inputs.extend(WORDS.iter().map(|word| format!("\"{word}\" :")));
        for _ in 0..8000 {
            let body = rng.text(&pieces, 8);
            let operator = ["=", ":", " = ", "\":", ":=", ""][rng.below(6)];
            inputs.push(format!("{body}{operator}"));
        }
        let mut hits = 0;
        for input in &inputs {
            let old = old_ends_with_secret_name(input);
            assert_eq!(ends_with_secret_name(input), old, "{input:?}");
            hits += usize::from(old);
        }
        assert!(hits > 20, "the generator must reach the positive cases");
    }
}
