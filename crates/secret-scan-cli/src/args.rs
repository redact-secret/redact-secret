//! Process-argument parsing.
//!
//! Parsing is total and side-effect free: it reads the argument list and
//! nothing else, and every rejection is one of the fixed reasons in
//! [`crate::failure`].

use std::ffi::OsString;
use std::path::PathBuf;

use crate::failure::{
    ACTION_POLICY_MISSING_PATH, ACTION_POLICY_REPEATED, COMPARE_MISSING_PATH, COMPARE_ONE_PATH,
    COMPARE_REQUIRES_FILE, COMPARE_TOO_MANY, COMPARE_WITH_REDACT, Failure, JSON_WITH_REDACT,
    PII_MISSING_SELECTOR, PRINT_PII_STANDALONE, REDACT_ONE_PATH, RULESET_MISSING_PATH,
    RULESET_REPEATED, RULESET_REQUIRES_FILE, SOLE_OPTION, UNKNOWN_OPTION,
};

/// The most candidates one comparison takes: with the baseline, the core's
/// `MAX_COMPARED_POLICIES`.
const MAX_CANDIDATES: usize = redact_secret::MAX_COMPARED_POLICIES - 1;

/// The identity standard input reports as in a check report.
pub const STDIN_IDENTITY: &str = "<stdin>";

/// Where one run reads its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Standard input, streamed through the incremental core.
    Stdin,
    /// A file, read whole under the explicit total-input limit.
    File(PathBuf),
}

impl Source {
    /// The safe identity this source reports.
    ///
    /// A path that is not valid UTF-8 is reported lossily: the report is a
    /// text document, and a replacement character is a safer identity than a
    /// raw byte sequence.
    pub fn identity(&self) -> String {
        match self {
            Self::Stdin => STDIN_IDENTITY.to_owned(),
            Self::File(path) => path.to_string_lossy().into_owned(),
        }
    }
}

/// How a check run renders its report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One line per finding, for a human or a line-oriented tool.
    Text,
    /// One JSON object, for a machine consumer.
    Json,
}

/// One `--compare-action-policy` run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareRequest {
    /// The single file to detect over, once.
    pub source: PathBuf,
    /// How to render the report.
    pub format: Format,
    /// The path `--ruleset` named, if any.
    pub ruleset: Option<PathBuf>,
    /// The path `--action-policy` named: the baseline. The default evaluation
    /// when absent.
    pub baseline: Option<PathBuf>,
    /// The paths `--compare-action-policy` named, in order (1 to 3).
    pub candidates: Vec<PathBuf>,
    /// Repeatable PII selectors.
    pub selectors: Vec<String>,
}

/// What the parsed command line asks the binary to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Print the usage document and exit cleanly.
    Help,
    /// Print the product version and exit cleanly.
    Version,
    /// Print canonical activation and exit without reading input.
    PiiActivation { selectors: Vec<String> },
    /// Scan every source and report safe finding metadata.
    Check {
        /// The sources to scan, in the order they were given.
        sources: Vec<Source>,
        /// How to render the report.
        format: Format,
        /// The path `--ruleset` named, if any.
        ruleset: Option<PathBuf>,
        /// The path `--action-policy` named, if any.
        action_policy: Option<PathBuf>,
        /// Repeatable PII selectors.
        selectors: Vec<String>,
    },
    /// Evaluate the baseline and every candidate action policy over the same
    /// finalized findings of one file, and report the actions. An
    /// observation: nothing is redacted and the exit code never reflects
    /// enforcement.
    Compare(CompareRequest),
    /// Write the sanitized form of one source to standard output.
    Redact {
        /// The single source to sanitize.
        source: Source,
        /// The path `--ruleset` named, if any.
        ruleset: Option<PathBuf>,
        /// The path `--action-policy` named, if any.
        action_policy: Option<PathBuf>,
        /// Repeatable PII selectors.
        selectors: Vec<String>,
    },
}

/// Interprets the argument list, excluding the program name.
///
/// # Errors
///
/// Returns [`Failure::Usage`] for an unrecognized option, for `--help` or
/// `--version` alongside another argument, for `--json` with `--redact`, for
/// `--redact` with more than one path, for `--ruleset` given more than once
/// or with no path following it, for `--ruleset` with no explicit file
/// path (standard input's incremental session accepts no custom detector), and
/// for `--action-policy` given more than once or with no path following it.
pub fn parse<I>(args: I) -> Result<Command, Failure>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    if let [sole] = args.as_slice() {
        match sole.to_str() {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--version" | "-V") => return Ok(Command::Version),
            _ => {}
        }
    }

    let mut parsed = Parsed::default();
    let mut paths_only = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if paths_only || arg.as_encoded_bytes().first() != Some(&b'-') {
            parsed.paths.push(PathBuf::from(arg));
            continue;
        }
        match arg.to_str() {
            Some("--") => paths_only = true,
            Some("--redact") => parsed.redact = true,
            Some("--json") => parsed.json = true,
            Some("--print-pii-activation") => parsed.print_pii_activation = true,
            Some("--pii") => {
                let selector = args.next().ok_or(Failure::Usage(PII_MISSING_SELECTOR))?;
                parsed.selectors.push(selector.into_string().map_err(|_| {
                    Failure::Core(redact_secret::SecretScanErrorCode::PiiSelectorInvalid)
                })?);
            }
            Some("--ruleset") => {
                let path = args.next().ok_or(Failure::Usage(RULESET_MISSING_PATH))?;
                if parsed.ruleset.replace(PathBuf::from(path)).is_some() {
                    return Err(Failure::Usage(RULESET_REPEATED));
                }
            }
            Some("--action-policy") => {
                let path = args
                    .next()
                    .ok_or(Failure::Usage(ACTION_POLICY_MISSING_PATH))?;
                if parsed.action_policy.replace(PathBuf::from(path)).is_some() {
                    return Err(Failure::Usage(ACTION_POLICY_REPEATED));
                }
            }
            Some("--compare-action-policy") => {
                let path = args.next().ok_or(Failure::Usage(COMPARE_MISSING_PATH))?;
                parsed.candidates.push(PathBuf::from(path));
                if parsed.candidates.len() > MAX_CANDIDATES {
                    return Err(Failure::Usage(COMPARE_TOO_MANY));
                }
            }
            Some("--help" | "-h" | "--version" | "-V") => {
                return Err(Failure::Usage(SOLE_OPTION));
            }
            _ => return Err(Failure::Usage(UNKNOWN_OPTION)),
        }
    }
    parsed.into_command()
}

/// Everything the option loop collected, before it is judged as one command.
#[derive(Default)]
struct Parsed {
    redact: bool,
    json: bool,
    print_pii_activation: bool,
    ruleset: Option<PathBuf>,
    action_policy: Option<PathBuf>,
    candidates: Vec<PathBuf>,
    selectors: Vec<String>,
    paths: Vec<PathBuf>,
}

impl Parsed {
    /// Chooses the one command the collected options describe.
    fn into_command(self) -> Result<Command, Failure> {
        let Self {
            redact,
            json,
            print_pii_activation,
            ruleset,
            action_policy,
            candidates,
            selectors,
            paths,
        } = self;

        if print_pii_activation {
            let other_inputs = [
                redact,
                json,
                ruleset.is_some(),
                action_policy.is_some(),
                !candidates.is_empty(),
                !paths.is_empty(),
            ];
            if other_inputs.contains(&true) {
                return Err(Failure::Usage(PRINT_PII_STANDALONE));
            }
            return Ok(Command::PiiActivation { selectors });
        }

        if !candidates.is_empty() {
            return compare_command(
                redact,
                json,
                paths,
                (ruleset, action_policy),
                (candidates, selectors),
            );
        }

        if redact {
            if json {
                return Err(Failure::Usage(JSON_WITH_REDACT));
            }
            let mut paths = paths.into_iter();
            let source = match (paths.next(), paths.next()) {
                (None, _) if ruleset.is_some() => {
                    return Err(Failure::Usage(RULESET_REQUIRES_FILE));
                }
                (None, _) => Source::Stdin,
                (Some(path), None) => Source::File(path),
                (Some(_), Some(_)) => return Err(Failure::Usage(REDACT_ONE_PATH)),
            };
            return Ok(Command::Redact {
                source,
                ruleset,
                action_policy,
                selectors,
            });
        }

        let sources = if paths.is_empty() {
            if ruleset.is_some() {
                return Err(Failure::Usage(RULESET_REQUIRES_FILE));
            }
            vec![Source::Stdin]
        } else {
            paths.into_iter().map(Source::File).collect()
        };
        let format = if json { Format::Json } else { Format::Text };
        Ok(Command::Check {
            sources,
            format,
            ruleset,
            action_policy,
            selectors,
        })
    }
}

/// The command a `--compare-action-policy` command line asks for.
///
/// `policies` is the `--ruleset` path and the baseline `--action-policy` path;
/// `rest` is the candidate paths and the PII selectors.
fn compare_command(
    redact: bool,
    json: bool,
    paths: Vec<PathBuf>,
    policies: (Option<PathBuf>, Option<PathBuf>),
    rest: (Vec<PathBuf>, Vec<String>),
) -> Result<Command, Failure> {
    if redact {
        return Err(Failure::Usage(COMPARE_WITH_REDACT));
    }
    let (ruleset, baseline) = policies;
    let (candidates, selectors) = rest;
    let mut paths = paths.into_iter();
    let source = match (paths.next(), paths.next()) {
        (None, _) => return Err(Failure::Usage(COMPARE_REQUIRES_FILE)),
        (Some(path), None) => path,
        (Some(_), Some(_)) => return Err(Failure::Usage(COMPARE_ONE_PATH)),
    };
    Ok(Command::Compare(CompareRequest {
        source,
        format: if json { Format::Json } else { Format::Text },
        ruleset,
        baseline,
        candidates,
        selectors,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Command, Failure> {
        parse(args.iter().map(OsString::from))
    }

    fn file(path: &str) -> Source {
        Source::File(PathBuf::from(path))
    }

    #[test]
    fn no_argument_checks_standard_input() {
        assert_eq!(
            parse_args(&[]).unwrap(),
            Command::Check {
                sources: vec![Source::Stdin],
                format: Format::Text,
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn paths_check_in_the_order_given() {
        assert_eq!(
            parse_args(&["b.txt", "a.txt"]).unwrap(),
            Command::Check {
                sources: vec![file("b.txt"), file("a.txt")],
                format: Format::Text,
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn json_selects_the_machine_report() {
        assert_eq!(
            parse_args(&["--json", "a.txt"]).unwrap(),
            Command::Check {
                sources: vec![file("a.txt")],
                format: Format::Json,
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn redact_defaults_to_standard_input_and_accepts_one_path() {
        assert_eq!(
            parse_args(&["--redact"]).unwrap(),
            Command::Redact {
                source: Source::Stdin,
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
        assert_eq!(
            parse_args(&["--redact", "a.txt"]).unwrap(),
            Command::Redact {
                source: file("a.txt"),
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn a_double_dash_ends_option_parsing() {
        assert_eq!(
            parse_args(&["--", "--json"]).unwrap(),
            Command::Check {
                sources: vec![file("--json")],
                format: Format::Text,
                ruleset: None,
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn ruleset_names_a_path_alongside_a_file_source_in_either_mode() {
        assert_eq!(
            parse_args(&["--ruleset", "rules.txt", "a.txt"]).unwrap(),
            Command::Check {
                sources: vec![file("a.txt")],
                format: Format::Text,
                ruleset: Some(PathBuf::from("rules.txt")),
                action_policy: None,
                selectors: Vec::new(),
            }
        );
        assert_eq!(
            parse_args(&["--redact", "--ruleset", "rules.txt", "a.txt"]).unwrap(),
            Command::Redact {
                source: file("a.txt"),
                ruleset: Some(PathBuf::from("rules.txt")),
                action_policy: None,
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn ruleset_without_an_explicit_path_is_rejected_in_either_mode() {
        assert_eq!(
            parse_args(&["--ruleset", "rules.txt"]),
            Err(Failure::Usage(RULESET_REQUIRES_FILE))
        );
        assert_eq!(
            parse_args(&["--redact", "--ruleset", "rules.txt"]),
            Err(Failure::Usage(RULESET_REQUIRES_FILE))
        );
    }

    #[test]
    fn ruleset_rejects_a_missing_value_and_a_repeated_flag() {
        assert_eq!(
            parse_args(&["--ruleset"]),
            Err(Failure::Usage(RULESET_MISSING_PATH))
        );
        assert_eq!(
            parse_args(&["--ruleset", "a.txt", "--ruleset", "b.txt", "c.txt"]),
            Err(Failure::Usage(RULESET_REPEATED))
        );
    }

    #[test]
    fn action_policy_names_a_path_alongside_any_source_in_either_mode() {
        assert_eq!(
            parse_args(&["--action-policy", "p.json", "a.txt"]).unwrap(),
            Command::Check {
                sources: vec![file("a.txt")],
                format: Format::Text,
                ruleset: None,
                action_policy: Some(PathBuf::from("p.json")),
                selectors: Vec::new(),
            }
        );
        assert_eq!(
            parse_args(&["--action-policy", "p.json"]).unwrap(),
            Command::Check {
                sources: vec![Source::Stdin],
                format: Format::Text,
                ruleset: None,
                action_policy: Some(PathBuf::from("p.json")),
                selectors: Vec::new(),
            }
        );
        assert_eq!(
            parse_args(&["--redact", "--action-policy", "p.json"]).unwrap(),
            Command::Redact {
                source: Source::Stdin,
                ruleset: None,
                action_policy: Some(PathBuf::from("p.json")),
                selectors: Vec::new(),
            }
        );
        assert_eq!(
            parse_args(&[
                "--redact",
                "--ruleset",
                "r.txt",
                "--action-policy",
                "p.json",
                "a.txt"
            ])
            .unwrap(),
            Command::Redact {
                source: file("a.txt"),
                ruleset: Some(PathBuf::from("r.txt")),
                action_policy: Some(PathBuf::from("p.json")),
                selectors: Vec::new(),
            }
        );
    }

    #[test]
    fn action_policy_rejects_a_missing_value_and_a_repeated_flag() {
        assert_eq!(
            parse_args(&["--action-policy"]),
            Err(Failure::Usage(ACTION_POLICY_MISSING_PATH))
        );
        assert_eq!(
            parse_args(&["--action-policy", "a.json", "--action-policy", "b.json"]),
            Err(Failure::Usage(ACTION_POLICY_REPEATED))
        );
        assert_eq!(
            parse_args(&["--print-pii-activation", "--action-policy", "a.json"]),
            Err(Failure::Usage(PRINT_PII_STANDALONE))
        );
    }

    #[test]
    fn compare_takes_one_file_a_baseline_and_up_to_three_candidates() {
        assert_eq!(
            parse_args(&[
                "--action-policy",
                "base.json",
                "--compare-action-policy",
                "a.json",
                "--compare-action-policy",
                "b.json",
                "--json",
                "in.txt"
            ])
            .unwrap(),
            Command::Compare(CompareRequest {
                source: PathBuf::from("in.txt"),
                format: Format::Json,
                ruleset: None,
                baseline: Some(PathBuf::from("base.json")),
                candidates: vec![PathBuf::from("a.json"), PathBuf::from("b.json")],
                selectors: Vec::new(),
            })
        );
        assert_eq!(
            parse_args(&["--compare-action-policy", "a.json", "in.txt"]).unwrap(),
            Command::Compare(CompareRequest {
                source: PathBuf::from("in.txt"),
                format: Format::Text,
                ruleset: None,
                baseline: None,
                candidates: vec![PathBuf::from("a.json")],
                selectors: Vec::new(),
            })
        );
    }

    #[test]
    fn compare_rejects_every_unsupported_shape_with_a_fixed_reason() {
        assert_eq!(
            parse_args(&["--compare-action-policy"]),
            Err(Failure::Usage(COMPARE_MISSING_PATH))
        );
        assert_eq!(
            parse_args(&["--compare-action-policy", "a.json"]),
            Err(Failure::Usage(COMPARE_REQUIRES_FILE))
        );
        assert_eq!(
            parse_args(&["--compare-action-policy", "a.json", "x.txt", "y.txt"]),
            Err(Failure::Usage(COMPARE_ONE_PATH))
        );
        assert_eq!(
            parse_args(&["--redact", "--compare-action-policy", "a.json", "x.txt"]),
            Err(Failure::Usage(COMPARE_WITH_REDACT))
        );
        assert_eq!(
            parse_args(&[
                "--compare-action-policy",
                "a",
                "--compare-action-policy",
                "b",
                "--compare-action-policy",
                "c",
                "--compare-action-policy",
                "d",
                "x.txt"
            ]),
            Err(Failure::Usage(COMPARE_TOO_MANY))
        );
        assert_eq!(
            parse_args(&[
                "--print-pii-activation",
                "--compare-action-policy",
                "a.json"
            ]),
            Err(Failure::Usage(PRINT_PII_STANDALONE))
        );
    }

    #[test]
    fn help_and_version_stand_alone() {
        assert_eq!(parse_args(&["--help"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["-h"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["--version"]).unwrap(), Command::Version);
        assert_eq!(parse_args(&["-V"]).unwrap(), Command::Version);
        assert_eq!(
            parse_args(&["--version", "a.txt"]),
            Err(Failure::Usage(SOLE_OPTION))
        );
        assert_eq!(
            parse_args(&["a.txt", "--help"]),
            Err(Failure::Usage(SOLE_OPTION))
        );
    }

    #[test]
    fn rejected_command_lines_never_echo_an_argument() {
        let rejections = [
            (
                parse_args(&["--sk-live-synthetic-revoked"]),
                Failure::Usage(UNKNOWN_OPTION),
            ),
            (parse_args(&["-"]), Failure::Usage(UNKNOWN_OPTION)),
            (
                parse_args(&["--redact", "--json"]),
                Failure::Usage(JSON_WITH_REDACT),
            ),
            (
                parse_args(&["--redact", "a.txt", "b.txt"]),
                Failure::Usage(REDACT_ONE_PATH),
            ),
        ];
        for (actual, expected) in rejections {
            assert_eq!(actual, Err(expected));
            assert!(!expected.message().contains("sk-live"));
        }
    }

    #[test]
    fn standard_input_identity_is_not_a_path() {
        assert_eq!(Source::Stdin.identity(), STDIN_IDENTITY);
        assert_eq!(file("dir/a.txt").identity(), "dir/a.txt");
    }

    #[test]
    fn pii_selectors_are_repeatable_and_activation_printing_is_input_free() {
        assert_eq!(
            parse_args(&[
                "--print-pii-activation",
                "--pii",
                "pii",
                "--pii",
                "pii:global"
            ])
            .unwrap(),
            Command::PiiActivation {
                selectors: vec!["pii".to_owned(), "pii:global".to_owned()]
            }
        );
        assert_eq!(
            parse_args(&["--pii"]),
            Err(Failure::Usage(PII_MISSING_SELECTOR))
        );
        assert_eq!(
            parse_args(&["--print-pii-activation", "file"]),
            Err(Failure::Usage(PRINT_PII_STANDALONE))
        );
    }
}
