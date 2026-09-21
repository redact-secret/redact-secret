//! Process-argument parsing.
//!
//! Parsing is total and side-effect free: it reads the argument list and
//! nothing else, and every rejection is one of the fixed reasons in
//! [`crate::failure`].

use std::ffi::OsString;
use std::path::PathBuf;

use crate::failure::{
    Failure, JSON_WITH_REDACT, REDACT_ONE_PATH, RULESET_MISSING_PATH, RULESET_REPEATED,
    RULESET_REQUIRES_FILE, SOLE_OPTION, UNKNOWN_OPTION,
};

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

/// What the parsed command line asks the binary to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Print the usage document and exit cleanly.
    Help,
    /// Print the product version and exit cleanly.
    Version,
    /// Scan every source and report safe finding metadata.
    Check {
        /// The sources to scan, in the order they were given.
        sources: Vec<Source>,
        /// How to render the report.
        format: Format,
        /// The path `--ruleset` named, if any.
        ruleset: Option<PathBuf>,
    },
    /// Write the sanitized form of one source to standard output.
    Redact {
        /// The single source to sanitize.
        source: Source,
        /// The path `--ruleset` named, if any.
        ruleset: Option<PathBuf>,
    },
}

/// Interprets the argument list, excluding the program name.
///
/// # Errors
///
/// Returns [`Failure::Usage`] for an unrecognized option, for `--help` or
/// `--version` alongside another argument, for `--json` with `--redact`, for
/// `--redact` with more than one path, for `--ruleset` given more than once
/// or with no path following it, and for `--ruleset` with no explicit file
/// path (standard input's incremental session accepts no custom detector).
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

    let mut redact = false;
    let mut json = false;
    let mut paths_only = false;
    let mut ruleset: Option<PathBuf> = None;
    let mut paths: Vec<PathBuf> = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if paths_only || arg.as_encoded_bytes().first() != Some(&b'-') {
            paths.push(PathBuf::from(arg));
            continue;
        }
        match arg.to_str() {
            Some("--") => paths_only = true,
            Some("--redact") => redact = true,
            Some("--json") => json = true,
            Some("--ruleset") => {
                let path = args.next().ok_or(Failure::Usage(RULESET_MISSING_PATH))?;
                if ruleset.replace(PathBuf::from(path)).is_some() {
                    return Err(Failure::Usage(RULESET_REPEATED));
                }
            }
            Some("--help" | "-h" | "--version" | "-V") => {
                return Err(Failure::Usage(SOLE_OPTION));
            }
            _ => return Err(Failure::Usage(UNKNOWN_OPTION)),
        }
    }

    if redact {
        if json {
            return Err(Failure::Usage(JSON_WITH_REDACT));
        }
        let mut paths = paths.into_iter();
        let source = match (paths.next(), paths.next()) {
            (None, _) if ruleset.is_some() => return Err(Failure::Usage(RULESET_REQUIRES_FILE)),
            (None, _) => Source::Stdin,
            (Some(path), None) => Source::File(path),
            (Some(_), Some(_)) => return Err(Failure::Usage(REDACT_ONE_PATH)),
        };
        return Ok(Command::Redact { source, ruleset });
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
    })
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
            }
        );
        assert_eq!(
            parse_args(&["--redact", "a.txt"]).unwrap(),
            Command::Redact {
                source: file("a.txt"),
                ruleset: None,
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
            }
        );
        assert_eq!(
            parse_args(&["--redact", "--ruleset", "rules.txt", "a.txt"]).unwrap(),
            Command::Redact {
                source: file("a.txt"),
                ruleset: Some(PathBuf::from("rules.txt")),
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
}
