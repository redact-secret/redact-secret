//! Safe, input-free CLI failures.
//!
//! Every failure the binary can report carries a fixed code and a fixed
//! message. No failure carries argument text, input, a matched value, or an
//! operating-system message that might quote either.

use redact_secret::{RulesetErrorClass, SecretScanError, SecretScanErrorCode};

/// The command line named an option the binary does not accept.
pub const UNKNOWN_OPTION: &str = "unrecognized option";
/// `--help` or `--version` appeared alongside another argument.
pub const SOLE_OPTION: &str = "--help and --version take no other arguments";
/// `--json` reports check findings, so it cannot describe a redaction.
pub const JSON_WITH_REDACT: &str = "--json is a check option and cannot be combined with --redact";
/// `--redact` writes one sanitized stream, so it reads one input.
pub const REDACT_ONE_PATH: &str = "--redact reads standard input or exactly one path";
/// `--ruleset` was the last argument, with no path following it.
pub const RULESET_MISSING_PATH: &str = "--ruleset requires a path argument";
/// `--ruleset` appeared more than once.
pub const RULESET_REPEATED: &str = "--ruleset may be given at most once";
/// `--ruleset` was combined with standard input. The core's incremental
/// session accepts no custom detector, ruleset or otherwise, because none
/// declares the retention bound a streaming session must enforce
/// (`crate::modes`'s own module docs); `--ruleset` therefore requires an
/// explicit file path.
pub const RULESET_REQUIRES_FILE: &str =
    "--ruleset requires an explicit path; standard input does not accept a ruleset";

/// A failure the CLI reports to its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The command line could not be interpreted. The payload is one of the
    /// fixed reasons in this module, never text taken from the arguments.
    Usage(&'static str),
    /// The input was not valid UTF-8. The bytes that proved it are dropped
    /// rather than reported.
    NotUtf8,
    /// Reading the input failed, including a partial or interrupted read
    /// that could not be resumed.
    ReadFailed,
    /// Writing the output failed, including a closed downstream pipe.
    WriteFailed,
    /// The core rejected the run. Core codes and messages are already
    /// sanitized, so they pass through unchanged.
    Core(SecretScanErrorCode),
    /// The file `--ruleset` named failed to load. The code is always the
    /// core's fixed `INVALID_RULESET`; the fixed rejection class picks this
    /// failure's message, never a byte from the rejected file.
    Ruleset(RulesetErrorClass),
}

impl Failure {
    /// The stable `SCREAMING_SNAKE_CASE` code a machine consumer matches on.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Usage(_) => "USAGE",
            Self::NotUtf8 => "NOT_UTF8",
            Self::ReadFailed => "READ_FAILED",
            Self::WriteFailed => "WRITE_FAILED",
            Self::Core(code) => code.as_str(),
            Self::Ruleset(_) => SecretScanErrorCode::InvalidRuleset.as_str(),
        }
    }

    /// The fixed, input-free message for this failure.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Usage(reason) => reason,
            Self::NotUtf8 => "Input is not valid UTF-8.",
            Self::ReadFailed => "Reading the input failed.",
            Self::WriteFailed => "Writing the output failed.",
            Self::Core(code) => code.message(),
            Self::Ruleset(class) => ruleset_class_message(class),
        }
    }
}

/// A fixed, human-readable message per [`RulesetErrorClass`]. The core's own
/// [`redact_secret::RulesetError::message`] stays deliberately generic (one
/// shared message for the one public `INVALID_RULESET` code); the CLI is a
/// terminal, so it is worth spending the fixed per-class text a ruleset
/// author needs to find and fix the rejected field, still without ever
/// quoting the file's own bytes.
const fn ruleset_class_message(class: RulesetErrorClass) -> &'static str {
    match class {
        RulesetErrorClass::RulesetTooLarge => "the ruleset file exceeds the maximum size.",
        RulesetErrorClass::UnknownRevision => "the ruleset-revision value is not supported.",
        RulesetErrorClass::UnknownField => "a detector block declares an unknown field.",
        RulesetErrorClass::UnsupportedConstruct => {
            "a line, block header, or value has an unsupported shape."
        }
        RulesetErrorClass::UnknownAlphabet => "a detector block declares an unknown alphabet.",
        RulesetErrorClass::UnknownValidator => "a detector block declares an unknown validator.",
        RulesetErrorClass::SpecificityNotClaimable => {
            "a detector block declares a specificity a ruleset cannot claim."
        }
        RulesetErrorClass::MissingField => "a detector block is missing a required field.",
        RulesetErrorClass::PrefixTooShort => "a detector block's prefix is too short.",
        RulesetErrorClass::PrefixTooLong => "a detector block's prefix is too long.",
        RulesetErrorClass::RunLengthOutOfBounds => {
            "a detector block's run length is out of bounds."
        }
        RulesetErrorClass::TooManyDetectors => "the ruleset declares too many detectors.",
        RulesetErrorClass::DuplicateDetectorId => "two detector blocks declare the same id.",
        RulesetErrorClass::ReservedDetectorId => {
            "a detector block's id collides with a built-in detector."
        }
        RulesetErrorClass::EmptyRuleset => "the ruleset declares no detectors.",
        RulesetErrorClass::NameBucketNotClaimable => {
            "a names block declares a bucket other than ambiguous."
        }
        RulesetErrorClass::NameTooLong => "a names block's name is too long.",
        RulesetErrorClass::TooManyNames => "the ruleset declares too many names.",
        _ => "the ruleset was rejected.",
    }
}

impl From<SecretScanError> for Failure {
    fn from(error: SecretScanError) -> Self {
        Self::Core(error.code())
    }
}

impl From<SecretScanErrorCode> for Failure {
    fn from(code: SecretScanErrorCode) -> Self {
        Self::Core(code)
    }
}

impl From<redact_secret::RulesetError> for Failure {
    fn from(error: redact_secret::RulesetError) -> Self {
        Self::Ruleset(error.class())
    }
}
