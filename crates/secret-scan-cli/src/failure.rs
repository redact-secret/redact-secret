//! Safe, input-free CLI failures.
//!
//! Every failure the binary can report carries a fixed code and a fixed
//! message. No failure carries argument text, input, a matched value, or an
//! operating-system message that might quote either.

use redact_secret::{
    ActionPolicyError, ActionPolicyErrorClass, RulesetErrorClass, SecretScanError,
    SecretScanErrorCode,
};

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
/// `--action-policy` was the last argument, with no path following it.
pub const ACTION_POLICY_MISSING_PATH: &str = "--action-policy requires a path argument";
/// `--action-policy` appeared more than once.
pub const ACTION_POLICY_REPEATED: &str = "--action-policy may be given at most once";
/// `--pii` requires one selector value.
pub const PII_MISSING_SELECTOR: &str = "--pii requires a selector argument";
/// Activation printing performs no scan and accepts only selector flags.
pub const PRINT_PII_STANDALONE: &str =
    "--print-pii-activation accepts only repeatable --pii selectors";

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
    /// The file `--action-policy` named was rejected by the core. The code is
    /// always the core's fixed `INVALID_ACTION_POLICY`; the fixed class and the
    /// rule index pick this failure's text, never a byte from the rejected
    /// file.
    ActionPolicy(ActionPolicyError),
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
            Self::ActionPolicy(error) => error.code().as_str(),
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
            Self::ActionPolicy(error) => action_policy_class_message(error.class()),
        }
    }

    /// The fixed machine-readable detail that follows the message, if any: the
    /// rejection class and, inside a rule, its zero-based index. Both are fixed
    /// identifiers and integers, never a byte of the rejected file.
    pub fn detail(self) -> Option<String> {
        match self {
            Self::ActionPolicy(error) => Some(match error.rule_index() {
                Some(index) => format!("class={} rule_index={index}", error.class().as_str()),
                None => format!("class={}", error.class().as_str()),
            }),
            _ => None,
        }
    }
}

/// A fixed, human-readable message per [`ActionPolicyErrorClass`], so a policy
/// author can find and fix the rejected member without the CLI ever quoting the
/// file's own bytes.
const fn action_policy_class_message(class: ActionPolicyErrorClass) -> &'static str {
    match class {
        ActionPolicyErrorClass::ActionPolicyTooLarge => {
            "the action policy file exceeds the maximum size."
        }
        ActionPolicyErrorClass::MalformedDocument => {
            "the action policy is not a well-formed document of the supported JSON subset."
        }
        ActionPolicyErrorClass::UnknownRevision => {
            "the actionPolicyRevision value is not supported."
        }
        ActionPolicyErrorClass::UnknownField => "the action policy declares an unknown member.",
        ActionPolicyErrorClass::DuplicateField => "the action policy repeats a member.",
        ActionPolicyErrorClass::MissingField => {
            "the action policy is missing a required member, or the revision is not first."
        }
        ActionPolicyErrorClass::WrongType => "an action policy value has the wrong type.",
        ActionPolicyErrorClass::UnknownBase => "the action policy base is not default.",
        ActionPolicyErrorClass::InvalidAction => "a rule action is not supported.",
        ActionPolicyErrorClass::InvalidIdentifier => {
            "a rule id, type or detector is not a valid identifier."
        }
        ActionPolicyErrorClass::DuplicateRuleId => "two rules share an id.",
        ActionPolicyErrorClass::EmptyMatch => "a rule has an empty match.",
        ActionPolicyErrorClass::EmptySet => "a match set has no member.",
        ActionPolicyErrorClass::DuplicateSetMember => "a match set repeats a member.",
        ActionPolicyErrorClass::UnknownVocabularyEntry => {
            "a confidence or obfuscation entry is not supported."
        }
        ActionPolicyErrorClass::TooManyRules => "the action policy declares too many rules.",
        ActionPolicyErrorClass::SetTooLarge => "a match set declares too many members.",
        _ => "the action policy was rejected.",
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
            "a line, block header, repeated field, or value has an unsupported shape."
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

impl From<ActionPolicyError> for Failure {
    fn from(error: ActionPolicyError) -> Self {
        Self::ActionPolicy(error)
    }
}

impl From<redact_secret::RulesetError> for Failure {
    fn from(error: redact_secret::RulesetError) -> Self {
        Self::Ruleset(error.class())
    }
}
