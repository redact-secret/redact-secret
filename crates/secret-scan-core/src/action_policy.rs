//! The versioned declarative action policy
//! (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`).
//!
//! An action policy is a small JSON document that maps the safe metadata of a
//! finalized finding (`type`, `detector`, `confidence`, `obfuscation`) to an
//! [`Action`]. It is an ordered overlay on the running artifact's own default
//! evaluation: the first matching rule decides, and a finding no rule matches
//! takes the default action, which is computed at evaluation time and never
//! copied into the document.
//!
//! # Parsing
//!
//! The core owns the whole format. [`load_action_policy`] is one strict,
//! single-pass, hand-written parser over the document bytes: no `serde`, no
//! new dependency, no recursion (the grammar has a fixed depth, and a value in
//! the wrong slot is rejected without reading its contents), and work linear
//! in the document, which is capped at [`MAX_ACTION_POLICY_BYTES`] before any
//! byte is parsed. It reports the first violation in document order, with two
//! fixed precedences: the byte bound, then the revision (which must be the
//! first member, so a future revision is never read under this grammar).
//! Loading returns the whole policy or rejects the whole document.
//!
//! The grammar admits only objects, arrays, printable-ASCII strings with no
//! backslash (so no escape sequence exists) and one canonical decimal integer.
//! Whitespace is space, tab, LF and CR. There is no other token, no comment,
//! no byte-order mark, and no trailing content.
//!
//! No error carries a byte of the document: an [`ActionPolicyError`] is a fixed
//! [`ActionPolicyErrorClass`] and the zero-based index of the rule being read.
//!
//! # Evaluation
//!
//! Evaluation is total, deterministic, infallible and free of I/O, so an
//! [`ActionPolicy`] never reports `POLICY_FAILURE`. Its cost per finding is
//! linear in the number of members in the document, which the byte bound caps.
//! The value is immutable and cheap to [`Clone`] (it shares its rules), so one
//! policy can serve many scans, sessions and threads.

use std::sync::Arc;

use crate::compare::DecisionBasis;
use crate::error::{PolicyFailure, SecretScanErrorCode};
use crate::incremental::{IncrementalPolicy, IncrementalPolicyContext};
use crate::policy::default_action_for;
use crate::types::{
    Action, Confidence, DetectedFinding, Obfuscation, Policy, PolicyContext, is_identifier,
};

/// The largest action policy document, in bytes. A longer document is rejected
/// with [`ActionPolicyErrorClass::ActionPolicyTooLarge`] before any byte of it
/// is parsed. A host that reads a file bounds its read by this value plus one.
pub const MAX_ACTION_POLICY_BYTES: usize = 64 * 1024;

/// The most rules one document may carry.
const MAX_RULES: usize = 128;

/// The most members one `match` set may carry.
const MAX_SET_MEMBERS: usize = 256;

/// The one supported `actionPolicyRevision`, as the digits it is written with.
const REVISION_DIGITS: &[u8] = b"1";

/// The one supported `base`.
const BASE_DEFAULT: &str = "default";

const KEY_REVISION: &str = "actionPolicyRevision";
const KEY_BASE: &str = "base";
const KEY_RULES: &str = "rules";
const KEY_ID: &str = "id";
const KEY_MATCH: &str = "match";
const KEY_ACTION: &str = "action";
const KEY_TYPE: &str = "type";
const KEY_DETECTOR: &str = "detector";
const KEY_CONFIDENCE: &str = "confidence";
const KEY_OBFUSCATION: &str = "obfuscation";

/// The fixed rejection class of a rejected action policy document.
///
/// Every variant is a content-free unit variant: no byte of the rejected
/// document is carried by one. The set is open (`#[non_exhaustive]`): a class
/// that relabels a rejection the core already makes is additive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActionPolicyErrorClass {
    /// The document is longer than [`MAX_ACTION_POLICY_BYTES`]. Checked before
    /// anything is parsed.
    ActionPolicyTooLarge,
    /// Invalid UTF-8, a byte-order mark, a syntax error, an unsupported token,
    /// an escape sequence, a non-ASCII byte, a non-canonical integer or
    /// trailing content.
    MalformedDocument,
    /// The revision is an integer other than `1`.
    UnknownRevision,
    /// A member the object does not define (a role, range or specificity
    /// matcher included). Rejected at the key, before its value is read.
    UnknownField,
    /// A member that appears twice. The last never wins.
    DuplicateField,
    /// A required member is absent, or the revision is not the first member.
    MissingField,
    /// A supported value kind in the wrong slot, including a scalar where a
    /// set belongs.
    WrongType,
    /// `base` is not `default`.
    UnknownBase,
    /// `action` is not `redact`, `block`, `warn`, `allow` or `default`.
    InvalidAction,
    /// A rule id, `type` member or `detector` member that is not an
    /// [identifier](crate::is_identifier).
    InvalidIdentifier,
    /// Two rules share an id.
    DuplicateRuleId,
    /// A `match` object with no key.
    EmptyMatch,
    /// A set with no member.
    EmptySet,
    /// A member repeated inside one set.
    DuplicateSetMember,
    /// A `confidence` or `obfuscation` member outside the revision 1
    /// vocabulary.
    UnknownVocabularyEntry,
    /// More than 128 rules.
    TooManyRules,
    /// More than 256 members in one set.
    SetTooLarge,
}

impl ActionPolicyErrorClass {
    /// Every class, in the order the specification lists them.
    pub const ALL: [Self; 17] = [
        Self::ActionPolicyTooLarge,
        Self::MalformedDocument,
        Self::UnknownRevision,
        Self::UnknownField,
        Self::DuplicateField,
        Self::MissingField,
        Self::WrongType,
        Self::UnknownBase,
        Self::InvalidAction,
        Self::InvalidIdentifier,
        Self::DuplicateRuleId,
        Self::EmptyMatch,
        Self::EmptySet,
        Self::DuplicateSetMember,
        Self::UnknownVocabularyEntry,
        Self::TooManyRules,
        Self::SetTooLarge,
    ];

    /// The stable `SCREAMING_SNAKE_CASE` class string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionPolicyTooLarge => "ACTION_POLICY_TOO_LARGE",
            Self::MalformedDocument => "MALFORMED_DOCUMENT",
            Self::UnknownRevision => "UNKNOWN_REVISION",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::DuplicateField => "DUPLICATE_FIELD",
            Self::MissingField => "MISSING_FIELD",
            Self::WrongType => "WRONG_TYPE",
            Self::UnknownBase => "UNKNOWN_BASE",
            Self::InvalidAction => "INVALID_ACTION",
            Self::InvalidIdentifier => "INVALID_IDENTIFIER",
            Self::DuplicateRuleId => "DUPLICATE_RULE_ID",
            Self::EmptyMatch => "EMPTY_MATCH",
            Self::EmptySet => "EMPTY_SET",
            Self::DuplicateSetMember => "DUPLICATE_SET_MEMBER",
            Self::UnknownVocabularyEntry => "UNKNOWN_VOCABULARY_ENTRY",
            Self::TooManyRules => "TOO_MANY_RULES",
            Self::SetTooLarge => "SET_TOO_LARGE",
        }
    }
}

impl std::fmt::Display for ActionPolicyErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected action policy document, returned by [`load_action_policy`].
///
/// It carries exactly two fixed, content-free facts, never a byte derived from
/// the rejected document:
///
/// - [`Self::class`] is the fixed [`ActionPolicyErrorClass`], and
/// - [`Self::rule_index`] is the zero-based index of the rule being read, or
///   `None` for a violation that is not inside a rule (the document, its
///   syntax, the size bound, a `rules` slot of the wrong type).
///
/// [`Self::code`] is always [`SecretScanErrorCode::InvalidActionPolicy`], the
/// one public code every binding maps to its own error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActionPolicyError {
    class: ActionPolicyErrorClass,
    rule_index: Option<usize>,
}

impl ActionPolicyError {
    /// The one public error code every rejected action policy carries.
    #[must_use]
    pub const fn code(self) -> SecretScanErrorCode {
        SecretScanErrorCode::InvalidActionPolicy
    }

    /// The fixed rejection class.
    #[must_use]
    pub const fn class(self) -> ActionPolicyErrorClass {
        self.class
    }

    /// The zero-based index of the rule being read, or `None` for a
    /// document-level violation.
    #[must_use]
    pub const fn rule_index(self) -> Option<usize> {
        self.rule_index
    }

    /// The fixed, input-free message for [`Self::code`]; identical to the
    /// `Display` output.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.code().message()
    }

    const fn document(class: ActionPolicyErrorClass) -> Self {
        Self {
            class,
            rule_index: None,
        }
    }

    const fn in_rule(class: ActionPolicyErrorClass, rule_index: Option<usize>) -> Self {
        Self { class, rule_index }
    }
}

impl std::fmt::Display for ActionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ActionPolicyError {}

/// What a rule does once it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleAction {
    /// Stop at this rule and return this action.
    Fixed(Action),
    /// Stop at this rule and return the base action.
    Default,
}

/// One validated rule. An empty set, or a zero mask, means "this key is not
/// part of the match": a document can never write an empty set, so the two are
/// never confused.
#[derive(Clone, Debug)]
struct Rule {
    id: Box<str>,
    action: RuleAction,
    types: Box<[Box<str>]>,
    detectors: Box<[Box<str>]>,
    confidences: u8,
    obfuscations: u8,
}

const CONFIDENCE_HIGH: u8 = 0b001;
const CONFIDENCE_MEDIUM: u8 = 0b010;
const CONFIDENCE_LOW: u8 = 0b100;
const OBFUSCATION_NONE: u8 = 0b01;
const OBFUSCATION_INVISIBLE: u8 = 0b10;

const fn confidence_bit(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::High => CONFIDENCE_HIGH,
        Confidence::Medium => CONFIDENCE_MEDIUM,
        Confidence::Low => CONFIDENCE_LOW,
    }
}

/// The bit of `obfuscation`, or `0` for a value this revision has no name for.
/// A finding with such a value matches only rules without an `obfuscation`
/// key, because a rule that names one needs a bit this value cannot hold.
///
/// Compared by equality rather than matched: `Obfuscation` is non-exhaustive,
/// and a later variant must fall to `0` here without editing this function.
fn obfuscation_bit(obfuscation: Obfuscation) -> u8 {
    if obfuscation == Obfuscation::None {
        OBFUSCATION_NONE
    } else if obfuscation == Obfuscation::InvisibleCharacters {
        OBFUSCATION_INVISIBLE
    } else {
        0
    }
}

fn contains(set: &[Box<str>], value: &str) -> bool {
    set.iter().any(|member| &**member == value)
}

impl Rule {
    fn matches(&self, finding: &DetectedFinding) -> bool {
        (self.types.is_empty() || contains(&self.types, finding.type_name()))
            && (self.detectors.is_empty() || contains(&self.detectors, finding.detector()))
            && (self.confidences == 0
                || self.confidences & confidence_bit(finding.confidence()) != 0)
            && (self.obfuscations == 0
                || self.obfuscations & obfuscation_bit(finding.obfuscation()) != 0)
    }
}

/// A parsed, validated, immutable action policy.
///
/// Build one with [`load_action_policy`] and pass it wherever a [`Policy`]
/// (whole-input calls) or an [`IncrementalPolicy`] (sessions) is accepted. It
/// is `Clone` (clones share the validated rules), `Send` and `Sync`, and has no
/// way to be edited, merged or reloaded: a different document is a different
/// value, and a session keeps the policy it was built with.
///
/// For one finalized finding the rules are tried in document order. A rule
/// matches when every key it has holds, and a key holds when the finding's
/// value is a member of the key's set. The first matching rule wins; its
/// action is the result, except that `default` means the base action. With no
/// matching rule the result is the base action, which is the running
/// artifact's own [`DefaultPolicy`](crate::DefaultPolicy) evaluation of the
/// same finding, computed at evaluation time.
///
/// Evaluation never fails, so this policy never produces
/// [`SecretScanErrorCode::PolicyFailure`].
///
/// # Examples
///
/// ```
/// use redact_secret::{Action, DetectorRegistry, load_action_policy, scan};
///
/// let policy = load_action_policy(
///     br#"{"actionPolicyRevision":1,"base":"default","rules":[
///         {"id":"warn-github","match":{"type":["github_token"]},"action":"warn"}]}"#,
/// )?;
/// let registry = DetectorRegistry::with_built_in([])?;
/// let findings = scan("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", &registry, &policy)?;
/// assert_eq!(findings[0].action(), Action::Warn);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct ActionPolicy {
    rules: Arc<[Rule]>,
    /// SHA-256 of the exact document bytes this policy was loaded from.
    document_sha256: [u8; 32],
}

impl ActionPolicy {
    /// The index of the first rule that matches `finding`, if any.
    fn matching_rule(&self, finding: &DetectedFinding) -> Option<usize> {
        self.rules.iter().position(|rule| rule.matches(finding))
    }

    /// The action for `finding` and the reason it was chosen. The one
    /// evaluation behind [`Policy::evaluate`], [`IncrementalPolicy::evaluate`]
    /// and the comparison, so the three cannot disagree.
    pub(crate) fn explain(&self, finding: &DetectedFinding) -> (Action, DecisionBasis) {
        let base = || default_action_for(finding.type_name(), finding.confidence());
        match self.matching_rule(finding) {
            Some(index) => {
                let rule = &self.rules[index];
                match rule.action {
                    RuleAction::Fixed(action) => (
                        action,
                        DecisionBasis::Rule {
                            rule_id: rule.id.to_string(),
                            rule_index: index,
                        },
                    ),
                    RuleAction::Default => (
                        base(),
                        DecisionBasis::RuleDefault {
                            rule_id: rule.id.to_string(),
                            rule_index: index,
                        },
                    ),
                }
            }
            None => (base(), DecisionBasis::NoRuleMatched),
        }
    }

    fn action_for(&self, finding: &DetectedFinding) -> Action {
        self.explain(finding).0
    }

    /// The SHA-256 of the exact document bytes this policy was loaded from:
    /// the policy's revision binding.
    ///
    /// Two policies loaded from the same bytes report the same digest on every
    /// surface, and any changed byte (including insignificant whitespace)
    /// changes it, so the digest identifies a document, not its meaning. It is
    /// computed once at load, over the bytes the caller handed the loader, and
    /// is configuration identity, never a hash of input or of a finding.
    #[must_use]
    pub const fn document_sha256(&self) -> [u8; 32] {
        self.document_sha256
    }

    /// [`Self::document_sha256`] as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn document_sha256_hex(&self) -> String {
        crate::sha256::to_hex(&self.document_sha256)
    }
}

impl Policy for ActionPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        _context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(self.action_for(finding))
    }
}

impl IncrementalPolicy for ActionPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        _context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(self.action_for(finding))
    }
}

/// Parses `bytes` as an action policy document (`actionPolicyRevision: 1`) and
/// returns the whole validated [`ActionPolicy`], or rejects the whole document.
///
/// There is no partial load and no fallback to the default. The core, not the
/// host, performs every size, grammar and vocabulary check; a host hands over
/// the document bytes unchanged.
///
/// # Errors
///
/// Returns an [`ActionPolicyError`] carrying the first violation in document
/// order: a fixed [`ActionPolicyErrorClass`] and, inside a rule, its zero-based
/// index. The error contains no byte of the document.
///
/// # Examples
///
/// ```
/// use redact_secret::{ActionPolicyErrorClass, load_action_policy};
///
/// let rejected = load_action_policy(
///     br#"{"actionPolicyRevision":1,"base":"default","rules":[
///         {"id":"r","match":{"type":["jwt"]},"action":"mask"}]}"#,
/// )
/// .unwrap_err();
/// assert_eq!(rejected.class(), ActionPolicyErrorClass::InvalidAction);
/// assert_eq!(rejected.rule_index(), Some(0));
/// assert_eq!(rejected.code().as_str(), "INVALID_ACTION_POLICY");
/// ```
pub fn load_action_policy(bytes: &[u8]) -> Result<ActionPolicy, ActionPolicyError> {
    if bytes.len() > MAX_ACTION_POLICY_BYTES {
        return Err(ActionPolicyError::document(
            ActionPolicyErrorClass::ActionPolicyTooLarge,
        ));
    }
    let mut policy = Parser { bytes, pos: 0 }.document()?;
    policy.document_sha256 = crate::sha256::sha256(bytes);
    Ok(policy)
}

/// The kind of value that starts at the parser's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Object,
    Array,
    String,
    Number,
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

type Parse<T> = Result<T, ActionPolicyError>;

const fn malformed() -> ActionPolicyError {
    ActionPolicyError::document(ActionPolicyErrorClass::MalformedDocument)
}

const fn in_rule(class: ActionPolicyErrorClass, rule: usize) -> ActionPolicyError {
    ActionPolicyError::in_rule(class, Some(rule))
}

impl<'a> Parser<'a> {
    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Consumes `expected` after optional whitespace, or reports a syntax
    /// error.
    fn expect(&mut self, expected: u8) -> Parse<()> {
        self.skip_whitespace();
        if self.bytes.get(self.pos) == Some(&expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(malformed())
        }
    }

    /// The kind of the value that starts next, or a syntax error for any other
    /// token (`null`, `true`, `false`, a sign, a non-ASCII byte, the end of the
    /// document).
    fn kind(&mut self) -> Parse<Kind> {
        self.skip_whitespace();
        match self.bytes.get(self.pos) {
            Some(b'{') => Ok(Kind::Object),
            Some(b'[') => Ok(Kind::Array),
            Some(b'"') => Ok(Kind::String),
            Some(b'0'..=b'9') => Ok(Kind::Number),
            _ => Err(malformed()),
        }
    }

    /// Reads one string token: printable ASCII with no backslash, so no escape
    /// sequence exists and every byte is one character.
    fn string(&mut self) -> Parse<&'a str> {
        self.expect(b'"')?;
        let start = self.pos;
        loop {
            match self.bytes.get(self.pos) {
                Some(b'"') => break,
                Some(&byte) if (0x20..=0x7e).contains(&byte) && byte != b'\\' => self.pos += 1,
                _ => return Err(malformed()),
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| malformed())?;
        self.pos += 1;
        Ok(text)
    }

    /// Reads one canonical decimal integer token (`0` or `[1-9][0-9]*`) and
    /// returns its digits. A fraction, an exponent, a sign, a leading zero or
    /// trailing token characters are syntax errors.
    fn number(&mut self) -> Parse<&'a [u8]> {
        let start = self.pos;
        match self.bytes.get(start) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(malformed()),
        }
        if matches!(
            self.bytes.get(self.pos),
            Some(b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'.' | b'+' | b'-')
        ) {
            return Err(malformed());
        }
        Ok(&self.bytes[start..self.pos])
    }

    /// The error for a value of kind `found` where `rule`'s slot wants another
    /// kind. A scalar is read as a token first, so a malformed token stays a
    /// syntax error; a container is rejected at its opening byte.
    fn wrong_type(&mut self, found: Kind, rule: Option<usize>) -> ActionPolicyError {
        let scanned = match found {
            Kind::String => self.string().map(|_| ()),
            Kind::Number => self.number().map(|_| ()),
            Kind::Object | Kind::Array => Ok(()),
        };
        match scanned {
            Ok(()) => ActionPolicyError::in_rule(ActionPolicyErrorClass::WrongType, rule),
            Err(error) => error,
        }
    }

    /// Requires the next value to be of kind `want`.
    fn expect_kind(&mut self, want: Kind, rule: Option<usize>) -> Parse<()> {
        let found = self.kind()?;
        if found == want {
            Ok(())
        } else {
            Err(self.wrong_type(found, rule))
        }
    }

    /// Requires the next value to be a string and returns it.
    fn expect_string(&mut self, rule: Option<usize>) -> Parse<&'a str> {
        self.expect_kind(Kind::String, rule)?;
        self.string()
    }

    /// Reads an object. `member` is called once per key, with the key read and
    /// the parser positioned right after it; it must consume the `:` and the
    /// value, or reject the key before reading either.
    fn object<F>(&mut self, mut member: F) -> Parse<()>
    where
        F: FnMut(&mut Self, &'a str) -> Parse<()>,
    {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            let key = self.string()?;
            member(self, key)?;
            self.skip_whitespace();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(malformed()),
            }
        }
    }

    /// Reads an array and returns its element count. `element` is called when
    /// each element begins, with its zero-based index, before any of the
    /// element is read; it must consume the element.
    fn array<F>(&mut self, mut element: F) -> Parse<usize>
    where
        F: FnMut(&mut Self, usize) -> Parse<()>,
    {
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(0);
        }
        let mut count = 0;
        loop {
            element(self, count)?;
            count += 1;
            self.skip_whitespace();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(count);
                }
                _ => return Err(malformed()),
            }
        }
    }

    /// Reads the whole document.
    fn document(mut self) -> Parse<ActionPolicy> {
        let top = self.kind()?;
        if top != Kind::Object {
            return Err(self.wrong_type(top, None));
        }

        let mut first = true;
        let mut base_seen = false;
        let mut rules: Option<Vec<Rule>> = None;
        let mut ids: Vec<&'a str> = Vec::new();
        let mut revision_seen = false;

        self.object(|parser, key| {
            if first {
                first = false;
                // The revision selects the grammar, so it must come first and
                // is judged before anything after it is read.
                if key != KEY_REVISION {
                    return Err(ActionPolicyError::document(
                        ActionPolicyErrorClass::MissingField,
                    ));
                }
                parser.expect(b':')?;
                parser.expect_kind(Kind::Number, None)?;
                if parser.number()? != REVISION_DIGITS {
                    return Err(ActionPolicyError::document(
                        ActionPolicyErrorClass::UnknownRevision,
                    ));
                }
                revision_seen = true;
                return Ok(());
            }
            match key {
                KEY_REVISION => Err(ActionPolicyError::document(
                    ActionPolicyErrorClass::DuplicateField,
                )),
                KEY_BASE => {
                    if base_seen {
                        return Err(ActionPolicyError::document(
                            ActionPolicyErrorClass::DuplicateField,
                        ));
                    }
                    base_seen = true;
                    parser.expect(b':')?;
                    if parser.expect_string(None)? != BASE_DEFAULT {
                        return Err(ActionPolicyError::document(
                            ActionPolicyErrorClass::UnknownBase,
                        ));
                    }
                    Ok(())
                }
                KEY_RULES => {
                    if rules.is_some() {
                        return Err(ActionPolicyError::document(
                            ActionPolicyErrorClass::DuplicateField,
                        ));
                    }
                    parser.expect(b':')?;
                    parser.expect_kind(Kind::Array, None)?;
                    let mut parsed = Vec::new();
                    parser.array(|parser, index| {
                        if index >= MAX_RULES {
                            return Err(in_rule(ActionPolicyErrorClass::TooManyRules, index));
                        }
                        parsed.push(parser.rule(index, &mut ids)?);
                        Ok(())
                    })?;
                    rules = Some(parsed);
                    Ok(())
                }
                _ => Err(ActionPolicyError::document(
                    ActionPolicyErrorClass::UnknownField,
                )),
            }
        })?;

        // The object has closed: a missing member is reported here, before any
        // trailing content that follows the closing brace.
        let (true, true, Some(rules)) = (revision_seen, base_seen, rules) else {
            return Err(ActionPolicyError::document(
                ActionPolicyErrorClass::MissingField,
            ));
        };
        self.skip_whitespace();
        if self.pos != self.bytes.len() {
            return Err(malformed());
        }
        Ok(ActionPolicy {
            rules: Arc::from(rules),
            document_sha256: [0; 32],
        })
    }

    /// Reads one rule object.
    fn rule(&mut self, index: usize, ids: &mut Vec<&'a str>) -> Parse<Rule> {
        self.expect_kind(Kind::Object, Some(index))?;

        let mut id_seen = false;
        let mut rule_id: Option<&'a str> = None;
        let mut action: Option<RuleAction> = None;
        let mut matcher: Option<Matcher> = None;

        self.object(|parser, key| {
            match key {
                KEY_ID => {
                    if id_seen {
                        return Err(in_rule(ActionPolicyErrorClass::DuplicateField, index));
                    }
                    id_seen = true;
                    parser.expect(b':')?;
                    let id = parser.expect_string(Some(index))?;
                    if !is_identifier(id) {
                        return Err(in_rule(ActionPolicyErrorClass::InvalidIdentifier, index));
                    }
                    if ids.contains(&id) {
                        return Err(in_rule(ActionPolicyErrorClass::DuplicateRuleId, index));
                    }
                    ids.push(id);
                    rule_id = Some(id);
                }
                KEY_MATCH => {
                    if matcher.is_some() {
                        return Err(in_rule(ActionPolicyErrorClass::DuplicateField, index));
                    }
                    parser.expect(b':')?;
                    matcher = Some(parser.matcher(index)?);
                }
                KEY_ACTION => {
                    if action.is_some() {
                        return Err(in_rule(ActionPolicyErrorClass::DuplicateField, index));
                    }
                    parser.expect(b':')?;
                    action = Some(match parser.expect_string(Some(index))? {
                        "redact" => RuleAction::Fixed(Action::Redact),
                        "block" => RuleAction::Fixed(Action::Block),
                        "warn" => RuleAction::Fixed(Action::Warn),
                        "allow" => RuleAction::Fixed(Action::Allow),
                        "default" => RuleAction::Default,
                        _ => return Err(in_rule(ActionPolicyErrorClass::InvalidAction, index)),
                    });
                }
                _ => return Err(in_rule(ActionPolicyErrorClass::UnknownField, index)),
            }
            Ok(())
        })?;

        match (rule_id, matcher, action) {
            (Some(id), Some(matcher), Some(action)) => Ok(Rule {
                id: id.into(),
                action,
                types: matcher.types,
                detectors: matcher.detectors,
                confidences: matcher.confidences,
                obfuscations: matcher.obfuscations,
            }),
            _ => Err(in_rule(ActionPolicyErrorClass::MissingField, index)),
        }
    }

    /// Reads one `match` object.
    fn matcher(&mut self, rule: usize) -> Parse<Matcher> {
        self.expect_kind(Kind::Object, Some(rule))?;

        let mut matcher = Matcher::default();
        let mut seen = [false; 4];

        self.object(|parser, key| {
            let slot = match key {
                KEY_TYPE => 0,
                KEY_DETECTOR => 1,
                KEY_CONFIDENCE => 2,
                KEY_OBFUSCATION => 3,
                _ => return Err(in_rule(ActionPolicyErrorClass::UnknownField, rule)),
            };
            if seen[slot] {
                return Err(in_rule(ActionPolicyErrorClass::DuplicateField, rule));
            }
            seen[slot] = true;
            parser.expect(b':')?;
            match slot {
                0 => matcher.types = parser.identifier_set(rule)?,
                1 => matcher.detectors = parser.identifier_set(rule)?,
                2 => matcher.confidences = parser.vocabulary_set(rule, confidence_entry)?,
                _ => matcher.obfuscations = parser.vocabulary_set(rule, obfuscation_entry)?,
            }
            Ok(())
        })?;

        if seen.iter().all(|present| !present) {
            return Err(in_rule(ActionPolicyErrorClass::EmptyMatch, rule));
        }
        Ok(matcher)
    }

    /// Reads a non-empty set of identifiers.
    fn identifier_set(&mut self, rule: usize) -> Parse<Box<[Box<str>]>> {
        let members = self.set(rule, |member| {
            if is_identifier(member) {
                Ok(())
            } else {
                Err(ActionPolicyErrorClass::InvalidIdentifier)
            }
        })?;
        Ok(members.into_iter().map(Box::from).collect())
    }

    /// Reads a non-empty set of vocabulary entries and returns their bit mask.
    fn vocabulary_set(&mut self, rule: usize, entry: fn(&str) -> Option<u8>) -> Parse<u8> {
        let members = self.set(rule, |member| {
            entry(member)
                .map(|_| ())
                .ok_or(ActionPolicyErrorClass::UnknownVocabularyEntry)
        })?;
        Ok(members
            .into_iter()
            .filter_map(entry)
            .fold(0, |mask, bit| mask | bit))
    }

    /// Reads one array of strings, validating each with `check`, and rejects
    /// an empty set, a set over [`MAX_SET_MEMBERS`] and a repeated member.
    fn set<F>(&mut self, rule: usize, check: F) -> Parse<Vec<&'a str>>
    where
        F: Fn(&str) -> Result<(), ActionPolicyErrorClass>,
    {
        self.expect_kind(Kind::Array, Some(rule))?;
        let mut members: Vec<&'a str> = Vec::new();
        let count = self.array(|parser, index| {
            if index >= MAX_SET_MEMBERS {
                return Err(in_rule(ActionPolicyErrorClass::SetTooLarge, rule));
            }
            let member = parser.expect_string(Some(rule))?;
            check(member).map_err(|class| in_rule(class, rule))?;
            if members.contains(&member) {
                return Err(in_rule(ActionPolicyErrorClass::DuplicateSetMember, rule));
            }
            members.push(member);
            Ok(())
        })?;
        if count == 0 {
            return Err(in_rule(ActionPolicyErrorClass::EmptySet, rule));
        }
        Ok(members)
    }
}

/// The keys of one `match` object, validated.
#[derive(Default)]
struct Matcher {
    types: Box<[Box<str>]>,
    detectors: Box<[Box<str>]>,
    confidences: u8,
    obfuscations: u8,
}

fn confidence_entry(name: &str) -> Option<u8> {
    match name {
        "high" => Some(CONFIDENCE_HIGH),
        "medium" => Some(CONFIDENCE_MEDIUM),
        "low" => Some(CONFIDENCE_LOW),
        _ => None,
    }
}

fn obfuscation_entry(name: &str) -> Option<u8> {
    match name {
        "none" => Some(OBFUSCATION_NONE),
        "invisible-characters" => Some(OBFUSCATION_INVISIBLE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ByteRange;

    fn load(text: &str) -> Result<ActionPolicy, ActionPolicyError> {
        load_action_policy(text.as_bytes())
    }

    fn rejection(text: &str) -> (ActionPolicyErrorClass, Option<usize>) {
        let error = load(text).expect_err("the document must be rejected");
        (error.class(), error.rule_index())
    }

    fn finding(
        type_name: &str,
        detector: &str,
        confidence: Confidence,
        obfuscation: Obfuscation,
    ) -> DetectedFinding {
        DetectedFinding::new(
            "finding-1",
            type_name,
            detector,
            confidence,
            ByteRange::new(0, 1).unwrap(),
        )
        .unwrap()
        .with_obfuscation(obfuscation)
    }

    fn evaluate(policy: &ActionPolicy, finding: &DetectedFinding) -> Action {
        let whole = Policy::evaluate(policy, finding, &PolicyContext::new(0, 1)).unwrap();
        let incremental =
            IncrementalPolicy::evaluate(policy, finding, &IncrementalPolicyContext::new(0))
                .unwrap();
        assert_eq!(whole, incremental);
        whole
    }

    fn doc(rules: &str) -> String {
        format!(r#"{{"actionPolicyRevision":1,"base":"default","rules":[{rules}]}}"#)
    }

    #[test]
    fn the_policy_is_immutable_clone_send_and_sync() {
        fn assert_traits<T: Clone + Send + Sync + 'static>() {}
        assert_traits::<ActionPolicy>();
        assert_traits::<ActionPolicyError>();
        let policy = load(&doc("")).unwrap();
        let clone = policy.clone();
        assert!(Arc::ptr_eq(&policy.rules, &clone.rules));
    }

    #[test]
    fn an_empty_rules_array_is_the_default() {
        let policy = load(&doc("")).unwrap();
        for (type_name, confidence) in [
            ("private_key", Confidence::Low),
            ("github_token", Confidence::Low),
            ("contextual_secret", Confidence::Medium),
            ("contextual_secret", Confidence::High),
        ] {
            let finding = finding(type_name, "x", confidence, Obfuscation::None);
            assert_eq!(
                evaluate(&policy, &finding),
                default_action_for(type_name, confidence)
            );
        }
    }

    #[test]
    fn the_first_matching_rule_wins_in_either_order() {
        let allow_first = load(&doc(
            r#"{"id":"a","match":{"type":["jwt"]},"action":"allow"},
               {"id":"b","match":{"confidence":["medium"]},"action":"block"}"#,
        ))
        .unwrap();
        let block_first = load(&doc(
            r#"{"id":"b","match":{"confidence":["medium"]},"action":"block"},
               {"id":"a","match":{"type":["jwt"]},"action":"allow"}"#,
        ))
        .unwrap();
        let jwt = finding("jwt", "jwt", Confidence::Medium, Obfuscation::None);
        assert_eq!(evaluate(&allow_first, &jwt), Action::Allow);
        assert_eq!(evaluate(&block_first, &jwt), Action::Block);
    }

    #[test]
    fn keys_are_anded_and_a_set_is_ored() {
        let policy = load(&doc(
            r#"{"id":"r","match":{"type":["jwt","github_token"],"confidence":["medium"],
               "detector":["jwt"],"obfuscation":["none"]},"action":"block"}"#,
        ))
        .unwrap();
        let hit = finding("jwt", "jwt", Confidence::Medium, Obfuscation::None);
        assert_eq!(evaluate(&policy, &hit), Action::Block);
        for miss in [
            finding("jwt", "jwt", Confidence::High, Obfuscation::None),
            finding("jwt", "other", Confidence::Medium, Obfuscation::None),
            finding("other", "jwt", Confidence::Medium, Obfuscation::None),
            finding(
                "jwt",
                "jwt",
                Confidence::Medium,
                Obfuscation::InvisibleCharacters,
            ),
        ] {
            assert_eq!(
                evaluate(&policy, &miss),
                default_action_for(miss.type_name(), miss.confidence())
            );
        }
        let second_member = finding("github_token", "jwt", Confidence::Medium, Obfuscation::None);
        assert_eq!(evaluate(&policy, &second_member), Action::Block);
    }

    #[test]
    fn the_default_action_returns_the_base_and_stops_evaluation() {
        let policy = load(&doc(
            r#"{"id":"keep","match":{"type":["jwt"]},"action":"default"},
               {"id":"all","match":{"confidence":["high","medium","low"]},"action":"allow"}"#,
        ))
        .unwrap();
        let jwt = finding("jwt", "jwt", Confidence::Medium, Obfuscation::None);
        assert_eq!(evaluate(&policy, &jwt), Action::Redact);
        let other = finding(
            "contextual_secret",
            "g",
            Confidence::Medium,
            Obfuscation::None,
        );
        assert_eq!(evaluate(&policy, &other), Action::Allow);
    }

    #[test]
    fn the_base_is_the_running_artifacts_default_never_a_copy() {
        // Every type the default table names redacts at any confidence, and a
        // document that never names one still gets that, because the base is
        // computed at evaluation time.
        let policy = load(&doc(
            r#"{"id":"r","match":{"type":["acme-alnum-token"]},"action":"redact"}"#,
        ))
        .unwrap();
        for confidence in [Confidence::High, Confidence::Medium, Confidence::Low] {
            let key = finding("private_key", "private-key", confidence, Obfuscation::None);
            assert_eq!(evaluate(&policy, &key), Action::Block);
            let token = finding(
                "github_token",
                "github-token",
                confidence,
                Obfuscation::None,
            );
            assert_eq!(evaluate(&policy, &token), Action::Redact);
        }
    }

    #[test]
    fn unknown_type_and_detector_names_load_and_match_only_their_own() {
        let policy = load(&doc(
            r#"{"id":"t","match":{"type":["acme-not-yet-emitted"]},"action":"block"},
               {"id":"d","match":{"detector":["acme-not-yet-detector"]},"action":"block"}"#,
        ))
        .unwrap();
        let by_type = finding(
            "acme-not-yet-emitted",
            "x",
            Confidence::High,
            Obfuscation::None,
        );
        assert_eq!(evaluate(&policy, &by_type), Action::Block);
        let by_detector = finding(
            "other",
            "acme-not-yet-detector",
            Confidence::High,
            Obfuscation::None,
        );
        assert_eq!(evaluate(&policy, &by_detector), Action::Block);
        let neither = finding(
            "github_token",
            "github-token",
            Confidence::High,
            Obfuscation::None,
        );
        assert_eq!(evaluate(&policy, &neither), Action::Redact);
    }

    #[test]
    fn obfuscation_matches_only_a_named_value() {
        let policy = load(&doc(
            r#"{"id":"o","match":{"obfuscation":["invisible-characters"]},"action":"block"}"#,
        ))
        .unwrap();
        let plain = finding("jwt", "jwt", Confidence::High, Obfuscation::None);
        let hidden = finding(
            "jwt",
            "jwt",
            Confidence::High,
            Obfuscation::InvisibleCharacters,
        );
        assert_eq!(evaluate(&policy, &plain), Action::Redact);
        assert_eq!(evaluate(&policy, &hidden), Action::Block);
        assert_eq!(obfuscation_bit(Obfuscation::None), OBFUSCATION_NONE);
    }

    #[test]
    fn accepted_documents_at_every_bound() {
        // Exactly the byte bound.
        let base = doc("");
        let padded = format!("{base}{}", " ".repeat(MAX_ACTION_POLICY_BYTES - base.len()));
        assert_eq!(padded.len(), MAX_ACTION_POLICY_BYTES);
        assert!(load(&padded).is_ok());
        // Exactly 128 rules.
        let rules = (0..MAX_RULES)
            .map(|index| {
                format!(r#"{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        assert!(load(&doc(&rules)).is_ok());
        // Exactly 256 members in one set.
        let members = (0..MAX_SET_MEMBERS)
            .map(|index| format!(r#""t{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            load(&doc(&format!(
                r#"{{"id":"r","match":{{"type":[{members}]}},"action":"warn"}}"#
            )))
            .is_ok()
        );
        // Exactly a 64-byte rule id and identifier.
        let id = "a".repeat(64);
        assert!(
            load(&doc(&format!(
                r#"{{"id":"{id}","match":{{"type":["{id}"]}},"action":"warn"}}"#
            )))
            .is_ok()
        );
    }

    #[test]
    fn one_over_every_bound_is_rejected_with_its_class() {
        let base = doc("");
        let padded = format!(
            "{base}{}",
            " ".repeat(MAX_ACTION_POLICY_BYTES + 1 - base.len())
        );
        assert_eq!(
            rejection(&padded),
            (ActionPolicyErrorClass::ActionPolicyTooLarge, None)
        );
        let rules = (0..=MAX_RULES)
            .map(|index| {
                format!(r#"{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            rejection(&doc(&rules)),
            (ActionPolicyErrorClass::TooManyRules, Some(MAX_RULES))
        );
        let members = (0..=MAX_SET_MEMBERS)
            .map(|index| format!(r#""t{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            rejection(&doc(&format!(
                r#"{{"id":"r","match":{{"type":[{members}]}},"action":"warn"}}"#
            ))),
            (ActionPolicyErrorClass::SetTooLarge, Some(0))
        );
        let id = "a".repeat(65);
        assert_eq!(
            rejection(&doc(&format!(
                r#"{{"id":"{id}","match":{{"type":["jwt"]}},"action":"warn"}}"#
            ))),
            (ActionPolicyErrorClass::InvalidIdentifier, Some(0))
        );
    }

    #[test]
    fn the_size_bound_is_judged_before_anything_is_parsed() {
        // Not UTF-8 and not JSON, but too long: the bound wins.
        let bytes = vec![0xff; MAX_ACTION_POLICY_BYTES + 1];
        assert_eq!(
            load_action_policy(&bytes).unwrap_err().class(),
            ActionPolicyErrorClass::ActionPolicyTooLarge
        );
    }

    #[test]
    fn the_revision_is_judged_first_and_immediately() {
        // A later revision is never read under this grammar, however broken
        // the rest is.
        assert_eq!(
            rejection(r#"{"actionPolicyRevision":2,"zzz":!!!"#),
            (ActionPolicyErrorClass::UnknownRevision, None)
        );
        assert_eq!(
            rejection(r#"{"actionPolicyRevision":99999999999999999999999999,"#),
            (ActionPolicyErrorClass::UnknownRevision, None)
        );
        assert_eq!(
            rejection(r#"{"base":"default","actionPolicyRevision":1,"rules":[]}"#),
            (ActionPolicyErrorClass::MissingField, None)
        );
        assert_eq!(
            rejection(r#"{"nonsense":1}"#),
            (ActionPolicyErrorClass::MissingField, None)
        );
    }

    #[test]
    fn the_first_violation_in_document_order_is_reported() {
        // The unknown field comes before the invalid action and wins.
        assert_eq!(
            rejection(&doc(
                r#"{"id":"r","extra":1,"match":{"type":["jwt"]},"action":"mask"}"#
            )),
            (ActionPolicyErrorClass::UnknownField, Some(0))
        );
        // The invalid action in rule 0 precedes a duplicate id in rule 1.
        assert_eq!(
            rejection(&doc(
                r#"{"id":"r","match":{"type":["jwt"]},"action":"mask"},
                   {"id":"r","match":{"type":["jwt"]},"action":"warn"}"#
            )),
            (ActionPolicyErrorClass::InvalidAction, Some(0))
        );
        // An unknown key is rejected at the key, before its value is read.
        assert_eq!(
            rejection(r#"{"actionPolicyRevision":1,"extra":@@@"#),
            (ActionPolicyErrorClass::UnknownField, None)
        );
        // A duplicate rule id is reported where the id is read.
        assert_eq!(
            rejection(&doc(
                r#"{"id":"r","match":{"type":["jwt"]},"action":"warn"},
                   {"id":"r","match":{}"#
            )),
            (ActionPolicyErrorClass::DuplicateRuleId, Some(1))
        );
        // A missing member is reported when its object closes.
        assert_eq!(
            rejection(&doc(r#"{"id":"r","match":{"type":["jwt"]}}"#)),
            (ActionPolicyErrorClass::MissingField, Some(0))
        );
    }

    #[test]
    fn syntax_errors_are_document_level_even_inside_a_rule() {
        for text in [
            doc(r#"{"id":"r","match":{"type":["j\u0077t"]},"action":"warn"}"#),
            doc("{\"id\":\"r\",\"match\":{\"type\":[\"jw\u{e9}t\"]},\"action\":\"warn\"}"),
            doc("{\"id\":\"r\",\"match\":{\"type\":[\"a\tb\"]},\"action\":\"warn\"}"),
            doc(r#"{"id":"r","match":{"type":["jwt"]},"action":"warn",}"#),
            doc(r#"{"id":"r","match":{"type":["jwt",]},"action":"warn"}"#),
            doc(r#"{"id":"r","match":{"type":["a\tb"]},"action":"warn"}"#),
        ] {
            assert_eq!(
                rejection(&text),
                (ActionPolicyErrorClass::MalformedDocument, None),
                "{text}"
            );
        }
    }

    #[test]
    fn integers_must_be_canonical() {
        for number in [
            "1.0", "01", "+1", "-1", "1e0", "1E0", "0x1", "1a", "1.", "-0", ".5",
        ] {
            let text =
                format!(r#"{{"actionPolicyRevision":{number},"base":"default","rules":[]}}"#);
            assert_eq!(
                rejection(&text),
                (ActionPolicyErrorClass::MalformedDocument, None),
                "{number}"
            );
        }
        assert_eq!(
            rejection(r#"{"actionPolicyRevision":0,"base":"default","rules":[]}"#),
            (ActionPolicyErrorClass::UnknownRevision, None)
        );
        assert_eq!(
            rejection(r#"{"actionPolicyRevision":"1","base":"default","rules":[]}"#),
            (ActionPolicyErrorClass::WrongType, None)
        );
    }

    #[test]
    fn whitespace_is_space_tab_lf_and_cr_only() {
        let accepted = "{\n\t\"actionPolicyRevision\" :\r1 ,\"base\":\"default\",\"rules\":[ ]}\n";
        assert!(load(accepted).is_ok());
        for other in ['\u{b}', '\u{c}', '\u{a0}', '\u{feff}', '\u{2028}'] {
            let text =
                format!(r#"{{"actionPolicyRevision":1,{other}"base":"default","rules":[]}}"#);
            assert_eq!(
                rejection(&text),
                (ActionPolicyErrorClass::MalformedDocument, None),
                "{other:?}"
            );
        }
    }

    #[test]
    fn invalid_utf8_and_a_byte_order_mark_are_malformed() {
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(doc("").as_bytes());
        assert_eq!(
            load_action_policy(&bom).unwrap_err().class(),
            ActionPolicyErrorClass::MalformedDocument
        );
        for bytes in [&b"\xff"[..], b"\xc3", b"{\"\xed\xa0\x80\":1}", b""] {
            assert_eq!(
                load_action_policy(bytes).unwrap_err().class(),
                ActionPolicyErrorClass::MalformedDocument
            );
        }
    }

    #[test]
    fn values_in_the_wrong_slot_are_rejected_without_being_read() {
        let deep = "[".repeat(10_000);
        let deep_object = "{".repeat(10_000);
        for (text, expected) in [
            (format!(r#"{{"actionPolicyRevision":{deep}"#), None),
            (format!(r#"{{"actionPolicyRevision":1,"base":{deep}"#), None),
            (
                format!(r#"{{"actionPolicyRevision":1,"base":"default","rules":{deep_object}"#),
                None,
            ),
            (
                format!(r#"{{"actionPolicyRevision":1,"base":"default","rules":[{deep}"#),
                Some(0),
            ),
            (
                format!(
                    r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":{deep}"#
                ),
                Some(0),
            ),
        ] {
            assert_eq!(
                rejection(&text),
                (ActionPolicyErrorClass::WrongType, expected)
            );
        }
        assert_eq!(rejection("[]"), (ActionPolicyErrorClass::WrongType, None));
        assert_eq!(rejection("7"), (ActionPolicyErrorClass::WrongType, None));
        assert_eq!(
            rejection("\"x\""),
            (ActionPolicyErrorClass::WrongType, None)
        );
        for literal in ["null", "true", "false"] {
            assert_eq!(
                rejection(literal),
                (ActionPolicyErrorClass::MalformedDocument, None)
            );
        }
    }

    #[test]
    fn every_class_has_a_distinct_fixed_name_and_the_code_is_one() {
        let mut names: Vec<&str> = ActionPolicyErrorClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        assert_eq!(names.len(), 17);
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 17);
        for class in ActionPolicyErrorClass::ALL {
            assert_eq!(class.to_string(), class.as_str());
            let error = ActionPolicyError::document(class);
            assert_eq!(error.code().as_str(), "INVALID_ACTION_POLICY");
            assert_eq!(error.to_string(), "The supplied action policy is invalid.");
            assert_eq!(error.message(), error.to_string());
        }
    }

    #[test]
    fn a_rejection_never_echoes_the_document() {
        let secret = "ghp_SYNTHETICREVOKED00000000000000000000";
        let text = format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"{secret}","match":{{"type":["jwt"]}},"action":"warn"}}]}}"#
        );
        let error = load(&text).unwrap_err();
        assert_eq!(error.class(), ActionPolicyErrorClass::InvalidIdentifier);
        for rendered in [
            format!("{error}"),
            format!("{error:?}"),
            error.message().to_owned(),
        ] {
            assert!(!rendered.contains("ghp_"), "{rendered}");
        }
    }
}
