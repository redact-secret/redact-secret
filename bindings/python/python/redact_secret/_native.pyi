"""Type stubs for the compiled ``redact_secret._native`` extension module.

Import from :mod:`redact_secret`, not this module directly; the names here
are re-exported there.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import TracebackType
from typing import Callable

# ---------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------

VERSION: str
"""The shared product version, identical across every core, CLI, and binding."""

RANGE_UNIT: str
"""The Unicode string-index unit every range in this module reports:
``"unicode-code-points"``."""

# ---------------------------------------------------------------------
# Sanitized exceptions
# ---------------------------------------------------------------------

class SecretScanError(Exception):
    """Base class for every sanitized redact-secret error."""

class InvalidInputError(SecretScanError):
    code: str

class InvalidOptionsError(SecretScanError):
    code: str

class InvalidDetectorError(SecretScanError):
    code: str

class DetectorFailureError(SecretScanError):
    code: str

class InvalidCandidateError(SecretScanError):
    code: str

class PolicyFailureError(SecretScanError):
    code: str

class InvalidPolicyActionError(SecretScanError):
    code: str

class InvalidFindingsError(SecretScanError):
    code: str

class PlaceholderFailureError(SecretScanError):
    code: str

class InvalidPlaceholderError(SecretScanError):
    code: str

class InvalidLimitsError(SecretScanError):
    code: str

class InputLimitExceededError(SecretScanError):
    code: str

class BufferLimitExceededError(SecretScanError):
    code: str

class TokenLimitExceededError(SecretScanError):
    code: str

class MultilineLimitExceededError(SecretScanError):
    code: str

class FindingLimitExceededError(SecretScanError):
    code: str

class InvalidStateError(SecretScanError):
    code: str

class InvalidRulesetError(SecretScanError):
    """A `ruleset` argument to scan()/scan_and_redact() was rejected while
    loading. The message carries the fixed rejection class in parentheses."""

    code: str

class InvalidActionPolicyError(SecretScanError):
    """An ``action_policy`` was rejected while loading. The message is fixed
    and repeats no byte of the document."""

    code: str
    error_class: str | None
    """The fixed rejection class, for example ``"INVALID_ACTION"``."""
    rule_index: int | None
    """The zero-based index of the rule being read, or ``None`` for a
    document-level violation."""

class PiiSelectorInvalidError(SecretScanError):
    code: str

class PiiSelectorUnsupportedError(SecretScanError):
    code: str

class PiiSelectorUnavailableError(SecretScanError):
    code: str

class PiiActivationConflictError(SecretScanError):
    code: str

# ---------------------------------------------------------------------
# Safe metadata types
#
# None of these types can be constructed from Python; they are only ever
# produced by scan(), redact(), and scan_and_redact() and passed to a
# policy or formatter callback.
# ---------------------------------------------------------------------

class DetectedFinding:
    """Pre-policy, immutable finding metadata passed to a policy callback."""

    id: str
    type: str
    detector: str
    confidence: str
    obfuscation: str
    start: int
    end: int

class PolicyContext:
    """Position of a finding, passed to a policy callback."""

    finding_index: int
    finding_count: int

class Finding:
    """Immutable, policy-evaluated finding: safe metadata plus the action."""

    id: str
    type: str
    detector: str
    confidence: str
    action: str
    obfuscation: str
    start: int
    end: int

class PlaceholderContext:
    """Position of a replaced finding, passed to a formatter callback."""

    placeholder_index: int

class ScanResult:
    """The result of scan_and_redact(): redacted text and its findings."""

    text: str
    findings: list[Finding]

class IncrementalPolicyContext:
    """Position of a finding among those an incremental session has
    finalized so far, passed to an incremental policy callback. There is no
    total count: progressive evaluation cannot know one."""

    finding_index: int

class IncrementalResult:
    """The immutable result of one append() or finalize() call."""

    text: str
    findings: list[Finding]

# ---------------------------------------------------------------------
# Callback protocols
# ---------------------------------------------------------------------

Policy = Callable[[DetectedFinding, PolicyContext], str]
IncrementalPolicy = Callable[[DetectedFinding, IncrementalPolicyContext], str]
Formatter = Callable[[Finding, PlaceholderContext], str]

# A declarative action policy: a ``dict`` (serialized once with the standard
# compact JSON encoder) or the document itself as ``bytes``, ``bytearray`` or
# ``str``. A call or session takes ``policy`` or ``action_policy``, never both.
ActionPolicyDocument = dict[str, object] | bytes | bytearray | str

# ---------------------------------------------------------------------
# Explain and compare action policies (whole input only)
#
# None of the result types can be constructed from Python; they are only
# produced by compare_action_policies(). There is no incremental, session
# or stream comparison.
# ---------------------------------------------------------------------

class ComparedPolicy:
    """One policy taking part in a comparison. Build one with
    :meth:`default`, :meth:`action_policy` or :meth:`callback`; the class has
    no public constructor. An action policy is loaded and validated when its
    side is built, so a rejected document raises ``InvalidActionPolicyError``
    before any comparison runs."""

    @staticmethod
    def default() -> ComparedPolicy:
        """The default policy: the running artifact's default evaluation."""
    @staticmethod
    def action_policy(document: ActionPolicyDocument) -> ComparedPolicy:
        """A declarative action policy, in the input forms ``action_policy=``
        accepts."""
    @staticmethod
    def callback(policy: Policy) -> ComparedPolicy:
        """A legacy ``policy`` callback, called once per finalized finding in
        finding order, exactly as ``scan(policy=...)`` calls it. Raises
        ``InvalidOptionsError`` when ``policy`` is not callable."""
    @property
    def kind(self) -> str:
        """``"default"``, ``"action-policy"`` or ``"callback"``."""
    @property
    def document_sha256(self) -> str | None:
        """The lowercase SHA-256 of the exact document bytes for an action
        policy; ``None`` for the default policy and for a callback."""

class ActionDecision:
    """The decision one policy reached for one finding, and why."""

    action: str
    """``"redact"``, ``"block"``, ``"warn"`` or ``"allow"``."""
    basis: str
    """``"rule"``, ``"rule-default"``, ``"no-rule-matched"``,
    ``"default-policy"`` or ``"callback"``."""
    rule_id: str | None
    """The matched rule's id for ``"rule"`` and ``"rule-default"``."""
    rule_index: int | None
    """The matched rule's zero-based index for ``"rule"`` and
    ``"rule-default"``."""

class ComparedFinding:
    """One finalized finding and the decision every compared policy reached
    for it. The finding fields are safe metadata (no matched value); ranges
    are Unicode code points."""

    id: str
    type: str
    detector: str
    confidence: str
    obfuscation: str
    start: int
    end: int
    differs: bool
    """Whether the compared policies do not all choose the same action. The
    action only: a changed reason with the same action does not differ."""
    @property
    def decisions(self) -> tuple[ActionDecision, ...]:
        """One decision per compared policy, in the order given."""

class ActionCounts:
    """How many findings a policy chose each action for."""

    redact: int
    block: int
    warn: int
    allow: int

class ComparedSide:
    """One compared policy: its kind, its document digest if it has one, and
    its per-action counts."""

    kind: str
    """``"default"``, ``"action-policy"`` or ``"callback"``."""
    document_sha256: str | None
    """The lowercase SHA-256 of the exact document bytes for an action
    policy; ``None`` for the default policy and for a callback."""
    @property
    def counts(self) -> ActionCounts: ...

class DetectionIdentity:
    """The detection configuration the findings were produced under, apart
    from every policy. It does not cover a custom ``ruleset``."""

    activation_identity: str
    profile: str | None
    detector_count: int

class ActionComparison:
    """What each compared policy would choose for the findings one detection
    pass produced. An observation, never enforcement."""

    changed_count: int
    """How many findings have ``differs`` true."""
    @property
    def mode(self) -> str:
        """Always ``"preview"``."""
    @property
    def enforced(self) -> bool:
        """Always ``False``: a comparison enforces nothing."""
    @property
    def detection(self) -> DetectionIdentity: ...
    @property
    def sides(self) -> tuple[ComparedSide, ...]:
        """One side per compared policy, in the order given."""
    @property
    def findings(self) -> tuple[ComparedFinding, ...]:
        """The finalized findings, in the order ``scan`` returns them."""

# ---------------------------------------------------------------------
# Incremental sanitization
# ---------------------------------------------------------------------

class IncrementalLimits:
    """The mandatory, positive UTF-8 byte limits of one session. All four
    are keyword-only and have no defaults."""

    def __init__(
        self,
        *,
        max_input_bytes: int,
        max_buffered_bytes: int,
        max_token_bytes: int,
        max_multiline_bytes: int,
    ) -> None: ...
    @staticmethod
    def minimum_buffered_bytes(max_token_bytes: int, max_multiline_bytes: int) -> int:
        """The smallest ``max_buffered_bytes`` this class accepts alongside
        these construct limits."""

    @property
    def max_input_bytes(self) -> int: ...
    @property
    def max_buffered_bytes(self) -> int: ...
    @property
    def max_token_bytes(self) -> int: ...
    @property
    def max_multiline_bytes(self) -> int: ...

class WholeInputLimits:
    """Explicit byte and finding-count bounds for scan(), redact(), and
    scan_and_redact(). Both are keyword-only. Omit an instance (pass
    ``limits=None``, the default) to use the core's default whole-input
    bound."""

    def __init__(self, *, max_input_bytes: int, max_findings: int) -> None: ...
    @property
    def max_input_bytes(self) -> int: ...
    @property
    def max_findings(self) -> int: ...

class CoreStatus:
    """Read-only snapshot returned by ``status()``. Never constructed from
    Python. Fixed values and public capability metadata only."""

    @property
    def initialized(self) -> bool: ...
    @property
    def profile(self) -> str: ...
    @property
    def activation(self) -> str | None: ...

class IncrementalSanitizer:
    """A bounded incremental sanitization session. Findings carry absolute
    Unicode code point offsets into the logical whole-session input."""

    def __init__(
        self,
        limits: IncrementalLimits,
        policy: IncrementalPolicy | None = None,
        formatter: Formatter | None = None,
        *,
        action_policy: ActionPolicyDocument | None = None,
    ) -> None: ...
    @property
    def state(self) -> str: ...
    @property
    def limits(self) -> IncrementalLimits: ...
    def append(self, chunk: str) -> IncrementalResult: ...
    def finalize(self) -> IncrementalResult: ...
    def abort(self) -> None: ...
    def __enter__(self) -> IncrementalSanitizer: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...

# ---------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------

def version() -> str: ...
def initialize(pii: Sequence[str] = ()) -> None: ...
def pii_activation() -> str: ...
def status() -> CoreStatus: ...
def byte_offset_to_char_offset(text: str, byte_offset: int) -> int: ...
def scan(
    text: str,
    policy: Policy | None = None,
    limits: WholeInputLimits | None = None,
    ruleset: bytes | bytearray | str | None = None,
    *,
    action_policy: ActionPolicyDocument | None = None,
) -> list[Finding]: ...
def redact(
    text: str,
    findings: list[Finding],
    formatter: Formatter | None = None,
    limits: WholeInputLimits | None = None,
) -> str: ...
def scan_and_redact(
    text: str,
    policy: Policy | None = None,
    formatter: Formatter | None = None,
    limits: WholeInputLimits | None = None,
    ruleset: bytes | bytearray | str | None = None,
    *,
    action_policy: ActionPolicyDocument | None = None,
) -> ScanResult: ...
def compare_action_policies(
    text: str,
    policies: list[ComparedPolicy] | tuple[ComparedPolicy, ...],
    limits: WholeInputLimits | None = None,
    ruleset: bytes | bytearray | str | None = None,
) -> ActionComparison:
    """Compare what 1 to 4 policies choose for the findings of one detection
    pass, without enforcing any of them. Whole input only."""

def default_policy(finding: DetectedFinding, context: PolicyContext) -> str: ...
def default_placeholder_formatter(finding: Finding, context: PlaceholderContext) -> str: ...
def typed_placeholder_formatter(finding: Finding, context: PlaceholderContext) -> str: ...
def default_incremental_policy(finding: DetectedFinding, context: IncrementalPolicyContext) -> str: ...
