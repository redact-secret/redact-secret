"""Type stubs for the compiled ``redact_secret._native`` extension module.

Import from :mod:`redact_secret`, not this module directly; the names here
are re-exported there.
"""

from __future__ import annotations

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

class InvalidStateError(SecretScanError):
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
    def minimum_buffered_bytes(
        max_token_bytes: int, max_multiline_bytes: int
    ) -> int:
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

class IncrementalSanitizer:
    """A bounded incremental sanitization session. Findings carry absolute
    Unicode code point offsets into the logical whole-session input."""

    def __init__(
        self,
        limits: IncrementalLimits,
        policy: IncrementalPolicy | None = None,
        formatter: Formatter | None = None,
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
def byte_offset_to_char_offset(text: str, byte_offset: int) -> int: ...
def scan(text: str, policy: Policy | None = None) -> list[Finding]: ...
def redact(
    text: str, findings: list[Finding], formatter: Formatter | None = None
) -> str: ...
def scan_and_redact(
    text: str,
    policy: Policy | None = None,
    formatter: Formatter | None = None,
) -> ScanResult: ...
def default_policy(finding: DetectedFinding, context: PolicyContext) -> str: ...
def default_placeholder_formatter(
    finding: Finding, context: PlaceholderContext
) -> str: ...
def typed_placeholder_formatter(
    finding: Finding, context: PlaceholderContext
) -> str: ...
def default_incremental_policy(
    finding: DetectedFinding, context: IncrementalPolicyContext
) -> str: ...
