"""Request-wide placeholder numbering across several leaves (issue #1180).

Every call numbers placeholders from 1, so a host that scans the string leaves
of one request needs request-wide unique numbers. `docs/guides/python.md`
("Request-wide placeholder numbering") documents a recipe that adds a running
offset to `PlaceholderContext.placeholder_index` inside a custom formatter.
This file runs that exact recipe against the real extension and pins every
claim the guide makes. Nothing here adds public API. Every input is synthetic.
"""

from __future__ import annotations

import pytest
import redact_secret

from .conftest import generous_limits

TOKEN_A = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"
TOKEN_B = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111"
WARN_LINE = "password=hunter2xyz"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRURfQ09ORk9STUFOQ0U=\n-----END PRIVATE KEY-----"


class RequestNumbering:
    """The documented recipe: only an integer offset survives from leaf to leaf."""

    def __init__(self) -> None:
        self.replaced_so_far = 0

    def redact_leaf(self, leaf: str) -> str:
        base = self.replaced_so_far
        used = 0

        def formatter(finding: redact_secret.Finding, context: redact_secret.PlaceholderContext) -> str:
            nonlocal used
            used = context.placeholder_index
            return f"<SECRET_{base + context.placeholder_index}>"

        text = redact_secret.scan_and_redact(leaf, formatter=formatter).text
        # Reached only when the call succeeded: an exception leaves the offset
        # alone and the host fails the whole request.
        self.replaced_so_far = base + used
        return text


def action_of(text: str) -> str:
    return redact_secret.scan_and_redact(text).findings[0].action


def test_a_bare_call_restarts_at_one_which_is_why_a_request_needs_an_offset() -> None:
    assert redact_secret.scan_and_redact(f"token={TOKEN_A}").text == "token=<SECRET_1>"
    assert redact_secret.scan_and_redact(f"token={TOKEN_B}").text == "token=<SECRET_1>"


def test_leaves_of_one_request_are_numbered_uniquely_in_visit_order() -> None:
    numbering = RequestNumbering()
    texts = [
        numbering.redact_leaf(f"first {TOKEN_A} and second {TOKEN_B}"),
        numbering.redact_leaf("nothing sensitive here"),
        numbering.redact_leaf(f"again {TOKEN_A}"),
        numbering.redact_leaf(PRIVATE_KEY),
    ]
    # Several findings in one leaf take consecutive numbers, a leaf with no
    # finding consumes none, and the same value in a later leaf is a new
    # occurrence with a new number. A `block` finding is numbered like `redact`.
    assert texts == [
        "first <SECRET_1> and second <SECRET_2>",
        "nothing sensitive here",
        "again <SECRET_3>",
        "<SECRET_4>",
    ]
    assert numbering.replaced_so_far == 4

    # A second request has its own offset and restarts at 1.
    assert RequestNumbering().redact_leaf(f"t {TOKEN_B}") == "t <SECRET_1>"


def test_identical_values_in_one_leaf_are_numbered_per_occurrence() -> None:
    numbering = RequestNumbering()
    assert numbering.redact_leaf(f"x {TOKEN_A} y {TOKEN_A}") == "x <SECRET_1> y <SECRET_2>"
    assert numbering.replaced_so_far == 2


def test_warn_consumes_no_number_and_block_does() -> None:
    assert action_of(WARN_LINE) == "warn"
    assert action_of(PRIVATE_KEY) == "block"
    assert action_of(TOKEN_A) == "redact"

    numbering = RequestNumbering()
    assert numbering.redact_leaf(WARN_LINE) == WARN_LINE
    assert numbering.replaced_so_far == 0
    assert numbering.redact_leaf(PRIVATE_KEY) == "<SECRET_1>"
    assert numbering.redact_leaf(f"t {TOKEN_A}") == "t <SECRET_2>"


def test_the_offset_equals_the_count_of_redact_and_block_findings() -> None:
    leaf = f"a {TOKEN_A} b {WARN_LINE} c {TOKEN_B}"
    findings = redact_secret.scan_and_redact(leaf).findings
    replaced = sum(1 for finding in findings if finding.action in {"redact", "block"})
    numbering = RequestNumbering()
    numbering.redact_leaf(leaf)
    assert numbering.replaced_so_far == replaced == 2


def test_a_failing_leaf_raises_and_does_not_advance_the_offset() -> None:
    numbering = RequestNumbering()
    numbering.redact_leaf(f"t {TOKEN_A}")

    def failing(finding: redact_secret.Finding, context: redact_secret.PlaceholderContext) -> str:
        raise RuntimeError("synthetic formatter failure")

    with pytest.raises(redact_secret.PlaceholderFailureError):
        redact_secret.scan_and_redact(f"t {TOKEN_B}", formatter=failing)
    assert numbering.replaced_so_far == 1


def test_the_same_recipe_numbers_an_incremental_session_per_leaf() -> None:
    # Each streamed leaf is its own session whose `placeholder_index` counts
    # across that session's appends. The offset is read after `finalize`.
    leaves = [
        (f"first {TOKEN_A} then ", f"{TOKEN_B} end"),
        ("clean ", "tail"),
        (f"again {TOKEN_A}", ""),
    ]
    replaced_so_far = 0
    texts: list[str] = []
    for head, tail in leaves:
        base = replaced_so_far
        used = 0

        def formatter(
            finding: redact_secret.Finding,
            context: redact_secret.PlaceholderContext,
            base: int = base,
        ) -> str:
            nonlocal used
            used = context.placeholder_index
            return f"<SECRET_{base + context.placeholder_index}>"

        session = redact_secret.IncrementalSanitizer(generous_limits(), formatter=formatter)
        text = session.append(head).text + session.append(tail).text + session.finalize().text
        replaced_so_far = base + used
        texts.append(text)

    assert texts == ["first <SECRET_1> then <SECRET_2> end", "clean tail", "again <SECRET_3>"]
