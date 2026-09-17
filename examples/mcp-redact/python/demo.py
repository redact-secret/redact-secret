#!/usr/bin/env python3
"""Side-by-side demo for issue #327, mirroring ``../demo.mjs``: the same
synthetic tool result run through block-all behavior (Docker MCP Gateway's
default ``--block-secrets``) and through this middleware's redact
behavior.

Uses the real, built ``redact_secret`` package -- like
``examples/tracing-masking/python/langfuse_mask.py``, this file is
exercised against the real package rather than unit tested.

Run: python3 examples/mcp-redact/python/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import redact_secret  # noqa: E402

from redact_tool_call import build_blocked_result, redact_tool_result  # noqa: E402

# AKIA + SYNTHETICEXAMPLE: this repo's synthetic AWS access key ID, also
# used in crates/secret-scan-core/src/detectors/aws.rs's own tests -- not a
# real credential.
SYNTHETIC_TOOL_RESULT = {
    "content": [
        {
            "type": "text",
            "text": "\n".join(
                [
                    "Deploy finished. Captured environment for debugging:",
                    "AWS_ACCESS_KEY_ID=AKIASYNTHETICEXAMPLE",
                    "DATABASE_URL=postgres://app:pw@db.internal:5432/app",
                    "Build artifact: build-8421.tar.gz (142 MB)",
                ]
            ),
        }
    ]
}


def block_all(result: dict) -> dict:
    """Docker MCP Gateway --block-secrets style: any finding anywhere
    rejects the whole call, with no partial or sanitized result returned."""
    probe = redact_tool_result(redact_secret.scan_and_redact, result)
    has_findings = probe["outcome"] == "blocked" or len(probe["findings"]) > 0
    if has_findings:
        return {"rejected": True, "reason": "secret detected; call rejected outright"}
    return result


def redact(result: dict) -> dict:
    outcome = redact_tool_result(redact_secret.scan_and_redact, result)
    return build_blocked_result() if outcome["outcome"] == "blocked" else outcome["result"]


def main() -> None:
    print("Synthetic tool result:\n" + json.dumps(SYNTHETIC_TOOL_RESULT, indent=2) + "\n")

    print("=== block-all (Docker MCP Gateway --block-secrets style) ===")
    print(json.dumps(block_all(SYNTHETIC_TOOL_RESULT), indent=2) + "\n")

    print("=== redact (examples/mcp-redact) ===")
    print(json.dumps(redact(SYNTHETIC_TOOL_RESULT), indent=2))


if __name__ == "__main__":
    main()
