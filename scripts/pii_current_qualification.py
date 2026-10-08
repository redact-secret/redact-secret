"""Read the optional benchmark-owned current target without promoting its public evidence."""

from __future__ import annotations

import re

GATES = {
    "publicQualification": "not-evaluated",
    "validator": "not-measured",
    "runtimeAndPackageCost": "unmeasured",
    "sizeRegressionBudget": "unmeasured",
    "profileCost": "unmeasured",
    "protectedPath": "pending-not-operational",
    "protectedPartition": "not-run",
}
REASONS = [
    "public-qualification-gates-not-evaluated",
    "runtime-and-package-cost-unmeasured",
    "size-regression-budget-unmeasured",
    "profile-cost-unmeasured",
    "protected-path-not-operational",
    "protected-partition-not-run",
]
TOP_KEYS = {
    "schemaVersion",
    "state",
    "sourceCommit",
    "supportClaims",
    "qualified",
    "evidenceScope",
    "publicMeasurement",
    "gates",
    "distribution",
    "families",
}
MEASUREMENT_KEYS = {
    "state",
    "mode",
    "reason",
    "receiptDigest",
    "productArtifactDigest",
    "baselineSourceCommit",
    "engineBinaryDigest",
}
DIGEST_KEYS = ("receiptDigest", "productArtifactDigest", "engineBinaryDigest")


def current_qualification_errors(current: dict | None, expected_families: set[str]) -> list[str]:
    """Absent is backward compatible; a present section must preserve the pending contract."""
    if current is None:
        return []
    errors = []
    if not isinstance(current, dict) or set(current) != TOP_KEYS:
        return ["piiCurrentQualification has an invalid field set"]
    if (
        type(current["schemaVersion"]) is not int
        or current["schemaVersion"] != 1
        or current["supportClaims"] is not False
        or current["qualified"] is not False
        or current["evidenceScope"] != "public-synthetic-only"
        or not isinstance(current["sourceCommit"], str)
        or not re.fullmatch(r"[a-f0-9]{40}", current["sourceCommit"])
    ):
        errors.append("piiCurrentQualification must name an exact unqualified public-only target")
    measurement = current["publicMeasurement"]
    if not isinstance(measurement, dict) or set(measurement) != MEASUREMENT_KEYS:
        return errors + ["piiCurrentQualification publicMeasurement has an invalid field set"]
    state = (
        {"not-recorded": "prepared", "recorded": "recorded", "invalid": "invalid"}.get(measurement["state"])
        if isinstance(measurement["state"], str)
        else None
    )
    if state is None or current["state"] != state:
        errors.append("piiCurrentQualification measurement state disagrees")
    if state == "recorded":
        if (
            measurement["mode"] not in ("official", "exploratory")
            or measurement["reason"] is not None
            or not isinstance(measurement["baselineSourceCommit"], str)
            or not re.fullmatch(r"[a-f0-9]{40}", measurement["baselineSourceCommit"])
            or any(
                not isinstance(measurement[k], str) or not re.fullmatch(r"[a-f0-9]{64}", measurement[k])
                for k in DIGEST_KEYS
            )
        ):
            errors.append("piiCurrentQualification recorded public evidence has invalid identity")
    elif (
        measurement["mode"] is not None
        or not isinstance(measurement["reason"], str)
        or not measurement["reason"]
        or any(measurement[k] is not None for k in (*DIGEST_KEYS, "baselineSourceCommit"))
    ):
        errors.append("piiCurrentQualification absent/invalid evidence must not carry measured identity")
    if current["gates"] != GATES:
        errors.append("piiCurrentQualification cannot claim a cost, validator or protected gate is met")
    rows = current["families"]
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or set(row) != {"family", "status", "reasonCodes"} for row in rows
    ):
        return errors + ["piiCurrentQualification families have invalid fields"]
    ids = [row["family"] for row in rows]
    if (
        any(not isinstance(value, str) for value in ids)
        or set(ids) != expected_families
        or len(ids) != len(expected_families)
    ):
        errors.append("piiCurrentQualification families differ from the shipped PII inventory")
    if (
        not isinstance(current["distribution"], dict)
        or any(type(value) is not int for value in current["distribution"].values())
        or current["distribution"]
        != {"stable": 0, "provisional": 0, "pending": len(expected_families), "unsupported": 0}
    ):
        errors.append("piiCurrentQualification distribution must recount all current families as pending")
    first = (
        "product-validator-primitive-seam-unavailable"
        if state == "recorded"
        else ("current-public-comparison-invalid" if state == "invalid" else "current-public-comparison-not-recorded")
    )
    if any(row["status"] != "pending" or row["reasonCodes"] != [first, *REASONS] for row in rows):
        errors.append("piiCurrentQualification status or unmet-gate reasons disagree")
    return errors


def current_qualification_sentence(current: dict | None) -> str:
    if current is None:
        return "The pinned matrix has no current-target PII qualification record; the historical disposition does not qualify later source."
    count = current["distribution"]["pending"]
    measured = current["publicMeasurement"]
    evidence = (
        f"{measured['mode']} public measurement recorded"
        if measured["state"] == "recorded"
        else f"public measurement {measured['state']}"
    )
    return (
        f"Current PII target `{current['sourceCommit']}`: {count} families pending, {evidence}, qualified false. "
        "Validator, public qualification, cost and protected gates remain unmet; this is not an owner-approved deferral."
    )
