import redact_secret
from redact_secret import ComparedPolicy

redact_secret.initialize()

# The action policy is an argument of each call, so any number of policies can
# be used in one process and one thread without sharing state.
TEXT = "API_KEY=" + "".join(["ghp", "_SYNTHETICREVOKED", "0" * 20])
KEEP_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "keep-github", "match": {"type": ["github_token"]}, "action": "warn"}],
}

print("default:", "unchanged" if redact_secret.scan_and_redact(TEXT).text == TEXT else "redacted")
kept = redact_secret.scan_and_redact(TEXT, action_policy=KEEP_GITHUB)
print("keep-github:", "unchanged" if kept.text == TEXT else "redacted")

# A policy change is previewed over one detection pass before it is adopted.
comparison = redact_secret.compare_action_policies(
    TEXT, [ComparedPolicy.default(), ComparedPolicy.action_policy(KEEP_GITHUB)]
)
finding = comparison.findings[0]
print(" -> ".join(str(decision.action) for decision in finding.decisions), "changed:", comparison.changed_count)
