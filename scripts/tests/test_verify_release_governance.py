from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "verify-release-governance.py"
SPEC = importlib.util.spec_from_file_location("verify_release_governance", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class FakeReader:
    """A reader keyed by path/URL, raising VERIFY.NotAvailable for a marked key."""

    def __init__(self, responses: dict[str, object], unavailable: set[str] | None = None) -> None:
        self.responses = responses
        self.unavailable = unavailable or set()

    def __call__(self, key: str) -> object:
        if key in self.unavailable:
            raise VERIFY.NotAvailable(f"no credential for {key}")
        if key not in self.responses:
            raise AssertionError(f"unexpected read: {key}")
        return self.responses[key]


class GitHubEnvironmentTests(unittest.TestCase):
    def test_unprotected_environment_reports_no_reviewers_and_bypass_allowed(self) -> None:
        reader = FakeReader(
            {
                "repos/o/r/environments/release": {
                    "protection_rules": [],
                    "can_admins_bypass": True,
                    "deployment_branch_policy": None,
                }
            }
        )
        result = VERIFY.check_github_environment(reader, "o/r", "release")
        self.assertEqual(
            result,
            {
                "check": "github-environment",
                "environment": "release",
                "exists": True,
                "has_required_reviewers": False,
                "required_reviewer_identities": [],
                "can_admins_bypass": True,
                "deployment_branch_policy": None,
            },
        )

    def test_protected_environment_reports_reviewers_and_branch_policy(self) -> None:
        reader = FakeReader(
            {
                "repos/o/r/environments/release": {
                    "protection_rules": [
                        {
                            "type": "required_reviewers",
                            "reviewers": [
                                {"reviewer": {"login": "octocat"}},
                                {"reviewer": {"slug": "release-approvers"}},
                            ],
                        }
                    ],
                    "can_admins_bypass": False,
                    "deployment_branch_policy": {"protected_branches": True},
                }
            }
        )
        result = VERIFY.check_github_environment(reader, "o/r", "release")
        self.assertTrue(result["has_required_reviewers"])
        self.assertEqual(result["required_reviewer_identities"], ["octocat", "release-approvers"])
        self.assertFalse(result["can_admins_bypass"])
        self.assertEqual(result["deployment_branch_policy"], {"protected_branches": True})

    def test_missing_environment(self) -> None:
        reader = FakeReader({"repos/o/r/environments/release": None})
        result = VERIFY.check_github_environment(reader, "o/r", "release")
        self.assertEqual(result, {"check": "github-environment", "environment": "release", "exists": False})


class GitHubBranchTests(unittest.TestCase):
    def test_unprotected_branch(self) -> None:
        reader = FakeReader({"repos/o/r/branches/main/protection": None})
        result = VERIFY.check_github_branch(reader, "o/r", "main")
        self.assertEqual(result, {"check": "github-branch", "branch": "main", "protected": False})

    def test_protected_branch_reports_checks(self) -> None:
        reader = FakeReader(
            {
                "repos/o/r/branches/main/protection": {
                    "required_pull_request_reviews": {"required_approving_review_count": 1},
                    "required_status_checks": {"contexts": ["ci / rust-native", "ci / rust-wasm"]},
                }
            }
        )
        result = VERIFY.check_github_branch(reader, "o/r", "main")
        self.assertTrue(result["protected"])
        self.assertTrue(result["requires_pull_request_reviews"])
        self.assertEqual(result["required_status_checks"], ["ci / rust-native", "ci / rust-wasm"])


class NpmTests(unittest.TestCase):
    def test_missing_package(self) -> None:
        reader = FakeReader({"https://registry.npmjs.org/@redact-secret/core": None})
        result = VERIFY.check_npm_package(reader, "@redact-secret/core")
        self.assertEqual(result, {"check": "npm", "package": "@redact-secret/core", "exists": False})

    def test_existing_package_reports_maintainers(self) -> None:
        reader = FakeReader(
            {
                "https://registry.npmjs.org/@redact-secret/core": {
                    "maintainers": [{"name": "release-bot"}, {"name": "octocat"}]
                }
            }
        )
        result = VERIFY.check_npm_package(reader, "@redact-secret/core")
        self.assertEqual(result["maintainer_identities"], ["octocat", "release-bot"])


class CrateTests(unittest.TestCase):
    def test_nonexistent_crate(self) -> None:
        reader = FakeReader({"https://crates.io/api/v1/crates/redact-secret": None})
        result = VERIFY.check_crate(reader, "redact-secret")
        self.assertEqual(result, {"check": "crate", "crate": "redact-secret", "exists": False})

    def test_existing_crate_reports_owners(self) -> None:
        reader = FakeReader(
            {
                "https://crates.io/api/v1/crates/redact-secret": {"crate": {"name": "redact-secret"}},
                "https://crates.io/api/v1/crates/redact-secret/owners": {
                    "users": [{"login": "octocat"}, {"login": "release-bot"}]
                },
            }
        )
        result = VERIFY.check_crate(reader, "redact-secret")
        self.assertEqual(result["owner_identities"], ["octocat", "release-bot"])


class PypiTests(unittest.TestCase):
    def test_reports_existence_and_defers_trusted_publisher_check(self) -> None:
        reader = FakeReader({"https://pypi.org/pypi/redact-secret/json": {"info": {}}})
        result = VERIFY.check_pypi_project(reader, "redact-secret")
        self.assertTrue(result["exists"])
        self.assertIn("Manage -> Publishing", result["trusted_publisher_configured"])

    def test_nonexistent_project(self) -> None:
        reader = FakeReader({"https://pypi.org/pypi/redact-secret/json": None})
        result = VERIFY.check_pypi_project(reader, "redact-secret")
        self.assertFalse(result["exists"])


class Pep503Tests(unittest.TestCase):
    def test_normalizes_hyphens_underscores_and_dots_to_one_hyphen(self) -> None:
        self.assertEqual(VERIFY.normalize_pep503("Redact_Secret"), "redact-secret")
        self.assertEqual(VERIFY.normalize_pep503("redact.secret"), "redact-secret")
        self.assertEqual(VERIFY.normalize_pep503("redact--secret"), "redact-secret")

    def test_aliases_that_agree_are_reported_as_one_project(self) -> None:
        reader = FakeReader(
            {
                "https://pypi.org/pypi/redact-secret/json": {"info": {"name": "redact-secret"}},
                "https://pypi.org/pypi/redact_secret/json": {"info": {"name": "redact-secret"}},
            }
        )
        result = VERIFY.check_pypi_normalized_aliases(reader, "redact-secret")
        self.assertEqual(result["aliases"], ["redact-secret", "redact_secret"])
        self.assertTrue(result["exists"])
        self.assertTrue(result["agree"])

    def test_no_public_project_under_any_alias_is_not_a_reservation(self) -> None:
        reader = FakeReader(
            {
                "https://pypi.org/pypi/redact-secret/json": None,
                "https://pypi.org/pypi/redact_secret/json": None,
            }
        )
        result = VERIFY.check_pypi_normalized_aliases(reader, "redact-secret")
        self.assertFalse(result["exists"])
        self.assertTrue(result["agree"])

    def test_aliases_that_disagree_are_flagged(self) -> None:
        reader = FakeReader(
            {
                "https://pypi.org/pypi/redact-secret/json": {"info": {"name": "redact-secret"}},
                "https://pypi.org/pypi/redact_secret/json": {"info": {"name": "some-other-project"}},
            }
        )
        result = VERIFY.check_pypi_normalized_aliases(reader, "redact-secret")
        self.assertFalse(result["agree"])


class GitHubRepoTests(unittest.TestCase):
    def test_nonexistent_repo_is_not_a_reservation(self) -> None:
        reader = FakeReader({"repos/redact-secret/redact-secret": None})
        result = VERIFY.check_github_repo(reader, "redact-secret/redact-secret")
        self.assertEqual(result, {"check": "github-repo", "repo": "redact-secret/redact-secret", "exists": False})

    def test_existing_repo_reports_visibility(self) -> None:
        reader = FakeReader({"repos/redact-secret/redact-secret": {"private": False}})
        result = VERIFY.check_github_repo(reader, "redact-secret/redact-secret")
        self.assertTrue(result["exists"])
        self.assertFalse(result["private"])


class BuildEvidenceTests(unittest.TestCase):
    def test_unavailable_check_is_recorded_not_raised(self) -> None:
        gh_reader = FakeReader({}, unavailable={"repos/o/r/environments/release", "repos/o/r/branches/main/protection"})
        http_reader = FakeReader({})

        evidence = VERIFY.build_evidence(
            gh_read=gh_reader,
            http_read=http_reader,
            repo="o/r",
            environment="release",
            branch="main",
            npm_packages=[],
            crates=[],
            pypi_project=None,
        )
        self.assertEqual(evidence["repo"], "o/r")
        self.assertEqual(len(evidence["results"]), 2)
        for result in evidence["results"]:
            self.assertFalse(result["verified"])
            self.assertIn("reason", result)

    def test_evidence_contains_no_secret_shaped_keys(self) -> None:
        gh_reader = FakeReader(
            {
                "repos/o/r/environments/release": {"protection_rules": [], "can_admins_bypass": True},
                "repos/o/r/branches/main/protection": None,
            }
        )
        http_reader = FakeReader(
            {
                "https://registry.npmjs.org/@redact-secret/core": {"maintainers": []},
                "https://crates.io/api/v1/crates/redact-secret": None,
                "https://pypi.org/pypi/redact-secret/json": None,
                "https://pypi.org/pypi/redact_secret/json": None,
            }
        )
        evidence = VERIFY.build_evidence(
            gh_read=gh_reader,
            http_read=http_reader,
            repo="o/r",
            environment="release",
            branch="main",
            npm_packages=["@redact-secret/core"],
            crates=["redact-secret"],
            pypi_project="redact-secret",
        )
        blob = str(evidence).lower()
        for forbidden in ("token", "secret_value", "password", "npm_token", "cargo_registry_token"):
            self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main()
