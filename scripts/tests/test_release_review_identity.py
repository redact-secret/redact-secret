from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import release_review_identity as identity  # noqa: E402

ROOT = SCRIPTS.parent
VERSION = "0.1.0-beta.14"
REVIEWED = "a" * 40
SOURCE = "b" * 40


def ancestor(*_: object) -> str:
    return "ancestor"


def review_text(**overrides: str | None) -> str:
    fields: dict[str, str | None] = {
        "owner": "#1263",
        "reviewed_source": REVIEWED,
        "status": "retained",
        "retire_on": f"after-release:{VERSION}",
        "candidate_version": VERSION,
        "review_scope": identity.REQUIRED_SCOPE,
        "disposition": "accepted",
    }
    fields.update(overrides)
    body = "".join(f"{key}: {value}\n" for key, value in fields.items() if value is not None)
    return f"---\n{body}---\n\n# Review\n"


class Tree:
    """A throwaway repository root holding review units."""

    def __init__(self, case: unittest.TestCase) -> None:
        directory = tempfile.TemporaryDirectory()
        case.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "docs/audits").mkdir(parents=True)

    def review(self, name: str, text: str) -> Path:
        path = self.root / "docs/audits" / name
        path.write_text(text, encoding="utf-8")
        return path

    def select(self, version: str = VERSION, **kwargs: object) -> dict:
        kwargs.setdefault("relation", ancestor)
        return identity.select_candidate_review(version, SOURCE, root=self.root, **kwargs)  # type: ignore[arg-type]


class FrontMatterTests(unittest.TestCase):
    def test_a_document_without_a_block_has_no_fields(self) -> None:
        self.assertEqual(identity.parse_front_matter("# Old review\n"), (None, []))

    def test_fields_comments_and_quotes_follow_the_decision_parser(self) -> None:
        fields, errors = identity.parse_front_matter('---\n# note\nowner: #1263\nname: "quoted"\n---\nbody\n')
        self.assertEqual(errors, [])
        self.assertEqual(fields, {"owner": "#1263", "name": "quoted"})

    def test_duplicate_and_unsupported_lines_are_reported(self) -> None:
        _, errors = identity.parse_front_matter("---\na: 1\na: 2\nNot A Field\n---\n")
        self.assertEqual(len(errors), 2)

    def test_an_unclosed_block_is_reported(self) -> None:
        _, errors = identity.parse_front_matter("---\na: 1\n")
        self.assertEqual(errors, ["front matter has no closing ---"])


class SelectCandidateReviewTests(unittest.TestCase):
    def test_the_review_bound_to_the_version_is_selected_and_hashed(self) -> None:
        tree = Tree(self)
        path = tree.review("beta14-review.md", review_text())
        selected = tree.select()
        self.assertEqual(selected["status"], identity.STATUS_BOUND)
        self.assertEqual(selected["path"], "docs/audits/beta14-review.md")
        self.assertEqual(selected["sha256"], identity.sha256_bytes(path.read_bytes()))
        self.assertEqual(selected["reviewedSource"], REVIEWED)
        self.assertEqual(selected["scope"], identity.REQUIRED_SCOPE)
        self.assertEqual(selected["disposition"], "accepted")
        self.assertIs(selected["reviewAuthorizesRelease"], False)

    def test_the_file_name_never_selects_a_review_only_the_bound_version_does(self) -> None:
        tree = Tree(self)
        tree.review("beta12-review.md", review_text(candidate_version="0.1.0-beta.12", retire_on="after-release:0.1.0-beta.12"))
        tree.review("anything-else.md", review_text())
        self.assertEqual(tree.select()["path"], "docs/audits/anything-else.md")

    def test_no_review_at_all_fails_and_names_what_was_expected(self) -> None:
        with self.assertRaisesRegex(identity.ReviewIdentityError, "no candidate public-contract review for 0.1.0-beta.14"):
            Tree(self).select()

    def test_a_historical_review_alone_cannot_satisfy_the_current_candidate(self) -> None:
        tree = Tree(self)
        tree.review(
            "beta12.md",
            review_text(candidate_version="0.1.0-beta.12", retire_on="after-release:0.1.0-beta.12"),
        )
        # A pre-lifecycle review has no block, so it carries no binding either.
        tree.review("candidate-public-contract-review.md", "# Beta.1 review\n\nNo front matter.\n")
        with self.assertRaises(identity.ReviewIdentityError) as raised:
            tree.select()
        message = str(raised.exception)
        self.assertIn("0.1.0-beta.12", message)
        self.assertIn("history, not this candidate's review", message)

    def test_two_reviews_bound_to_one_version_are_ambiguous(self) -> None:
        tree = Tree(self)
        tree.review("one.md", review_text())
        tree.review("two.md", review_text())
        with self.assertRaisesRegex(identity.ReviewIdentityError, "more than one review"):
            tree.select()

    def test_each_lifecycle_and_binding_mismatch_is_reported_with_the_file(self) -> None:
        cases = {
            "status: 'final'": ({"status": "final"}, "must be 'retained'"),
            "retire_on for another version": ({"retire_on": "after-release:0.1.0-beta.13"}, "retire_on must be"),
            "short reviewed_source": ({"reviewed_source": "abc123"}, "40-hex"),
            "wrong scope": ({"review_scope": "changelog"}, "requires 'public-api-and-compatibility'"),
            "rejected disposition": ({"disposition": "rejected"}, "does not accept the candidate"),
            "limitations missing": ({"disposition": "accepted-with-limitations"}, "requires a limitations field"),
            "owner missing": ({"owner": None}, "missing front matter field owner"),
            "disposition missing": ({"disposition": None}, "missing front matter field disposition"),
        }
        for label, (overrides, expected) in cases.items():
            with self.subTest(label):
                tree = Tree(self)
                tree.review("review.md", review_text(**overrides))
                with self.assertRaisesRegex(identity.ReviewIdentityError, expected) as raised:
                    tree.select()
                self.assertIn("docs/audits/review.md", str(raised.exception))

    def test_limitations_are_recorded_when_accepted_with_limitations(self) -> None:
        tree = Tree(self)
        tree.review("review.md", review_text(disposition="accepted-with-limitations", limitations="array length"))
        selected = tree.select()
        self.assertEqual(selected["disposition"], "accepted-with-limitations")
        self.assertEqual(selected["limitations"], "array length")

    def test_the_reviewed_source_must_be_an_ancestor_of_the_qualified_source(self) -> None:
        tree = Tree(self)
        tree.review("review.md", review_text())
        with self.assertRaisesRegex(identity.ReviewIdentityError, "is not an ancestor"):
            tree.select(relation=lambda *_: "not-ancestor")
        with self.assertRaisesRegex(identity.ReviewIdentityError, "cannot resolve reviewed_source"):
            tree.select(relation=lambda *_: "unresolvable")

    def test_a_cited_historical_record_needs_a_permalink_and_a_matching_digest(self) -> None:
        link = f"https://github.com/redact-secret/redact-secret/blob/{'c' * 40}/docs/audits/old.md"
        tree = Tree(self)
        tree.review("review.md", review_text(previous_review_record=link, previous_review_sha256="d" * 64))
        history = tree.select()["history"][0]
        self.assertEqual(history["role"], "history")
        self.assertEqual(history["record"], link)
        self.assertIs(history["verifiedLocally"], False)  # the commit is not in this temp root
        for label, overrides, expected in (
            ("branch link", {"previous_review_record": link.replace("c" * 40, "main"), "previous_review_sha256": "d" * 64}, "40-hex permalink"),
            ("bad digest", {"previous_review_record": link, "previous_review_sha256": "xyz"}, "64-hex"),
            ("record alone", {"previous_review_record": link}, "must be given together"),
        ):
            with self.subTest(label):
                other = Tree(self)
                other.review("review.md", review_text(**overrides))
                with self.assertRaisesRegex(identity.ReviewIdentityError, expected):
                    other.select()

    def test_a_cited_record_is_checked_against_the_git_blob_when_it_is_local(self) -> None:
        tree = Tree(self)
        run = lambda *args: subprocess.run(["git", *args], cwd=tree.root, check=True, capture_output=True, text=True)  # noqa: E731
        run("init", "-q")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        old = tree.root / "docs/audits/old.md"
        old.write_text("old review\n")
        run("add", ".")
        run("commit", "-q", "-m", "old")
        commit = run("rev-parse", "HEAD").stdout.strip()
        link = f"https://github.com/redact-secret/redact-secret/blob/{commit}/docs/audits/old.md"
        good = identity.sha256_bytes(b"old review\n")
        tree.review("review.md", review_text(previous_review_record=link, previous_review_sha256=good))
        self.assertIs(tree.select()["history"][0]["verifiedLocally"], True)
        tree.review("review.md", review_text(previous_review_record=link, previous_review_sha256="0" * 64))
        with self.assertRaisesRegex(identity.ReviewIdentityError, "is not previous_review_sha256"):
            tree.select()

    def test_a_published_release_record_discharges_a_retired_review(self) -> None:
        tree = Tree(self)
        record = tree.root / "docs/releases" / VERSION
        record.mkdir(parents=True)
        (record / "manifest.json").write_text("{}")
        selected = tree.select()
        self.assertEqual(selected["status"], identity.STATUS_RELEASE_RECORD)
        self.assertEqual(selected["releaseRecord"], f"docs/releases/{VERSION}/README.md")

    def test_another_versions_release_record_does_not_discharge_this_candidate(self) -> None:
        tree = Tree(self)
        record = tree.root / "docs/releases/0.1.0-beta.13"
        record.mkdir(parents=True)
        (record / "manifest.json").write_text("{}")
        with self.assertRaises(identity.ReviewIdentityError):
            tree.select()

    def test_a_rehearsal_waives_a_missing_review_but_never_a_bad_one(self) -> None:
        self.assertEqual(Tree(self).select(rehearsal=True)["status"], identity.STATUS_REHEARSAL)
        tree = Tree(self)
        tree.review("review.md", review_text(status="final"))
        with self.assertRaises(identity.ReviewIdentityError):
            tree.select(rehearsal=True)


class GitRelationTests(unittest.TestCase):
    def test_ancestor_not_ancestor_and_unresolvable(self) -> None:
        tree = Tree(self)

        def run(*args: str) -> str:
            return subprocess.run(["git", *args], cwd=tree.root, check=True, capture_output=True, text=True).stdout.strip()

        run("init", "-q")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        commits = []
        for name in ("one", "two"):
            (tree.root / f"{name}.txt").write_text(name)
            run("add", ".")
            run("commit", "-q", "-m", name)
            commits.append(run("rev-parse", "HEAD"))
        first, second = commits
        self.assertEqual(identity.git_relation(tree.root, first, second), "ancestor")
        self.assertEqual(identity.git_relation(tree.root, second, second), "ancestor")
        self.assertEqual(identity.git_relation(tree.root, second, first), "not-ancestor")
        self.assertEqual(identity.git_relation(tree.root, "f" * 40, second), "unresolvable")


LEGACY = {
    "sourceCommit": "9" * 40,
    "releaseReadiness": {
        "issue": 1112,
        "publicApiAndChangelogReview": {
            "status": "required-before-release-approval",
            "currentPublicApiReview": {"path": "docs/audits/beta12-candidate-public-contract-review.md", "sha256": "1" * 64},
            "publicApiReview": {
                "path": "docs/audits/candidate-public-contract-review.md",
                "sha256": "2" * 64,
                "scope": "historical-beta.1-candidate-review",
            },
            "changelog": {"path": "CHANGELOG.md", "sha256": "3" * 64},
        },
    },
}


class RecordedIdentityTests(unittest.TestCase):
    def test_a_legacy_inventory_reports_its_recorded_digest_and_permalink_without_any_file(self) -> None:
        # Nothing is read from disk: the review bodies may already be retired.
        view = identity.read_recorded_identity(LEGACY)
        assert view is not None
        self.assertEqual(view["schema"], "legacy")
        current, historical = view["reviews"]
        self.assertEqual((current["role"], current["sha256"]), ("current", "1" * 64))
        self.assertEqual(
            current["permalink"],
            f"https://github.com/redact-secret/redact-secret/blob/{'9' * 40}/docs/audits/beta12-candidate-public-contract-review.md",
        )
        self.assertEqual((historical["role"], historical["scope"]), ("historical", "historical-beta.1-candidate-review"))

    def test_an_inventory_with_no_readiness_is_not_an_error(self) -> None:
        self.assertIsNone(identity.read_recorded_identity({"sourceCommit": "9" * 40}))

    def test_malformed_legacy_entries_are_rejected(self) -> None:
        for mutate in (
            lambda r: r["currentPublicApiReview"].update(sha256="short"),
            lambda r: r["currentPublicApiReview"].update(path="elsewhere/x.md"),
            lambda r: (r.pop("currentPublicApiReview"), r.pop("publicApiReview")),
        ):
            inventory = json.loads(json.dumps(LEGACY))
            mutate(inventory["releaseReadiness"]["publicApiAndChangelogReview"])
            with self.subTest(mutate), self.assertRaises(identity.ReviewIdentityError):
                identity.read_recorded_identity(inventory)

    def test_schema_two_round_trips_through_the_reader(self) -> None:
        tree = Tree(self)
        tree.review("review.md", review_text())
        candidate = tree.select()
        inventory = {
            "sourceCommit": SOURCE,
            "releaseReadiness": {
                "schemaVersion": identity.SCHEMA_VERSION,
                "publicApiAndChangelogReview": {"candidateReview": candidate},
            },
        }
        view = identity.read_recorded_identity(inventory)
        assert view is not None
        self.assertEqual(view["schema"], identity.SCHEMA_VERSION)
        self.assertEqual(view["reviews"][0]["role"], "candidate")
        self.assertEqual(view["reviews"][0]["sha256"], candidate["sha256"])
        self.assertIn(f"/blob/{SOURCE}/docs/audits/review.md", view["reviews"][0]["permalink"])

    def test_schema_two_rejects_unknown_versions_and_an_authorizing_review(self) -> None:
        tree = Tree(self)
        tree.review("review.md", review_text())
        candidate = tree.select()
        base = {"sourceCommit": SOURCE, "releaseReadiness": {"schemaVersion": 2, "publicApiAndChangelogReview": {}}}
        future = json.loads(json.dumps(base))
        future["releaseReadiness"]["schemaVersion"] = 3
        authorizing = json.loads(json.dumps(base))
        authorizing["releaseReadiness"]["publicApiAndChangelogReview"]["candidateReview"] = dict(
            candidate, reviewAuthorizesRelease=True
        )
        for inventory in (base, future, authorizing):
            with self.subTest(inventory["releaseReadiness"]), self.assertRaises(identity.ReviewIdentityError):
                identity.read_recorded_identity(inventory)

    def test_every_frozen_release_inventory_is_still_interpreted(self) -> None:
        inventories = sorted((ROOT / "docs/releases").glob("*/artifact-inventory.json"))
        self.assertGreaterEqual(len(inventories), 12)
        reviews = 0
        for path in inventories:
            inventory = json.loads(path.read_text())
            view = identity.read_recorded_identity(inventory)
            if view is None:
                continue
            self.assertEqual(view["schema"], "legacy", path)
            for review in view["reviews"]:
                reviews += 1
                self.assertRegex(review["sha256"], r"^[0-9a-f]{64}$", path)
        self.assertGreaterEqual(reviews, 24)

    def test_recorded_digests_match_the_blob_at_each_inventorys_source_commit(self) -> None:
        # Judged against git objects, not the working tree, so it holds after
        # the review bodies leave the tree. A clone that lacks a source commit
        # (a shallow CI checkout) reports `unavailable`; a disagreement fails.
        states: list[str] = []
        for path in sorted((ROOT / "docs/releases").glob("*/artifact-inventory.json")):
            inventory = json.loads(path.read_text())
            view = identity.read_recorded_identity(inventory)
            if view is not None:
                states.extend(identity.verify_recorded_blob(view, inventory["sourceCommit"], ROOT))
        self.assertNotIn("mismatch", states)


if __name__ == "__main__":
    unittest.main()
