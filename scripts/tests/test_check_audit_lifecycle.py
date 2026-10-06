from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
REPO = SCRIPTS.parent
SCRIPT = SCRIPTS / "check-audit-lifecycle.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECK = _load("check_audit_lifecycle", SCRIPT)
GATE = _load("check_release_gate_for_lifecycle", SCRIPTS / "check-release-gate.py")

SHA = "a" * 40
REPO_URL = "https://github.com/redact-secret/redact-secret"
GIT = shutil.which("git")


def block(**overrides: str | None) -> str:
    fields = {"owner": "#1266", "reviewed_source": SHA, "status": "in-progress", "retire_on": "before-qualification"}
    fields.update(overrides)
    body = "".join(f"{key}: {value}\n" for key, value in fields.items() if value is not None)
    return f"---\n{body}---\n\n# A review\n"


class Tree:
    """A temporary repository-shaped tree."""

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.write("packages/javascript/package.json", '{"version": "0.1.0-beta.14"}\n')

    def write(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def doc(self, name: str, text: str) -> str:
        self.write(f"docs/audits/{name}.md", text)
        return f"docs/audits/{name}.md"

    def evidence(self, unit: str, text: str) -> str:
        self.write(f"docs/audits/evidence/{unit}/README.md", text)
        return f"docs/audits/evidence/{unit}"

    def released(self, version: str) -> None:
        self.write(f"docs/releases/{version}/manifest.json", "{}\n")

    def snapshot(self) -> dict[str, str]:
        return {
            str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(self.root.rglob("*"))
            if p.is_file()
        }

    def findings(self, **kwargs):
        kwargs.setdefault("verify_records", False)
        return CHECK.run(self.root, **kwargs)

    def errors(self, **kwargs) -> list:
        return [f for f in self.findings(**kwargs) if f.level == "error"]


class LifecycleCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree()
        self.addCleanup(self.tree.directory.cleanup)

    def categories(self, **kwargs) -> list[tuple[str, str]]:
        return sorted((f.category, f.path) for f in self.tree.errors(**kwargs))


class DevelopmentModeTest(LifecycleCase):
    def test_valid_temporary_reviews_are_accepted(self) -> None:
        self.tree.doc("review", block())
        self.tree.evidence("1266", block(owner="milo-kang"))
        self.tree.doc("deferred", block(status="deferred", retire_on="after-issue:#900"))
        self.assertEqual(self.tree.errors(), [])

    def test_trailing_comment_in_the_adr_example_form_is_accepted(self) -> None:
        self.tree.doc("review", block(owner="#1260                # issue number, or GitHub login"))
        self.assertEqual(self.tree.errors(), [])

    def test_a_new_unclassified_audit_fails(self) -> None:
        self.tree.doc("new-review", "# No block\n")
        self.tree.evidence("2000", "# No block\n")
        self.tree.write("docs/audits/evidence/2001/data.json", "{}\n")  # unit with no entry file at all
        self.assertEqual(
            self.categories(),
            [
                ("unclassified", "docs/audits/evidence/2000"),
                ("unclassified", "docs/audits/evidence/2001"),
                ("unclassified", "docs/audits/new-review.md"),
            ],
        )

    def test_an_unclosed_or_malformed_block_fails(self) -> None:
        self.tree.doc("open", "---\nowner: #1\n# no closer\n")
        self.tree.doc("syntax", "---\nowner #1\n---\n")
        self.assertEqual({path for _, path in self.categories()}, {"docs/audits/open.md", "docs/audits/syntax.md"})

    def test_invalid_fields_fail(self) -> None:
        cases = {
            "owner": block(owner="not a login!"),
            "sha": block(reviewed_source="abc123"),
            "status": block(status="done"),
            "trigger": block(retire_on="next-week"),
            "missing": "---\nowner: #1\n---\n",
            "final-trigger": block(
                status="final", retire_on="after-issue:#1", record=f"{REPO_URL}/blob/{SHA}/docs/audits/final-trigger.md"
            ),
            "deferred-trigger": block(status="deferred"),
            "retained-trigger": block(status="retained", retire_on="after-issue:#1"),
        }
        for name, text in cases.items():
            self.tree.doc(name, text)
        self.assertEqual(
            {path for category, path in self.categories() if category == "invalid"},
            {f"docs/audits/{name}.md" for name in cases},
        )

    def test_a_final_unit_needs_a_commit_pinned_record_naming_itself(self) -> None:
        good = f"{REPO_URL}/blob/{SHA}/docs/audits/good.md"
        self.tree.doc("good", block(status="final", record=good))
        self.tree.doc("absent", block(status="final"))
        self.tree.doc("moving", block(status="final", record=f"{REPO_URL}/blob/main/docs/audits/moving.md"))
        self.tree.doc("branch", block(status="final", record=f"{REPO_URL}/blob/workbench/x/docs/audits/branch.md"))
        self.tree.doc("short", block(status="final", record=f"{REPO_URL}/blob/abc1234/docs/audits/short.md"))
        self.tree.doc("other", block(status="final", record=f"{REPO_URL}/blob/{SHA}/docs/audits/elsewhere.md"))
        got = {path for category, path in self.categories() if category == "record"}
        self.assertEqual(
            got,
            {f"docs/audits/{n}.md" for n in ("absent", "moving", "branch", "short", "other")},
        )

    def test_a_published_release_makes_an_after_release_exception_stale(self) -> None:
        self.tree.doc("review", block(status="retained", retire_on="after-release:0.1.0-beta.13"))
        self.assertEqual(self.categories(), [])
        self.tree.released("0.1.0-beta.13")
        self.assertEqual(self.categories(), [("stale", "docs/audits/review.md")])

    def test_after_issue_staleness_comes_from_the_snapshot_only(self) -> None:
        self.tree.doc("waiting", block(status="deferred", retire_on="after-issue:#777"))
        self.assertEqual(self.categories(closed=None), [])
        self.assertEqual(self.categories(closed={1, 2}), [])
        self.assertEqual(self.categories(closed={777}), [("stale", "docs/audits/waiting.md")])

    def test_closed_issue_snapshot_formats(self) -> None:
        path = self.tree.write("closed.txt", "12\n#777\n")
        self.assertEqual(CHECK.load_closed_issues(path), {12, 777})
        path = self.tree.write("closed.json", "[12, 777]\n")
        self.assertEqual(CHECK.load_closed_issues(path), {12, 777})

    def test_at_most_one_retained_unit(self) -> None:
        for name in ("one", "two"):
            self.tree.doc(name, block(status="retained", retire_on="after-release:0.1.0-beta.14"))
        self.assertEqual([category for category, _ in self.categories()], ["retained", "retained"])

    def test_a_stray_file_under_the_audit_tree_fails(self) -> None:
        self.tree.write("docs/audits/generated.json", "{}\n")
        self.tree.write("docs/audits/evidence/loose.txt", "x\n")
        self.assertEqual(
            self.categories(),
            [("stray", "docs/audits/evidence/loose.txt"), ("stray", "docs/audits/generated.json")],
        )

    def test_readme_is_not_a_unit(self) -> None:
        self.tree.write("docs/audits/README.md", "# Index\n")
        self.assertEqual(self.tree.errors(), [])

    def test_valid_live_contracts_and_release_records_are_not_units(self) -> None:
        self.tree.write("docs/contracts/precision/x.json", "{}\n")
        self.tree.write("docs/releases/0.1.0-beta.13/manifest.json", "{}\n")
        self.tree.write("docs/specs/engine.md", "# Engine\n")
        self.assertEqual(self.tree.findings(), [])
        self.assertEqual(self.tree.findings(release=True), [])


class MigrationListTest(LifecycleCase):
    def setUp(self) -> None:
        super().setUp()
        self.tree.doc("old", "# historical\n")
        self.tree.evidence("9", "# historical\n")
        self.tree.write(CHECK.LEGACY_FILE, "# comment\ndocs/audits/old.md\ndocs/audits/evidence/9\n")

    def test_listed_historical_bodies_are_warnings_in_development(self) -> None:
        findings = self.tree.findings()
        self.assertEqual([f for f in findings if f.level == "error"], [])
        self.assertEqual(
            sorted(f.path for f in findings if f.level == "warning" and f.category == "historical"),
            ["docs/audits/evidence/9", "docs/audits/old.md"],
        )

    def test_they_are_errors_in_release_mode_and_so_is_the_list(self) -> None:
        errors = self.tree.errors(release=True)
        self.assertEqual(
            sorted((f.category, f.path) for f in errors),
            [
                ("historical", "docs/audits/evidence/9"),
                ("historical", "docs/audits/old.md"),
                ("legacy-file", CHECK.LEGACY_FILE),
            ],
        )

    def test_an_unlisted_unclassified_unit_is_not_grandfathered(self) -> None:
        self.tree.doc("brand-new", "# no block\n")
        self.assertEqual(self.categories(), [("unclassified", "docs/audits/brand-new.md")])

    def test_a_listed_unit_that_gained_a_block_is_judged_by_its_block(self) -> None:
        self.tree.doc("old", block(status="deferred", retire_on="after-issue:#5"))
        self.assertEqual([f.category for f in self.tree.findings() if f.path == "docs/audits/old.md"], [])

    def test_a_listed_unit_that_is_gone_is_a_warning(self) -> None:
        self.tree.write(CHECK.LEGACY_FILE, "docs/audits/old.md\ndocs/audits/evidence/9\ndocs/audits/gone.md\n")
        findings = self.tree.findings()
        self.assertIn(("legacy-stale", "docs/audits/gone.md"), {(f.category, f.path) for f in findings})
        self.assertEqual([f for f in findings if f.level == "error"], [])

    def test_a_malformed_list_entry_is_an_error(self) -> None:
        self.tree.write(CHECK.LEGACY_FILE, "../outside.md\n")
        self.assertEqual([c for c, _ in self.categories()], ["invalid", "unclassified", "unclassified"])


class ReleaseModeTest(LifecycleCase):
    def test_deferred_and_the_candidate_review_pass(self) -> None:
        self.tree.doc("backlog", block(status="deferred", retire_on="after-issue:#900"))
        self.tree.doc("candidate", block(status="retained", retire_on="after-release:0.1.0-beta.14"))
        findings = self.tree.findings(release=True)
        self.assertEqual([f for f in findings if f.level == "error"], [])
        self.assertEqual([(f.level, f.path) for f in findings], [("notice", "docs/audits/backlog.md")])

    def test_closed_snapshot_silences_the_unverified_notice(self) -> None:
        self.tree.doc("backlog", block(status="deferred", retire_on="after-issue:#900"))
        self.assertEqual(self.tree.findings(release=True, closed={1}), [])

    def test_final_in_progress_and_before_qualification_units_are_rejected(self) -> None:
        self.tree.doc("done", block(status="final", record=f"{REPO_URL}/blob/{SHA}/docs/audits/done.md"))
        self.tree.doc("wip", block())
        self.tree.doc("odd", block(status="deferred", retire_on="after-issue:#4"))  # control: allowed
        self.tree.evidence("42", block())
        self.assertEqual(
            self.categories(release=True),
            [
                ("not-releasable", "docs/audits/done.md"),
                ("not-releasable", "docs/audits/evidence/42"),
                ("not-releasable", "docs/audits/wip.md"),
            ],
        )
        self.assertEqual(self.tree.errors(), [])  # the same tree is fine in development

    def test_an_unclassified_unit_is_rejected(self) -> None:
        self.tree.doc("new", "# no block\n")
        self.assertEqual(self.categories(release=True), [("unclassified", "docs/audits/new.md")])

    def test_retained_for_another_version_is_rejected(self) -> None:
        self.tree.doc("candidate", block(status="retained", retire_on="after-release:0.1.0-beta.15"))
        self.assertEqual(self.categories(release=True), [("expired", "docs/audits/candidate.md")])
        self.assertEqual(self.categories(release=True, version="0.1.0-beta.15"), [])
        self.assertEqual(self.categories(), [])

    def test_retained_for_a_published_version_is_rejected_in_both_modes(self) -> None:
        self.tree.doc("candidate", block(status="retained", retire_on="after-release:0.1.0-beta.14"))
        self.tree.released("0.1.0-beta.14")
        expected = [("stale", "docs/audits/candidate.md")]
        self.assertEqual(self.categories(release=True), expected)
        self.assertEqual(self.categories(), expected)

    def test_the_version_defaults_to_the_javascript_package(self) -> None:
        self.assertEqual(CHECK.candidate_version(self.tree.root), "0.1.0-beta.14")

    def test_a_large_tree_of_valid_deferred_units_is_not_judged_by_count(self) -> None:
        for number in range(150):
            self.tree.doc(f"unit-{number}", block(status="deferred", retire_on=f"after-issue:#{1000 + number}"))
        self.assertEqual(self.tree.errors(release=True), [])

    def test_messages_name_every_offending_path_and_the_remediation(self) -> None:
        self.tree.doc("a", block())
        self.tree.doc("b", "# none\n")
        text = CHECK.render(self.tree.findings(release=True), release=True)
        self.assertIn("docs/audits/a.md", text)
        self.assertIn("docs/audits/b.md", text)
        self.assertIn("Remediation", text)
        self.assertIn("[not-releasable]", text)
        self.assertIn("[unclassified]", text)


class CommandLineTest(LifecycleCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--root", str(self.tree.root), "--no-verify-records", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_exit_codes(self) -> None:
        self.tree.doc("wip", block())
        self.assertEqual(self.run_cli().returncode, 0)
        self.assertEqual(self.run_cli("--release").returncode, 1)
        self.assertEqual(self.run_cli("--root", str(self.tree.root / "missing")).returncode, 2)
        self.assertEqual(self.run_cli("--closed-issues", str(self.tree.root / "nope.txt")).returncode, 2)

    def test_closed_issue_snapshot_is_honoured(self) -> None:
        self.tree.doc("waiting", block(status="deferred", retire_on="after-issue:#31"))
        snapshot = self.tree.write("closed.txt", "31\n")
        self.assertEqual(self.run_cli("--release", "--closed-issues", str(snapshot)).returncode, 1)

    def test_running_the_check_never_changes_a_file(self) -> None:
        self.tree.doc("old", "# no block\n")
        self.tree.write(CHECK.LEGACY_FILE, "docs/audits/old.md\n")
        self.tree.doc("wip", block())
        self.tree.doc("final", block(status="final", record=f"{REPO_URL}/blob/{SHA}/docs/audits/final.md"))
        before = self.tree.snapshot()
        for args in ((), ("--release",)):
            self.run_cli(*args)
            CHECK.run(self.tree.root, release=bool(args))
        self.assertEqual(self.tree.snapshot(), before)

    def test_the_source_has_no_write_network_or_publication_operations(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        forbidden_attributes = {
            "write_text",
            "write_bytes",
            "unlink",
            "rmdir",
            "rename",
            "replace",
            "mkdir",
            "touch",
            "remove",
            "rmtree",
            "copy",
            "copyfile",
            "move",
            "chmod",
            "symlink_to",
            "run",
            "Popen",
            "check_call",
            "check_output",
            "system",
            "urlopen",
            "connect",
            "request",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, forbidden_attributes, f"line {node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                self.fail(f"line {node.lineno}: open() is not used by this read-only check")
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                )
                for name in names:
                    self.assertNotIn(name.split(".")[0], {"socket", "urllib", "http", "requests", "shutil", "os"})


@unittest.skipUnless(GIT, "git is required")
class RecordVerificationTest(unittest.TestCase):
    def git(self, *args: str) -> str:
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        out = subprocess.run(
            [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
            cwd=self.tree.root,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        return out.stdout.strip()

    def setUp(self) -> None:
        self.tree = Tree()
        self.addCleanup(self.tree.directory.cleanup)
        self.git("init", "-q", "-b", "main")

    PATH = "docs/audits/done.md"

    def commit(self, text: str, message: str = "unit") -> str:
        self.tree.write(self.PATH, text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def record_errors(self) -> list:
        return [f for f in CHECK.run(self.tree.root) if f.level == "error" and f.category == "record"]

    def final(self, pin: str, body: str = "# A review\n") -> str:
        head = block(status="final", record=f"{REPO_URL}/blob/{pin}/{self.PATH}").split("---\n\n")[0]
        return head + "---\n\n" + body

    def test_a_record_naming_a_missing_commit_fails_in_a_full_clone(self) -> None:
        self.commit(self.final(SHA))
        self.assertEqual(len(self.record_errors()), 1)
        self.assertIn("not in the local history", self.record_errors()[0].message)

    def test_a_record_naming_the_preceding_commit_with_the_same_body_verifies(self) -> None:
        pin = self.commit(block())  # in-progress, written first
        self.commit(self.final(pin), "mark final")  # only the block changed
        self.assertEqual(self.record_errors(), [])

    def test_a_record_whose_pinned_body_differs_fails(self) -> None:
        pin = self.commit(block())
        self.commit(self.final(pin, "# A review, edited after the pin\n"), "edited")
        errors = self.record_errors()
        self.assertEqual(len(errors), 1)
        self.assertIn("differs", errors[0].message)

    def test_a_record_off_main_fails(self) -> None:
        self.commit(block(), "base")
        self.git("checkout", "-q", "-b", "side")
        side = self.commit(block(owner="#2"), "side body")
        self.git("checkout", "-q", "main")
        self.commit(self.final(side), "final")
        errors = self.record_errors()
        self.assertEqual(len(errors), 1)
        self.assertIn("not an ancestor", errors[0].message)

    def test_the_other_files_of_an_evidence_unit_must_be_byte_identical(self) -> None:
        self.tree.write("docs/audits/evidence/7/README.md", block())
        self.tree.write("docs/audits/evidence/7/data.json", "{}\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "unit")
        pin = self.git("rev-parse", "HEAD")
        record = f"{REPO_URL}/blob/{pin}/docs/audits/evidence/7/README.md"
        self.tree.write("docs/audits/evidence/7/README.md", block(status="final", record=record))
        self.tree.write("docs/audits/evidence/7/data.json", '{"edited": true}\n')
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "final")
        errors = self.record_errors()
        self.assertEqual([f.message.split(":")[0] for f in errors], ["docs/audits/evidence/7/data.json"])

    def test_trees_without_history_warn_instead_of_failing_development(self) -> None:
        bare = Tree()
        self.addCleanup(bare.directory.cleanup)
        bare.write(self.PATH, block(status="final", record=f"{REPO_URL}/blob/{SHA}/{self.PATH}"))
        findings = CHECK.run(bare.root)
        self.assertEqual([f for f in findings if f.level == "error"], [])
        self.assertEqual([f.category for f in findings if f.level == "warning"], ["record"])


class WorkflowEntryPointTest(unittest.TestCase):
    def workflow(self, name: str) -> tuple[str, dict[str, str]]:
        text = (REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")
        return text, GATE.job_blocks(GATE.jobs_section(text))

    @staticmethod
    def ancestors(jobs: dict[str, str], job: str) -> set[str]:
        seen: set[str] = set()
        stack = list(GATE.extract_needs(jobs[job]))
        while stack:
            current = stack.pop()
            if current in seen or current not in jobs:
                continue
            seen.add(current)
            stack.extend(GATE.extract_needs(jobs[current]))
        return seen

    def test_artifact_qualification_gates_every_job_on_the_check(self) -> None:
        text, jobs = self.workflow("artifact-qualification.yml")
        self.assertIn("lifecycle", jobs)
        body = jobs["lifecycle"]
        self.assertIn("python3 -B scripts/check-audit-lifecycle.py --release", body)
        self.assertIn("test_check_audit_lifecycle.py", body)
        self.assertIn("github.event_name == 'workflow_dispatch'", body)
        self.assertIn("refs/heads/rc/", body)
        self.assertNotIn("continue-on-error", body)
        self.assertNotIn("|| true", body)
        self.assertNotRegex(body, r"(?m)^      - name: .*\n(?:        .*\n)*?        if:")
        for job in jobs:
            if job not in ("plan", "lifecycle"):
                self.assertIn("lifecycle", self.ancestors(jobs, job), f"{job} can run without the lifecycle check")

    def test_release_workflow_cannot_build_or_publish_without_the_check(self) -> None:
        text, jobs = self.workflow("release.yml")
        self.assertIn("python3 -B scripts/check-audit-lifecycle.py --release", jobs["lifecycle"])
        self.assertNotIn("continue-on-error", jobs["lifecycle"])
        self.assertEqual(GATE.extract_needs(jobs["lifecycle"]), [])
        for job in jobs:
            if job != "lifecycle":
                self.assertIn("lifecycle", self.ancestors(jobs, job), f"{job} can run without the lifecycle check")
        for job in ("ci", "artifact-qualification"):
            self.assertIn("lifecycle", GATE.extract_needs(jobs[job]))
        self.assertNotIn("inputs:", text.split("jobs:")[0].split("workflow_dispatch:")[1].split("permissions:")[0])

    def test_rehearsal_reaches_the_check_through_artifact_qualification(self) -> None:
        _, jobs = self.workflow("package-release-rehearsal.yml")
        self.assertEqual(
            GATE.extract_uses(jobs["artifact-qualification"]), "./.github/workflows/artifact-qualification.yml"
        )
        self.assertIn("artifact-qualification", GATE.extract_needs(jobs["rehearse"]))
        self.assertNotRegex(jobs["artifact-qualification"], r"(?m)^    if:")

    def test_reconcile_runs_the_source_revision_check_before_any_repair_step(self) -> None:
        text, jobs = self.workflow("reconcile-release.yml")
        steps = GATE.extract_step_blocks(jobs["reconcile"])
        names = [name for _, name, _ in steps]
        gate = names.index("Verify the source revision's audit lifecycle")
        self.assertEqual(names[gate - 1], "Evaluate reconcile guard")
        self.assertLess(gate, names.index("Verify original run and artifact inventory"))
        self.assertLess(gate, names.index("Reconcile npm dependency packages"))
        body = steps[gate][2]
        for needle in (
            '--release --root "$source_tree" --version "$VERSION"',
            "steps.guard.outputs.source_revision",
            "predates the audit lifecycle check",
            'git worktree add --detach "$source_tree" "$SOURCE_REVISION"',
        ):
            self.assertIn(needle, body)
        self.assertNotRegex(body, r"(?m)^        if:")
        self.assertNotIn("continue-on-error", body)
        triggers = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertNotRegex(triggers.lower(), r"skip|bypass|lifecycle|ignore")

    def run_reconcile_step(self, source: Path, revision: str, version: str) -> subprocess.CompletedProcess:
        _, jobs = self.workflow("reconcile-release.yml")
        steps = GATE.extract_step_blocks(jobs["reconcile"])
        body = next(b for _, n, b in steps if n == "Verify the source revision's audit lifecycle")
        script = body.split("run: |\n", 1)[1]
        script = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in script.splitlines())
        with tempfile.TemporaryDirectory() as runner_temp:
            env = {
                **os.environ,
                "RUNNER_TEMP": runner_temp,
                "VERSION": version,
                "SOURCE_REVISION": revision,
                "GIT_CONFIG_GLOBAL": os.devnull,
            }
            return subprocess.run(
                ["bash", "-c", script], cwd=source, env=env, capture_output=True, text=True, check=False
            )

    @unittest.skipUnless(GIT, "git is required")
    def test_reconcile_semantics_on_real_commits(self) -> None:
        tree = Tree()
        self.addCleanup(tree.directory.cleanup)
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}

        def git(*args: str) -> str:
            return subprocess.run(
                [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
                cwd=tree.root,
                capture_output=True,
                text=True,
                check=True,
                env=env,
            ).stdout.strip()

        def install_check() -> None:
            for name in ("check-audit-lifecycle.py", "check-historical-permalinks.py", "check-doc-links.py"):
                tree.write(f"scripts/{name}", (SCRIPTS / name).read_text(encoding="utf-8"))

        git("init", "-q", "-b", "main")
        # 1. A revision that predates the check and carries a historical body.
        tree.doc("old", "# historical, no block\n")
        git("add", "-A")
        git("commit", "-q", "-m", "pre-policy")
        before = git("rev-parse", "HEAD")
        # 2. A revision with the check but a historical body: the original run could not have passed.
        install_check()
        git("add", "-A")
        git("commit", "-q", "-m", "policy, dirty")
        dirty = git("rev-parse", "HEAD")
        # 3. A cleaned revision with the check and one declared deferred unit.
        (tree.root / "docs/audits/old.md").unlink()
        tree.doc("backlog", block(status="deferred", retire_on="after-issue:#900"))
        git("add", "-A")
        git("commit", "-q", "-m", "cleaned")
        clean = git("rev-parse", "HEAD")

        legacy = self.run_reconcile_step(tree.root, before, "0.1.0-beta.1")
        self.assertEqual(legacy.returncode, 0, legacy.stderr + legacy.stdout)
        self.assertIn("predates the audit lifecycle check", legacy.stdout)

        blocked = self.run_reconcile_step(tree.root, dirty, "0.1.0-beta.14")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("docs/audits/old.md", blocked.stdout)

        repaired = self.run_reconcile_step(tree.root, clean, "0.1.0-beta.14")
        self.assertEqual(repaired.returncode, 0, repaired.stderr + repaired.stdout)
        # The step leaves no worktree behind and changes nothing in the checkout.
        self.assertEqual(git("worktree", "list").count("\n"), 0)
        self.assertEqual(git("status", "--porcelain"), "")


class ScriptsDoNotTargetTheAuditTreeTest(unittest.TestCase):
    """Guard: no generator, default output path or usage example under `scripts/`
    writes into `docs/audits/` (#1262 fixed the measure scripts; this is general).
    """

    # Scripts that legitimately name the audit tree because they check or index it.
    CHECKS = {
        "scripts/check-audit-lifecycle.py",
        "scripts/check-audits-index.py",
        "scripts/check-doc-links.py",
        "scripts/check-docs-reachability.py",
        "scripts/check-historical-permalinks.py",
        "scripts/check-json-path-citations.py",
        "scripts/check-legacy-identifiers.py",
        "scripts/check-shape-inventory.py",
        "scripts/release_review_identity.py",
        "scripts/generate-coverage-declarations.py",
        "scripts/audit-precision-contracts.py",
    }
    PERMALINK = re.compile(r"https://github\.com/redact-secret/[A-Za-z0-9._-]+/(?:blob|tree)/[0-9a-f]{40}/\S*")
    SUFFIXES = {".py", ".mjs", ".js", ".ts", ".sh", ".yml", ".yaml"}

    def sources(self):
        for path in sorted(SCRIPTS.rglob("*")):
            relative = path.relative_to(REPO).as_posix()
            if (
                path.suffix in self.SUFFIXES
                and path.is_file()
                and "/tests/" not in relative
                and "__pycache__" not in relative
            ):
                yield relative, self.PERMALINK.sub("", path.read_text(encoding="utf-8"))

    def test_only_checks_name_the_audit_tree(self) -> None:
        offenders = [r for r, text in self.sources() if "docs/audits" in text and r not in self.CHECKS]
        self.assertEqual(
            offenders, [], "a script outside the allowlist names docs/audits; write generated output elsewhere"
        )

    def test_no_default_output_or_example_targets_the_audit_tree(self) -> None:
        pattern = re.compile(r"(?:--out(?:put)?(?:-dir|-file)?|--write|-o)[= ]+\S*docs/audits")
        for relative, text in self.sources():
            self.assertIsNone(pattern.search(text), f"{relative}: an example writes into docs/audits")
            if relative.endswith(".py"):
                for node in ast.walk(ast.parse(text)):
                    if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument":
                        for keyword in node.keywords:
                            if keyword.arg == "default":
                                self.assertNotIn(
                                    "docs/audits",
                                    ast.unparse(keyword.value),
                                    f"{relative}:{node.lineno}: default targets the audit tree",
                                )

    def test_no_script_writes_into_the_audit_tree(self) -> None:
        for relative, text in self.sources():
            if relative in self.CHECKS:
                continue
            self.assertNotRegex(text, r"audits[\"'/].{0,80}(write_text|writeFileSync|open\()", relative)


if __name__ == "__main__":
    unittest.main()
