#!/usr/bin/env python3
"""Read live GitHub and registry state and record safe evidence for issue
#143 ("Enforce release approval and verify registry publisher
prerequisites").

This script is a **read-only evidence tool**, not a settings tool. It never
writes a GitHub branch-protection or environment-protection rule, never
publishes a package, and never configures a registry's Trusted Publisher --
those are repository- or registry-administrator actions outside a pull
request's reach (see `AGENTS.md`'s release authority section and issue
#143's own Authority clause) and this script performs none of them. What it
does is read the same live state a human administrator would read by hand,
and print it as the safe evidence issue #143 asks a Task to record: setting
names, identities (team slugs, package/crate/project names, npm usernames --
none of these are secrets), timestamps, and API results. It never reads or
prints a token, secret value, or credential, and it never requests one.

Four checks, each independently runnable and each degrading to an explicit
"unable to verify" result instead of failing the whole run when the
credential or tool it needs is unavailable locally:

- `github-environment NAME` -- `GET /repos/{repo}/environments/{NAME}` via
  the `gh` CLI (reuses whatever `gh auth` session is already active).
- `github-branch NAME` -- `GET /repos/{repo}/branches/{NAME}/protection`,
  likewise via `gh`.
- `npm PACKAGE...` -- each package's public registry metadata
  (`registry.npmjs.org/{package}`), which includes its maintainer list
  without requiring authentication. This can show who already maintains a
  package; it cannot show whether a not-yet-authenticated CI identity has
  scope-level rights to publish a *new* package under `@redact-secret` -- an
  admin must confirm that with `npm access ls-collaborators` (or the npm
  website) as that identity.
- `crate NAME...` -- crates.io's public API: whether the name exists, and if
  so, its current owners (`crates.io/api/v1/crates/{name}/owners`, public,
  read-only).
- `pypi PROJECT` -- PyPI's public JSON API confirms whether the project name
  exists. PyPI's Trusted Publisher configuration is not exposed by any
  public API; this script says so and defers to an admin checking the
  project's "Manage -> Publishing" page. Given `--pypi`, this also rechecks
  every PEP 503 alias of that name (see below).
- `--check-repo` -- `GET /repos/{repo}` via `gh`: whether the GitHub
  repository itself exists, distinct from whether its `release` environment
  or `main` branch are protected (issue #153's registry-name preflight,
  which targets a *candidate* identity that may not be the operational
  repository yet).

PEP 503 normalizes a PyPI project name by lowercasing it and collapsing
every run of `-`, `_`, and `.` to a single `-`; `redact-secret`,
`redact_secret`, and `redact.secret` are therefore the same project
identity, not three candidate names. `--pypi` fetches every alias's own
JSON response and confirms they all report the same canonical `info.name`
(`check_pypi_normalized_aliases`), rather than assuming PyPI's own
normalization without checking it.

A 404 for a candidate name -- on npm, crates.io, PyPI, or a candidate
GitHub repository path -- means no public project exists under that name
today. It is **not** evidence of a *reservation*: this script does not
create, and does not recommend creating, a placeholder package or project
to hold a name for later. Rechecking these names immediately before a
release candidate's sign-off (rather than trusting an earlier, dated check)
is what issue #153's registry-name preflight is for.

Run with `all` and repeated `--npm`, `--crate`, and one `--pypi` to produce
one evidence record; run a single subcommand to check one thing.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

GitHubReader = Callable[[str], object]
HttpReader = Callable[[str], object]


class NotAvailable(Exception):
    """Raised when a check cannot be performed locally (no credential, no tool)."""


def gh_api(path: str) -> object:
    """Read a GitHub REST API path via the `gh` CLI. `None` on 404."""
    try:
        result = subprocess.run(
            ["gh", "api", path],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as error:
        raise NotAvailable("the `gh` CLI is not installed") from error
    except subprocess.TimeoutExpired as error:
        raise NotAvailable(f"gh api {path} timed out") from error
    except subprocess.CalledProcessError as error:
        stderr = (error.stderr or "").strip()
        if "HTTP 404" in stderr or "'404'" in stderr or "Not Found" in stderr:
            return None
        raise NotAvailable(f"gh api {path} failed: {stderr}") from error
    return json.loads(result.stdout) if result.stdout.strip() else None


def http_get_json(url: str) -> object:
    """Read a public JSON API. `None` on 404."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise NotAvailable(f"GET {url} failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise NotAvailable(f"GET {url} failed: {error.reason}") from error


def check_github_environment(read: GitHubReader, repo: str, environment: str) -> dict:
    data = read(f"repos/{repo}/environments/{environment}")
    if data is None:
        return {"check": "github-environment", "environment": environment, "exists": False}
    rules = data.get("protection_rules", []) if isinstance(data, dict) else []
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    reviewer_identities = sorted(
        reviewer.get("reviewer", {}).get("login") or reviewer.get("reviewer", {}).get("slug") or "unknown"
        for rule in reviewer_rules
        for reviewer in rule.get("reviewers", [])
    )
    branch_policy = data.get("deployment_branch_policy") if isinstance(data, dict) else None
    return {
        "check": "github-environment",
        "environment": environment,
        "exists": True,
        "has_required_reviewers": bool(reviewer_rules),
        "required_reviewer_identities": reviewer_identities,
        "can_admins_bypass": data.get("can_admins_bypass") if isinstance(data, dict) else None,
        "deployment_branch_policy": branch_policy,
    }


def check_github_branch(read: GitHubReader, repo: str, branch: str) -> dict:
    data = read(f"repos/{repo}/branches/{branch}/protection")
    if data is None:
        return {"check": "github-branch", "branch": branch, "protected": False}
    reviews = data.get("required_pull_request_reviews") if isinstance(data, dict) else None
    checks = (data.get("required_status_checks") or {}) if isinstance(data, dict) else {}
    return {
        "check": "github-branch",
        "branch": branch,
        "protected": True,
        "requires_pull_request_reviews": reviews is not None,
        "required_status_checks": sorted(checks.get("contexts", [])),
    }


def check_npm_package(read: HttpReader, package: str) -> dict:
    data = read(f"https://registry.npmjs.org/{package}")
    if data is None:
        return {"check": "npm", "package": package, "exists": False}
    maintainers = sorted(
        (maintainer.get("name") for maintainer in data.get("maintainers", []) if maintainer.get("name"))
    )
    return {"check": "npm", "package": package, "exists": True, "maintainer_identities": maintainers}


def check_crate(read: HttpReader, crate: str) -> dict:
    exists = read(f"https://crates.io/api/v1/crates/{crate}") is not None
    if not exists:
        return {"check": "crate", "crate": crate, "exists": False}
    owners_data = read(f"https://crates.io/api/v1/crates/{crate}/owners")
    owners = owners_data.get("users", []) if isinstance(owners_data, dict) else []
    owner_identities = sorted(owner.get("login", "unknown") for owner in owners)
    return {"check": "crate", "crate": crate, "exists": True, "owner_identities": owner_identities}


def check_pypi_project(read: HttpReader, project: str) -> dict:
    data = read(f"https://pypi.org/pypi/{project}/json")
    return {
        "check": "pypi",
        "project": project,
        "exists": data is not None,
        "trusted_publisher_configured": "not queryable via a public API -- confirm in the "
        "project's Manage -> Publishing page",
    }


PEP_503_RUNS = re.compile(r"[-_.]+")


def normalize_pep503(name: str) -> str:
    """PEP 503: lowercase, with every run of `-`, `_`, `.` collapsed to `-`."""
    return PEP_503_RUNS.sub("-", name).lower()


def check_pypi_normalized_aliases(read: HttpReader, name: str) -> dict:
    """Confirm every PEP 503 spelling of `name` is one PyPI project, not
    several. A 404 on every alias means no public project exists under any
    of them today -- not evidence that the name is reserved."""
    normalized = normalize_pep503(name)
    aliases = sorted({name, normalized, normalized.replace("-", "_")})
    responses = {alias: read(f"https://pypi.org/pypi/{alias}/json") for alias in aliases}
    reported_names = {
        alias: (data.get("info", {}).get("name") if isinstance(data, dict) else None)
        for alias, data in responses.items()
    }
    distinct = {value for value in reported_names.values() if value is not None}
    return {
        "check": "pypi-normalized-aliases",
        "aliases": aliases,
        "exists": bool(distinct),
        "reported_names": reported_names,
        "agree": len(distinct) <= 1,
    }


def check_github_repo(read: GitHubReader, repo: str) -> dict:
    data = read(f"repos/{repo}")
    if data is None:
        return {"check": "github-repo", "repo": repo, "exists": False}
    return {
        "check": "github-repo",
        "repo": repo,
        "exists": True,
        "private": data.get("private") if isinstance(data, dict) else None,
    }


def _run(label: str, fn: Callable[[], dict]) -> dict:
    try:
        return fn()
    except NotAvailable as error:
        return {"check": label, "verified": False, "reason": str(error)}


def build_evidence(
    *,
    gh_read: GitHubReader,
    http_read: HttpReader,
    repo: str,
    environment: str | None,
    branch: str | None,
    npm_packages: list[str],
    crates: list[str],
    pypi_project: str | None,
    check_repo: bool = False,
) -> dict:
    results: list[dict] = []
    if check_repo:
        results.append(_run("github-repo", lambda: check_github_repo(gh_read, repo)))
    if environment:
        results.append(_run("github-environment", lambda: check_github_environment(gh_read, repo, environment)))
    if branch:
        results.append(_run("github-branch", lambda: check_github_branch(gh_read, repo, branch)))
    for package in npm_packages:
        results.append(_run("npm", lambda package=package: check_npm_package(http_read, package)))
    for crate in crates:
        results.append(_run("crate", lambda crate=crate: check_crate(http_read, crate)))
    if pypi_project:
        results.append(_run("pypi", lambda: check_pypi_project(http_read, pypi_project)))
        results.append(_run("pypi-normalized-aliases", lambda: check_pypi_normalized_aliases(http_read, pypi_project)))

    return {
        "issue": 143,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "repo": repo,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default="redact-secret/redact-secret")
    parser.add_argument("--environment", default="release")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--npm", dest="npm_packages", action="append", default=[])
    parser.add_argument("--crate", dest="crates", action="append", default=[])
    parser.add_argument("--pypi", dest="pypi_project", default=None)
    parser.add_argument("--check-repo", action="store_true", help="check whether --repo itself exists on GitHub")
    parser.add_argument("--out", type=argparse.FileType("w"), default=sys.stdout)
    args = parser.parse_args(argv)

    evidence = build_evidence(
        gh_read=gh_api,
        http_read=http_get_json,
        repo=args.repo,
        environment=args.environment,
        branch=args.branch,
        npm_packages=args.npm_packages,
        crates=args.crates,
        pypi_project=args.pypi_project,
        check_repo=args.check_repo,
    )
    json.dump(evidence, args.out, indent=2, sort_keys=True)
    args.out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
