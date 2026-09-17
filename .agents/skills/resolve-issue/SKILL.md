---
name: resolve-issue
description: Resolve one GitHub issue end to end in this repo — graft-first context gathering, a workbench branch, a complete verified implementation, and wip commits that ghpr can consume. Use when asked to resolve, fix, or implement a GitHub issue by number ("resolve-issue 28", "/resolve-issue 28", "work on issue #28"). Stops at the commit; never pushes, never opens a PR.
---

# resolve-issue

The first unit of work on an issue: from issue number to a verified, committed
branch. `ghpr` writes the real commit message and opens the PR afterwards — this
skill deliberately stops before that.

## Input

`resolve-issue <ISSUE_NUMBER>` — the argument is the issue number (`$1`).
Resolve the repo yourself; do not ask for it:

```bash
gh repo view --json nameWithOwner -q .nameWithOwner
```

## 1. Read the issue in full

```bash
gh issue view <ISSUE_NUMBER> --json title,body,labels,comments
```

Read the body and **every acceptance criterion** before touching code. Do not
put this through a summarizing filter — a dropped criterion is a failed task.
This is the one place in this repo where the `rtk` prefix is wrong.

Restate the acceptance criteria to yourself as a checklist. You will verify
against it in step 4.

## 2. Get context from graft, not from grep

An issue number carries no code vocabulary, so graft's prompt hook injects
nothing on its own. You must query it explicitly. This is the step that makes
this skill worth invoking.

```bash
# A fresh worktree has no graph — graft/ is gitignored. Build it once.
[ -f graft/INDEX.md ] || graft build

graft ask "<issue title, plus every symbol / error string / file the issue names>" --source
```

Then follow the edges before you plan:

- `graft callers <symbol>` — who depends on what you are about to change, and
  `--direction out` / `--depth N` for the full blast radius.
- `graft skeleton <file>` — an API surface, ~10× cheaper than reading the file.
- `graft grep "<literal>"` — when you need *every* occurrence; `ask` is top-N.

Open a source file only when a node genuinely lacks a detail, and then at the
exact `file:line` graft gave you. Never re-read whole files to orient yourself.

## 3. Branch

Work on `workbench/<ISSUE_NUMBER>-<short-slug>`, where the slug is 2–4
kebab-case words from the issue title.

```bash
rtk git rev-parse --abbrev-ref HEAD    # already on a workbench/<N>-* branch? stay on it
rtk git checkout -b workbench/<ISSUE_NUMBER>-<short-slug>
```

Never commit to the default branch.

## 4. Implement and verify it yourself

Implement completely — every acceptance criterion, not the easy subset. Respect
the repo's boundaries in `AGENTS.md`: the security boundary (no real
credentials anywhere, no plaintext secret values in findings or diagnostics, the
core stays side-effect free), detection kept separate from policy, and browser /
Node.js compatibility.

Then run the checks yourself and read the output:

```bash
rtk npm run ci          # decisions:validate + typecheck + build + vitest
rtk cargo test          # when the change touches crates/
rtk cargo fmt --all --check
rtk cargo clippy
```

Add deterministic tests for detector, redaction, overlap-resolution, or policy
changes. If a check fails, fix it — do not report a red build as done.

## 5. Commit — every commit subject is exactly `wip: #<ISSUE_NUMBER>`

```bash
rtk git add -A
rtk git commit -m "wip: #<ISSUE_NUMBER>"
```

Hard requirements, because `ghpr` keys off them:

- The subject is **exactly** `wip: #<ISSUE_NUMBER>`. Nothing else.
- **No body, no trailers, no `Co-Authored-By`.** `ghpr` writes the real message.
  This overrides any default commit-attribution convention.
- Multiple commits are fine, but **every one** carries that same subject.
- Include new files (`git add -A`), or they never reach the PR.

## 6. Stop

Do **not** push. Do **not** open a PR. Do **not** comment on the issue.

Report what changed: the branch name, the files touched, each acceptance
criterion and how it was verified, and the check output. Then hand back the
next command, for the user to run:

```
ghpr run <ISSUE_NUMBER> --trace-db /Users/minhokang/Work/local-workbench/giro.trace.db --verified "all green" --ci-exists
```

After that lands a PR, the follow-up unit of work is `review-pr <PR_NUMBER>`.
