# Redact Secret agent instructions

## Required context

1. Read `README.md`, `ARCHITECTURE.md`, `CONVENTIONS.md`, `docs/decisions/DECISIONS.md`, and `docs/rust-workspace.md` before making material changes. Read `_notes/GOVERNANCE.md` as additional local policy when it exists.
2. When the temporary local `.agents/skills/context-governance/SKILL.md` is installed, use it for governed planning, Decisions, Conventions, Constraints, Git policy, and Version policy.
3. Keep changes within the deterministic secret-detection and redaction boundary described by the architecture.

Project-wide ADRs live under `docs/decisions` with `scope: workspace`; do not
also create `_notes/decisions`. Validate them with `npm run decisions:validate`.

New evidence goes where
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](docs/decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
places its kind: final evidence for a product judgement lands frozen under
`docs/audits/evidence/<issue>/`; final evidence from a benchmark or scanner
run belongs in `redact-secret-benchmarks`, never copied here; and an
iterative or exploratory log stays in an issue comment, linked by permalink
from whichever final record cites it, not duplicated into a repository file.

Current rules are stated in the five spec files under `docs/specs/`
(`detector-families.md`, `contextual-detection.md`, `engine.md`,
`distribution.md`, `evidence-and-gates.md`); each links the ADR that decided
it. A decision that applies an existing policy to one more provider family or
one more instance is a spec-file row plus its supporting evidence, not a new
ADR — a new ADR is warranted only for new policy, a new trade-off, or a
precedent that spans families.

## Security boundary

- Never place real credentials in source, fixtures, logs, errors, snapshots, documentation, or agent context. Use unmistakably synthetic or revoked examples.
- Findings and diagnostics must not expose plaintext secret values.
- Keep the core side-effect free: no runtime network access, telemetry, secret storage, or environment-dependent behavior.
- Treat client-side scanning as preventive UX and server-side scanning as the authoritative enforcement boundary.

## Change rules

- Preserve browser and Node.js compatibility and keep the public API runtime-neutral.
- Keep detection separate from policy enforcement; additions should state their false-positive and false-negative tradeoffs.
- Add deterministic tests for detector, redaction, overlap-resolution, or policy behavior changes.
- Follow `_notes/GOVERNANCE.md` for branch, commit, review, merge, version, and changelog policy when that local governance file exists. Governance declarations do not authorize Git or release operations.

## Release authority

A release requires explicit user approval after tests pass and the public API and changelog have been reviewed. Do not choose a version, create a tag or release, publish a package, or deploy without that approval.

Prepare an approved version on `rc/{version}` (for example, `rc/0.1.0-beta.1`) from reviewed `main`, and dispatch publication from that RC branch after qualification and explicit release approval. The branch version must match the product manifests. The release workflow creates annotated `v{version}` only after all publication jobs and registry-install verification succeed, and records a durable release manifest (source revision, conformance corpus identity, version, artifact set, registry state) for every run, including a failed one. After publication, merge the release changes back into `main` through a reviewed PR and retain the RC branch. Use `Reconcile Release` only with explicit authorization to repair a matching published version without republishing it; dispatch from its matching RC branch. Its repair window is any commit that is an ancestor of that RC branch's current tip (its exact tip included) for which the manifest still exists, or that is named explicitly via the workflow's `source_commit` input — never a commit that fell out of that RC branch's history. See the [release runbook](docs/releasing.md#branching-model).

## 일 좀 똑바로 하자

- 5분 이상 걸리는 명령을 제안하기 전에, 그 입력을 먼저 읽어서 검증한다. 검증 비용이 실행 비용보다 두 자릿수 작으면 무조건 먼저 검증한다. 
- 시험/검증 작업에서는 "무엇을 측정하는가"와 "무엇이 입력으로 필요한가"를 분리한다. 입력은 측정 대상을 만족하는 최소 크기여야 한다. 
- 기존 자산(이슈, 브랜치, 파일)에서 고르는 것이 유일한 선택지라고 가정하지 않는다. 새로 만드는 쪽이 더 싸면 그쪽을 먼저 제안한다. 
- 반론이 들어오면, 내가 답하기 쉬운 반론이 아니라 실제로 제기된 반론에 답한다.
- benchmarks 측정(`eval:classify`, `eval:matrix`, `benchmark:candidate`) 전에 `trufflehog --version`이 핀(3.97.4)과 같은지 확인한다. 자동 업데이트로 patch만 올라가도 stable 수가 43에서 5로 바뀐다(redact-secret-benchmarks#180). 다르면 수치를 보고하지 말고 핀 버전 바이너리를 PATH 앞에 두고 다시 돌린다. stable 수에는 항상 모드(published/candidate)를 함께 적는다.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->

## Tool precedence — graft first, rtk second

They answer different questions; do not let one stand in for the other.

- **Where is the code / who calls it / what does this change break** → graft
  (`graft ask`, `graft grep`, `graft skeleton`, `graft callers`). Query it
  before any `grep`, `rtk grep`, or whole-file read.
- **Compressing the output of a command you are already running** (build, test,
  git, gh, package managers) → prefix it with `rtk`. See `RTK.md`.

`rtk read` / `rtk grep` / `rtk find` are the fallback for files graft has not
indexed, or for opening the exact `file:line` graft already pointed you at.

## Issue workflow — two units of work

Both live in `.agents/skills/` so Claude Code and Codex read the same file.

| step | command | ends at |
|---|---|---|
| 1 | `resolve-issue <ISSUE_NUMBER>` | a verified `workbench/<N>-<slug>` branch, committed, not pushed |
| 2 | *(you)* `ghpr run <N> --trace-db …/giro.trace.db` | commit message written, PR opened |
| 3 | `review-pr <PR_NUMBER>` | final review + wrap-up done, ready to close |

`resolve-issue` owns the `wip: #<N>` commit-subject rule that `ghpr` depends on:
every commit on the branch carries that exact subject, with no body and no
trailers. Once the PR exists that rule is over.

## Working from a GitHub issue

An issue URL carries no code vocabulary, so graft's prompt hook has nothing to
match on and injects nothing. Before touching source, read the issue body and
run `graft ask "<the issue title or the symbols it names>" --source` yourself.
A fresh worktree also has no `graft/` (it is gitignored) — run `graft build`
once before starting.

@RTK.md
