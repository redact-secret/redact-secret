# CI maintenance review — 2026-09-16

Eight workflow files do not imply eight independent gates. Inspection shows:

| Workflow | Trigger / role |
| --- | --- |
| CI | PR, RC push, reusable; JavaScript and Rust checks |
| Python wheels | PR, RC push, manual, reusable; wheel qualification |
| Artifact qualification | PR, main/RC push, manual, reusable; matrix artifacts and installed-package checks; calls CI and Python wheels on full runs |
| SAST | PR and push; separate security scan |
| Complete assessment | Manual; one-host non-gating accuracy/performance evidence |
| Package release rehearsal | Manual; calls artifact qualification without publication |
| Release | Manual; calls CI, Python wheels, and artifact qualification before publishing |
| Reconcile Release | Manual; controlled repair of an existing publication |

Confirmed duplication: a full Artifact qualification run calls CI and Python
wheels, while Release also calls both directly. RC push triggers can also
run standalone CI and Python workflows alongside qualification's nested calls.
PR qualification has a run planner, so PR cost depends on whether it selects a
full run; file count alone cannot quantify cost.

Follow-up candidate: make Artifact qualification own the full release validation
graph and remove Release's direct duplicate calls, rewiring publication `needs`
and required-check expectations together. Audit artifact names and download
selection first: callers currently consume Python artifacts, and duplicate
names must not be resolved by accidental ordering. For PR/push, select one owner
for full checks while preserving fast PR feedback and branch-protection checks.

No workflows or security gates were removed in this change. No measured CI-minute
saving is claimed. Documentation/script size ratios exclude or include generated
evidence differently and are not a trustworthiness metric; this review targets
specific repeated work rather than a line-count quota.
