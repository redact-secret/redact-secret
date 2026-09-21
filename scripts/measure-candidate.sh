#!/usr/bin/env bash
#
# Build this checkout as candidate npm artifacts, evaluate them at an exact
# redact-secret-benchmarks commit, validate the evidence with that commit's own
# validator, and print the outcome tally.
#
# This wraps `npm run benchmark:candidate` (scripts/benchmark-candidate.mjs).
# It adds only the preflight checks that script assumes and the validation step
# the benchmark-candidate skill requires; it makes no measurement decisions.
#
#   ./scripts/measure-candidate.sh
#   ./scripts/measure-candidate.sh --benchmark-ref <full-40-character-sha>
#   ./scripts/measure-candidate.sh --benchmark-repo /abs/path --output-dir /abs/path
#   ./scripts/measure-candidate.sh --filter sendgrid-token --skip-validate
#
# The benchmarks checkout is located, in order: --benchmark-repo, the
# REDACT_SECRET_BENCHMARKS environment variable, then a sibling directory named
# redact-secret-benchmarks.

set -euo pipefail

product_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

benchmark_repo=${REDACT_SECRET_BENCHMARKS:-"$(dirname -- "$product_root")/redact-secret-benchmarks"}
benchmark_ref=""
output_dir=""
filter=""
skip_validate=0

die() { printf '\nerror: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --benchmark-repo) benchmark_repo=${2:-}; shift 2 ;;
    --benchmark-ref)  benchmark_ref=${2:-};  shift 2 ;;
    --output-dir)     output_dir=${2:-};     shift 2 ;;
    --filter)         filter=${2:-};         shift 2 ;;
    --skip-validate)  skip_validate=1;       shift ;;
    -h|--help)        awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)                die "unknown argument: $1" ;;
  esac
done

[ -d "$benchmark_repo/.git" ] || die "no benchmarks checkout at $benchmark_repo
       pass --benchmark-repo <absolute-path> or set REDACT_SECRET_BENCHMARKS"
benchmark_repo=$(cd -- "$benchmark_repo" && pwd)

# A dirty worktree is not reproducible, so it is not evidence. Refuse rather
# than emit a report that cannot be tied to a commit.
[ -z "$(git -C "$product_root"   status --porcelain)" ] || die "product worktree is dirty: $product_root"
[ -z "$(git -C "$benchmark_repo" status --porcelain)" ] || die "benchmarks worktree is dirty: $benchmark_repo"

# scripts/build-browser-artifact.mjs requires the wasm-bindgen CLI to be the
# exact version the crate links; a mismatch surfaces late as wasm-build-failed.
wasm_bindgen_need=$(awk '/^name = "wasm-bindgen"$/ { found = 1 } found && /^version/ { gsub(/"/, "", $3); print $3; exit }' "$product_root/Cargo.lock")
wasm_bindgen_have=$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)
[ "$wasm_bindgen_need" = "$wasm_bindgen_have" ] || die "wasm-bindgen $wasm_bindgen_need required, found ${wasm_bindgen_have:-none}
       cargo install wasm-bindgen-cli --version $wasm_bindgen_need --locked"

printf 'Fetching…\n'
git -C "$product_root"   fetch origin --quiet
git -C "$benchmark_repo" fetch origin --quiet

# The product side is measured at whatever this checkout has; the benchmark side
# is pinned to an exact commit, never a moving ref.
if [ -z "$benchmark_ref" ]; then
  benchmark_ref=$(git -C "$benchmark_repo" rev-parse origin/main)
else
  case "$benchmark_ref" in
    *[!0-9a-f]* | "" ) die "benchmark-ref must be a full lowercase 40-character sha" ;;
  esac
  [ ${#benchmark_ref} -eq 40 ] || die "benchmark-ref must be a full lowercase 40-character sha"
  git -C "$benchmark_repo" cat-file -e "${benchmark_ref}^{commit}" 2>/dev/null \
    || die "benchmark-ref $benchmark_ref is not in $benchmark_repo"
fi

product_sha=$(git -C "$product_root" rev-parse HEAD)
[ -n "$output_dir" ] || output_dir="$product_root/benchmark-evidence/candidate/$(date +%Y%m%d-%H%M%S)"
case "$output_dir" in
  /*) ;;
  *) die "--output-dir must be absolute" ;;
esac

printf '\nproduct    %s (clean)\nbenchmark  %s (clean)\noutput     %s\n\n' \
  "$product_sha" "$benchmark_ref" "$output_dir"

candidate_args=(--benchmark-ref "$benchmark_ref" --benchmark-repo "$benchmark_repo" --output-dir "$output_dir")
[ -z "$filter" ] || candidate_args+=(--filter "$filter")

( cd "$product_root" && npm run benchmark:candidate -- "${candidate_args[@]}" )

evidence="$output_dir/candidate-evidence-v1.json"
[ -f "$evidence" ] || die "no evidence written at $evidence"

# Validate with the benchmark revision's own validator, not this checkout's
# idea of it, in a throwaway worktree at the exact measured commit.
if [ "$skip_validate" -eq 0 ]; then
  printf '\nValidating against %s…\n' "${benchmark_ref:0:12}"
  validate_worktree=$(mktemp -d)
  cleanup() { git -C "$benchmark_repo" worktree remove --force "$validate_worktree" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  git -C "$benchmark_repo" worktree add --detach --quiet "$validate_worktree" "$benchmark_ref"
  # Reuse the benchmarks checkout's install; the validator needs tsx only.
  [ -d "$benchmark_repo/node_modules" ] && ln -s "$benchmark_repo/node_modules" "$validate_worktree/node_modules"
  ( cd "$validate_worktree" && npm run eval:validate -- "$evidence" )
fi

printf '\n'
node -e '
const evidence = require(process.argv[1]);
const rows = Object.values(evidence.results);
console.log(`status ${evidence.status} · failures ${evidence.failures.length} · fixtures ${evidence.completeness.scannedFixtures}/${evidence.completeness.selectedFixtures} · scope ${evidence.selection.scope}`);
const tally = {};
for (const row of rows) {
  const key = `${row.corpusSection} ${row.kind} ${row.outcome}`;
  tally[key] = (tally[key] ?? 0) + 1;
}
for (const [key, count] of Object.entries(tally).sort()) console.log(String(count).padStart(5), key);
const clean = new Set(["EXACT", "EXACT,EXACT", "clean"]);
const defects = rows.filter(row => !clean.has(row.outcome));
console.log(`\n${defects.length} non-clean row(s)`);
for (const row of defects) console.log(" ", row.outcome.padEnd(11), row.fixtureId, `(baseline ${row.baseline?.outcome ?? "none"})`);
' "$evidence"

printf '\nevidence: %s\n' "$evidence"
