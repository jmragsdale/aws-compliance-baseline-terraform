#!/usr/bin/env bash
# Local gate. Mirrors .github/workflows/ci.yml so you find problems before pushing.
#
#   ./scripts/validate.sh            # human-readable run
#   ./scripts/validate.sh --json     # one JSON object of per-check results
#   ./scripts/validate.sh --strict   # treat a skipped check as a failure
#
# Requires: terraform, python3 (+pyyaml). tflint, checkov, trivy, conftest and
# gitleaks are run when present and skipped with a notice when not.
#
# --json exists so an automated fix loop can tell "was green, now red" apart
# from "still red" -- a single exit code cannot. Each check reports
# pass | fail | skip independently, and a skip is NEVER folded into pass: a
# check that did not run is unverified, not clean. See
# .claude/commands/loop-fix.md.
set -uo pipefail

cd "$(dirname "$0")/.."

JSON=0
STRICT=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

FAIL=0
LOGDIR=".loop/logs"
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"
RESULTS=()

# In JSON mode every check's chatter goes to its log file, never to stdout,
# so stdout stays a single parseable object.
if [ "$JSON" -eq 1 ]; then
  step() { :; }
  note() { :; }
else
  step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
  note() { printf '    %s\n' "$1"; }
fi

# record <check-id> <pass|fail|skip> <one-line detail>
record() {
  RESULTS+=("$1|$2|$3")
  case "$2" in
    fail) FAIL=1 ;;
    skip) [ "$STRICT" -eq 1 ] && FAIL=1 ;;
  esac
  return 0
}

# first_error <logfile> -- a short, JSON-safe summary line for the report.
# Falls back to the first non-blank line: some tools (terraform fmt) fail with
# a diff and no error keyword, and a failure with an empty detail tells the
# builder agent nothing.
first_error() {
  local line
  line=$(grep -m1 -aE 'Error|error|FAILED|failed|✗' "$1" 2>/dev/null)
  [ -n "$line" ] || line=$(grep -m1 -a '[^[:space:]]' "$1" 2>/dev/null)
  printf '%s' "$line" | tr -d '"\\' | tr -s '[:space:]' ' ' | cut -c1-160
}

# check <check-id> <required-binary|-> <label> -- <command...>
check() {
  local id="$1" bin="$2" label="$3"; shift 4   # shift past the literal --
  local log="$LOGDIR/$id.log" rc=0

  if [ "$bin" != "-" ] && ! command -v "$bin" >/dev/null; then
    printf 'skipped: %s not installed\n' "$bin" >"$log"
    [ "$JSON" -eq 1 ] || printf '    \033[2mskipped: %s not installed\033[0m\n' "$bin"
    record "$id" skip "$bin not installed"
    return 0
  fi

  "$@" >"$log" 2>&1 || rc=$?
  [ "$JSON" -eq 1 ] || cat "$log"

  if [ "$rc" -ne 0 ]; then
    [ "$JSON" -eq 1 ] || printf '\033[31m    FAILED: %s\033[0m\n' "$label"
    record "$id" fail "$(first_error "$log")"
  else
    record "$id" pass ""
  fi
  return 0
}

# --- terraform fmt --------------------------------------------------------
step "terraform fmt"
check terraform-fmt terraform "terraform fmt" -- terraform fmt -check -recursive -diff

# --- terraform validate ---------------------------------------------------
# Each directory is its own check so the loop can see one example regress
# while the others stay green.
step "terraform validate"
if command -v terraform >/dev/null; then
  for dir in terraform examples/*/; do
    [ -f "$dir/main.tf" ] || continue
    id="terraform-validate-$(printf '%s' "$dir" | tr -cd '[:alnum:]')"
    log="$LOGDIR/$id.log"; rc=0
    note "$dir"
    {
      terraform -chdir="$dir" init -backend=false -input=false -no-color &&
      terraform -chdir="$dir" validate -no-color
    } >"$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
      [ "$JSON" -eq 1 ] || { tail -n 20 "$log"; printf '\033[31m    FAILED: validate %s\033[0m\n' "$dir"; }
      record "$id" fail "$(first_error "$log")"
    else
      note "Success! The configuration is valid."
      record "$id" pass ""
    fi
  done
else
  [ "$JSON" -eq 1 ] || printf '    \033[2mskipped: terraform not installed\033[0m\n'
  record terraform-validate skip "terraform not installed"
fi

# --- tflint ---------------------------------------------------------------
step "tflint"
command -v tflint >/dev/null && tflint --init >"$LOGDIR/tflint-init.log" 2>&1
check tflint tflint "tflint" -- tflint --recursive --format compact

# --- checkov --------------------------------------------------------------
step "checkov"
check checkov checkov "checkov" -- checkov -d . --framework terraform --quiet --compact

# --- trivy ----------------------------------------------------------------
step "trivy config"
check trivy trivy "trivy" -- trivy config . --severity HIGH,CRITICAL --exit-code 1

# --- conftest -------------------------------------------------------------
step "conftest policy unit tests"
check conftest conftest "conftest" -- conftest verify --policy policies

# --- control matrix -------------------------------------------------------
step "control matrix integrity"
check controls-matrix - "control matrix" -- python3 controls/render.py --check

# --- gitleaks -------------------------------------------------------------
step "gitleaks"
check gitleaks gitleaks "gitleaks" -- gitleaks detect --no-banner --redact

# --- report ---------------------------------------------------------------
n_pass=0; n_fail=0; n_skip=0
for r in "${RESULTS[@]}"; do
  case "${r#*|}" in pass\|*) n_pass=$((n_pass+1)) ;; fail\|*) n_fail=$((n_fail+1)) ;; skip\|*) n_skip=$((n_skip+1)) ;; esac
done

if [ "$JSON" -eq 1 ]; then
  printf '{\n  "checks": [\n'
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id status detail <<<"$r"
    [ "$first" -eq 1 ] || printf ',\n'
    first=0
    printf '    {"check": "%s", "status": "%s", "detail": "%s", "log": "%s/%s.log"}' \
      "$id" "$status" "$detail" "$LOGDIR" "$id"
  done
  printf '\n  ],\n  "summary": {"pass": %d, "fail": %d, "skip": %d},\n' "$n_pass" "$n_fail" "$n_skip"
  # all_green is true only when nothing failed AND nothing was skipped.
  if [ "$n_fail" -eq 0 ] && [ "$n_skip" -eq 0 ]; then
    printf '  "all_green": true\n}\n'
  else
    printf '  "all_green": false\n}\n'
  fi
  exit "$FAIL"
fi

printf '\n'
for r in "${RESULTS[@]}"; do
  IFS='|' read -r id status detail <<<"$r"
  [ "$status" = "skip" ] && printf '\033[33m  SKIP  %-34s %s\033[0m\n' "$id" "$detail"
done
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m%d checks passed\033[0m\n' "$n_pass"
  [ "$n_skip" -gt 0 ] && printf '\033[33m%d checks were SKIPPED -- unverified, not clean. Use --strict to fail on them.\033[0m\n' "$n_skip"
else
  printf '\033[31m%d checks failed, %d passed, %d skipped\033[0m\n' "$n_fail" "$n_pass" "$n_skip"
fi
exit "$FAIL"
