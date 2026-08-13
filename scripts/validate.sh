#!/usr/bin/env bash
# Local gate. Mirrors .github/workflows/ci.yml so you find problems before pushing.
#
#   ./scripts/validate.sh
#
# Requires: terraform, python3 (+pyyaml). tflint, checkov, trivy, conftest and
# gitleaks are run when present and skipped with a notice when not.
set -uo pipefail

cd "$(dirname "$0")/.."
FAIL=0

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
skip() { printf '    \033[2mskipped: %s not installed\033[0m\n' "$1"; }
fail() { FAIL=1; printf '\033[31m    FAILED: %s\033[0m\n' "$1"; }

step "terraform fmt"
if command -v terraform >/dev/null; then
  terraform fmt -check -recursive -diff || fail "terraform fmt"
else
  skip terraform
fi

step "terraform validate"
if command -v terraform >/dev/null; then
  for dir in terraform examples/*/; do
    [ -f "$dir/main.tf" ] || continue
    echo "    $dir"
    terraform -chdir="$dir" init -backend=false -input=false -no-color >/dev/null || fail "init $dir"
    terraform -chdir="$dir" validate -no-color || fail "validate $dir"
  done
else
  skip terraform
fi

step "tflint"
if command -v tflint >/dev/null; then
  tflint --init >/dev/null && tflint --recursive --format compact || fail tflint
else
  skip tflint
fi

step "checkov"
if command -v checkov >/dev/null; then
  checkov -d . --framework terraform --quiet --compact || fail checkov
else
  skip checkov
fi

step "trivy config"
if command -v trivy >/dev/null; then
  trivy config . --severity HIGH,CRITICAL --exit-code 1 || fail trivy
else
  skip trivy
fi

step "conftest policy unit tests"
if command -v conftest >/dev/null; then
  conftest verify --policy policies || fail conftest
else
  skip conftest
fi

step "control matrix integrity"
python3 controls/render.py --check || fail "control matrix"

step "gitleaks"
if command -v gitleaks >/dev/null; then
  gitleaks detect --no-banner --redact || fail gitleaks
else
  skip gitleaks
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mall checks passed\033[0m\n'
else
  printf '\033[31mone or more checks failed\033[0m\n'
fi
exit "$FAIL"
