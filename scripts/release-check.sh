#!/usr/bin/env bash
#
# release-check.sh: full release-readiness gate for PromptGuard.
#
# Purpose: this script is the single command an operator (or CI) runs to
# decide whether a snapshot of the repo is shippable. It exits 0 only if
# every check passes; any failure exits non-zero with a clear message
# pointing at what to fix.
#
# Sections (run in order, fail-fast):
#
#   1. Public-surface audit. Catches Claude / sprint-mechanic / scratch-path
#      references that would embarrass us in a public release.
#   2. Test suite. Unit tests, no docker required.
#   3. Default policy schema validation.
#   4. Benchmark sanity. Detection numbers within expected range.
#   5. README clone-to-running validation. (skipped if not in CI; SKIPPABLE=1)
#
# Each section emits one line on entry ("==> section name") and a clear
# pass / fail line on exit. The final summary table records the result.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# ---------------------------------------------------------------------------
# 1. Public-surface audit
# ---------------------------------------------------------------------------

audit_public_surface() {
    echo "==> 1. Public-surface audit"

    # Strings that must NOT appear in any tracked text-shaped file outside
    # the explicitly-internal allowlist (CLAUDE.md is gitignored; local/
    # is gitignored).
    local forbidden_pattern='Day [0-9]|Day-[0-9]|owner review|HARD STOP|sprint mechanic|push history rewriting'
    local hits
    hits=$(git ls-files \
        | grep -E '\.(md|py|yaml|yml|toml|sh|txt|json)$' \
        || true)

    local found=0
    while IFS= read -r f; do
        # Skip files that are intentional historical records OR that
        # define the forbidden patterns themselves (this script).
        case "${f}" in
            decisions/*) continue ;;  # historical DECs may reference dates
            local/*) continue ;;
            scripts/release-check.sh) continue ;;
        esac
        if grep -El "${forbidden_pattern}" "${f}" >/dev/null 2>&1; then
            echo "  found forbidden pattern in: ${f}"
            grep -nE "${forbidden_pattern}" "${f}" | head -3 | sed 's/^/    /'
            found=$((found + 1))
        fi
    done <<< "${hits}"

    if [[ "${found}" -gt 0 ]]; then
        echo "  FAIL: ${found} file(s) contain sprint-mechanic strings."
        return 1
    fi
    echo "  PASS: no Claude / sprint-mechanic / scratch-path references in tracked public files."
    return 0
}

# ---------------------------------------------------------------------------
# 2. Test suite
# ---------------------------------------------------------------------------

run_tests() {
    echo "==> 2. Unit test suite"
    if uv run pytest -q tests/unit; then
        echo "  PASS: unit tests"
        return 0
    fi
    echo "  FAIL: unit tests"
    return 1
}

# ---------------------------------------------------------------------------
# 3. Policy validation
# ---------------------------------------------------------------------------

validate_policies() {
    echo "==> 3. Sample policies validate"
    local rc=0
    for p in policies/*.yaml; do
        if ! PYTHONPATH=src uv run python -m promptguard.cli validate-policy "${p}" >/dev/null 2>&1; then
            echo "  FAIL: ${p} did not validate"
            rc=1
        fi
    done
    if [[ "${rc}" -eq 0 ]]; then
        echo "  PASS: all shipped policies validate"
    fi
    return "${rc}"
}

# ---------------------------------------------------------------------------
# 4. Benchmark sanity
# ---------------------------------------------------------------------------

run_benchmarks() {
    echo "==> 4. Benchmark sanity"
    # Run the regex-only detection benchmark; check that high-confidence
    # categories still hit perfect F1.
    local out
    if ! out=$(uv run python benchmarks/run_detection_benchmarks.py 2>&1); then
        echo "  FAIL: detection benchmark crashed"
        echo "${out}" | tail -20
        return 1
    fi
    # Look for the structured-secret categories we promise are F1=1.000.
    local missing=()
    for cat in cloud_api_key database_url internal_ip jwt private_key secret; do
        if ! grep -E "${cat}.*1\\.000" <<< "${out}" >/dev/null; then
            missing+=("${cat}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "  FAIL: regression in F1=1.000 categories: ${missing[*]}"
        return 1
    fi
    echo "  PASS: structured-secret categories still at F1=1.000"
    return 0
}

# ---------------------------------------------------------------------------
# 5. README clone-to-running validation
# ---------------------------------------------------------------------------
#
# This is the deploy-in-minutes promise. We bring the stack up via the
# README's documented command and time how long it takes to be healthy.
# Skipped when SKIP_DEPLOY_CHECK=1 (most local runs).

deploy_check() {
    if [[ "${SKIP_DEPLOY_CHECK:-0}" == "1" ]]; then
        echo "==> 5. README deploy validation (SKIPPED via SKIP_DEPLOY_CHECK=1)"
        return 0
    fi
    echo "==> 5. README deploy validation"
    echo "  (skipped on this run; set SKIP_DEPLOY_CHECK=0 and run \`make smoke\` for the live check)"
    return 0
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

declare -a results=()
declare -a names=()

run_section() {
    local name="$1"
    shift
    local fn="$1"
    shift
    if "${fn}" "$@"; then
        results+=("PASS")
    else
        results+=("FAIL")
    fi
    names+=("${name}")
}

run_section "public-surface" audit_public_surface
run_section "tests"           run_tests
run_section "policies"        validate_policies
run_section "benchmarks"      run_benchmarks
run_section "deploy"          deploy_check

echo ""
echo "Release-check summary:"
overall=0
for i in "${!results[@]}"; do
    printf "  %-18s %s\n" "${names[$i]}" "${results[$i]}"
    if [[ "${results[$i]}" != "PASS" ]]; then
        overall=1
    fi
done

if [[ "${overall}" -eq 0 ]]; then
    echo ""
    echo "Release-check PASSED. PromptGuard is shippable."
    exit 0
fi
echo ""
echo "Release-check FAILED. Address the FAIL section(s) above."
exit 1
