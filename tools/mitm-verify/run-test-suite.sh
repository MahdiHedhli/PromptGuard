#!/usr/bin/env bash
# tools/mitm-verify/run-test-suite.sh
#
# Runs every prompt under tools/mitm-verify/test-prompts/ through the
# proxy with the MITM verification overlay active, then writes a
# summary report at ./local/mitm-captures/summary-<timestamp>.md.
#
# Prerequisites:
#   1. The MITM stack is up:
#        make -C tools/mitm-verify up
#   2. ANTHROPIC_API_KEY is in .env (or already exported in the shell).
#   3. The proxy is reachable at http://localhost:${PROMPTGUARD_LITELLM_PORT:-4100}.
#
# Output:
#   ./local/mitm-captures/<UTC>-<flow>-{req,resp}.json   (per-flow)
#   ./local/mitm-captures/summary-<UTC>.md               (one summary)

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

LITELLM_PORT="${PROMPTGUARD_LITELLM_PORT:-4100}"
LITELLM_URL="http://localhost:${LITELLM_PORT}"
MASTER_KEY="${LITELLM_MASTER_KEY:-sk-promptguard-dev}"
MODEL="${PROMPTGUARD_TEST_MODEL:-claude-sonnet-4-6}"

CAPTURES_DIR="${ROOT_DIR}/local/mitm-captures"
PROMPTS_DIR="${ROOT_DIR}/tools/mitm-verify/test-prompts"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="${CAPTURES_DIR}/summary-${TS}.md"

mkdir -p "${CAPTURES_DIR}"

# Sanity: stack reachable?
if ! curl -fsS -o /dev/null -m 5 "${LITELLM_URL}/health/liveliness"; then
    echo "ERROR: LiteLLM not reachable at ${LITELLM_URL}." >&2
    echo "  Bring up the MITM stack first: make -C tools/mitm-verify up" >&2
    exit 1
fi

# Sanity: mitmproxy reachable from this script for status?
# (We don't strictly need direct access; the inline addon writes the
#  captures. We do test that the CA file is present so we know the
#  mitmproxy container is actually positioned in the upstream path.)
CA_PATH="${ROOT_DIR}/local/mitm-ca/mitmproxy-ca-cert.pem"
if [[ ! -f "${CA_PATH}" ]]; then
    echo "ERROR: ${CA_PATH} not found." >&2
    echo "  The mitmproxy container should have generated this on first start." >&2
    echo "  Check 'docker compose -f docker-compose.yml -f tools/mitm-verify/docker-compose.mitm.yml ps'" >&2
    exit 2
fi

# Header.
{
    echo "# PromptGuard wire-verification summary"
    echo
    echo "Run: ${TS}"
    echo "Stack: docker-compose + tools/mitm-verify/docker-compose.mitm.yml"
    echo "Model: ${MODEL}"
    echo "Captures dir: ${CAPTURES_DIR}"
    echo
    echo "## How to read this report"
    echo
    echo "Each prompt under \`tools/mitm-verify/test-prompts/\` is sent"
    echo "through the proxy. The mitmproxy addon captures every byte the"
    echo "proxy sends to api.anthropic.com (or any other configured upstream)."
    echo "The summary below lists, for each prompt:"
    echo
    echo "  - what the user typed (the original prompt)"
    echo "  - the proxy's HTTP response status code (200 = forwarded; 400 = BLOCKed)"
    echo "  - whether the upstream-side capture leaked any obvious PII pattern"
    echo "  - paths to the per-flow capture files for inspection"
    echo
    echo "**The verification gate:** the upstream capture should NEVER"
    echo "contain the original PII for TOKENIZE/MASK categories, and BLOCK"
    echo "rules should produce no upstream capture at all."
    echo
} > "${SUMMARY}"

PROMPT_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

for prompt_file in "${PROMPTS_DIR}"/*.txt; do
    PROMPT_COUNT=$((PROMPT_COUNT + 1))
    prompt_name=$(basename "${prompt_file}" .txt)

    # Strip header comments; keep payload.
    payload=$(grep -v '^#' "${prompt_file}" | sed '/^[[:space:]]*$/d' | head -c 8000)
    payload_short=$(printf '%s' "${payload}" | head -c 200)

    # Pre-test snapshot of capture file count, so we can list NEW captures.
    before_count=$(find "${CAPTURES_DIR}" -name '*.json' -type f 2>/dev/null | wc -l | awk '{print $1}')

    # Build a JSON body. Use python so we don't have to escape the
    # payload manually.
    body=$(.venv/bin/python -c "
import json, sys
payload = sys.stdin.read()
print(json.dumps({
    'model': '${MODEL}',
    'max_tokens': 80,
    'messages': [{'role': 'user', 'content': payload}],
}))" <<< "${payload}")

    # Issue the request.
    http_code=$(curl -sS -o /tmp/promptguard-mitm-resp.json -w '%{http_code}' \
        -X POST "${LITELLM_URL}/v1/messages" \
        -H "Authorization: Bearer ${MASTER_KEY}" \
        -H "x-api-key: ${MASTER_KEY}" \
        -H "anthropic-version: 2023-06-01" \
        -H "Content-Type: application/json" \
        --data-binary "${body}" \
        --max-time 30 || echo 000)

    # Wait briefly for mitmproxy to flush captures.
    sleep 0.5
    after_count=$(find "${CAPTURES_DIR}" -name '*.json' -type f 2>/dev/null | wc -l | awk '{print $1}')

    # Inspect new captures: any suspicious-pattern counts?
    new_captures=$(find "${CAPTURES_DIR}" -name '*-req.json' -type f -newer "${SUMMARY}" 2>/dev/null | sort)
    leak_summary="(no upstream capture; expected for BLOCK)"
    if [[ -n "${new_captures}" ]]; then
        # Build a single-line leak summary from all new capture files.
        leak_summary=$(.venv/bin/python -c "
import json, sys
totals = {}
for path in sys.argv[1:]:
    try:
        with open(path) as f:
            cap = json.load(f)
    except Exception:
        continue
    counts = cap.get('suspicious_pattern_counts', {}) or {}
    for k, v in counts.items():
        totals[k] = totals.get(k, 0) + int(v)
if not totals:
    print('clean (no suspicious patterns in upstream-bound bytes)')
else:
    print('LEAK: ' + ', '.join(f'{k}={v}' for k, v in sorted(totals.items())))
" ${new_captures})
    fi

    # Determine pass/fail.
    pass="PASS"
    if [[ "${http_code}" != "200" && "${http_code}" != "400" ]]; then
        pass="FAIL: unexpected HTTP ${http_code}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    elif [[ "${leak_summary}" == LEAK:* ]]; then
        pass="FAIL: ${leak_summary}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        PASS_COUNT=$((PASS_COUNT + 1))
    fi

    {
        echo "## ${prompt_name}"
        echo
        echo "**Prompt (truncated to 200 chars):**"
        echo
        echo '```'
        printf '%s\n' "${payload_short}"
        echo '```'
        echo
        echo "**Proxy HTTP status:** ${http_code}"
        echo
        echo "**Upstream-bound bytes:** ${leak_summary}"
        echo
        echo "**New capture files this run:**"
        echo
        if [[ -n "${new_captures}" ]]; then
            for cap in ${new_captures}; do
                echo "  - \`${cap#$ROOT_DIR/}\`"
            done
        else
            echo "  (none)"
        fi
        echo
        echo "**Verdict:** ${pass}"
        echo
        echo "---"
        echo
    } >> "${SUMMARY}"

    # Touch summary so the "newer than" check resets for the next prompt.
    touch "${SUMMARY}"
done

# Tail.
{
    echo "## Run summary"
    echo
    echo "Total prompts: ${PROMPT_COUNT}"
    echo "Pass:          ${PASS_COUNT}"
    echo "Fail:          ${FAIL_COUNT}"
    echo
    if [[ "${FAIL_COUNT}" -eq 0 ]]; then
        echo "**Result: VERIFIED.** No PII pattern leaked into upstream-bound bytes for any prompt."
    else
        echo "**Result: NOT VERIFIED.** ${FAIL_COUNT} of ${PROMPT_COUNT} prompts produced upstream leakage."
        echo
        echo "Inspect the per-flow capture files listed above to see what reached the wire."
    fi
} >> "${SUMMARY}"

echo
echo "Summary written to: ${SUMMARY}"
echo "${PASS_COUNT}/${PROMPT_COUNT} pass, ${FAIL_COUNT} fail."
exit "${FAIL_COUNT}"
