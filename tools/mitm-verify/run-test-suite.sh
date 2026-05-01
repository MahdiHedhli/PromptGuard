#!/usr/bin/env bash
# tools/mitm-verify/run-test-suite.sh
#
# Runs every prompt under tools/mitm-verify/test-prompts/ through the
# proxy with the MITM overlay active and produces a summary report at
# ./local/mitm-captures/summary-<UTC>.md.
#
# For each prompt, the report shows:
#   * what the user typed (truncated)
#   * the proxy's HTTP status
#   * for TOKENIZE/MASK prompts (200 status): the actual user-message
#     content the upstream RECEIVED, so the operator sees the
#     substituted token / mask tag in place. Plus positive assertions:
#     - the literal PII string IS NOT present in upstream bytes
#     - the expected substitution shape IS present
#   * for BLOCK prompts (400 status): "no upstream capture; expected"
#     (the request never reached the upstream)
#   * a per-prompt verdict
#
# Verdict logic per prompt:
#   BLOCK expected     -> 400 status AND no upstream capture                  -> PASS
#   TOKENIZE expected  -> 200 status AND original-PII absent
#                         AND token shape [CATEGORY_<16hex>] present          -> PASS
#   MASK expected      -> 200 status AND original-PII absent
#                         AND mask tag [CATEGORY_REDACTED] present            -> PASS
#   anything else                                                             -> FAIL

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

# Stack reachability check.
if ! curl -fsS -o /dev/null -m 5 "${LITELLM_URL}/health/liveliness"; then
    echo "ERROR: LiteLLM not reachable at ${LITELLM_URL}." >&2
    echo "  Bring up the MITM stack first: make -C tools/mitm-verify up" >&2
    exit 1
fi

CA_PATH="${ROOT_DIR}/local/mitm-ca/mitmproxy-ca-cert.pem"
if [[ ! -f "${CA_PATH}" ]]; then
    echo "ERROR: ${CA_PATH} not found." >&2
    echo "  The mitmproxy container should have generated this on first start." >&2
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
    echo "proxy sends to the upstream provider."
    echo
    echo "For prompts whose policy action is **BLOCK**, the request"
    echo "never leaves the host; the report shows \"no upstream capture\"."
    echo
    echo "For prompts whose policy action is **TOKENIZE** or **MASK**,"
    echo "the request IS forwarded with the PII replaced; the report"
    echo "shows the actual upstream-bound user-message content so the"
    echo "operator can see the token / mask tag in place. Two positive"
    echo "assertions run automatically: the literal PII is absent from"
    echo "the upstream bytes, and the expected substitution shape is"
    echo "present."
    echo
} > "${SUMMARY}"

# Per-prompt expectations: action and PII strings to assert about.
EXPECTATIONS=(
    "01-internal-ip|TOKENIZE|10.0.13.42"
    "02-email|MASK|alice@internal-corp.example"
    "03-aws-key|BLOCK|AKIAIOSFODNN7EXAMPLE"
    "04-mixed|BLOCK|AKIAIOSFODNN7EXAMPLE,10.0.13.42,alice@internal-corp.example"
    "05-private-key|BLOCK|-----BEGIN PRIVATE KEY-----"
    "06-database-url|BLOCK|postgres://user:pass@db.internal:5432/prod"
)

PROMPT_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

for entry in "${EXPECTATIONS[@]}"; do
    PROMPT_COUNT=$((PROMPT_COUNT + 1))

    prompt_name="${entry%%|*}"
    rest="${entry#*|}"
    expected_action="${rest%%|*}"
    pii_csv="${rest#*|}"

    prompt_file="${PROMPTS_DIR}/${prompt_name}.txt"
    if [[ ! -f "${prompt_file}" ]]; then
        echo "WARN: ${prompt_file} missing; skipping" >&2
        FAIL_COUNT=$((FAIL_COUNT + 1))
        continue
    fi

    payload=$(grep -v '^#' "${prompt_file}" | sed '/^[[:space:]]*$/d')
    payload_short=$(printf '%s' "${payload}" | head -c 200)

    body=$(.venv/bin/python -c "
import json, sys
payload = sys.stdin.read()
print(json.dumps({
    'model': '${MODEL}',
    'max_tokens': 80,
    'messages': [{'role': 'user', 'content': payload}],
}))" <<< "${payload}")

    http_code=$(curl -sS -o /tmp/promptguard-mitm-resp.json -w '%{http_code}' \
        -X POST "${LITELLM_URL}/v1/messages" \
        -H "Authorization: Bearer ${MASTER_KEY}" \
        -H "x-api-key: ${MASTER_KEY}" \
        -H "anthropic-version: 2023-06-01" \
        -H "Content-Type: application/json" \
        --data-binary "${body}" \
        --max-time 30 || echo 000)

    sleep 0.5

    new_request_captures=$(find "${CAPTURES_DIR}" -name '*-req.json' -type f \
        -newer "${SUMMARY}" 2>/dev/null | sort)

    upstream_user_text=""
    upstream_blob=""
    upstream_capture_path=""
    if [[ -n "${new_request_captures}" ]]; then
        for cap in ${new_request_captures}; do
            host_match=$(.venv/bin/python -c "
import json, sys
d = json.load(open('${cap}'))
url = (d.get('request_url') or d.get('url') or '').lower()
host = (d.get('host') or '').lower()
if 'anthropic.com' in url or 'openai.com' in url or 'anthropic.com' in host:
    print('YES')
" 2>/dev/null || echo "")
            if [[ "${host_match}" == "YES" ]]; then
                upstream_capture_path="${cap}"
                upstream_user_text=$(.venv/bin/python -c "
import json, sys
cap = json.load(open('${cap}'))
body = cap.get('body')
if isinstance(body, dict):
    msgs = body.get('messages') or []
    for m in msgs:
        if m.get('role') == 'user':
            c = m.get('content')
            if isinstance(c, str):
                print(c)
                break
            if isinstance(c, list):
                parts = [b.get('text', '') for b in c if isinstance(b, dict) and b.get('type') == 'text']
                print('\\n'.join(parts))
                break
" 2>/dev/null || echo "")
                upstream_blob=$(.venv/bin/python -c "
import json, sys
cap = json.load(open('${cap}'))
print(json.dumps(cap.get('body', '')))
" 2>/dev/null || echo "")
                break
            fi
        done
    fi

    verdict_lines=()
    pass_this=true

    case "${expected_action}" in
    BLOCK)
        if [[ "${http_code}" != "400" ]]; then
            verdict_lines+=("  - expected HTTP 400 (BLOCK); got ${http_code}")
            pass_this=false
        fi
        if [[ -n "${upstream_capture_path}" ]]; then
            verdict_lines+=("  - upstream capture exists (${upstream_capture_path}); should not for BLOCK")
            pass_this=false
        fi
        ;;
    TOKENIZE)
        if [[ "${http_code}" != "200" ]]; then
            verdict_lines+=("  - expected HTTP 200 (TOKENIZE forwards); got ${http_code}")
            pass_this=false
        fi
        if [[ -z "${upstream_capture_path}" ]]; then
            verdict_lines+=("  - expected an upstream capture for TOKENIZE; none found")
            pass_this=false
        else
            IFS=',' read -ra pii_strings <<< "${pii_csv}"
            for pii in "${pii_strings[@]}"; do
                if [[ -n "${pii}" ]] && grep -qF -- "${pii}" <<< "${upstream_blob}"; then
                    verdict_lines+=("  - LITERAL PII LEAK: \"${pii}\" found in upstream-bound body")
                    pass_this=false
                fi
            done
            if ! grep -qE '\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]' <<< "${upstream_blob}"; then
                verdict_lines+=("  - expected a token-shaped substitution [CATEGORY_<hex>] in upstream body; not present")
                pass_this=false
            fi
        fi
        ;;
    MASK)
        if [[ "${http_code}" != "200" ]]; then
            verdict_lines+=("  - expected HTTP 200 (MASK forwards); got ${http_code}")
            pass_this=false
        fi
        if [[ -z "${upstream_capture_path}" ]]; then
            verdict_lines+=("  - expected an upstream capture for MASK; none found")
            pass_this=false
        else
            IFS=',' read -ra pii_strings <<< "${pii_csv}"
            for pii in "${pii_strings[@]}"; do
                if [[ -n "${pii}" ]] && grep -qF -- "${pii}" <<< "${upstream_blob}"; then
                    verdict_lines+=("  - LITERAL PII LEAK: \"${pii}\" found in upstream-bound body")
                    pass_this=false
                fi
            done
            if ! grep -qE '\[[A-Z][A-Z_]*_REDACTED\]' <<< "${upstream_blob}"; then
                verdict_lines+=("  - expected a mask tag [<CATEGORY>_REDACTED] in upstream body; not present")
                pass_this=false
            fi
        fi
        ;;
    *)
        verdict_lines+=("  - unknown expected action ${expected_action}")
        pass_this=false
        ;;
    esac

    if ${pass_this}; then
        verdict="PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        verdict="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    {
        echo "## ${prompt_name}"
        echo
        echo "**Expected action:** ${expected_action}"
        echo
        echo "**Prompt (truncated to 200 chars):**"
        echo
        echo '```'
        printf '%s\n' "${payload_short}"
        echo '```'
        echo
        echo "**Proxy HTTP status:** ${http_code}"
        echo
        if [[ "${expected_action}" == "BLOCK" ]]; then
            if [[ -z "${upstream_capture_path}" ]]; then
                echo "**Upstream capture:** none (request blocked at proxy, never reached upstream)"
            else
                echo "**Upstream capture (UNEXPECTED for BLOCK):**"
                echo
                echo "  - \`${upstream_capture_path#$ROOT_DIR/}\`"
            fi
        else
            if [[ -n "${upstream_capture_path}" ]]; then
                echo "**Upstream-bound user-message content (what api.anthropic.com received):**"
                echo
                echo '```'
                if [[ -n "${upstream_user_text}" ]]; then
                    printf '%s\n' "${upstream_user_text}" | head -c 800
                    echo
                else
                    echo "(no user-message content extracted; full capture body file below)"
                fi
                echo '```'
                echo
                echo "**Capture file:** \`${upstream_capture_path#$ROOT_DIR/}\`"
            else
                echo "**Upstream capture:** MISSING (expected one for ${expected_action})"
            fi
        fi
        echo
        if ${pass_this}; then
            echo "**Verdict: PASS**"
        else
            echo "**Verdict: FAIL**"
            echo
            for line in "${verdict_lines[@]}"; do
                echo "${line}"
            done
        fi
        echo
        echo "---"
        echo
    } >> "${SUMMARY}"

    touch "${SUMMARY}"
done

{
    echo "## Run summary"
    echo
    echo "Total prompts: ${PROMPT_COUNT}"
    echo "Pass:          ${PASS_COUNT}"
    echo "Fail:          ${FAIL_COUNT}"
    echo
    if [[ "${FAIL_COUNT}" -eq 0 ]]; then
        echo "**Result: VERIFIED.** Every prompt produced the expected wire outcome:"
        echo "BLOCK prompts never reached the upstream; TOKENIZE / MASK prompts"
        echo "reached the upstream with the literal PII absent and the substitution"
        echo "shape present."
    else
        echo "**Result: NOT VERIFIED.** ${FAIL_COUNT} of ${PROMPT_COUNT} prompts produced"
        echo "an unexpected wire outcome. See per-prompt verdict details above."
    fi
} >> "${SUMMARY}"

echo
echo "Summary written to: ${SUMMARY}"
echo "${PASS_COUNT}/${PROMPT_COUNT} pass, ${FAIL_COUNT} fail."
exit "${FAIL_COUNT}"
