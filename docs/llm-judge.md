# PromptGuard LLM judge

Stage-4 detector. Off by default. When operators enable it,
PromptGuard makes one HTTP call per request to a local Ollama server
and asks a small instruction-tuned model to flag PII / secrets the
deterministic stages may have missed.

## When to enable it

Turn the judge on if your prompts routinely contain paraphrased PII or
adversarially-worded secrets that escape the regex / OPF / Presidio
layers. Common triggers:

- Conversational PII: "the user lives roughly downtown, near the train station"
- Phone numbers spelled out: "nine fifty five, six two two, eighty seven thirty"
- Customer names rendered as initials or codenames not in the Presidio recognizers
- Adversarial reformulations of secrets ("base64 of the key starts with QU...")

Leave the judge OFF if your prompts are mostly structured (code, docs,
tabular data) or if you cannot tolerate the latency / model-quality
risk. The earlier stages cover most of what an LLM judge would
otherwise catch.

## Latency

The judge adds one HTTP round-trip plus model inference time per
request. With a 3B-parameter quantized model on CPU, expect ~200-800ms
per call; on GPU, 50-150ms. The configurable timeout (default 2s)
puts an upper bound on the wait.

If the judge times out or Ollama is unreachable, the adapter returns
zero detections. The pipeline keeps the regex / OPF / Presidio
findings; the judge being a backstop is by design.

## Recommended models

Tested with Ollama-served models. Pick by latency-quality trade-off:

| Model                                | Size    | Notes |
|--------------------------------------|---------|-------|
| `llama3.2:3b-instruct-q4_K_M`        | ~2 GB   | Default. Fast on CPU; reliable JSON output. |
| `llama3.2:1b-instruct-q4_K_M`        | ~700 MB | Fastest; lower recall on subtle paraphrasing. |
| `qwen2.5:3b-instruct`                | ~2 GB   | Strong instruction-following; tolerable JSON output. |
| `mistral-nemo:12b-instruct-q4_K_M`   | ~7 GB   | Highest recall; slowest on CPU. |

Set the model with `PROMPTGUARD_LLM_JUDGE_MODEL`. Pull it once with
`docker exec -it promptguard-ollama ollama pull <model>` (assuming
you have an Ollama container in your stack; see deployment notes).

## False positive / false negative tendencies

Day-9 benchmarks will quote concrete F1 numbers. Expected behavior
based on early integration testing:

- **FP**: small models tend to over-flag generic phrases as "secret"
  or "private_name" when prompted aggressively. Mitigated by the
  default prompt's strict category list.
- **FN**: small models miss steganographic PII (e.g. names embedded
  inside acronyms, deliberate misspellings).

The judge runs alongside the deterministic stages. Its findings ADD to
the layered output; they do not replace earlier-stage findings.

## Prompt template

Default prompt template ships in
`src/promptguard/detectors/llm_judge.py` as `DEFAULT_PROMPT_TEMPLATE`.
The template is single-shot, structured, and asks for JSON-only output.

### Override

Operators with strict requirements can override the template via
`PROMPTGUARD_LLM_JUDGE_PROMPT_PATH=<file>`. The file is a Python
`str.format()` template. Argument `{0}` is the user text. The template
SHOULD instruct the model to output ONLY a JSON array of
`{"category", "start", "end"}` objects; any other output is treated as
zero findings.

Example minimal override:

```text
Find PII in the input. Return JSON array of spans (no prose).
Schema: [{"category": "...", "start": int, "end": int}, ...]
INPUT: {0}
```

## Configuration

| Env var                                  | Default                                  | Effect |
|------------------------------------------|------------------------------------------|--------|
| `PROMPTGUARD_OLLAMA_URL`                 | `http://ollama:11434`                    | Ollama server URL |
| `PROMPTGUARD_LLM_JUDGE_MODEL`            | `llama3.2:3b-instruct-q4_K_M`            | Model name |
| `PROMPTGUARD_LLM_JUDGE_TIMEOUT_S`        | `2.0`                                    | Per-request timeout in seconds |
| `PROMPTGUARD_LLM_JUDGE_PROMPT_PATH`      | (unset)                                  | Optional prompt-template file path |

Enable in policy:

```yaml
detectors:
  llm_judge:
    enabled: true
```

## Testing

CI tests use canned mock Ollama responses (see
`tests/unit/test_llm_judge.py`). They cover happy path, malformed
output, partial validity, timeout, HTTP error, unknown category,
out-of-range spans, and empty input.

### Opt-in real-Ollama integration test

If you want to verify against a real Ollama server, bring it up
locally:

```bash
docker run --rm -d --name ollama -p 11434:11434 ollama/ollama:latest
docker exec -it ollama ollama pull llama3.2:3b-instruct-q4_K_M

PROMPTGUARD_OLLAMA_URL=http://localhost:11434 \
    .venv/bin/python -c "
import asyncio
from promptguard.detectors.llm_judge import LLMJudgeDetector
async def main():
    d = LLMJudgeDetector()
    print(await d.detect('Email me at noreply@example.com please'))
    await d.aclose()
asyncio.run(main())
"
```

## Tolerance posture

The judge is the most failure-prone detector in the pipeline by design:
local model availability, version drift, output-shape variance. The
adapter therefore returns zero detections for any of: HTTP error,
timeout, malformed output, top-level object instead of array,
partially-invalid items. Each failure path logs a warning at INFO
level so operators can spot recurring issues; none of them break the
pipeline.

The deterministic stages stay correct without the judge. The judge is
a recall booster, not a precision floor.
