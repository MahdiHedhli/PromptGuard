"""LLMJudgeDetector tests.

Validates:
  * happy path: model returns a JSON array with valid spans
  * malformed output: zero detections, no exception
  * partially valid output: invalid items dropped, valid items kept
  * timeout: zero detections, no exception
  * HTTP error from Ollama: zero detections, no exception
  * unknown category: maps to Category.OTHER
  * out-of-range / inverted spans: dropped silently

All tests use respx to mock the Ollama HTTP endpoint. CI never reaches
a real Ollama; the v1 plan explicitly says "tests use canned mock
LLM responses, NOT real Ollama calls".

For an opt-in real-Ollama integration test, see docs/llm-judge.md.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from promptguard.core.policy import Category
from promptguard.detectors.llm_judge import LLMJudgeDetector


def _ollama_response(text: str) -> httpx.Response:
    """Wrap a model output string into Ollama's /api/generate envelope."""
    return httpx.Response(200, json={"model": "test", "response": text, "done": True})


@respx.mock
async def test_judge_happy_path_emits_detections() -> None:
    text = "Email me at noreply@example.com please"
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response(
            json.dumps([{"category": "email", "start": 12, "end": 31}])
        )
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect(text)
    await judge.aclose()
    assert len(detections) == 1
    d = detections[0]
    assert d.category == Category.EMAIL
    assert d.matched_text == text[d.start : d.end]
    assert d.detector == "llm_judge:email"


@respx.mock
async def test_judge_handles_prose_around_json_array() -> None:
    """Some models add explanatory prose. The parser must extract the array."""
    text = "The host is 10.0.0.5"
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response(
            "Sure, here is the JSON:\n"
            + json.dumps([{"category": "internal_ip", "start": 12, "end": 20}])
            + "\nLet me know if you need more."
        )
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect(text)
    await judge.aclose()
    assert len(detections) == 1
    assert detections[0].category == Category.INTERNAL_IP


@respx.mock
async def test_judge_malformed_output_returns_empty() -> None:
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response("this is not json and there is no array here")
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect("anything")
    await judge.aclose()
    assert detections == []


@respx.mock
async def test_judge_top_level_object_not_array_returns_empty() -> None:
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response('{"category": "email", "start": 0, "end": 5}')
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    assert await judge.detect("anything") == []
    await judge.aclose()


@respx.mock
async def test_judge_drops_out_of_range_spans() -> None:
    text = "short"  # length 5
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response(
            json.dumps(
                [
                    {"category": "email", "start": 0, "end": 100},  # end out of range
                    {"category": "email", "start": -1, "end": 3},  # negative start
                    {"category": "email", "start": 3, "end": 1},  # inverted
                    {"category": "email", "start": 0, "end": 5},  # OK
                ]
            )
        )
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect(text)
    await judge.aclose()
    assert len(detections) == 1
    assert detections[0].matched_text == "short"


@respx.mock
async def test_judge_unknown_category_maps_to_other() -> None:
    text = "abc"
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response(
            json.dumps([{"category": "made_up_category", "start": 0, "end": 3}])
        )
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect(text)
    await judge.aclose()
    assert len(detections) == 1
    assert detections[0].category == Category.OTHER


@respx.mock
async def test_judge_timeout_returns_empty_no_exception() -> None:
    respx.post("http://ollama.test/api/generate").mock(
        side_effect=httpx.TimeoutException("simulated timeout")
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test", timeout_s=0.1)
    detections = await judge.detect("anything")
    await judge.aclose()
    assert detections == []


@respx.mock
async def test_judge_http_500_returns_empty_no_exception() -> None:
    respx.post("http://ollama.test/api/generate").mock(
        return_value=httpx.Response(500, text="Ollama exploded")
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect("anything")
    await judge.aclose()
    assert detections == []


@respx.mock
async def test_judge_connection_error_returns_empty_no_exception() -> None:
    respx.post("http://ollama.test/api/generate").mock(
        side_effect=httpx.ConnectError("simulated")
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect("anything")
    await judge.aclose()
    assert detections == []


@respx.mock
async def test_judge_empty_input_short_circuits() -> None:
    """The judge must NOT call Ollama on empty input."""
    route = respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response("[]")
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    assert await judge.detect("") == []
    await judge.aclose()
    assert route.call_count == 0


@respx.mock
async def test_judge_skips_partially_invalid_items() -> None:
    text = "Email noreply@example.com on 2026-01-01"
    respx.post("http://ollama.test/api/generate").mock(
        return_value=_ollama_response(
            json.dumps(
                [
                    {"category": "email", "start": 6, "end": 25},  # OK
                    "not an object",  # dropped
                    {"category": "email"},  # missing start/end -> dropped
                    {"start": 0, "end": 5},  # missing category -> dropped
                    {"category": "email", "start": "0", "end": "5"},  # OK after int coerce
                ]
            )
        )
    )
    judge = LLMJudgeDetector(base_url="http://ollama.test")
    detections = await judge.detect(text)
    await judge.aclose()
    assert len(detections) == 2  # only the two valid ones
