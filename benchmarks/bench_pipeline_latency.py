"""Latency benchmark: detection + action engine on a synthetic PII prompt.

Compares:
  * Day-1 baseline: RegexDetector raw `detect_sync` over the prompt
  * Day-2 path:    DetectionPipeline (regex only) + ActionEngine.apply
                   with the default policy. Includes JSON-safe extract /
                   rewrite via the proxy.messages helpers.

Run:
    PYTHONPATH=src .venv/bin/python benchmarks/bench_pipeline_latency.py

Prints n, prompt length, and p50/p95/p99/avg in ms for each path.
"""

from __future__ import annotations

import asyncio
import statistics
import time

from promptguard.actions import ActionContext, ActionEngine
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Action, Category, Policy, PolicyRule
from promptguard.detectors.regex_detector import RegexDetector
from promptguard.proxy.messages import (
    extract_inspectable_strings,
    join_for_inspection,
    set_at_path,
    split_after_inspection,
)


SAMPLE_PROMPT = (
    "Hi team, please debug this for user jane.doe@example.com on host 10.0.13.42. "
    "Connection: postgres://app:s3cret@db.internal/app_prod . "
    "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.aBcDeFgHiJk_LmNoPqR. "
    "Cluster URL https://api.example.com (api ref). "
    "Also AWS key AKIAIOSFODNN7EXAMPLE was leaked yesterday. "
)


def _quantile(samples: list[float], q: float) -> float:
    samples = sorted(samples)
    if not samples:
        return 0.0
    idx = max(0, min(len(samples) - 1, int(round((len(samples) - 1) * q))))
    return samples[idx]


def _summary(label: str, samples_ms: list[float]) -> None:
    p50 = _quantile(samples_ms, 0.50)
    p95 = _quantile(samples_ms, 0.95)
    p99 = _quantile(samples_ms, 0.99)
    avg = statistics.fmean(samples_ms)
    print(
        f"{label:32s}  n={len(samples_ms)}  "
        f"avg={avg:.3f}ms  p50={p50:.3f}ms  p95={p95:.3f}ms  p99={p99:.3f}ms"
    )


def _bench_day1_regex_only(prompt: str, n: int) -> list[float]:
    det = RegexDetector()
    det.detect_sync(prompt)  # warm
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        det.detect_sync(prompt)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


async def _bench_day2_pipeline(prompt: str, n: int) -> list[float]:
    """End-to-end pipeline + action-engine + JSON-safe extract/rewrite path."""
    pipeline = DetectionPipeline([RegexDetector()])
    policy = Policy(
        name="bench",
        rules=[
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.CLOUD_API_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.DATABASE_URL, action=Action.BLOCK),
            PolicyRule(category=Category.JWT, action=Action.BLOCK),
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE),
            PolicyRule(category=Category.DOMAIN, action=Action.TOKENIZE),
        ],
    )
    engine = ActionEngine(policy)
    body = {"messages": [{"role": "user", "content": prompt}]}
    # warm
    await pipeline.detect_all(prompt)
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        # Mimic the LiteLLM hook path end-to-end: extract, join, detect,
        # action engine, split, set_at_path. This is what every real request
        # incurs.
        local = {"messages": [{"role": "user", "content": prompt}]}
        paths_and_strings = extract_inspectable_strings(local)
        joined = join_for_inspection([s for _p, s in paths_and_strings])
        detections = await pipeline.detect_all(joined)
        result = engine.apply(
            joined,
            detections,
            ActionContext(conversation_id="bench", request_id=f"r{_}"),
        )
        if not result.blocked:
            parts = split_after_inspection(
                result.rewritten_text, len(paths_and_strings)
            )
            for (path, _orig), new_value in zip(paths_and_strings, parts, strict=True):
                set_at_path(local, path, new_value)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


def main() -> None:
    n = 1000
    print(
        f"prompt_len_chars={len(SAMPLE_PROMPT)}  "
        f"n={n}  python=cpython-3.11"
    )
    print("-" * 80)
    day1 = _bench_day1_regex_only(SAMPLE_PROMPT, n)
    _summary("day1: RegexDetector.detect_sync", day1)
    day2 = asyncio.run(_bench_day2_pipeline(SAMPLE_PROMPT, n))
    _summary("day2: pipeline + engine + JSON", day2)
    delta_avg = statistics.fmean(day2) - statistics.fmean(day1)
    print("-" * 80)
    print(f"delta_avg = {delta_avg:+.3f} ms (overhead vs day1)")


if __name__ == "__main__":
    main()
