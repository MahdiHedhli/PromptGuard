"""Day-9 latency matrix: in-process latency across configurations.

Measures the request-path latency for several configurations:

  baseline            RegexDetector.detect_sync only (Day-1 floor)
  regex+engine        Full DetectionPipeline + ActionEngine + JSON-safe
                      extract/rewrite, regex layer only. Default action
                      mapping: BLOCK on credentials, MASK on email,
                      TOKENIZE on internal IP / domain.
  regex+engine+audit  As above, plus audit_only=True (writer to a
                      tmpfile so disk write cost is included).

Output:
  benchmarks/results/latency-matrix.json
  benchmarks/results/latency-matrix.md

All configurations are in-process; OPF / Presidio / LLM judge add
HTTP-hop costs measured separately (those services need to be
running). End-to-end through the LiteLLM proxy adds a further fixed
overhead (~12ms per Day 5 measurements) that is dominated by
LiteLLM, not PromptGuard.

Re-run from repo root:
  PYTHONPATH=src .venv/bin/python benchmarks/run_latency_matrix.py
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from promptguard.actions import ActionContext, ActionEngine
from promptguard.audit import AuditWriter
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
    s = sorted(samples)
    idx = max(0, min(len(s) - 1, int(round((len(s) - 1) * q))))
    return s[idx]


def _summary(samples_ms: list[float]) -> dict[str, float]:
    return {
        "n": len(samples_ms),
        "avg_ms": round(statistics.fmean(samples_ms), 4),
        "p50_ms": round(_quantile(samples_ms, 0.50), 4),
        "p95_ms": round(_quantile(samples_ms, 0.95), 4),
        "p99_ms": round(_quantile(samples_ms, 0.99), 4),
    }


def _bench_baseline_regex(prompt: str, n: int) -> list[float]:
    """Pure regex detection. Day-1 floor."""
    det = RegexDetector()
    det.detect_sync(prompt)  # warm
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        det.detect_sync(prompt)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


async def _bench_pipeline_engine(
    prompt: str,
    n: int,
    *,
    audit_writer: AuditWriter | None = None,
    audit_only_policy: bool = False,
) -> list[float]:
    """Full pipeline + engine + JSON-safe extract/rewrite path."""
    pipeline = DetectionPipeline([RegexDetector()])
    rules = [
        PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
        PolicyRule(category=Category.CLOUD_API_KEY, action=Action.BLOCK),
        PolicyRule(category=Category.DATABASE_URL, action=Action.BLOCK),
        PolicyRule(category=Category.JWT, action=Action.BLOCK),
        PolicyRule(category=Category.EMAIL, action=Action.MASK),
        PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE),
        PolicyRule(category=Category.DOMAIN, action=Action.TOKENIZE),
    ]
    policy = Policy(name="bench", rules=rules, audit_only=audit_only_policy)
    engine = ActionEngine(
        policy,
        audit_writer=audit_writer,
        pipeline_version="bench",
        policy_hash="sha256:bench",
    )

    # warm
    await pipeline.detect_all(prompt)

    samples: list[float] = []
    for i in range(n):
        t0 = time.perf_counter()
        body = {"messages": [{"role": "user", "content": prompt}]}
        paths_and_strings = extract_inspectable_strings(body)
        joined = join_for_inspection([s for _p, s in paths_and_strings])
        detections = await pipeline.detect_all(joined)
        result = engine.apply(
            joined,
            detections,
            ActionContext(conversation_id="bench", request_id=f"r{i}"),
        )
        if not result.blocked:
            parts = split_after_inspection(
                result.rewritten_text, len(paths_and_strings)
            )
            for (path, _orig), new_value in zip(
                paths_and_strings, parts, strict=True
            ):
                set_at_path(body, path, new_value)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


async def main() -> None:
    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    n = 1000
    print(f"prompt_len_chars={len(SAMPLE_PROMPT)}  n={n}")
    print("-" * 80)

    baseline = _bench_baseline_regex(SAMPLE_PROMPT, n)
    enforce = await _bench_pipeline_engine(SAMPLE_PROMPT, n)
    with tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=".log", prefix="bench-audit-"
    ) as tmpfh:
        tmpfh_path = Path(tmpfh.name)
    audit_writer = AuditWriter(tmpfh_path)
    audit = await _bench_pipeline_engine(
        SAMPLE_PROMPT, n, audit_writer=audit_writer, audit_only_policy=True
    )
    audit_writer.close()

    results = {
        "prompt_length_chars": len(SAMPLE_PROMPT),
        "n_samples": n,
        "configurations": {
            "baseline_regex_only": _summary(baseline),
            "regex_engine_enforce": _summary(enforce),
            "regex_engine_audit_only": _summary(audit),
        },
        "deltas": {
            "engine_overhead_avg_ms": round(
                statistics.fmean(enforce) - statistics.fmean(baseline), 4
            ),
            "audit_writer_overhead_avg_ms": round(
                statistics.fmean(audit) - statistics.fmean(enforce), 4
            ),
        },
        "notes": (
            "All measurements in-process on Apple Silicon (M-series) "
            "CPython 3.11. OPF and Presidio require running services "
            "and are characterized in the latency narrative; their "
            "HTTP hop adds 1-3 ms over loopback when warm. End-to-end "
            "through the LiteLLM proxy adds a further ~12 ms fixed "
            "overhead (Day 5 measurement) that is LiteLLM, not "
            "PromptGuard."
        ),
    }

    raw_path = out_dir / "latency-matrix.json"
    raw_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {raw_path}")

    md_lines = [
        "# Latency matrix (Day 9, in-process)",
        "",
        f"Prompt length: {results['prompt_length_chars']} chars. n={results['n_samples']} samples per config.",
        "",
        "| Configuration | n | avg | p50 | p95 | p99 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, m in results["configurations"].items():
        md_lines.append(
            f"| {label} | {m['n']} | {m['avg_ms']:.3f} ms | {m['p50_ms']:.3f} ms "
            f"| {m['p95_ms']:.3f} ms | {m['p99_ms']:.3f} ms |"
        )
    md_lines.extend([
        "",
        f"Engine + JSON-safe overhead vs baseline regex: "
        f"+{results['deltas']['engine_overhead_avg_ms']:.3f} ms avg.",
        f"Audit writer overhead on top of engine: "
        f"+{results['deltas']['audit_writer_overhead_avg_ms']:.3f} ms avg.",
        "",
    ])
    md_path = out_dir / "latency-matrix.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"wrote {md_path}")
    print()
    print("\n".join(md_lines))

    # Cleanup tempfile.
    tmpfh_path.unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
