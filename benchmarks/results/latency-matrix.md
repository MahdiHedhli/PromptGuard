# Latency matrix (v1, in-process)

Prompt length: 305 chars. n=1000 samples per config.

| Configuration | n | avg | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| baseline_regex_only | 1000 | 0.146 ms | 0.069 ms | 0.182 ms | 1.671 ms |
| regex_engine_enforce | 1000 | 0.305 ms | 0.298 ms | 0.545 ms | 1.008 ms |
| regex_engine_audit_only | 1000 | 0.606 ms | 0.316 ms | 0.911 ms | 3.469 ms |

Engine + JSON-safe overhead vs baseline regex: +0.159 ms avg.
Audit writer overhead on top of engine: +0.301 ms avg.
