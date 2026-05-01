"""mitmproxy addon for PromptGuard wire-verification.

Positioned between the LiteLLM container and the upstream provider
(api.anthropic.com or wherever LiteLLM is configured to send). Captures
every request and response body so the operator can inspect what
actually leaves the proxy.

Important constraints:

  1. The Authorization header is redacted to last 4 chars in capture
     output. API keys never land on disk even if the operator inspects.
  2. The flow's full URL, method, status code, headers (with
     Authorization redacted), and prettified body land in
     ./local/mitm-captures/<UTC-timestamp>-<flow-id>-{req,resp}.json.
  3. Every request emits one line of console output: timestamp, method
     URL, body size, count of suspicious-pattern matches.
     Suspicious patterns are SANITY HEURISTICS only (raw IPv4,
     raw email, raw PEM-key marker). They are NOT detection.
     The point is "did anything obvious leak."
  4. The addon fails loudly if it cannot write captures (no silent
     "looks clean" output).
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from mitmproxy import http
from mitmproxy.script import concurrent

CAPTURES_DIR = Path(os.environ.get("PROMPTGUARD_MITM_CAPTURES_DIR", "/captures"))

SUSPICIOUS_PATTERNS = {
    "raw_ipv4_rfc1918": re.compile(
        r"\b(?:"
        r"10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r")\b"
    ),
    "raw_email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "raw_pem_marker": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----"),
    "raw_aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
}


def _ensure_captures_dir() -> None:
    """Create captures dir on first event. Fails loudly if we cannot
    write; the brief explicitly says silent passthrough is worse than
    failure."""
    try:
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        # Probe write access by touching a sentinel file.
        sentinel = CAPTURES_DIR / ".write-probe"
        sentinel.write_text("ok", encoding="utf-8")
        sentinel.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"PromptGuard MITM addon cannot write to {CAPTURES_DIR} ({exc}). "
            "Refusing to silently pass traffic through; check the volume mount."
        ) from exc


def _redact_auth(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            tail = v[-4:] if len(v) >= 4 else "?"
            out[k] = f"<redacted last 4: {tail}>"
        elif kl == "x-api-key":
            tail = v[-4:] if len(v) >= 4 else "?"
            out[k] = f"<redacted last 4: {tail}>"
        else:
            out[k] = v
    return out


def _try_pretty_json(raw: bytes) -> Any:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(raw)} bytes binary>"
    if not decoded.strip():
        return ""
    try:
        return json.loads(decoded)
    except json.JSONDecodeError:
        return decoded


def _scan_suspicious(body: bytes) -> dict[str, int]:
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return {}
    return {
        name: len(pattern.findall(text))
        for name, pattern in SUSPICIOUS_PATTERNS.items()
        if pattern.search(text) is not None
    }


def _now_utc() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def load(loader: Any) -> None:
    _ensure_captures_dir()


@concurrent
def request(flow: http.HTTPFlow) -> None:
    _ensure_captures_dir()
    flow_id = flow.id[:8]
    ts = _now_utc()
    body_bytes = flow.request.get_content() or b""
    capture = {
        "phase": "request",
        "timestamp_utc": ts,
        "flow_id": flow.id,
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": flow.request.host,
        "headers": _redact_auth(dict(flow.request.headers)),
        "body_size_bytes": len(body_bytes),
        "body": _try_pretty_json(body_bytes),
    }
    suspicious = _scan_suspicious(body_bytes)
    capture["suspicious_pattern_counts"] = suspicious
    out_path = CAPTURES_DIR / f"{ts}-{flow_id}-req.json"
    out_path.write_text(
        json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    flag = " " if not suspicious else " *** SUSPICIOUS: " + ",".join(
        f"{k}={v}" for k, v in suspicious.items()
    ) + " ***"
    print(
        f"[mitm-verify {ts}] {flow.request.method} {flow.request.pretty_url} "
        f"body_size={len(body_bytes)}{flag}",
        flush=True,
    )


@concurrent
def response(flow: http.HTTPFlow) -> None:
    _ensure_captures_dir()
    flow_id = flow.id[:8]
    ts = _now_utc()
    body_bytes = flow.response.get_content() if flow.response else b""
    capture = {
        "phase": "response",
        "timestamp_utc": ts,
        "flow_id": flow.id,
        "request_url": flow.request.pretty_url,
        "status_code": flow.response.status_code if flow.response else None,
        "headers": _redact_auth(
            dict(flow.response.headers) if flow.response else {}
        ),
        "body_size_bytes": len(body_bytes),
        "body": _try_pretty_json(body_bytes),
    }
    suspicious = _scan_suspicious(body_bytes)
    capture["suspicious_pattern_counts"] = suspicious
    out_path = CAPTURES_DIR / f"{ts}-{flow_id}-resp.json"
    out_path.write_text(
        json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    flag = " " if not suspicious else " *** SUSPICIOUS in response: " + ",".join(
        f"{k}={v}" for k, v in suspicious.items()
    ) + " ***"
    print(
        f"[mitm-verify {ts}] <- {flow.response.status_code if flow.response else '???'} "
        f"body_size={len(body_bytes)}{flag}",
        flush=True,
    )
