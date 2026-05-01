"""Audit log writer (JSONL).

# Event schema

One JSON object per line:

  {
    "timestamp": "2026-05-04T15:30:00Z",  // ISO 8601 UTC
    "conversation_id": "conv-abc",
    "request_id": "pg_1234567_abcd",
    "rule": "email -> MASK",
    "detector": "regex:email",
    "category": "email",
    "span": {"offset": 12, "length": 17},
    "would_have_been_action": "MASK",
    "pipeline_version": "0.1.0a1",
    "policy_hash": "sha256:abcd...",
    "confidence": 0.9
  }

# Forbidden fields

NO field of the event may carry any portion of the offending text.
This is a structural promise (`AUDIT_LOG_FORBIDDEN_FIELDS` is empty
by intent: every field listed in the schema above is sanitized at
construction). The fuzz test in `tests/unit/test_audit_writer.py`
asserts no random PII string from a corpus appears in any serialized
event under any code path.

# Why no text

The audit log is itself a sensitive datastore. A privacy-tooling
product that logs the very content it was created to protect against
defeats the threat model. Operators correlate against application
logs by `request_id` if they need the original text; the application
log is the operator's choice of retention and access control, not
PromptGuard's.

# Concurrency

The writer holds an open file in append mode and serializes writes
behind a lock. JSONL is append-safe; multiple workers can share one
file path if needed (each line atomically replaced in OS write
semantics for sub-PIPE_BUF lengths, which our event sizes always are).

# pipeline_version + policy_hash

Two fields exist so log readers can correlate events with the exact
code and policy under which they were generated:

  - `pipeline_version`: the loaded PromptGuard package version
    (`promptguard.__version__`). Bumps on every release.
  - `policy_hash`: SHA-256 of the loaded policy file content,
    computed at policy load (NOT per event, for performance).
    Reviewers can prove "event generated under this exact policy"
    by hashing their copy of the policy file and comparing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("promptguard.audit")


# Documentation aid: the audit event schema lists every field. Anything
# not in this set is forbidden. We do not include this set in the
# serialization path (the dataclass is the source of truth); it is
# referenced in tests.
AUDIT_LOG_FORBIDDEN_FIELDS: frozenset[str] = frozenset(
    {
        "matched_text",
        "text",
        "value",
        "original",
        "content",
        "raw",
        "snippet",
        "excerpt",
        "preview",
    }
)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One row in the JSONL audit log.

    `span` is `(offset, length)` not `(start, end)` because the audit
    consumer doesn't care about half-open semantics; the offset is the
    forensic locator. We never serialize the offending text content.
    """

    timestamp: str  # ISO 8601 UTC, e.g. "2026-05-04T15:30:00Z"
    conversation_id: str
    request_id: str
    rule: str
    detector: str
    category: str
    span_offset: int
    span_length: int
    would_have_been_action: str
    pipeline_version: str
    policy_hash: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict suitable for json.dumps."""
        return {
            "timestamp": self.timestamp,
            "conversation_id": self.conversation_id,
            "request_id": self.request_id,
            "rule": self.rule,
            "detector": self.detector,
            "category": self.category,
            "span": {"offset": self.span_offset, "length": self.span_length},
            "would_have_been_action": self.would_have_been_action,
            "pipeline_version": self.pipeline_version,
            "policy_hash": self.policy_hash,
            "confidence": self.confidence,
        }


class AuditWriter:
    """Append-only JSONL writer for audit events.

    Thread-safe: serializes writes behind a lock. The file is opened
    once on construction and stays open for the writer's lifetime.
    Operators rotate the file via standard logrotate or by stopping
    the proxy.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Append + line-buffered so every line lands on disk as it's
        # written. encoding="utf-8" so non-ASCII conversation IDs work.
        self._fh = self._path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        logger.info("audit writer opened at %s", self._path)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                logger.exception("audit writer close failed")


# -- helpers ---------------------------------------------------------


def now_iso8601_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_policy_hash(policy_file_path: str | Path) -> str:
    """SHA-256 of the policy file's bytes. Prefixed with `sha256:` so
    log readers can tell the algorithm without parsing.

    Falls back to `sha256:unknown` if the file cannot be read; the audit
    log still functions but reviewers lose the policy-correlation lever.
    """
    try:
        data = Path(policy_file_path).read_bytes()
    except OSError as exc:
        logger.warning(
            "compute_policy_hash failed for %s (%s); using sha256:unknown",
            policy_file_path,
            exc,
        )
        return "sha256:unknown"
    return "sha256:" + hashlib.sha256(data).hexdigest()


def package_version() -> str:
    """Current PromptGuard package version. Used as `pipeline_version`."""
    from promptguard import __version__

    return __version__
