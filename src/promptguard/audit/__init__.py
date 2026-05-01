"""Audit log writer.

When `policy.audit_only: true`, the action engine runs in dry-run mode:
detections fire, decisions are computed, but the request is forwarded
unmodified and an event is appended to the audit log instead.

The audit log is JSONL, one event per line. Each event carries enough
forensic information to reconstruct what would have happened, but
NEVER contains the offending text. The audit log is itself a sensitive
datastore (threat-model A6); including the text it was created to
protect against would defeat the purpose.
"""

from promptguard.audit.writer import (
    AUDIT_LOG_FORBIDDEN_FIELDS,
    AuditEvent,
    AuditWriter,
    compute_policy_hash,
    now_iso8601_utc,
    package_version,
)

__all__ = [
    "AUDIT_LOG_FORBIDDEN_FIELDS",
    "AuditEvent",
    "AuditWriter",
    "compute_policy_hash",
    "now_iso8601_utc",
    "package_version",
]
