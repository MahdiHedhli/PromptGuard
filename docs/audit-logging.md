# PromptGuard audit logging

PromptGuard's audit log is a JSONL file recording what would have happened under the active policy when a rule has `audit_only` mode enabled. It is operator-facing forensic data: enough to reconstruct what fired, never enough to reconstruct the user's text.

## When events are written

Two granularities (DEC-019):

1. **Policy-wide:** `audit_only: true` at the policy level. Every rule defaults to audit-only; events emit, no enforcement happens. Use during initial policy bring-up.
2. **Per rule:** `audit_only: true` (or `false`) inside an individual rule. Per-rule wins over policy-level. Useful for the workflow "audit-only this one rule for two weeks then promote".

When a rule is in audit-only mode:

- The detection pipeline runs as normal.
- The action engine computes the would-be decision per detection (BLOCK / MASK / TOKENIZE).
- The proxy forwards the **original** request to the upstream LLM unmodified for that rule's findings.
- One audit event is appended to the log per non-ALLOW detection.

When a rule is in enforce mode (the default), it applies its action: rewrites for MASK/TOKENIZE or rejects with the BLOCK envelope. No audit events emitted.

Audit and enforce can mix on a single request. A BLOCK-enforce on a credential blocks the request, and an audit-only email rule emits its events for the same request so operators see everything that fired.

## Event schema

JSONL, one event per line. Compact JSON encoding (no whitespace).

```json
{
  "timestamp": "2026-05-04T15:30:00Z",
  "conversation_id": "conv-abc",
  "request_id": "pg_1234567_abcd",
  "rule": "email -> MASK",
  "detector": "regex:email",
  "category": "email",
  "span": {"offset": 12, "length": 17},
  "would_have_been_action": "MASK",
  "pipeline_version": "0.1.0a1",
  "policy_hash": "sha256:abcdef0123456789...",
  "confidence": 0.9
}
```

| Field                      | Type    | Notes |
|----------------------------|---------|-------|
| `timestamp`                | string  | ISO 8601 UTC, second precision. |
| `conversation_id`          | string  | From the request body's `metadata.conversation_id`, or the request_id if not set. |
| `request_id`               | string  | PromptGuard's internal request ID (`pg_<unix>_<hex>`). |
| `rule`                     | string  | `<category> -> <action>` shorthand for fast grepping. |
| `detector`                 | string  | Which detector fired (`regex:email`, `opf:private_name`, etc). |
| `category`                 | string  | One of the `Category` enum values. |
| `span`                     | object  | `{offset: int, length: int}`. Forensic locator. |
| `would_have_been_action`   | string  | `BLOCK`, `MASK`, or `TOKENIZE`. |
| `pipeline_version`         | string  | The PromptGuard package version that produced the event. Bumps on every release. |
| `policy_hash`              | string  | SHA-256 of the policy file content at load time. Lets reviewers prove "event generated under this exact policy" by hashing their own copy. |
| `confidence`               | number  | Detector-reported confidence, rounded to 4 decimal places. |

## What is NOT in the event

The audit log MUST NOT contain any portion of the offending text. This is a structural promise enforced by the writer's schema and verified by a fuzz test (`tests/unit/test_audit_writer.py::test_fuzz_no_offending_text_in_audit_events`) that injects 200 random PII-like strings into prompts and asserts none appear verbatim in the resulting log file.

The reasoning: a privacy-tooling product that logs the very content it was created to protect against defeats the threat model. The audit log is itself a sensitive datastore (threat-model A6), and an audit log carrying the offending content is a worse forensic liability than the original prompt because it concentrates flagged text in a structured, indexable form.

If operators need the original text for an investigation, they correlate by `request_id` against the application log on their side. The application's retention and access controls govern that data, not PromptGuard's.

Do not add fields like `matched_text`, `text`, `value`, `original`, `content`, `raw`, `snippet`, `excerpt`, or `preview` to the audit event. The set `AUDIT_LOG_FORBIDDEN_FIELDS` in `promptguard.audit.writer` documents the names; tests assert events do not include them.

## Configuration

| Env var                       | Default                       | Effect |
|-------------------------------|-------------------------------|--------|
| `PROMPTGUARD_AUDIT_LOG_PATH`  | `./promptguard-audit.log`     | File path. Created with parent directories if missing. |

Enable audit-only mode in policy YAML:

```yaml
name: audit-bringup
audit_only: true
detectors:
  regex:     { enabled: true }
  opf:       { enabled: true }
  presidio:  { enabled: true }
  llm_judge: { enabled: false }
rules:
  - { category: email,         action: MASK }
  - { category: cloud_api_key, action: BLOCK }
  - { category: internal_ip,   action: TOKENIZE }
```

## Concurrency and rotation

The writer holds the file open in append mode and serializes writes behind a lock. Multiple in-process callers can share one writer; multiple processes pointing at the same file is supported by OS append semantics (each line is short enough that POSIX guarantees atomic append).

Rotation is the operator's choice. `logrotate(8)` configurations work: rename the file out of the way, signal the proxy to restart (or rely on hot-reload to pick up a new file), and the next event opens a fresh file.

## Hot-reload and audit_only

Policy hot-reload (DEC-016) honors changes to `audit_only`. Flipping a running policy from `audit_only: false` to `true` (by editing the YAML and saving) turns enforcement off and starts emitting audit events on the next request. Flipping back resumes enforcement. The same audit log file receives events across reloads; correlation by `policy_hash` lets reviewers separate events by policy version.

## Programmatic access

The writer is at `promptguard.audit.AuditWriter`. Construction takes a path; `write(event)` appends one event. The `AuditEvent` dataclass is the schema. Unit tests demonstrate the contract.

## Verifying the no-text invariant locally

```bash
.venv/bin/pytest tests/unit/test_audit_writer.py::test_fuzz_no_offending_text_in_audit_events -v
```

The test runs 200 iterations with random PII-like strings and asserts no sample appears in the resulting log file content. Increase the iteration count by editing the test if your security review wants stronger evidence.
