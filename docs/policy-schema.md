# PromptGuard Policy Schema

This document is the canonical reference for PromptGuard policy YAML files.

A policy specifies two things:

1. Which detectors run (`detectors`).
2. Which action applies to each PII / secret category (`rules`).

A policy is loaded by the `LocalYAMLPolicy` adapter at proxy startup. Schema errors are surfaced with file path, line and column, field path, and the offending value, so an operator can fix the file directly without hunting.

## Top-level keys

| Key          | Type    | Default     | Description |
|--------------|---------|-------------|-------------|
| `name`       | string  | (required)  | Operator-friendly name. Echoed in BLOCK error envelopes. |
| `version`    | string  | `"1"`       | Operator-managed; bump to invalidate cache, audit. |
| `audit_only` | boolean | `false`     | When `true`, every detection is logged, no rewrite or block applies. |
| `detectors`  | mapping | (see below) | Per-detector enable flags. |
| `rules`      | list    | `[]`        | Per-category action overrides. |

Unknown top-level keys are rejected. Unknown keys inside `detectors` or `rules` items are rejected. Strict-by-default validation prevents typos like `dector:` from silently falling back to defaults.

## `detectors`

```yaml
detectors:
  regex:     { enabled: true }
  opf:       { enabled: true }
  presidio:  { enabled: true }
  llm_judge: { enabled: false }
```

Defaults match the v1 shipping posture: regex, OPF, Presidio enabled; LLM judge off (research-notes Decision 6). At v1 there are no per-detector parameters; all per-detector tuning lives on the detector side. v1.1 will add confidence thresholds and per-recognizer toggles.

Hard-fail behavior at startup:

- If `opf.enabled = true` and the OPF service does not return 200 from `/ready` within 5 seconds, the proxy refuses to start with the message:

  ```
  OPF model not available at $url. Refusing to start pipeline. To run
  without OPF detection, set detectors.opf.enabled = false in your policy file.
  ```

- If `llm_judge.enabled = true`, the proxy refuses to start. The LLM judge ships in v1.1.

- If every detector is disabled, the proxy refuses to start. PromptGuard with no detectors would forward all traffic unchecked, which contradicts the threat-model promise.

## `rules`

Each rule maps a category to an action, with an optional confidence floor:

```yaml
rules:
  - category: private_key
    action: BLOCK
  - category: email
    action: MASK
    min_confidence: 0.6
```

`category` must be one of:

| Category          | What it covers                                        |
|-------------------|-------------------------------------------------------|
| `private_key`     | PEM-format private keys                               |
| `cloud_api_key`   | AWS / GCP / Azure credentials                         |
| `database_url`    | postgres / mysql / mongodb / redis URLs               |
| `jwt`             | JSON Web Tokens                                       |
| `secret`          | Slack tokens, GitHub PATs, generic secrets            |
| `email`           | Email addresses                                       |
| `domain`          | Hostnames matching the conservative TLD list          |
| `internal_ip`     | RFC 1918 private IPv4                                 |
| `customer_name`   | Custom Presidio recognizer for org-specific names     |
| `private_name`    | OPF / Presidio person-name detection                  |
| `private_phone`   | OPF / Presidio phone detection                        |
| `private_address` | OPF / Presidio address detection                      |
| `account_number`  | Credit card / SSN / IBAN / OPF account_number         |
| `other`           | Catch-all for unmapped detector outputs               |

`action` must be one of `BLOCK`, `MASK`, `TOKENIZE`, `ALLOW`. Categories without a rule default to `ALLOW`.

`min_confidence` is a float in [0.0, 1.0]. A detection below the floor falls back to `ALLOW` for that category. Default 0.0 (no floor).

## Schema errors

Loaders use a line-tracking YAML parser. A typo produces:

```
policy file: /etc/promptguard/policies/default.yaml
  at line 7, column 12 (rules.2.action): Input should be 'BLOCK',
  'MASK', 'TOKENIZE' or 'ALLOW'; got 'REJECT'
```

Errors include line, column, field path, the validation message, and the offending value. Operators can navigate directly to the broken line.

## Worked examples

Three sample policies ship in `policies/`:

- [`default.yaml`](../policies/default.yaml): the locked mapping in research-notes section 5.
- [`nda-strict.yaml`](../policies/nda-strict.yaml): contractual workflows. Customer names, emails, and account numbers escalate to `BLOCK`.
- [`healthcare-leaning.yaml`](../policies/healthcare-leaning.yaml): PHI-adjacent workflows. Personal identifiers `MASK` (no token-map ledger), credentials `BLOCK`.

To add a custom policy, copy one of these into `policies/` (or any path mounted into the LiteLLM container) and point the proxy at it:

```bash
PROMPTGUARD_POLICY_FILE=/app/policies/my-policy.yaml docker compose up -d
```
