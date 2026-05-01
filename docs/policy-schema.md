# PromptGuard Policy Schema

This document is the canonical reference for PromptGuard policy YAML files.

A policy specifies two things:

1. Which detectors run (`detectors`).
2. Which action applies to each PII / secret category (`rules`).

A policy is loaded by the `LocalYAMLPolicy` adapter at proxy startup. Schema errors are surfaced with file path, line and column, field path, and the offending value, so an operator can fix the file directly without hunting.

## Top-level keys

| Key          | Type    | Default     | Description |
|--------------|---------|-------------|-------------|
| `name`       | string  | (required)  | Operator-friendly name. Echoed in BLOCK error envelopes (`error.promptguard.policy_name`). |
| `version`    | string  | `"1"`       | Operator-managed. Bump to invalidate any external cache that keys on policy identity. Echoed in BLOCK error envelopes. |
| `audit_only` | boolean | `false`     | When `true`, every detection is logged, no rewrite or block applies. v1 ships the field; the full audit-log writer lands in v1.1. |
| `detectors`  | mapping | (see below) | Per-detector enable flags. Strict-extra: unknown sub-keys are rejected. |
| `rules`      | list    | `[]`        | Per-category action overrides. An empty list means every category falls back to `ALLOW`. |

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

Five sample policies ship in `policies/`:

- [`default.yaml`](../policies/default.yaml): the locked mapping in research-notes section 5. Use this when in doubt.
- [`nda-strict.yaml`](../policies/nda-strict.yaml): contractual workflows. Customer names, emails, and account numbers escalate to `BLOCK`. Domain and internal IP de-escalate to `MASK` (no ledger).
- [`healthcare-leaning.yaml`](../policies/healthcare-leaning.yaml): PHI-adjacent workflows. Every personal identifier is `MASK` (no token-map ledger that might exceed retention rules under HIPAA). Credentials `BLOCK`.
- [`pentest-engagement.yaml`](../policies/pentest-engagement.yaml): external security testing under client NDA. Customer infrastructure (domains, internal IPs, codenames, cloud account IDs) all `BLOCK`. Personal identifiers `MASK`.
- [`regex-only.yaml`](../policies/regex-only.yaml): regex stage only, OPF and Presidio disabled. Documented escape hatch for environments without OPF model access (offline install, restricted egress).

To add a custom policy, copy one of these into `policies/` (or any path mounted into the LiteLLM container) and point the proxy at it:

```bash
PROMPTGUARD_POLICY_FILE=/app/policies/my-policy.yaml docker compose up -d
```

## Override mechanism

There is no per-request override mechanism in v1. The active policy is selected at proxy startup and applies to every request that arrives until the proxy restarts. This is intentional:

1. Per-request overrides via headers would be an obvious bypass surface for a malicious or careless tool. PromptGuard is meant to make the policy hard to disable accidentally, not easy.
2. Policy selection is an operator concern, not an application concern. The application sends the same request body it always would; the proxy decides what to do.

Three documented escape hatches exist for the cases where strict enforcement is wrong:

- **`audit_only: true`** in the policy YAML logs every detection but does not rewrite or block. Use during policy bring-up to see what would have fired without disrupting the user. (v1 ships the field; full audit-log writer lands in v1.1 with the audit-log work.)
- **`detectors.opf.enabled: false`** (and the equivalent for `presidio`, `llm_judge`) disables specific detector stages. Useful for offline installs and the `regex-only.yaml` shipped policy.
- **Restart with a different `PROMPTGUARD_POLICY_FILE`** picks up a new policy file.
- **Hot-reload (opt-in, DEC-016).** Set `PROMPTGUARD_POLICY_RELOAD_INTERVAL_S` to a positive float to poll the policy file at that interval. On change the proxy validates, re-probes detector readiness, and atomically swaps the policy. Live conversations keep their TokenMap (reverse mappings stay valid). A broken edit is rejected with the same line + column + field-path error format; the previous policy stays active.

A v1.1 candidate is the **per-conversation override**: a tool could include a header like `x-promptguard-policy: pentest-engagement` to pick a non-default policy on a per-request basis. v1 does not ship this; the threat model rejects per-request overrides as too easy to abuse.

## Error format

When a policy file fails to validate, `LocalYAMLPolicy.load()` raises `PolicySchemaError` with a multi-line message:

```
policy file: /app/policies/default.yaml
  at line 7, column 12 (rules.2.action): Input should be 'BLOCK',
  'MASK', 'TOKENIZE' or 'ALLOW'; got 'REJECT'
```

The error format is:

```
policy file: <path>
  at line <N>, column <M> (<dotted.field.path>): <message>; got <repr-of-value>
```

Multiple validation errors produce multiple `at ...` lines, one per error. The line and column are 1-indexed and refer to the position in the source YAML file. The dotted field path follows pydantic's convention: `rules.0.action` is the `action` field of the first rule; `detectors.opf.enabled` is the `enabled` field of the OPF detector.

When a request is BLOCKed at runtime, the proxy returns HTTP 400 with an envelope shaped to be parseable by both Anthropic and OpenAI clients. See [`docs/research-notes.md`](research-notes.md) section 5 and `src/promptguard/proxy/errors.py`.

## How the proxy validates the schema at startup

The LiteLLM container runs `handler.py` at startup, which builds a `PromptGuardHook` from environment variables. The first thing it does is call `LocalYAMLPolicy(...).load()` against the file pointed to by `PROMPTGUARD_POLICY_FILE`. If validation fails, the exception is uncaught, the handler module fails to import, and LiteLLM startup aborts. This is intentional: a misconfigured policy file means the operator should know before traffic flows.
