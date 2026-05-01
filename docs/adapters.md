# PromptGuard Adapter Framework

PromptGuard has two adapter layers, each with its own contract:

1. **Detectors** decide what is sensitive. Output is a list of spans.
2. **Policy sources** decide what to do about it. Output is a `Policy`.

This document is the operator-facing spec for both. Day 6-7's deliverable.

## Detector adapters

```
DetectorAdapter (abstract base)
├── RegexDetector              # in-process; deterministic shape match
├── OPFDetector                # HTTP -> opf-service container
├── PresidioDetector           # HTTP -> presidio-analyzer container
└── LLMJudgeDetector           # skeleton at v1; real impl Day 8
```

### Contract

A `DetectorAdapter` produces zero or more `Detection` spans for a given input text. Four binding rules:

1. **Span-based output.** Each `Detection` is `{category, start, end, matched_text, confidence, detector}`. `matched_text` MUST equal `text[start:end]` verbatim.
2. **Category mapping discipline.** Output is a `Category` enum value. Adapters wrapping a third-party detector document their label-to-category mapping inline; unknown labels map to `Category.OTHER`.
3. **Deterministic-ish.** Same input + same adapter + same process yields the same span set. Adapters wrapping non-deterministic models (LLM judge) MUST set a deterministic seed where the model exposes one.
4. **Failure isolation.** Adapters MAY raise; the pipeline isolates exceptions per adapter so one detector failing does not abort the others.

### Naming

Lowercase, no spaces. Standard names: `regex`, `opf`, `presidio`, `llm_judge`. The name appears in audit logs and on each `Detection.detector` field, so operators can grep by detector cleanly.

### Adding a new detector

```python
from promptguard.detectors.base import DetectorAdapter

class MyDetector(DetectorAdapter):
    name = "my_detector"

    async def detect(self, text: str) -> list[Detection]:
        ...
```

Then either inject it into the pipeline directly (in tests) or register it in `pipeline_factory.build_pipeline_from_policy` (in the proxy). v1 hardcodes the four shipped detectors; v1.1 may switch to entry-point registration.

## Policy source adapters

```
PolicyAdapter (abstract base)
├── LocalYAMLPolicy            # reference, default
├── GitManifestPolicy          # signed-manifest pull, scaffold for v1.1
├── PurviewDLPPolicy           # Microsoft Purview DLP integration, sample SIT export
└── ICAPPolicy                 # ICAP servers (Symantec/Forcepoint/Trellix), sample fixture
```

### Contract

A `PolicyAdapter` produces a `Policy` instance ready for the action engine. Three binding rules:

1. **Same shape, same target.** Every adapter returns a `Policy` (not a vendor-specific dict). The action engine never sees the source format.
2. **Schema validation is the adapter's job.** The adapter translates from the source format (YAML, JSON, XML, ICAP wire, Purview API JSON) to PromptGuard categories and actions. On malformed input, raise `PolicySchemaError` with a message that includes the source location (line / column for textual sources, field path for structured sources).
3. **Fail loud, never silent.** Misconfigured policy at startup means the proxy refuses to start. Adapters MUST raise on failure rather than returning an empty or default-allow policy.

### One-line config swap

The proxy reads `PROMPTGUARD_POLICY_SOURCE` and `PROMPTGUARD_POLICY_FILE` at startup. Switching from local YAML to a Purview SIT export is one env var change.

```bash
# Default: local YAML
docker compose up -d --wait

# Or: Purview SIT export (v1 ships with the sample fixture)
PROMPTGUARD_POLICY_SOURCE=purview_dlp \
PROMPTGUARD_POLICY_FILE=/app/tests/fixtures/purview/sample-sit-export.json \
    docker compose up -d --wait

# Or: ICAP-recorded response
PROMPTGUARD_POLICY_SOURCE=icap \
PROMPTGUARD_POLICY_FILE=/app/tests/fixtures/icap/sample-rules-response.txt \
    docker compose up -d --wait
```

Valid `PROMPTGUARD_POLICY_SOURCE` values:

| Source         | What it reads                                 | v1 status |
|----------------|-----------------------------------------------|-----------|
| `local_yaml`   | Path to a YAML policy file (default)          | Reference |
| `purview_dlp`  | Path to a Purview SIT export JSON             | Stub: parsing real, Graph fetch is v1.1 |
| `icap`         | Path to a recorded ICAP response file         | Stub: parsing real, network call is v1.1 |
| `git_manifest` | Repo URL for signed policy manifest           | Skeleton: raises NotImplementedError; v1.1 |

### Sample import file formats

#### Purview SIT export (JSON)

Path: `tests/fixtures/purview/sample-sit-export.json`. Synthetic, ships with the repo. Shape:

```json
{
  "policyName": "...",
  "policyVersion": "...",
  "informationTypes": [
    {
      "id": "...",
      "displayName": "...",
      "promptguardCategory": "<one of the Category enum values>",
      "recommendedAction": "BLOCK | MASK | TOKENIZE | ALLOW",
      "minConfidence": 0.95,
      "description": "..."
    }
  ]
}
```

Each `informationType` translates to one `PolicyRule`. Each `promptguardCategory` must appear at most once (one rule per category, by design). Unknown categories or actions raise `PolicySchemaError`.

The `_v1_1_todo` field in the shipped fixture documents the v1.1 work: live fetch from `GET /security/informationProtection/sensitivityLabels` via Graph API, with service-principal auth.

#### ICAP rules response (PromptGuard intermediate format)

Path: `tests/fixtures/icap/sample-rules-response.txt`. Synthetic, ships with the repo. Shape:

```
ICAP/1.0 200 OK
Server: ...
Content-Type: application/x-promptguard-rules+text
Content-Length: ...

# comments OK
<category>\t<action>\t<min_confidence>
<category>\t<action>\t<min_confidence>
...
```

The body is tab-separated. `min_confidence` is optional (default 0.0). Real ICAP integrations (Symantec, Forcepoint, Trellix) translate vendor-specific bodies to this intermediate format inside their respective v1.1 adapter implementations; v1 ships the parser for the intermediate format only.

### Adding a new policy source

```python
from promptguard.policies.base import PolicyAdapter
from promptguard.core.policy import Policy

class MyPolicy(PolicyAdapter):
    name = "my_source"

    def __init__(self, source_arg: str) -> None:
        ...

    def load(self) -> Policy:
        ...
```

Then register the source in `promptguard.policies.factory._build`. v1 keeps the registry hardcoded for clarity; v1.1 may switch to entry-point registration.

## Hot-reload across adapters

`PROMPTGUARD_POLICY_RELOAD_INTERVAL_S` (DEC-016) is adapter-agnostic. The reloader stats the `PROMPTGUARD_POLICY_FILE` path; on mtime change, it calls the configured adapter's `load()` again. A YAML edit reloads the YAML; a Purview fixture edit reloads the Purview translation. Schema-error rejection works the same way for every adapter because they share the `PolicySchemaError` raise path.

Real Graph API / ICAP server polling for live policy changes is v1.1; v1 hot-reload watches a local file regardless of adapter type.

## Audit conformance

`tests/unit/test_detector_adapter_contract.py` and `tests/unit/test_policy_adapters.py` are the conformance suites. Every shipped adapter is required to pass:

- Subclass check against the abstract base.
- `name` class attribute, lowercase, no spaces.
- Output type and shape invariants (`matched_text == text[start:end]` for detectors; `Policy` instance for policy sources).
- Schema-error path for invalid inputs.

Adding a new adapter requires adding it to the `parametrize` lists in those tests so its conformance is checked automatically.
