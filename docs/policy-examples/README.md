# Reference policies

Three policies ship in `policies/`:

| File | Audience |
|---|---|
| `default.yaml` | The recommended starting point: layered detection on, structured-secret categories block, PII categories tokenize. |
| `regex-only.yaml` | Air-gapped / restricted-egress hosts. OPF and Presidio off; structured-secret coverage unchanged. |
| `pentest-engagement.yaml` | Engagement-time policy that lets test data through while still blocking real-customer leak shapes. |

The reference policies in this directory are scenario examples. They illustrate
how to express a posture but are not in the shipped enable-out-of-the-box set;
copy and adapt as needed.

| File | Scenario |
|---|---|
| `healthcare-leaning.yaml` | PHI-flavored posture: medical record numbers, conditions, demographics tokenized; structured secrets blocked. |
| `nda-strict.yaml` | Maximum strictness: TOKENIZE rules promoted to BLOCK on every sensitive category. |
| `passthrough-test.yaml` | All detectors disabled. Only useful for measuring overhead-free baselines. |

To activate any of these, copy to your operator-controlled directory and point
the proxy at it:

```
PROMPTGUARD_POLICY_FILE=/path/to/your-copy.yaml docker compose up -d
```

`promptguard validate-policy` checks the schema before activation:

```
uv run python -m promptguard.cli validate-policy /path/to/your-copy.yaml
```

`promptguard policy-diff` shows what would change behaviorally between two
policy files:

```
uv run python -m promptguard.cli policy-diff policies/default.yaml /path/to/your-copy.yaml
```
