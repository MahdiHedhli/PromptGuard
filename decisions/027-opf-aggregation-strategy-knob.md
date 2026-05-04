# DEC-027: OPF aggregation-strategy knob and the default-vs-recall-tuned investigation

**Date:** 2026-05-04
**Status:** Accepted
**Phase:** v1.1.2 (pre-release cleanup)
**Author:** MahdiHedhli

---

## Context

The v1.1.1 sprint (DEC-026) shipped real-corpus benchmark numbers
against AI4Privacy English using OPF at its default operating point.
The v1.1.2 brief required adding a recall-tuned operating point so
the published numbers surface the precision / recall trade-off OPF
offers rather than picking one in the dark.

The HuggingFace token-classification pipeline behind OPF
(`openai/privacy-filter`) accepts an `aggregation_strategy`
parameter that controls how token-level outputs aggregate into
entity spans. Four valid values: `simple` (current default),
`max`, `first`, `average`. They differ in how same-entity adjacent
tokens merge and how the final span score is computed.

v1.1's OPF service hardcoded `aggregation_strategy="simple"` at
container startup. No way to compare without rebuilding the
container. v1.1.2 needed a clean knob.

A second issue surfaced while wiring the knob: the v1.1
`OPF_LABEL_TO_CATEGORY` map missed three labels the model emits.
`private_person` was collapsing to OTHER instead of mapping to
PRIVATE_NAME. `private_url` was collapsing to OTHER instead of
mapping to DOMAIN. `private_id` was correctly OTHER but had to be
made explicit. Detections were still happening, but they audit-
logged under OTHER rather than the intended category. The bug did
not affect F1 because Presidio's PERSON recognizer + the action
engine's `_select_outer_spans` (DEC-023) collapsed overlapping
spans to one detection regardless of category source. But the
audit log clarity was wrong: an operator looking at OPF detections
to understand what fired would see OTHER instead of PRIVATE_NAME.

## Options considered

### Option 1: Add `aggregation_strategy` as a per-request body field (chosen)
- Pros: Lets the harness A/B between strategies in the same process.
  Pipeline cached per-strategy in service memory so the second
  request after a strategy switch is fast. Operator can change
  strategy via service-level env var (`OPF_AGGREGATION`) or
  per-request body (`{"aggregation_strategy": "max"}`).
- Cons: Adds an opt-in field to the API surface. Still backward
  compatible (None falls back to service default).

### Option 2: Pure environment-variable knob, no per-request control
- Pros: Simpler API. One global setting per container.
- Cons: A/B benchmarking would require two containers running
  simultaneously, doubling RAM (the model is ~3 GB). Or container
  restarts between runs, which lose the warm cache.

### Option 3: Run a sweep at HF model-load time (preload all four pipelines)
- Pros: Zero per-request cost when switching strategy. All four
  pipelines preloaded.
- Cons: 4x memory cost (~12 GB) just to support an opt-in operator
  setting. v2 if recall-tuned mode becomes default; v1.1.2 lazy-
  loads on first request per strategy and that is sufficient.

## Decision

Adopt option 1. Pass-through field on POST /detect; pipelines lazy-
loaded per strategy and cached in process memory. Default behavior
unchanged; operators opt into the alternative via either the body
field or the `OPF_AGGREGATION` env var. The benchmark harness gains
a `promptguard_full_recall_tuned` pipeline that uses `max`.

Also fix the `OPF_LABEL_TO_CATEGORY` map:

```
private_person -> PRIVATE_NAME
private_url    -> DOMAIN
private_id     -> OTHER (no v1 vocabulary match; explicit so it does
                         not silently default into OTHER via missing
                         key fallback)
```

## Findings on AI4Privacy English

Direct A/B test on a sample sentence shows the strategies do produce
different spans:

- `simple` returns two email fragments and two phone fragments
  (sub-token boundaries).
- `max` returns one merged email span and one merged phone span.

But at span-IoU >= 0.5 (the harness's match threshold) the F1
numbers are byte-identical between `simple` and `max` on the
7,946-record AI4Privacy English corpus:

| Category | `simple` F1 | `max` F1 |
|---|---:|---:|
| email | 0.658 | 0.658 |
| private_address | 0.358 | 0.358 |
| private_name | 0.273 | 0.273 |
| private_phone | 0.306 | 0.306 |

**Why identical?** The longest `simple` fragment of an email gold
span (16 of 19 characters) clears IoU 0.5 by itself. Both strategies
produce one matching detection per gold span at this threshold.
At stricter thresholds (IoU 0.8) the merged `max` span would still
match while the longest `simple` fragment would no longer clear.

Operator takeaway: at the published AI4Privacy benchmark threshold,
strategy choice does not move F1. For use cases that require
stricter span fidelity, `max` produces cleaner contiguous spans and
should be preferred. v1.2 sweep across (strategy x IoU threshold)
will quantify the trade-off frontier.

## Consequences

### Enables
- The published benchmark numbers honestly surface that strategy
  choice does not affect F1 at the standard threshold; operators
  do not have a hidden lever to tune.
- Stricter-span-fidelity downstream use cases can opt into `max`
  per-request without any service-level configuration.
- Audit-log clarity: OPF detections of names, URLs land in
  PRIVATE_NAME / DOMAIN instead of OTHER.

### Constrains
- The OPF service caches one HF pipeline per strategy in memory;
  if all four strategies get used in one process the RAM cost is
  4x the single-strategy cost (~12 GB). Default operation loads
  one strategy and stays at the documented ~3 GB RSS.
- The label-map fix is a behavioral change: detections previously
  audit-logged under OTHER now audit-log under PRIVATE_NAME /
  DOMAIN. Operators with audit-log dashboards filtered on OTHER
  for OPF detections will see those rows move.

### Revisit if
- The v1.2 IoU-sweep finds a strategy that materially lifts F1
  at IoU >= 0.5. Then default would change.
- A new OPF model release ships different label names; the
  label-map needs reaudit.

## Implementation notes

- Service: `src/promptguard/services/opf_service/server.py`. New
  `_pipes: dict[str, Any]` cache, `ALLOWED_AGGREGATIONS` allowlist,
  `aggregation_strategy` field on `DetectRequest`. `/ready` endpoint
  reports `loaded_aggregations` so an operator can see which
  pipelines are warm.
- Detector: `src/promptguard/detectors/opf.py`. New constructor
  parameter `aggregation_strategy` (None → service default).
  Request body conditionally includes the field.
- Harness: `benchmarks/run_real_corpus_benchmarks.py`. New pipeline
  name `promptguard_full_recall_tuned` configures the OPF detector
  with `aggregation_strategy="max"`.
- Backward compatibility: clients that do not send
  `aggregation_strategy` see the v1.1 behavior unchanged. The new
  `/ready` field is additive.
