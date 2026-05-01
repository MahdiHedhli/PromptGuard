# DEC-003: Regex baseline pattern sourcing and attribution

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** v1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

v1 deliverable 4 calls for a baseline regex pattern set covering PEM keys, AWS / GCP / Azure credentials, DB URLs, JWTs, RFC 1918, domains, emails, and similar. The bootstrap prompt explicitly suggests vendoring from `detect-secrets` and `gitleaks` "where licensing allows."

Constraints:
- Apache 2.0-compatible deps only (CLAUDE.md).
- Patterns are battle-tested elsewhere; rolling our own is wasteful and inferior.

## Options considered

### Option 1: Take a runtime dependency on `detect-secrets` and call its plugins
- Pros: Always up-to-date with upstream additions.
- Cons:
  - Adds heavy plugin loading overhead per call.
  - We would be calling into their plugin classes, which is a different abstraction than our `Detection` shape; integration is awkward.
  - `detect-secrets` plugin classes are stable but not a "library API"; coupling to internals is fragile.

### Option 2: Take a runtime dependency on `gitleaks` (Go binary)
- Pros: Most comprehensive secret rule set in the open-source world.
- Cons: Subprocessing a Go binary from a Python proxy is operationally awkward; not aligned with the in-process detector contract.

### Option 3: Vendor a curated subset of patterns, attribute per-pattern (chosen)
- Pros: Zero runtime deps; patterns live in our repo and are reviewable; clean integration with our `PatternSpec`/`Detection` shape; we control regex flags and confidence per pattern.
- Cons: We have to keep an eye on upstream and pull new patterns when relevant.

## Decision

Vendor a curated subset of regex patterns into `src/promptguard/detectors/regex_patterns.py`. Source attribution is recorded per-pattern via the `source` field on `PatternSpec`. Aggregate attribution is in `/NOTICE`.

Sources used at v1:
- **gitleaks** rules, MIT (Apache 2.0-compatible). Used for AWS, GCP, Azure, JWT, Slack, GitHub PAT, PEM private key shapes.
- **detect-secrets** plugins, Apache 2.0. Used for keyword and DB URL heuristics.
- **Microsoft Presidio** recognizer shapes, MIT. Used as reference for the email pattern.
- **Custom**: RFC 1918 IPv4 octet validation, conservative TLD list for domains, internal-corp / .local / .internal additions.

Confidence scores are conservative. The regex layer is the "shape" floor; OPF (stage 2) and Presidio custom recognizers (stage 3) refine context.

## Consequences

### Enables
- Zero-cost secret detection at the request edge.
- License compliance with one-time per-pattern attribution.
- Easy iteration: a new pattern is one PR with a `PatternSpec`.

### Constrains
- We carry the cost of tracking upstream changes.
- Pattern coverage is intentionally narrower than full gitleaks; we cover the common cases listed in the bootstrap, not every cloud provider's quirky token format.

### Revisit if
- A benchmark run (v1) shows the regex layer is missing a high-incidence secret class on the GitHub-Issues-Secrets corpus.
- Upstream gitleaks releases a comprehensive pattern set under a friendlier-to-vendor format (e.g., a JSON manifest).

## Implementation notes

- `regex_patterns.PATTERNS` is a tuple of `PatternSpec` objects. New patterns append to the tuple; tests in `tests/unit/test_regex_detector.py` cover positive and negative cases.
- The `aws_secret_access_key` and `azure_ad_client_secret` patterns have low confidence (0.7 and 0.55) because base64-shape collisions are common; they exist as warnings, not as ironclad blocks.
- The domain pattern uses a conservative TLD list. v1.1 should swap it for a public-suffix-list-based check.
- Patterns that fire on plain prose are tested for in `test_regex_negative` to guard against false positives shipping accidentally.
