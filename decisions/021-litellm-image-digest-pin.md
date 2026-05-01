# DEC-021: Pin LiteLLM image to digest, not floating tag

**Date:** 2026-05-07
**Status:** Accepted
**Phase:** v1 (packaging polish)
**Author:** MahdiHedhli

---

## Context

v1 daily report flagged "LiteLLM image is `main-stable` floating tag;
want a digest pin pre-ship?" as an open question. the v1 plan approved
the pin as packaging polish.

A floating tag like `main-stable` resolves to whatever digest the
upstream registry has at pull time. Builds against the same Dockerfile
on different days can produce different runtime behavior. The v1
DEC-002 already cited reproducibility as a v1.1 / packaging-polish
concern; this DEC closes it.

## Decision

Pin via SHA-256 digest in `docker/litellm/Dockerfile`:

  FROM ghcr.io/berriai/litellm@sha256:<digest>

The pinned digest is the one we built against on v1 (v1 daily
report includes the cold-start measurement, which would otherwise be
unreproducible). To bump: `docker pull ghcr.io/berriai/litellm:main-stable`,
read the resolved digest from `docker images --digests`, replace the
`LITELLM_DIGEST` build arg in the Dockerfile.

## Consequences

### Enables
- Reproducible builds across machines and dates.
- v1 cold-start, latency, and integration test numbers are
  reproducible by anyone who clones the repo.

### Constrains
- Operators who want the latest LiteLLM features have to bump the
  digest manually. Documented in the Dockerfile comment.
- A digest bump is now an explicit decision, not a side effect of
  rebuild timing.

### Revisit if
- We need to react quickly to a LiteLLM CVE; the bump is a one-line
  change.
- LiteLLM ships a new feature we depend on; same one-line change.

## Implementation notes

- `docker/litellm/Dockerfile`: `ARG LITELLM_DIGEST=...` then
  `FROM ghcr.io/berriai/litellm@${LITELLM_DIGEST}`.
- `docker-compose.yml`: build args section updated; explicit override
  path documented in a comment.
- The digest pin does not affect `mock-anthropic` (we build that image
  ourselves) or the OPF service (also built locally).
