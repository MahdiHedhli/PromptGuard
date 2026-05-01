# DEC-005: Use Presidio Analyzer, not Presidio Anonymizer

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** v1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

The bootstrap prompt lists "Presidio analyzer + anonymizer (containerized)" as a v1 service. Microsoft Presidio ships two complementary services: the analyzer (detects entity spans) and the anonymizer (rewrites them according to operators).

Our action engine has its own semantics (BLOCK / MASK / TOKENIZE) with specific properties that Presidio's anonymizer vocabulary does not directly model:
- TOKENIZE is reversible per-conversation. Tokens are unguessable random IDs scoped to a conversation; restoration is pure substitution by the proxy on the streamed response.
- MASK leaves no ledger anywhere. The original is dropped at the action boundary.
- BLOCK rejects the request entirely with a structured violation.

Presidio anonymizer's operators (`replace`, `redact`, `hash`, `encrypt`, `mask`) overlap partially but do not match. Worse, encrypt-with-key produces a reversible mapping owned by Presidio rather than us, which violates threat-model A6 (token-map ledger as attack surface).

## Decision

PromptGuard runs Presidio Analyzer only. The anonymizer service is not in the docker-compose stack. PromptGuard's own `ActionEngine` performs all rewriting.

## Consequences

### Enables
- Single source of truth for action semantics. The threat-model claims about reversibility, ledger ownership, and per-conversation scoping live in our code, not in Presidio's.
- Easier to reason about TOKENIZE attack surface (DEC- forthcoming on v1).

### Constrains
- We give up Presidio anonymizer's tested operator set; we re-implement equivalents under our semantics.

### Revisit if
- We ever need to hand a payload to a downstream system that consumes Presidio's exact format.

## Implementation notes

- `docker-compose.yml` exposes only `presidio-analyzer:latest`. Anonymizer is intentionally omitted.
- `PresidioDetector` calls `/analyze`. There is no call to `/anonymize`.
- README's architecture section documents the deliberate omission.
