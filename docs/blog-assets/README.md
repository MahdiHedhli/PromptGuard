# Blog assets

Pre-collected artifacts for the v1 launch blog post. One bullet per file:
filename, what it shows, where it slots into the blog outline (research-notes
section 14).

The outline numbering tracks `docs/research-notes.md` section 14:

> 1. Hook (NDA problem reframed)
> 2. Why Rama's pattern approach is right v0 / wrong v1
> 3. Threat model
> 4. Three architectural axes
> 5. Local proxy + central policy sync
> 6. Multi-stage detection
> 7. OpenAI Privacy Filter spotlight
> 8. Three actions: BLOCK / MASK / TOKENIZE
> 9. Adapter framework + DLP integration
> 10. The LLM judge
> 11. Repo, deployment, what's next

## Catalog

- **[01-tokenize-roundtrip-user-terminal.txt](01-tokenize-roundtrip-user-terminal.txt)**: terminal capture of a real claude CLI session through the PromptGuard proxy. User sees their original IP and hostnames in the response. Slots into **section 8** (TOKENIZE round-trip). Pair with asset 02.
- **[02-tokenize-roundtrip-upstream-view.json](02-tokenize-roundtrip-upstream-view.json)**: upstream-side capture from the integration test fixture (`mock-anthropic`'s `/_test/last_received` endpoint). Shows what the upstream provider actually received: tokens, never originals. Slots into **section 8** as the "split-screen" visual paired with asset 01.
- **[03-real-anthropic-roundtrip.txt](03-real-anthropic-roundtrip.txt)**: directional capture annotated for honesty. Shows that PromptGuard tokenized the user's IP before the upstream saw it, and that PromptGuard does not mangle upstream provider errors when they happen. Does NOT prove the reverse path because the model paraphrased rather than echoing the token verbatim. See asset 04 for the canonical end-to-end visual.
- **[04-claude-cli-roundtrip.txt](04-claude-cli-roundtrip.txt)**: canonical end-to-end TOKENIZE round-trip. Real claude CLI v2.x against real api.anthropic.com via the digest-pinned LiteLLM proxy. mitmproxy capture proves the upstream saw the token (not the IP), the model echoed the token verbatim, the reverse path restored the original to the user's terminal, and claude CLI's SSE parser accepted the restored stream without the "Content block is not a text block" error that v1 deferred. Slots into **section 8** as the headline visual.

## Capture protocol

New blog-quotable artifacts (benchmark numbers, code snippets,
screenshots, latency charts) land here with a numbered filename and a
one-line entry in the catalog above. The README is the master index.

## Pending captures

- Latency p50/p95/p99 chart from the real-corpus benchmarks.
- Side-by-side regex / OPF / Presidio / layered F1 numbers from the
  real-corpus benchmarks (per-pipeline, per-category).
- Schema-error UX example: `at line 7, column 12 (rules.2.action): ... got 'REJECT'` (slots into the policy-schema sidebar).
