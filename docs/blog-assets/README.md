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
- **[03-real-anthropic-roundtrip.txt](03-real-anthropic-roundtrip.txt)**: PARTIAL real-Anthropic capture. The free-tier API key had zero credit on Day 6 so the upstream returned a "credit balance too low" error before generating a response. The artifact still shows one useful thing for **section 8**: PromptGuard does NOT mangle upstream provider errors. The Anthropic-shaped error reached the user verbatim, which means our error envelope only owns our own BLOCK path; everything else passes through unmodified.

## Capture protocol

Per `~/.claude/projects/.../memory/feedback_blog_asset_protocol.md`:
whenever I produce something blog-quotable (benchmark numbers, code
snippets that illustrate a design point, screenshots, latency charts),
drop it here with a numbered filename and a one-line entry above. The
README stays the master index.

## Pending captures

- Real-Anthropic full round-trip (deferred until the free-tier account has credit).
- Latency p50/p95/p99 chart from Day 9 benchmarks.
- Side-by-side regex / OPF / Presidio / layered F1 numbers from Day 9 benchmarks.
- Schema-error UX example: `at line 7, column 12 (rules.2.action): ... got 'REJECT'` (slots into the policy-schema sidebar).
