# CLAUDE.md — PromptGuard Autonomy Guidelines

Read this at the start of every Claude Code session.

## Project context

PromptGuard is a local LLM proxy that prevents PII and sensitive data from leaving developer machines. Deploy-in-minutes UX, multi-stage detection (regex + OPF + Presidio + opt-in LLM judge), configurable per-pattern actions (BLOCK/MASK/TOKENIZE).

- **Owner:** Mahdi Hedhli (github.com/MahdiHedhli, 42 Holdings)
- **Timeline:** 14 calendar days from kickoff (2026-04-30)
- **License:** Apache 2.0
- **Target shipping audience:** CISOs and security engineers, not hobbyists

## Required reading at session start

Before any code changes, read in this order:

1. `docs/research-notes.md` — all locked architectural decisions, threat model, roadmap
2. This file (`CLAUDE.md`)
3. `reports/` — the most recent daily report
4. `decisions/` — all autonomous decisions logged so far

If any of these contradict each other, the locked decisions in research-notes.md win. If something seems wrong, escalate.

## Autonomy boundaries

### Decide autonomously, log to `decisions/`
- Implementation details (libraries, code patterns, file organization within established architecture)
- Test strategy specifics
- Bug fixes and refactoring
- Documentation wording
- Choice between equivalent technical approaches
- Performance optimizations within stated budgets
- Naming of internal symbols, modules, fixtures

### Escalate (write to daily report under "Blockers requiring input")
- Decisions contradicting locked decisions in research-notes.md
- Architectural choices not already covered
- License or legal questions
- Public-facing naming, branding, or marketing copy
- Anything requiring credentials, accounts, or external paid resources
- A blocker preventing forward progress for more than 2 hours

Default toward decide-and-log. Don't paralyze on small choices.

## Quality standards

### Code
- Apache 2.0 compatible dependencies only. Reject GPL, AGPL, source-available, custom-restrictive licenses.
- Type hints on all public interfaces.
- Tests for everything in `src/`. No exceptions.
- No silent failures. Explicit error handling. Failures get logged and surfaced.
- No hardcoded secrets, paths, or tenant IDs. Use config + env vars.
- No hardcoded customer/example PII in test data. Use fixtures or generators.

### Testing
- Unit tests for all detector adapters and policy adapters.
- Integration tests for the proxy + detection pipeline end-to-end.
- Benchmark suite that runs against AI4Privacy PII-Masking-300k (eval subset) and arxiv 2410.23657 secrets corpus.
- A phase is NOT done until: tests pass, benchmark numbers recorded, daily report written, decisions logged.

### Style
- Direct, technical writing in comments and docs.
- **No mid-sentence em dashes anywhere.** Mahdi specifically dislikes them as an LLM tell. Use commas, colons, parens, or sentence breaks.
- No marketing language. No "blazingly fast", "cutting-edge", "revolutionary", "seamlessly".
- Code comments explain WHY, not WHAT.
- Production-quality, not prototype-quality.

### Git
- Commit locally only. Do not push to a remote without explicit Mahdi approval.
- Commit messages reference phase and decision IDs where relevant: `[phase-3] [DEC-007] reversible tokenization round-trip`
- Each commit should leave the build green.

## Operating procedure

### Each working session
1. Read CLAUDE.md, research-notes.md, latest daily report, recent decision logs.
2. Identify current phase from roadmap (research-notes.md section 9).
3. Work through phase deliverables.
4. Run tests after each substantial change.
5. At session end (or end of working day): write daily report.

### Daily report
- Path: `reports/YYYY-MM-DD.md`
- Template: `reports/TEMPLATE.md`
- Required every working day, even on days with little progress (especially those days).
- Mahdi pastes this back to the planning chat. It must be useful at a glance.

### Decision logs
- Path: `decisions/NNN-short-title.md`
- Template: `decisions/TEMPLATE.md`
- Numbered sequentially.
- Logged for any non-trivial choice. Better to over-log than under-log.

## When stuck

1. Try the obvious approach first.
2. If it fails, document why and try the alternative.
3. After 2 hours of no progress, write up the blocker in the daily report and continue with other roadmap items.
4. Don't silently fail. Don't fake-complete. Document what's broken and move on.

## Things Mahdi specifically wants to see in reports

- FP/FN data on every detection change, not vibes.
- Latency p50/p95/p99 on every change touching the request path.
- Honest reporting of what didn't work and why.
- Code snippets and design diagrams that will become blog post material.
- Trajectory assessment: on-track / behind / ahead, with reasoning.

## Failure modes to avoid

- Over-engineering. Ship the simple version, iterate. Don't build configurability for cases nobody asked for.
- Rabbit holes on a single problem. Timebox to 2 hours, then move on or escalate.
- Silent regressions. If a benchmark number gets worse, surface it.
- Placeholder data left in production paths. If you put a TODO, log a decision or a blocker.
- Generating code that "looks right" but isn't tested end-to-end. Run it.
- Adding dependencies for things the standard library handles fine.
