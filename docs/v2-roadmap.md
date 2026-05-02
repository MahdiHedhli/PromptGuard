# PromptGuard v2 roadmap

v1.1 is the first publicly-defensible release. The items below are deferred
out of v1.1 to keep the public surface narrow and focused on the segments
PromptGuard already covers cleanly (API/CLI traffic, developer machines).
v2 is engagement-driven: shipped on demand, not built up-front.

## Microsoft Purview integration

Translate Microsoft Purview Sensitive Information Types (SITs) into
PromptGuard `Policy` objects via the Microsoft Graph API. v1.1 ships the
`PolicyAdapter` ABC that real integration will satisfy. Real network
calls and tenant authentication are v2.

## ICAP integration

Route detection through an ICAP server so existing DLP appliances
participate in the decision. v1.1 ships the `PolicyAdapter` ABC; the
real ICAP client lives in v2.

## Centralized proxy mode

A multi-tenant deployment shape: PromptGuard hosted as a service rather
than a per-developer-machine local proxy. Mobile clients are addressed
here. The TokenMap durability story changes (Redis-backed instead of
in-memory) and the threat model gains a "tenant isolation" attack class.

## Browser extension

API/CLI coverage solves the bigger part of the prompt-egress problem,
but browser-based ChatGPT and Claude.ai are out of scope at v1.1. A
browser extension is on the v2 roadmap to close that gap.

## Image and file uploads

v1 inspects text only. Image / file scanning (PDFs, screenshots,
attachments) is structurally a different detection problem and is on
the v2 list.

## LLM judge: async / batch mode

DEC-025 removed the inline LLM judge after v1.1 validation. Detection
capability is real (qwen2.5:7b + tightened prompt: 100% recall lift on
paraphrased PII at 0% FP). The latency budget rules out the inline path;
an async / batch / offline mode that runs the judge against audit-eligible
requests after the fact is a v2 candidate. The validation harness shape
and the v2 prompt template are preserved in DEC-025.

## Audit log size-based rotation

v1.1 ships the JSONL audit writer; rotation is the operator's concern
(logrotate works). A built-in size-based rotation with retention rules
is a v2 polish item.

## Per-conversation policy override

A header like `x-promptguard-policy: pentest-engagement` to pick a
non-default policy on a per-request basis. Currently rejected on threat-
model grounds (too easy to abuse). Revisit if the operator workflow
demands it.

## TokenMap durability across process restart

v1.1's TokenMap is in-memory only. A persistent, encrypted-at-rest
TokenMap is a v2 candidate when centralized-proxy mode arrives.
