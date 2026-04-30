# PromptGuard Threat Model

This document is standalone. It assumes no prior context about PromptGuard or the wider research notes.

## What PromptGuard is

PromptGuard is a local proxy for outbound LLM API traffic. AI tooling on a developer's machine is configured to send requests through PromptGuard instead of directly to the upstream provider. PromptGuard inspects each prompt, applies a policy, and either forwards it (possibly rewritten), masks parts of it, swaps sensitive spans for round-trippable tokens, or blocks the request entirely.

## What PromptGuard defends against

### A1. Inadvertent disclosure by cooperative-but-fallible users

A developer pastes credentials, a customer record, an internal IP, or a snippet of confidential source into a prompt without realizing the implication. The user is not malicious, but the data should not have left the host.

**Mitigation:** layered detection (regex for structured secrets, OPF for context-aware PII, Presidio for org-specific entities) with default policies that BLOCK credentials and MASK or TOKENIZE personal data before the request leaves the host.

### A2. NDA / contractual exposure

A developer is working with client data that the contract prohibits sharing with a third-party LLM provider. The current LLM provider is not covered by the NDA chain.

**Mitigation:** policies can be authored at the org level (via the `GitManifestPolicy` adapter or the Purview / ICAP integrations) so that contract-driven rules apply uniformly across developers and tools, not per-machine.

### A3. Regulatory exposure

PHI (HIPAA), PCI cardholder data, ITAR-controlled descriptions, GDPR-protected personal data flow to a non-compliant processor. The provider may be technically capable but not contractually compliant for that data class.

**Mitigation:** healthcare-leaning, NDA-strict, and other domain policies ship as starting points. Detection categories map onto regulatory categories (account_number, private_email, private_address) so policy authors can reason about coverage.

### A4. Compromised LLM provider

The upstream provider suffers a breach, retains data longer than promised, or receives a subpoena that exposes prompt content. Anything that left the host is now out of the user's control.

**Mitigation:** "data not sent" is the only durable mitigation. PromptGuard's primary value is reducing what leaves the host in the first place.

### A5. Policy drift

A developer (or a tool acting on their behalf) reconfigures the local environment to bypass PromptGuard, perhaps by setting `ANTHROPIC_BASE_URL` back to the upstream or unsetting it.

**Mitigation:** v1 ships an audit log. Policy attestation, EDR integration, and reporting are deferred to v1.1+. The primary defense at v1 is awareness, not enforcement.

### A6. Token-map ledger as an attack surface

This one is specific to PromptGuard's reversible TOKENIZE action. To restore tokenized values in streaming LLM responses, PromptGuard maintains a per-conversation map of `token -> original`. That map is itself a sensitive datastore: it is subject to subpoena, may exceed retention windows under some compliance regimes, and is a high-value target for an attacker who has gained local access.

**Mitigation:** for any data class where the ledger itself is the threat (PHI, regulated identifiers, anything with a strict retention requirement), the default action is MASK rather than TOKENIZE. MASK leaves no ledger because the original value is not retained anywhere. TOKENIZE is reserved for data classes where workflow continuity outweighs ledger risk (internal hostnames, codenames, domains used as analysis context).

### A7. Prompt-injection-driven manipulation of restoration logic

A malicious LLM response could try to manipulate the substitution that restores tokenized values, for example by emitting a chosen token to surface another conversation's secret.

**Mitigation:** tokens use unguessable random IDs (not sequential counters). Restoration is pure string substitution from the per-conversation map; the LLM never selects a key, only emits one that the proxy looks up. Tokens are scoped per conversation, so cross-conversation access through a guessed token is not possible.

## What PromptGuard does not defend against

### N1. Adversarial users

A developer who actively wants to exfiltrate data has many channels (clipboard, email, SCP, screenshots, retyping). PromptGuard assumes a cooperative user who would accept a guardrail if one existed. It is not an insider-threat tool.

### N2. LLM provider behavior post-receipt

Once a payload reaches the provider, PromptGuard has no influence on what the provider stores, retains, logs, or processes. Mitigation here lives in the contract with the provider, not in any client-side tool.

### N3. Cross-document prompt-injection-driven exfiltration

An LLM agent that reads a poisoned document and is then instructed to send its contents elsewhere is a separate problem class (agent permissions, sandboxing, deny-by-default tooling). PromptGuard inspects outbound prompts at the LLM-API boundary; it does not reason about agent intent.

### N4. On-device LLMs

A model running entirely on the user's machine never makes outbound requests. PromptGuard has nothing to inspect and is not in the loop.

### N5. Browser-based ChatGPT / Claude.ai (v1)

The v1 proxy intercepts API traffic from tools that respect `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`. Browser-based chat UIs do not. A browser extension covering this is on the v1.1/v2 roadmap.

### N6. Image and file uploads to LLMs (v1)

v1 inspects text payloads only. Image and file content scanning is on the v1.x roadmap; until then, file uploads to an LLM are out of scope for PromptGuard.

### N7. Mobile clients (v1)

Mobile LLM clients typically do not honor a developer-configured base URL and may pin certificates against the provider directly. The v1.1 centralized proxy mode addresses the mobile case; the v1 local proxy does not.

## Trust boundaries

```
+-------------------+                +------------------+              +----------------+
|  AI tool on host  |                |   PromptGuard    |              |  LLM provider  |
|  (Claude Code,    | --> trusted -> |  (local proxy +  | -- public -> |  (Anthropic,   |
|  Cursor, agent)   |                |   detectors)     |              |   OpenAI, ...) |
+-------------------+                +------------------+              +----------------+
                                              |
                                       trusted, on host
                                              v
                                     +-------------------+
                                     |  Policy adapter   |
                                     |  (LocalYAML, Git, |
                                     |   Purview, ICAP)  |
                                     +-------------------+
```

- **Host (AI tool to PromptGuard):** trusted. Both run as the same user. Communication is over loopback.
- **PromptGuard to policy source:** trusted but authenticated. Local YAML is a file; Git manifests must be signature-verified; Purview and ICAP run over authenticated channels.
- **PromptGuard to LLM provider:** untrusted in the sense relevant here. Everything that crosses this boundary is assumed to potentially escape PromptGuard's control.
- **Token-map ledger:** in-memory, scoped per conversation, never persisted across process restarts in v1. Treated as sensitive in its own right (see A6).

## Assumptions

1. The user runs PromptGuard themselves; there is no privileged installer in v1.
2. The host is reasonably trusted: PromptGuard is not an EDR replacement and does not defend against root-level compromise of the developer machine.
3. Detectors are imperfect. The defense is depth (layered detectors, conservative defaults), not any single perfect classifier.
4. The token map and audit log live under the user's home directory, with file permissions set so that only the user can read them. Multi-user host scenarios are out of scope for v1.

## Cross-references

- Action semantics (BLOCK / MASK / TOKENIZE) and the per-pattern policy mapping live in `docs/research-notes.md` section 5.
- Detector architecture and the OPF integration notes are in `docs/research-notes.md` section 6.
- Open questions, including streaming buffer sizing and false-positive UX, are in `docs/research-notes.md` section 10.
