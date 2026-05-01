# PromptGuard segment coverage

What v1 protects, what it does not, and why.

## What v1 protects

PromptGuard intercepts outbound LLM API traffic at the local proxy. Any tool or app that sends a request to an Anthropic-compatible or OpenAI-compatible HTTP endpoint, AND that respects the standard `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `OPENAI_BASE_URL`-equivalent environment variables, is in scope.

Concrete coverage:

- **`claude` CLI v2.x.** `ANTHROPIC_BASE_URL=http://localhost:4000` (or the configured PromptGuard port) routes the CLI through the proxy. Streaming responses round-trip end-to-end after [DEC-020](../decisions/020-streaming-restorer-preserve-content-block-index.md). Verified by the MITM harness (`tools/mitm-verify/`).
- **Custom API integrations.** Any code that uses `httpx`, `requests`, the official Anthropic Python SDK, the official OpenAI Python SDK, or any other client that honors the base-URL environment variables. The proxy is shape-compatible with the upstream so no SDK changes are required.
- **API-respecting third-party clients.** Cursor, Continue.dev, Aider, custom agents that respect `ANTHROPIC_BASE_URL`. We have not run end-to-end test suites against each of these for v1 (they are out-of-scope for our test budget); their compatibility is structural rather than tested. The MITM harness lets operators verify any of them on their own machine in a few minutes.

In every case, the operator points the tool at PromptGuard's local port, and PromptGuard's pre-call hook runs before the request reaches the upstream provider.

## What v1 does NOT protect

### Claude desktop app

The Anthropic Claude desktop app (Mac, Windows, Linux Electron) authenticates the user against the Anthropic subscription via OAuth and talks to api.anthropic.com directly. It does not respect `ANTHROPIC_BASE_URL`, and it pins TLS against api.anthropic.com.

The realistic interception point is host-level TLS interception with a custom CA cert installed in the OS trust store, plus app-binary modification to disable cert pinning (or relying on a CA-tied workaround that pinning permits). Neither fits cleanly in a 14-day MVP.

### Claude.ai web app

Browser tab to `claude.ai`. Same auth path, same problem. The realistic interception point is a browser extension that hooks `fetch` / WebSocket calls to api.anthropic.com before they leave the page. Implementing a proper browser extension (Manifest V3, Chrome and Firefox parity, the cross-browser auth dance) is a separate ship.

## Why these are deferred (technical, not strategic)

The deferral is technical, not because the use case is unimportant. The opposite: many operators' real exposure to "PII leaks via LLM" is the desktop app or the browser tab, not the API. We deferred those because they are hard, not because we don't see them.

Concretely:

1. **Subscription auth path.** Both the desktop app and `claude.ai` use OAuth bearer tokens that are NOT licensed for programmatic API use. The auth tokens are not extractable for use with our proxy even if we wanted to (and we don't; that would be a license violation regardless). API billing is the correct surface for a programmatic interception layer; PromptGuard targets the API by design.
2. **No `ANTHROPIC_BASE_URL` honored.** Both clients hard-code their server endpoint. They have to be redirected at a lower level than the application's HTTP client.
3. **TLS pinning.** Modern desktop apps and many browsers pin certificates against api.anthropic.com. A custom CA cert in the OS trust store is rejected.
4. **Browser-extension complexity.** Manifest V3 changed the rules for content scripts that intercept network calls. Doing this properly across Chrome and Firefox in a way that does not break with the next browser update is a project of its own.

## v1.1 commitment

In rough priority order, with realistic effort estimates:

1. **Browser extension** for `claude.ai` (Chrome MV3 + Firefox WebExtension). Estimated 2-3 weeks. Hooks `fetch` and WebSocket; routes outbound payload through a small browser-side detection pipeline; calls back to the local PromptGuard proxy for shared rule evaluation if the user is running it.
2. **Desktop app interception spike**. Investigate what TLS interception actually requires given current macOS / Windows certificate-store and code-signing semantics. Output: a feasibility document, not a shipping integration. Estimated 1 week of investigation.
3. **Centralized proxy mode for mobile and corporate networks.** Out of scope for v1 by design (research-notes section 11). v1.1 if the desktop / web work surfaces a path that makes this cheaper.

## Day-10 desktop interception spike

Spent ~45 minutes on the desktop spike per the Day-10 brief allocation.

**What desktop app interception actually requires (macOS Apple Silicon, claude.app version current as of 2026-05-07):**

1. **Custom CA in the system trust store.** Adding a CA via `Keychain Access` -> `System Roots` is feasible but requires admin authentication. Operator-side friction, but not blocking.

2. **App-binary code signing** for cert-pinning behavior. Inspection of the claude.app bundle (`codesign -d --entitlements - /Applications/Claude.app`) shows it is hardened-runtime-signed. Network entitlements (`com.apple.security.network.client`) are present. There is no obvious cert-pinning entitlement, but pinning at the application level is implementation-internal and not visible from entitlements alone. Empirically:

   - Setting `HTTPS_PROXY=http://localhost:8088` in the launching shell environment AND adding the mitmproxy CA to the user's keychain login (NOT system roots) DID cause claude.app to send traffic via mitmproxy. We saw the SNI for `api.anthropic.com` and `claude.ai` flow through.
   - However, the TLS handshake failed on the app side with a certificate-trust error. The app does not honor user-keychain CAs, only system-roots CAs. Promoting the CA to system roots is the next gate; we did not do that for the spike (it would persist a CA across the host that survives the harness and is undesirable).
   - Some claude.app traffic appears to use HTTP/3 (QUIC) which mitmproxy 11.0.0 supports but with rougher edges. A v1.1 integration would need to verify QUIC interception works robustly.

3. **Subscription token extraction is not viable.** The app stores its OAuth token in macOS Keychain under an Anthropic-controlled service identifier, scoped to the app's signature. Even with read access, the token is licensed for the desktop app's own use, not for programmatic forwarding through our proxy.

4. **Path forward for v1.1 desktop interception:**
   - Option A: distribute a CA installer that the operator runs once (with admin auth) to install our CA in system roots; provide a Launch Agent that sets `HTTPS_PROXY` for claude.app's launch environment; the app then talks to api.anthropic.com via mitmproxy / our proxy. Operator-side friction acceptable for security-conscious teams.
   - Option B: file an Anthropic feature request for a configurable proxy URL the desktop app honors. Lowest-friction path but depends on the upstream.
   - Option C: build a separate macOS network extension (Apple's framework for system-wide content filters) that intercepts at the kernel-network-extension layer. Industrial-strength but a much bigger build (Network Extension framework requires a developer-program membership and an entitlement allow-list).

Recommendation: prioritize the browser extension (Option A in the desktop spike list above) because it covers `claude.ai` cleanly without OS-level changes; revisit the desktop story once the browser extension ships and we can measure how much usage actually flows through claude.app vs the web vs the API.

## How an operator can verify their own coverage

PromptGuard ships [`tools/mitm-verify/`](../tools/mitm-verify/README.md), a wire-verification harness that runs canned prompts through the proxy with mitmproxy positioned between PromptGuard and the upstream. The summary report tells the operator, per-prompt, what bytes reached the upstream and whether any obvious PII pattern leaked.

For the desktop / web cases, the harness is not directly useful (those tools bypass the proxy). The harness is the way operators verify the API path is trustworthy; for the desktop / web paths, the operator's exposure is the upstream bypass, full stop, and the only mitigation is the v1.1 work described above.
