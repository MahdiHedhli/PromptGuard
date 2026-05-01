# DEC-022: MITM verification harness positioned between LiteLLM and upstream

**Date:** 2026-05-07
**Status:** Accepted
**Phase:** v1 (independent wire verification)
**Author:** MahdiHedhli

---

## Context

the v1 plan introduced an explicit owner requirement: independently
verify what bytes actually leave the machine. The test suite asserts
correctness. Benchmarks measure detection F1. The audit log carries
forensic events. None of those show you what went out on the wire.

The harness is the operator's tool to satisfy themselves that the
threat-model promise ("PII never leaves the host") holds in practice.
It is also the strongest possible blog-post visual: "we ran every
canned prompt through the proxy with a wire monitor in place; the
monitor saw zero PII for the categories that should have been
intercepted."

## Options considered

### Option A: mitmproxy between LiteLLM and the upstream provider (chosen)
- Pros: We see exactly what PromptGuard's outbound rewrite produced.
  This is the question we want answered: "did the rewrite actually
  happen?" The capture sits AFTER every PromptGuard hook.
- Cons: Requires the LiteLLM container to trust the mitmproxy CA.
  Operationally a little fiddly on first run. Acceptable.

### Option B: mitmproxy between the client and LiteLLM
- Pros: Captures both the client's request shape and the proxy's
  response.
- Cons: We already know what the client sent in (the operator wrote
  the prompt). Capturing the client request answers the wrong
  question. Worse: it captures BEFORE PromptGuard runs, so it cannot
  see the rewrite.

### Option C: tcpdump / Wireshark on the host
- Pros: No code change.
- Cons: TLS-encrypted traffic is opaque without a key-log. Operators
  would have to set up SSLKEYLOGFILE in LiteLLM and post-decrypt.
  Friction defeats the harness's purpose.

### Option D: A debug-log inside PromptGuard that records what would-be-
sent to the upstream
- Pros: Simplest.
- Cons: Trust circular. If we're verifying PromptGuard, we cannot
  verify with PromptGuard's own log. The verification has to be
  external.

## Decision

Option A. mitmproxy as an upstream HTTPS proxy with auto-generated
CA, trusted only by the LiteLLM container, captures persisted to
`./local/mitm-captures/`.

Concrete shape:

  - `tools/mitm-verify/docker-compose.mitm.yml`: an overlay compose
    file added on top of the main one. Adds a mitmproxy container in
    the `promptguard` network. Re-points LiteLLM at it via
    `HTTPS_PROXY` and `SSL_CERT_FILE` environment variables. NOT
    active in the default `docker compose up` flow; opt-in via the
    overlay or via `make -C tools/mitm-verify up`.

  - `tools/mitm-verify/addon.py`: mitmdump addon that writes one
    capture file per request and one per response. Authorization /
    x-api-key headers redacted to last 4 chars. Suspicious-pattern
    counts on each body (raw IPv4, raw email, raw PEM marker, raw
    AWS access key). The patterns are SANITY HEURISTICS only; the
    intent is "did anything obvious leak," not detection. Genuine
    detection lives in the proxy itself.

  - `tools/mitm-verify/test-prompts/`: canned prompts covering each
    detection category. Synthetic data only: openssl-generated PEM
    in 05, AWS's documented example key in 03, RFC-2606-reserved
    domains throughout. Each file has a comment header describing
    what the prompt should produce under default policy.

  - `tools/mitm-verify/run-test-suite.sh`: runs every prompt through
    the proxy and produces one summary report at
    `./local/mitm-captures/summary-<UTC>.md` with per-prompt verdict.
    Exit code is the number of failed prompts; CI-friendly.

  - `tools/mitm-verify/Makefile`: `up` / `test` / `logs` / `down` /
    `scrub` targets. Convenience over correctness; the underlying
    docker compose commands are the source of truth.

## Constraints

- **Opt-in.** Default `docker compose up` does not include the
  overlay. Operators have to explicitly invoke `make up` or pass
  `-f tools/mitm-verify/docker-compose.mitm.yml`.

- **Captures stay local.** `./local/` is gitignored. Captures never
  reach the public repo unless an operator copies them out.

- **Fail loudly, not silently.** If the addon cannot write to
  `/captures`, it raises. If the CA file does not appear within the
  start period, the healthcheck fails. If LiteLLM cannot trust the
  CA, outbound HTTPS to api.anthropic.com errors with a TLS message
  in the LiteLLM log; the harness does NOT silently pass traffic
  through unmonitored.

- **CA is per-machine and per-run.** `make scrub` removes it; the
  next `make up` regenerates. No shared certs. No host trust-store
  modification.

- **Authorization redaction.** The capture writes "<redacted last 4:
  XXXX>" for any Authorization or x-api-key header value. Keys
  never land on disk.

- **Synthetic data only.** All test prompts use synthetic values:
  openssl-generated PEM blocks regenerated per checkout, AWS's
  documented example keys, RFC-2606-reserved domains, plausibly-
  shaped but obviously-synthetic content. No real customer data,
  no production keys, no PII from any external source.

## Consequences

### Enables
- Independent wire verification the operator can run on demand.
- The strongest blog-post visual: "we ran the suite, no PII leaked,
  here is the summary report."
- Regression tripwire: any future change that bypasses the rewrite
  path is caught the next time the suite runs.

### Constrains
- Operators who want to inspect responses on a live customer-facing
  workload have to copy the addon and write their own; the v1 harness
  is a verification tool, not a production tap.
- The suspicious-pattern check is heuristic. A regression that
  encoded PII in base64 before sending would slip past the heuristic
  while landing in the capture file content (operators reading
  capture bodies directly would see it). v1.1 may add a deeper scan.

### Revisit if
- Real workloads need long-running observation; the captures-per-flow
  model would produce too many files, and we'd switch to a rolling
  log.
- The suspicious-pattern set needs broadening (encoded forms,
  international IP ranges, more credential shapes). Easy add to
  `addon.py`.

## Implementation notes

- mitmproxy version pinned to `mitmproxy/mitmproxy:11.0.0` in the
  overlay. Bump on operator demand.
- The harness assumes LiteLLM is the only thing in the network whose
  outbound traffic we want to capture. If a future PromptGuard service
  also makes outbound HTTPS calls (none today; OPF and Presidio are
  internal-network-only), they would need the same `HTTPS_PROXY`
  and `SSL_CERT_FILE` overrides.
- The Makefile's `make up` waits 8 minutes (--wait-timeout 480) to
  cover the first-run OPF model download. Subsequent boots are
  seconds.
- Captures preserve a `body_size_bytes` field separate from `body`
  so a JSON-incompatible body (large binary) still produces a
  capture file with a useful size signal even if the body itself
  is rendered as a placeholder.
