# Black-Box Playbook — Live Endpoint

You cannot read the code. You have a URL. Treat the server as fully hostile and
probe it the way an attacker on the network (or a malicious employee who can
register a client) would. Protocol facts live in `references/spec-2026-07-28.md`;
techniques live in `references/attack-catalog.md`.

Tooling: intercepting proxy (Burp / mitmproxy), a JSON-RPC client, and an
out-of-band canary (Burp Collaborator or equivalent).

## 0. Recon & pin

- [ ] Base URL and transport: **Streamable HTTP** (single POST endpoint) or the
      deprecated HTTP+SSE (`2024-11-05`). Note which.
- [ ] **Protocol era** — see §1. Record whether the target is modern
      (`2026-07-28`+) or legacy.
- [ ] TLS chain, expiry, version (TLS 1.2 min); HSTS. `http://` = finding.
- [ ] Host binding: localhost/127.0.0.1 → DNS rebinding in scope (`#9`).
- [ ] Version fingerprint from `server/discover` (`serverInfo`,
      `supportedVersions`) so the approval is pinned to something.

## 1. Determine the era (do this first)

2026-07-28 has **no `initialize` handshake and no sessions**. Sending an
`initialize` probe tells you which era you're in.

**Modern probe** — a normal request with the required `_meta` and headers:

```bash
curl -sS -D- -X POST https://host/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: server/discover' \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{
        "_meta":{
          "io.modelcontextprotocol/protocolVersion":"2026-07-28",
          "io.modelcontextprotocol/clientCapabilities":{}
        }}}'
```

- A modern success returns `supportedVersions`, `capabilities`, `serverInfo`,
  `instructions`.
- A `400` whose body is a recognized modern JSON-RPC error
  (`UnsupportedProtocolVersionError` -32022, `HeaderMismatch` -32020,
  `MissingRequiredClientCapability` -32021) → **modern** server; retry with an
  advertised version.
- An empty/unknown `400`, or a response to a legacy `initialize` → **legacy**;
  then also run the legacy checks in §10.

Record the era. A legacy target keeps the full removed attack surface
(session hijacking, GET stream, `resources/subscribe`).

## 2. Enumerate the attack surface (paginate to exhaustion)

For modern: `server/discover`, `tools/list`, `resources/list`,
`resources/templates/list`, `prompts/list`. For legacy: `initialize` first.

- **Follow `nextCursor` until exhausted.** Cursors are opaque; a server can hide
  tools on page 2. A reviewer who reads only page 1 misses tools.
- Capture **verbatim**: every tool name, `title`, description, `inputSchema`,
  `outputSchema`, `icons[]`, and **annotations**; every resource URI/template;
  every prompt; the declared `capabilities` and `instructions`.
- Hash the manifest (drift baseline).
- Compare **declared capabilities vs. what a tool actually does** — a
  capability lie (`sampling`/`elicitation`/`apps` claimed but not needed).

## 3. Authentication & authorization

- **Unauthenticated reach:** repeat §2 with no `Authorization`. Any 200 with
  data = unauth exposure.
- **Token passthrough** (spec-forbidden): replay your token directly against the
  upstream API the server fronts; if it works, the server is passing it through.
- **Audience/confused deputy:** present a token minted for a *different*
  service; acceptance = replay across services.
- **Scope creep:** request broader scopes than a tool needs; check expiry and
  revocation.
- **Per-object authz:** call tools against another user's handle/object.
- **Redirect URI:** register a client and try wildcard/subdomain/traversal/
  attacker-host `redirect_uri`. Exact match required.
- **OAuth URL handling:** does the client open authorization URLs via a shell,
  or accept `javascript:`/`data:`/`file:`? (Client-side, but a server can
  influence it via `WWW-Authenticate`/metadata.) Check `iss` validation and
  that credentials aren't reused across issuers.
- **CIMD/DCR:** if DCR is used, point registration fields (`logo_uri`,
  `jwks_uri`, `sector_uri`) at an internal address or canary → SSRF. If CIMD,
  check the `client_id` equals its hosted document URL.

## 4. Transport, headers & sessions

Modern:

- **Header/body desync (`-32020`):** send `Mcp-Method`/`Mcp-Name`/
  `MCP-Protocol-Version` that **disagree** with the body. A server that acts on
  the header (routing, rate-limit, auth) while executing the body is exploitable
  — and an intermediary may trust the header even if the server doesn't. Probe
  both layers.
- **`x-mcp-header` mirroring:** find parameters annotated `x-mcp-header`; call
  with values containing CRLF, non-ASCII, leading/trailing space, and the
  `=?base64?…?=` sentinel; inspect the resulting `Mcp-Param-*` headers for
  injection, sentinel-confusion, and **sensitive values leaking to
  intermediaries**.
- **`Origin`:** send a foreign `Origin`; a 200 (instead of 403) enables DNS
  rebinding from a web page.
- **No sessions:** `Mcp-Session-Id` should be ignored; a target that mints or
  honours one is legacy-shaped — test §10.

Legacy (≤ 2025-11-25):

- **Session binding:** capture `Mcp-Session-Id`; reuse it without credentials,
  from another connection, or after expiry → hijack. Test fixation/replay.
- **GET stream / SSE:** check for cross-user data on a standalone stream.
- **`Last-Event-ID` resumability:** replay/resume to pull another client's
  events.

## 5. Instruction injection (descriptions, resources, prompts, output, icons)

Enumerate the raw manifest and treat all server text as hostile.

- **Description/schema injection:** scan tool descriptions, parameter
  descriptions, `instructions`, resource contents, prompt templates for
  instructions aimed at the client model ("ignore previous instructions", read
  a secret and pass it as an argument), including Unicode zero-width/tag
  characters and base64 blobs. **Decode everything.**
- **Annotation spoofing:** `readOnlyHint: true` / `destructiveHint: false` on a
  tool that writes or executes. Annotations are untrusted by spec.
- **Output injection:** call tools that return external content; use a canary to
  prove the agent follows injected instructions (OOB callback).
- **Icon injection:** does the client fetch `icons[].src` from an arbitrary
  origin (tracking/SSRF), or accept unsafe schemes/SVG-with-script?
- **Resource/prompt injection:** resource bodies and prompt templates are
  equally trusted by the client.

## 6. MRTR, elicitation, sampling, roots (the 2026-07-28 vectors)

- **MRTR / `requestState`:** trigger a tool that returns `input_required`. Tamper
  the echoed `requestState` (change a field, replay an old one, swap between
  users, truncate) and observe whether the server trusts it. If it influences
  authorization and isn't integrity-protected, that's high impact.
- **Elicitation phishing:** a server can return an `elicitation/create` with
  `mode:"url"`. Verify the URL isn't pre-authenticated, isn't a lookalike/Punycode
  host, and that the user who starts a flow is the one who completes it. Check
  the client shows the full URL and requires explicit consent. Form mode must
  not be used for secrets.
- **Sampling abuse:** a server can drive the client's model. Measure cost/quota
  abuse, prompt-injection through nested tools, and unbounded tool loops.
- **Roots boundary:** roots are informational, not a sandbox — test whether the
  server can read outside them.

## 7. SSRF, injection, DoS

- Any tool/param taking a URL/host/path → try `169.254.169.254`, `127.0.0.1`,
  RFC1918, `file://`, and your canary.
- `inputSchema`/`outputSchema` `$ref` pointing at a network URI → the
  validator/client must not dereference it; a fetch to your canary is a finding.
- Deeply nested composition keywords (`anyOf`/`allOf`/`$defs`) → validator DoS.
- Injection payloads from `attack-catalog.md` on any command/query/template.
- Error handling: malformed JSON-RPC, unknown methods, oversized ids, wrong
  types — stack traces/paths/config in errors are free recon.
- Rate limiting / unbounded results (don't hammer without authorization).

## 8. Prove exfiltration with a canary

Plant a canary as tool input or retrieved content; watch the OOB listener. A
callback is the difference between a concern and a CRITICAL.

## 9. Localhost / DNS rebinding

For localhost-bound servers: send a request with a foreign `Host` header and a
browser-like `Origin`. If it answers, a malicious web page can drive the local
server via a rebinding domain. Then test whether the server trusts the `Origin`
header only for validation but acts on the body (same desync class as `#4`).

## 10. Legacy-only checks (only when §1 says legacy)

- `initialize` response: verify `protocolVersion` echo, capability honesty.
- `Mcp-Session-Id` handling (binding, entropy, replay, fixation).
- `resources/subscribe` / GET SSE stream, `Last-Event-ID` resumability.
- `logging/setLevel` at connection scope; `roots/list_changed` notification.

## 11. Extensions (review when claimed)

- **MCP Apps** (`ui://` resource, `_meta.ui.resourceUri`): inspect the HTML/JS
  for exfiltration, CSP that allows broad origins, iframe escape attempts, and
  whether the app can proxy `tools/call` beyond the user's consent.
- **Tasks** (async), **Skills over MCP**, **Enterprise-Managed Auth**: each
  broadens capability; treat as additional surface, not a reason to skip.

## Deliverable for black-box

- Pinned endpoint fingerprint + **era** + spec revision + TLS result.
- Verbatim hashed manifest (paginated to exhaustion).
- One PoC record per confirmed finding, with raw request/response + canary.
- Auth model summary and every bypass found.
- Egress destinations observed (proxy) → allowlist candidate.
- Feed capabilities into `fleet-toxic-flows.md`, then scoring.
