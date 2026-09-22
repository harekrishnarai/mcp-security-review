# MCP Approval Verdict — <name>

- **Artifact:** <name> @ <version>
- **Pinned digest:** sha256:<...> (tarball / image / endpoint fingerprint)
- **Transport:** stdio / SSE / Streamable HTTP | **Spec revision:** <YYYY-MM-DD>
- **Input mode reviewed:** white-box / black-box / both
- **Requested by:** <team/person> | **Date:** <YYYY-MM-DD>
- **Target clients:** Claude Desktop / Claude Code / OpenCode / Codex
- **Reviewed by:** <offensive engineer> | **Second reviewer:** <name or N/A>
- **Data classification reached:** public / internal / confidential / regulated

## Verdict

☐ APPROVE ☐ APPROVE WITH CONDITIONS ☐ APPROVE WITH ENFORCED CONDITIONS
☐ REJECT ☐ REJECT + BLOCKLIST

**Top finding (drives verdict):**
`[MCPxx:SHORT_DESC|severity|reach|conf|status]`

Reason (one paragraph): ...

## Findings summary

| ID | MCP tag | Severity | Finding | Reach | Confidence | Status |
|---|---|---|---|---|---|---|
| F-1 | MCP05 | CRITICAL | RCE via `run` tool arg | auth-remote | executed-PoC | open |
| F-2 | | | | | | |

Full detail per finding: `templates/poc-record.md`.

## Tool manifest hash (drift baseline)

- Manifest hash: sha256:<...>
- Captured from: `tools/list` / source registration
- Any future change to descriptions/schemas/annotations = incident (rug-pull).

## Fleet toxic-flow delta

- Added capabilities: <reads_pii, network_egress, ...>
- New chains created: <list pairings + control status>
- Aggregator / transitive trust: <yes/no>

## Egress allowlist

Destinations legitimately needed (enforce deny-all default):
- <host:port / FQDN>
Observed-but-undocumented destinations: <hosts>

## Enforced conditions (only for APPROVE WITH ENFORCED CONDITIONS)

| # | Finding | Control | Where enforced | Owner | Expiry |
|---|---|---|---|---|---|
| 1 | | egress allowlist | proxy | | |

If any condition cannot be enforced, the verdict must be REJECT instead.

## Auto-reject check (all must be NO to approve)

| Check | Result |
|---|---|
| Hardcoded secrets reachable | yes/no |
| RCE from tool input | yes/no |
| Unauth remote data access | yes/no |
| Plaintext HTTP remote | yes/no |
| Tampered / malicious artifact | yes/no |
| Live instruction injection (proven) | yes/no |
| Project-config auto-spawn unsigned | yes/no |

## Lifecycle

- Re-review trigger(s): manifest hash change / version bump / new scope / CVE /
  drift alert — whichever first.
- Re-review due: <date>
- **Kill switch:** how to revoke for every employee (client config removal /
  registry revoke / blocklist entry) — <steps>
- Registered in inventory: <ref>
- Immutable log / ticket: <ref>

## Attestation

- Signature / approval ID: <...>
- Second offensive sign-off required (regulated data / prod): ☐ obtained
