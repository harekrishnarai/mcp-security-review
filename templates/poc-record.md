# PoC Record — <finding id>

- **Server / endpoint:** <name> @ <pinned digest / host+version>
- **Finding tag:** `[MCPxx:SHORT_DESC|severity|reach|conf|status]`
- **Reviewer:** <name> | **Date:** <YYYY-MM-DD>
- **Input mode:** white-box (source/package) / black-box (endpoint)

## Attack path
Shortest route from attacker-controlled input to impact. Be concrete.

1. Attacker does: ...
2. Server/tool does: ...
3. Impact: ...

## Evidence

**Reachability:** unauthenticated-remote / authenticated-remote / local /
user-action / chain-only

**Confidence:** executed-PoC / data-flow-trace-verified / static-only (cap MEDIUM)

### Raw evidence
```
<request, command, source snippet, or data-flow trace>
```

### Result
```
<response, side effect, or canary callback>
```

- OOB canary used: <yes/no> — payload id / timestamp / source IP:
- If no PoC: why not, and what would confirm it:

## Impact
- What data/systems can the attacker reach?
- Data classification: public / internal / confidential / regulated
- Does it cross a trust boundary (per-user, per-tenant, org→internet)?

## Mitigation (if any)
| Control | Where enforced | Owner | Blocks finding? |
|---|---|---|---|
| | | | yes/no |

If no control fully blocks it, this finding is not containable → drives verdict.

## Status
open / mitigated-by-<control> / accepted-risk (requires sign-off) / fixed-in-<version>
