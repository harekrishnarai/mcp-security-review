# Fleet Toxic-Flow Analysis (Org-Wide Blast Radius)

An org-wide approval is a decision about the **whole fleet**, not one server.
Three individually-innocent servers can combine into an exfiltration pipeline. A
server that looks harmless in isolation must be judged by what it adds to the
approved capability graph.

Do this step for every review, even when the server scores clean alone.

## 1. Model each server as capabilities

For each approved server (and the one under review), record its capability set
using the primitives from `attack-catalog.md` §13:

`reads_secrets` · `reads_pii` · `reads_code_repo` · `reads_email` ·
`reads_browser` · `browses_web` · `network_egress` · `sends_external` ·
`executes_code` · `writes_prod` · `moves_money` · `auth_admin` ·
`elicits_user` (MRTR/elicitation) · `samples_model` (drives the client LLM) ·
`renders_ui` (MCP Apps HTML in the host)

A capability is only real if the tool can be invoked by an ordinary employee
under the current auth model. "Theoretically possible" on a server nobody can
authenticate to isn't a capability.

## 2. Find the chains

The dangerous property is: **sensitive read** ∪ **outbound channel**, with no
control between them. Search for these patterns across the fleet:

| Chain | Example | Why it's a finding |
|---|---|---|
| Read + send | CRM read + email/slack send | Steal all customer data |
| Secrets + egress | Vault/file read + any HTTP fetch or web tool | Credential exfiltration |
| Code + egress | Shell/exec tool + network tool | C2, reverse shell, data staging |
| Web + PII + send | Web browse (injection source) + PII read + send | Prompt-injection → exfil |
| Shadowing | Two servers exposing the same tool name | Call hijacking (MCP03) |
| Aggregator | A proxy server fronting downstream servers | Transitive trust: downstreams unreviewed |

A chain that ends at an endpoint outside the org, with no human in the loop and
no egress control, is at least **HIGH** — even if no single server is worse than
MEDIUM.

## 3. Account for the client, not just the server

The agent that hosts MCP servers has its own tools (file read, shell, web).
Toxic flows span the agent's native tools too:

- An approved web-browse tool that can fetch attacker content, combined with a
  file-read capability and any tool that writes externally, is a complete exfil
  path regardless of which server each part comes from.
- Check the client's permission model (`Bash(*)`, filesystem roots, network
  policy). A permissive agent config turns two MEDIUM servers into one CRITICAL
  chain.

## 4. Aggregators and transitive trust

If the server under review is a proxy/aggregator (fronts other MCP servers, a
hosted connector platform, or `npx`-style launcher):

- Every downstream server inherits the aggregator's approval. Review them as if
  they were submitted directly, or refuse to approve the aggregator.
- A downstream server can change without the aggregator's manifest changing —
  pin and hash downstreams, or this becomes an unreviewed drift channel.

## 5. The review output for this step

Produce a short delta statement:

1. **New capabilities** this server adds to the fleet.
2. **New chains** created by combining it with already-approved capabilities
   (list the specific pairing).
3. **Existing chains strengthened** (e.g. it becomes the missing send channel).
4. **Control gaps** — which new chains lack an enforceable control.

Template:

```
Fleet delta — <server>
Added capabilities: reads_pii, network_egress
New chains:
  - C1: [this server: reads_pii] + [approved: email-send] => customer exfil
         control: NONE  -> blocking finding (HIGH)
  - C2: [this server: network_egress] + [approved: vault-read] => secret exfil
         control: egress allowlist (proxy) -> containable
Shadowing: tool `send` collides with approved `mail.send` -> MCP03 finding
Aggregator: no
```

## 6. Enforcement is the point

Capabilities are only safe when something enforces the boundary:

- Egress allowlist (proxy/firewall) that blocks every destination not needed.
- HITL confirmation on the "send/execute/pay/delete" leg of a chain.
- Tool-proxy redaction so sensitive fields never reach the outbound tool.
- Name-collision detection at client registration.

If a new chain can't be broken by a control you can enforce, it drives the
verdict to at least "APPROVE WITH ENFORCED CONDITIONS," or REJECT if unbreakable
in practice.
