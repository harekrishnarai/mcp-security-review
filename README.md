# MCP Offensive Security Review

An agent skill for **offensive security triage and org-wide approval of MCP
servers and connectors** before employees are allowed to use them in Claude
Desktop, Claude Code, OpenCode, Codex CLI, or any MCP-compatible client.

This is not a compliance checklist. It is written for product-security and red
teams who have to answer one question under pressure:

> **If this MCP server is hostile right now, what can I do to this org with it,
> how easily, and how far does it spread?**

If the answer isn't "nothing meaningful," it doesn't get approved.

## Why

An approved MCP server runs with employee privileges — their credentials, their
code, their data, their ability to send mail and touch production. Approval is
usually org-wide. A single vulnerable or malicious connector is a fleet-wide
incident waiting to happen.

Most MCP review material is compliance-shaped: weighted scores, policy
checkboxes, "SBOM required." A weighted average lets a clean logging section
cancel out an RCE. This skill refuses that: the verdict is a **forcing function
on the worst finding you can demonstrate**.

## What it does

- Reviews a request from **two input modes**: the **source/package** (white-box)
  or a **live endpoint URL** (black-box).
- Hunts MCP-specific attacks: tool-description injection, **annotation spoofing**
  (`readOnlyHint` lies), rug-pull / manifest drift (including live
  `subscriptions/listen` mutation), tool shadowing, command injection, indirect
  prompt injection, token passthrough, confused deputy, DCR/CIMD SSRF, DNS
  rebinding, **header–body desync / `x-mcp-header` injection**, **MRTR
  `requestState` tampering**, session hijacking, elicitation URL phishing,
  cache-scope leakage, pagination evasion, state-handle IDOR, `$ref` schema
  SSRF, icon injection, and MCP Apps surface.
- Anchored to the **current MCP spec revision (2026-07-28)** with explicit
  legacy-era handling — recon runs in the right wire format (stateless
  per-request `_meta`, `server/discover`) instead of the removed `initialize`
  handshake.
- Proves out-of-band **exfiltration** with a canary instead of guessing.
- Analyzes **fleet-wide toxic flows** — the combined capability graph of
  everything already approved plus the new server.
- Produces an **enforced approval verdict**: approve, approve with enforceable
  conditions, or reject + blocklist.

## Decision model

No numeric threshold to argue about. First match wins:

| Situation | Verdict |
|---|---|
| Any confirmed CRITICAL | REJECT + BLOCKLIST |
| Any HIGH with no technically enforceable mitigation | REJECT |
| Every HIGH containable by an enforceable control | APPROVE WITH ENFORCED CONDITIONS |
| MEDIUM only, low blast radius | APPROVE WITH CONDITIONS |
| LOW / INFO only | APPROVE |

Conditions must be *enforceable* (egress allowlist, HITL gate, sandbox, proxy
redaction) — "the team promises to" is not a control.

## Layout

```
SKILL.md                              # entry point: stance, workflow, gates
references/
  spec-2026-07-28.md                  # protocol facts, eras, wire formats, security requirements
  playbook-code.md                    # white-box: artifact pinning, taint→sinks, supply chain, config
  playbook-endpoint.md                # black-box: live auth/session/injection/SSRF probing
  attack-catalog.md                   # MCP techniques + canary payloads + MCP01–MCP10 tags
  exploitability-scoring.md           # severity, reachability, verdict gating
  fleet-toxic-flows.md                # org-wide capability graph and exfil chains
templates/
  poc-record.md                       # per-finding evidence record
  approval-verdict.md                 # machine-readable decision record
```

## Install

This repo is an [agent skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills).
Drop the folder where your agent looks for skills:

```bash
# Claude Code / general agent skills directory
git clone https://github.com/harekrishnarai/mcp-security-review.git \
  ~/.claude/skills/mcp-security-review

# OpenCode
git clone https://github.com/harekrishnarai/mcp-security-review.git \
  ~/.config/opencode/skills/mcp-security-review
```

Then ask your agent to review an MCP server or connector request. The skill
triggers on MCP/connector approval, red-team review, tool poisoning, prompt
injection, and similar contexts.

### Install by prompt (no terminal needed)

Paste this into Claude Code, OpenCode, Codex, Cursor, or any agent with shell
access. It installs the skill globally and kicks off the workflow.

```text
Install the "mcp-security-review" agent skill from
https://github.com/harekrishnarai/mcp-security-review so it is available now and
in future sessions.

Steps:
1. Run: npx -y skills@latest add harekrishnarai/mcp-security-review -g --all -y
   If npx is unavailable, clone the repo into your global skills directory:
     Claude Code -> ~/.claude/skills/mcp-security-review
     OpenCode    -> ~/.config/opencode/skills/mcp-security-review
     Codex       -> ~/.codex/skills/mcp-security-review
2. Verify SKILL.md exists and its frontmatter name is "mcp-security-review".
3. Read the installed SKILL.md and confirm the skill is available.
4. Report the install path and whether it succeeded.

Then act as an offensive product-security reviewer for this skill. When I give
you an MCP server or connector to review for org-wide approval — as a source
repo/package OR a live endpoint URL — load the mcp-security-review skill and
follow it end to end: pin the artifact and the MCP spec era (2026-07-28 vs
legacy), run the white-box and/or black-box playbook, prove impact with an
out-of-band canary, do the fleet toxic-flow analysis, and produce an
approval-verdict.md plus one poc-record.md per confirmed finding. Do not approve
on incomplete data.
```

Then give it a target:

```text
Using the mcp-security-review skill, review this MCP server for org-wide
approval: <source repo or endpoint URL>
```

## Usage

Point it at a request. Example prompts:

- `Review this MCP server for org-wide approval: https://github.com/acme/mcp-vault`
- `Black-box review this MCP endpoint before we approve it: https://mcp.vendor.com/mcp`
- `We want to approve the @acme/analytics MCP connector. Run the security review.`

The output is an `approval-verdict.md` decision record and one `poc-record.md`
per confirmed finding, plus the tool-manifest hash used as the drift baseline.

## Authorization & ethics

This skill is for **authorized security review only** — reviewing software and
endpoints your organization has permission to assess. The payloads in
`references/attack-catalog.md` are canary-based and non-destructive. Do not run
impact/load testing against systems you do not own or have written
authorization to test.

## Contributing

Issues and PRs welcome — especially new MCP attack techniques, false-positive
notes, and client-specific config red flags. Keep contributions technique-first
and evidence-based.

## License

MIT — see [LICENSE](LICENSE).
