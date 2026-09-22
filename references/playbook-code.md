# White-Box Playbook — Source / Package / Container

You have the artifact. Your job is to find what a hostile version of it could do
to the org, and whether the artifact you can read is actually the artifact the
employees will run.

Read with `references/attack-catalog.md` open — that file defines the techniques
this playbook hunts for.

## 0. Pin the artifact

Everything downstream is meaningless if you don't know what you reviewed.

- [ ] Exact commit SHA, not a branch.
- [ ] Package tarball **digest** (`npm pack` / `pip download` / `docker pull`
      then `sha256sum`). Record it. This digest is the approval anchor.
- [ ] Container image digest (`repo@sha256:...`), not a tag.
- [ ] MCP spec revision the server targets, and its advertised transport.
- [ ] Any signature / attestation (sigstore, SLSA provenance) — verify it, don't
      trust its presence.

Unpinned version, moving git ref, or `latest` in the delivery config is a
finding on its own (it defeats the drift baseline later).

## 1. Does the published artifact match the source?

The most dangerous supply-chain attack is a clean repo and a dirty release.
Diff them.

```bash
npm pack <pkg>            # or: pip download / cargo vendor / git archive
tar -xzf *.tgz && diff -r package/ <repo-at-tag>/
```

Look for files present in the release but absent from the repo (or vice versa):
bundled binaries, minified blobs, extra `.js`, `postinstall`/`preinstall`
scripts, native `.node`/`.so`, extra dependencies not in the lockfile.

- Hunt install-time execution: `scripts` in `package.json`, `setup.py`,
  `build.rs`, `Makefile`, Dockerfile `RUN` on untrusted input.
- Verify the lockfile is committed and matches; a missing lockfile allows
  dependency substitution.
- Dependency confusion: if the package name is scoped (`@org/pkg`), check
  whether the unscoped name is claimable and whether internal registries are
  configured — a private name resolving to a public registry is a hijack.
- `npm audit` / `pip-audit` / `cargo audit` / `osv-scanner` for known CVEs in
  deps — but treat as one input, not the whole review.

## 2. Extract the attack surface

Before reading sinks, enumerate what the server exposes.

```bash
# Tool/resource/prompt registrations and their descriptions
rg -n "registerTool|setRequestHandler|ListTools|tools/list|server\.tool|@mcp\.tool|addTool" .
rg -n "registerResource|resources/list|registerPrompt|prompts/list" .
```

Capture every tool name, description, input schema, **output schema**,
`icons[]`, and **annotation** (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) verbatim into the manifest. Annotations are
untrusted self-labels — a hostile server can mark a delete tool
`readOnlyHint: true`. Note any annotation that contradicts what the code
actually does; that is an annotation-spoofing finding (`attack-catalog.md` §3).

Also flag, from the schema and resources:

- **`x-mcp-header`** parameters — values are mirrored into `Mcp-Param-*` HTTP
  headers (visible to every intermediary). Safe-coded or not?
- **`$ref` to a network URI** in a schema — must not be auto-dereferenced (SSRF).
- **`icons[].src`** — must be HTTPS/`data:`, same-origin, no credentials;
  SVG treated as executable.
- **`ui://` resources** (`_meta.ui.resourceUri`) — MCP Apps HTML rendered in the
  host (see `attack-catalog.md` §23).
- **Server-minted handles** — is authorization re-checked on every use, and is
  the handle sufficiently random? (spec: a handle is a name, not a capability).

## 3. Taint: tool input → dangerous sinks

This is the core of the review. For each tool that takes input, trace whether
attacker-influenced input reaches a sink without validation.

Sinks to trace:

| Sink class | Grep seeds | Impact |
|---|---|---|
| Command execution | `child_process`, `exec(`, `execSync`, `spawn`, `os.system`, `subprocess`, `Popen`, `Runtime.exec`, `os/exec`, `shell=True` | RCE |
| Dynamic eval | `eval`, `Function(`, `new Function`, `vm.runIn`, `pickle.loads`, `yaml.load(` (unsafe), `unserialize`, `Marshal.load`, `deserialize` | RCE / object injection |
| File / path | `fs.readFile`, `fs.writeFile`, `open(`, `os.remove`, `shutil`, `path.join`, `send_file`, `readfile`, `..` handling | Path traversal, arbitrary read/write |
| SQL / query | string-built queries, `execute(f"`, `query(`+concat, `$where` | Injection |
| Network fetch | `fetch(`, `axios`, `requests.get`, `http.get`, `urllib`, `net.Dial` | SSRF, exfil |
| Template / shell-out | `render_string`, `template`, `printf` into shell, `sh -c` | Injection |

Trace the argument from the MCP tool handler to the sink. A sink reachable from
tool input with no allowlist/validation and no containment boundary is a
CRITICAL (see scoring). Pay special attention to:

- String interpolation into shell (`exec("echo " + arg)`) — the classic MCP RCE.
- Path joins with tool-supplied names and no `..`/symlink handling.
- URL fetches where the tool accepts a target URL (SSRF straight to cloud
  metadata `169.254.169.254` or internal services).
- `pickle`/`yaml.load`/native deserialization of tool input.

Use a canary to prove the path when you can run the server locally. If you
cannot execute it, write the data-flow trace in the PoC record and mark
confidence explicitly.

## 4. Secrets

- Committed secrets, tokens, keys — including in examples, fixtures, `.env`,
  test files, and CI configs.
- Secrets used as defaults that ship to every employee.
- Credentials written to logs, error messages, or returned in tool output
  (a tool that echoes its config on error leaks every user's token).
- Long-lived static credentials where short-lived/OAuth would do — this is both
  a hygiene and a blast-radius issue (one leaked token = org-wide access until
  rotated). Tag `[MCP01]`.

## 5. Egress & network behavior

Enumerate every outbound destination the code can reach.

```bash
rg -n "https?://|fetch\(|axios|requests\.|urllib|net\.|socket|ws://|wss://" .
```

Build the **egress allowlist** — the set of hostnames this server legitimately
needs. Anything else, especially hardcoded IPs, `ngrok`/`webhook.site`-style
hosts, raw IPs, or dynamic subdomains, is a potential exfil or C2 channel. This
allowlist becomes an enforcement artifact in the verdict.

- Telemetry/analytics endpoints that receive tool inputs or results (data
  leaving the org through the side door).
- Any endpoint that receives data which could include secrets/PII read by
  another tool — the exfil path (`fleet-toxic-flows.md`).

## 6. Stdio launch hygiene (local servers)

For stdio servers the client launches a command. That command is an attack
surface.

- Resolve the launched command: is it an absolute path to a pinned binary, or a
  name resolved via `PATH`? A bare name is hijackable via PATH manipulation.
- `npx -y <pkg>` / `uvx` / `pipx run` with an unpinned package = fetch-and-run
  arbitrary code from a registry on every launch.
- Symlink handling for any file paths the server opens.
- Does it spawn subprocesses whose environment inherits the user's full shell
  env (leaking ambient secrets)? See config review below.

## 7. Config review (client side — always do this)

Read the exact config the requestor intends to ship. Red flags per client:

**All clients**
- Unpinned version (`latest`, moving ref) — forbidden.
- Inline secrets in env/args where a secret manager or keychain ref is possible.
- Rejected servers should be removed, not merely disabled.

**Claude Desktop (`claude_desktop_config.json`)**
- `command` must be absolute + pinned, not `npx -y <unpinned>`.
- `args` must not interpolate user-controlled paths.

**Claude Code (`.mcp.json` project scope + user scope)**
- Project scope is the danger zone: a repo's `.mcp.json` auto-spawns servers
  when the user trusts the folder. Treat project-scope as untrusted input; it
  needs signed/pinned servers to be acceptable.
- Check `.claude/settings.json` for over-broad allowlists (e.g. `Bash(*)`
  combined with an MCP shell tool = pre-approved RCE).

**OpenCode (`opencode.json`, `~/.config/opencode/`)**
- Local and remote MCP entries; flag any `http://` remote URL.
- Plugin-enabled servers inherit plugin permissions — review the manifest.

**Codex CLI (`~/.codex/config.toml`)**
- `[mcp_servers.*]` `command`/`args` same rules.
- Env passthrough can inherit ambient shell secrets — require explicit
  allowlist.
- Check `sandbox_mode` / `network_access` interplay with MCP egress.

## 8. Tool-manifest hash (drift baseline)

Serialize every tool/resource/prompt definition (name, description, schema,
annotations, `x-mcp-header`, `ttlMs`/`cacheScope`) into a stable form and hash
it. Record the hash in the verdict. It is how a future rug-pull
(`attack-catalog.md` §4) gets detected: any change to the manifest after
approval is an incident, not a routine update.

Note the limit: on 2026-07-28 a server can mutate its tool/resource set
mid-session via `subscriptions/listen` (`toolsListChanged`,
`resourcesListChanged`). A one-time hash is necessary but not sufficient —
require continuous drift monitoring, not a static snapshot.

## 9. Protocol-era checks (2026-07-28)

Confirm the server implements the modern model and does so safely:

- **`server/discover`** implements the required discovery method; `serverInfo`
  and `instructions` are treated by the client as untrusted (self-reported).
- **Statelessness:** no reliance on `Mcp-Session-Id`; every request carries
  `_meta` `protocolVersion` + `clientCapabilities`.
- **No stale session surface:** a modern server should ignore
  `Mcp-Session-Id`/`Last-Event-ID` rather than honour them.
- **`requestState`** (MRTR): integrity-protected and bound to the principal if
  it influences authorization.
- **`Origin` validation** present (403 on invalid); local bind is `127.0.0.1`.
- **`Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version`** header/body validation
  implemented (`-32020`).
- **stdio:** server writes only valid MCP messages to stdout.

If the artifact is a legacy (≤ 2025-11-25) server, keep the removed-surface
checks from `playbook-endpoint.md` §10 in scope.

## Deliverable for white-box

- Pinned artifact digest + verified provenance result.
- Verbatim hashed tool manifest.
- One `templates/poc-record.md` per confirmed finding (with data-flow trace or
  executed PoC).
- Egress allowlist derived from code.
- Config findings for the target client(s).
- Feed capabilities into `fleet-toxic-flows.md`, then to scoring.
