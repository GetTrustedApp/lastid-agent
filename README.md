# LastID Agent Plugin

Cryptographic identity for AI agents. The plugin provisions a
LastID-issued `LastID.Agent.Base` verifiable credential the first time
an agent runtime starts on a host — approved one-time in the operator's
LastID wallet — then runs authenticated on every subsequent session.

The plugin installs into:

- **Claude Code** via the marketplace below
- **ChatGPT** (Custom Connector via Developer Mode) as an HTTP MCP server
- **Codex CLI** as a stdio MCP server (`codex mcp add`)
- **OpenAI Agents SDK** (Python/JS) as `MCPServerStdio`

All four paths bind the same underlying `lastid-agent` CLI + MCP server.

---

## Install in Claude Code

```text
/plugin marketplace add GetTrustedApp/lastid-agent
/plugin install lastid-agent
```

On the next session start, the plugin reports provisioning status. If
no agent credential exists yet, run:

```text
/lastid-agent:provision
```

You'll be asked for your LastID canonical DID (`did:lastid:z…`). The
CLI then surfaces a verification URL + user code; open the URL on the
device that holds your LastID, approve the agent in your wallet, and
the issued SD-JWT VC is persisted to the host keychain.

## Install in ChatGPT (Custom Connector)

1. Run the MCP server on a publicly reachable HTTPS endpoint:
   ```bash
   npx -y @lastid/agent serve --http 0.0.0.0:8787
   ```
2. In ChatGPT: **Settings → Connectors → Advanced → Developer mode →
   Add custom connector** and paste your `/mcp` URL.

(For local-only testing, expose the HTTP server via a tunnel — e.g.
Cloudflare Tunnel or ngrok — and use the public URL.)

## Install in Codex CLI

```bash
codex mcp add lastid-agent -- npx -y @lastid/agent serve
```

Then run `lastid-agent provision` once to register this host's agent
with your LastID wallet.

## Install in OpenAI Agents SDK

Python:

```python
from agents.mcp import MCPServerStdio

server = MCPServerStdio(
    name="lastid-agent",
    params={"command": "npx", "args": ["-y", "@lastid/agent", "serve"]},
)
```

JS/TS:

```ts
import { MCPServerStdio } from '@openai/agents';

const server = new MCPServerStdio({
  name: 'lastid-agent',
  command: 'npx',
  args: ['-y', '@lastid/agent', 'serve'],
});
```

---

## CLI

```text
lastid-agent provision        # one-time: provision this host's agent identity
lastid-agent status [--json]  # report provisioning state
lastid-agent show             # print the stored agent VC (debug)
lastid-agent serve            # MCP server on stdio (Claude/Codex/Agents)
lastid-agent serve --http :8787   # MCP server on HTTP (ChatGPT)
```

Flags accepted by `provision`:

```text
--parent-human-did did:lastid:z…    REQUIRED (or env LASTID_PARENT_HUMAN_DID)
--idp <url>                         Default: https://human.lastid.co
--runtime <name>                    Default: lastid-agent-cli
--project-hint <hex>                Optional SHA-256 prefix
--scope <slug>                      Default: main
--force                             Overwrite existing keychain entry
```

## Tools exposed over MCP

The first release surfaces a single tool so the install + handshake
work end-to-end across runtimes:

- `lastid_whoami` — returns the agent's DID, parent human DID,
  capabilities, and expiry. Reports `{ provisioned: false }` when no
  agent credential is present.

Memory (`lastid_memory_*`), signing (`lastid_sign`), and messaging
(`lastid_message_*`) tools land in subsequent releases on the same MCP
server.

## Repo layout

```
.claude-plugin/marketplace.json     # Claude Code marketplace index
plugins/lastid-agent/
  .claude-plugin/
    plugin.json                     # plugin manifest
    hooks.json                      # SessionStart wiring
  .mcp.json                         # Claude Code MCP autodiscovery
  bin/lastid-agent.js               # CLI: provision / status / show / serve
  hooks/session-start.js            # thin CLI shell (no native keychain calls)
  commands/provision.md             # /lastid-agent:provision slash command
  lib/
    agent-provisioning.js           # OID4VCI client
    keychain.js                     # OS-keychain adapter
    mcp-server.js                   # MCP server, stdio + HTTP
  tests/
package.json                        # bin: lastid-agent
```

## License

Apache-2.0. © LastID.
