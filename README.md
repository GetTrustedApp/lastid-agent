# LastID Agent Plugin

Give your Claude Code agent a verifiable cryptographic identity. Once
provisioned, your agent can chat with you while it's idle, share its
work-in-progress, use your vault credentials without ever seeing them,
and remember things across sessions — all bound to a credential you
approved in your LastID wallet.

## Install

In Claude Code:

```text
/plugin marketplace add GetTrustedApp/lastid-agent
/plugin install lastid-agent
/lastid-agent:provision
```

`provision` prints a QR + URL. Scan the QR with the LastID app (or
open the URL on a device that holds your LastID), approve the agent
in your wallet, and the issued credential is saved to your host's
keychain. Steady-state sessions skip provisioning automatically.

Relaunch Claude with the LastID channel enabled so the agent receives
your chats in real time even when it's idle:

```bash
claude --dangerously-load-development-channels plugin:lastid-agent@lastid-agent
```

Channels are a Claude Code research-preview feature (requires v2.1.80+).
The development flag is what loads the LastID channel.

## Run more than one agent

Prefix the launch with a scope. Each scope is its own agent identity,
usable in any directory. No prefix is the default `main`:

```bash
LASTID_AGENT_SCOPE=research claude
```

## CLI

```text
lastid-agent provision                                # one-time: pair this host's agent to your LastID
lastid-agent status [--json]                          # report provisioning + listener state
lastid-agent listen                                   # background listener (auto-started)
lastid-agent show                                     # print the stored agent VC (debug)
lastid-agent run --handle <token> -- <cmd> [args]     # run a CLI command with one vault credential injected
```

### Run a CLI command with a vault credential

Pair `vault_use` (MCP) with `lastid-agent run` to run shell commands
that need your operator's credentials — without ever seeing them. Same
single-use handle pattern as `http_fetch`, just at the command line:

```bash
# 1. Mint a single-use handle for one vault item (MCP, in-agent).
# 2. Spend the handle to run a command. The plugin attaches the
#    credential per the injection policy (env var, basic-auth, etc.)
#    and your CLI never sees the plaintext.
lastid-agent run --handle <token> -- aws cloudtrail lookup-events --max-results 5
```

The handle is single-use, 5-minute TTL, and bound to this agent. Any
attempt to reuse it or hand it to another tool fails closed.

`provision` accepts:

```text
--parent-human-did did:lastid:z…    REQUIRED (or env LASTID_PARENT_HUMAN_DID)
--idp <url>                         Default: https://human.lastid.co
--runtime <name>                    Default: claude-code
--project-hint <hex>                Optional SHA-256 prefix
--scope <slug>                      Default: main
--force                             Overwrite existing keychain entry
```

## What the plugin gives your agent

### Talk to your operator

| Tool | Action |
|---|---|
| `lastid_send_message` | Send a chat message to your operator |
| `lastid_react` | React to your operator's last message with an emoji |
| `lastid_progress` | Post a progress update on long-running work |
| `lastid_report_bug` | File a bug report against this plugin |
| `lastid_whoami` | Show this agent's identity card |

The listener daemon receives operator messages from any device (phone,
web, desktop) and delivers them as channel events while Claude is idle.
End-to-end encrypted via MLS — only your agent can decrypt them.

### Use your operator's credentials safely

| Tool | Action |
|---|---|
| `vault_list` | List the vault items your operator shared with this agent |
| `vault_use` | Request a single-use handle for one item |
| `http_fetch` | Make an HTTP call with the handle attached at the network boundary |
| `lastid-agent run` (CLI) | Run a shell command with the handle injected as env/arg (see CLI section) |

The plaintext credential never enters the agent's context window. The
LastID desktop unfurls the handle at the wire (or process-spawn) and
attaches it per the operator's policy.

### Remember things across sessions

| Tool | Action |
|---|---|
| `lastid_memory_write` | Save a memory (operator approves) |
| `lastid_memory_draft` | Propose a memory for operator review |
| `lastid_memory_search` | Find memories by topic |
| `lastid_memory_get` | Fetch one memory by ID |
| `lastid_memory_list` | List memories in this scope |
| `lastid_memory_update` | Edit an existing memory |
| `lastid_memory_forget` | Delete a memory |

### Spawn helpers

| Tool | Action |
|---|---|
| `lastid_list_subagents` | List the sub-agents your operator authored |
| `lastid_invoke_subagent` | Run one with a task |
| `lastid_subagent_list_running` | Show in-flight sub-agent jobs |
| `lastid_subagent_result` | Fetch the result when it finishes |

Sub-agents are full identities of their own (own DID, own credential,
own capability set). Cascade-revoking the parent revokes the children
automatically.

## Slash commands

```text
/lastid-agent:provision    Pair this host's agent to your LastID
/lastid-agent:memory-setup Walk through memory configuration
```

## License

Apache-2.0. © LastID.
