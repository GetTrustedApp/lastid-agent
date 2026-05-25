---
description: Provision this agent's LastID-issued credential. Scan a QR with your LastID wallet — no DID typing.
---

Run the LastID Agent provisioning flow. Zero configuration required.

The CLI will:

1. Print a QR code in the terminal (and a `lastid://` deep link).
2. You scan the QR with your LastID wallet (or tap the deep link on the device that holds your LastID).
3. Your wallet presents your `LastID.Base` credential — the plugin extracts your DID automatically.
4. The plugin then runs the agent provisioning flow: surfaces a verification URL + user code, you approve in your wallet, and the issued `LastID.Agent.Base` SD-JWT is persisted to the OS keychain.

Future Claude Code sessions on this host run authenticated — no re-provisioning.

Run:

```bash
node ${CLAUDE_PLUGIN_ROOT}/bin/lastid-agent.js provision
```

Status check (no re-run):

```bash
node ${CLAUDE_PLUGIN_ROOT}/bin/lastid-agent.js status
```

Advanced flags:
- `--parent-human-did did:lastid:z…` — skip the QR step if you already know your DID (or set `LASTID_PARENT_HUMAN_DID`).
- `--idp <url>` — override the IdP base URL (default: `https://human.dev.lastid.co` while the agent flow is pre-prod).
- `--reissue` — replace the agent already provisioned on this host. Mints a new identity, clears this host's local state (synced rules, memories, MLS group state, inbox, sync cursor), and reconnects the listener on the new identity. Use this to re-pair after revoking, or to pick up newly-sealed seeds. (`--force` still works as a deprecated alias.)

## Run several agents on one host (scopes)

Set `LASTID_AGENT_SCOPE` to pin a whole Claude Code session to a distinct agent — its own identity, listener, and local state — usable in any directory:

```bash
LASTID_AGENT_SCOPE=lastid claude   # provisions/runs the "lastid" agent
LASTID_AGENT_SCOPE=work   claude   # a separate "work" agent on the same machine
claude                             # default scope = "main"
```

Provision each scope once (`LASTID_AGENT_SCOPE=lastid` then `/lastid-agent:provision`). All scopes share one host — and one embedding model (a one-time download); only the memories are per-identity. The default with nothing set is `main`.
