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
- `--idp <url>` — override the IdP base URL (default: `https://human.lastid.co`).
- `--force` — overwrite an existing keychain entry.
