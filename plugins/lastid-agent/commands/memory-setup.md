---
description: Enable semantic memory search — installs the local embedding model so memory retrieval ranks by meaning, not just keywords. One-time, opt-in, on-device.
---

Turn on semantic memory search for this agent. This is the opt-in step offered
right after provisioning — if you skipped it then, run it now. Until it runs,
memory retrieval still works but degrades to keyword scoring.

It runs entirely on this host (no server, no account flag). It:

1. Installs the embedding runtime (`@xenova/transformers`) into a stable,
   version-independent dir (`~/.lastid-agent/embeddings-runtime`) that survives
   `/plugin update`.
2. Downloads + warms the `all-MiniLM-L6-v2` model (~137MB, cached under
   `~/.lastid-agent/models`).
3. Backfills embeddings for this agent's existing memories so the first
   semantic search is fast.

Idempotent and safe to re-run: an already-installed dep is skipped and the model
cache is reused. The model download is shared across every agent scope on the
host; only the memories are per-identity.

## How to run this (agent: do this yourself — do NOT tell the operator to run it)

The model download can take a while, so launch it **in the background** or it
will stall your session. It inherits `LASTID_AGENT_SCOPE`, so it targets the
right agent automatically.

1. Launch it in the background:

   ```bash
   node ${CLAUDE_PLUGIN_ROOT}/bin/lastid-agent.js memory-setup
   ```

2. Tell the operator it's installing (one line — "enabling semantic memory,
   downloading the model now"), then let it run. Read the background output as
   it progresses; it prints the install step, "Downloading + warming the
   embedding model…", the backfill count, and finally
   **"Done. Semantic memory search is now active."**
3. On completion, confirm to the operator. If it prints
   `another install is in progress`, a prior run (or the listener's self-heal)
   is already doing it — just wait and re-check, don't relaunch.

If the model fails to load, it exits non-zero and memory search stays on keyword
fallback — report that rather than claiming success.

Advanced:
- `--scope <name>` — target a specific agent scope explicitly (otherwise inherits `LASTID_AGENT_SCOPE`, default `main`). The model is shared across scopes; this only controls which agent's memories get backfilled.
