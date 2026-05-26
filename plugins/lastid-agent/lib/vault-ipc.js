/**
 * Vault IPC — the local trusted boundary. Runs INSIDE the listener (the single
 * process that holds slot_seed + the handle store + does injection), served as
 * newline-delimited JSON over a unix socket (same pattern as the embedding
 * daemon). The MCP tool process is a thin client: `vault_use` and `http_fetch`
 * forward here, so the secret is unfurled + attached ONLY in the listener and
 * the agent's tool process never holds it.
 *
 *   {op:'vault_use', item_id, ctx?, approved?, approval_id?}
 *       → {ok, vault_handle, expires_at_ms, item_id, injection}      (minted)
 *       | {policy_approval_required:true, ...}                       (needs phone)
 *       | {error:'policy_denied'|'share_not_found', ...}
 *   {op:'http_fetch', vault_handle, url, method?, headers?, body?}
 *       → {ok, status, headers, body, truncated}                     (injected+called)
 *       | {error:'handle_invalid'|'inject_failed'|'fetch_failed', ...}
 *
 * The request HANDLER (`handleVaultRequest`) is dependency-injected + pure of
 * sockets, so the allow/deny/approval + single-use + inject flow is unit-tested
 * without a real socket, fetch, or crypto.
 */
import { createServer, createConnection } from 'node:net';
import { unlink, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { evalShareForUse, OUTCOME } from './vault-policy.js';
import { applyInjection, injectionSummary } from './vault-inject.js';

const BODY_CAP = 256 * 1024; // 256 KiB, matches the desktop http_fetch cap

export function vaultSocketPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'vault.sock');
}

/**
 * Handle one vault IPC request. Deps:
 *   agentDid               this listener's agent DID (handles bind to it)
 *   resolveShare(itemId)   → decoded+verified share content, or null. The
 *                           caller owns decrypt + operator-sig verification, so
 *                           a forged/unverifiable share resolves to null.
 *   handles                VaultHandleStore
 *   fetchImpl              (url, opts) => Response-like
 *   now()                  clock (ms)
 *   recordUse(kind,handle) optional timing hook ('mint' | 'consume')
 */
export async function handleVaultRequest(req, deps) {
  const { agentDid, resolveShare, handles, fetchImpl, recordUse } = deps;
  const op = req?.op;

  if (op === 'vault_use') {
    const itemId = typeof req.item_id === 'string' ? req.item_id : '';
    if (!itemId) return { error: 'bad_request', detail: 'item_id required' };
    const content = await resolveShare(itemId);
    if (!content) return { error: 'share_not_found', detail: 'no verified share for this item' };

    const policy = evalShareForUse({ content, ctx: req.ctx ?? {} });
    if (policy.outcome === OUTCOME.DENY) {
      return { error: 'policy_denied', reason_kind: policy.reason_kind, reason_detail: policy.reason_detail, constraint_kind: policy.constraint_kind };
    }
    if (policy.outcome === OUTCOME.APPROVAL && req.approved !== true) {
      // The MCP drives the cross-device approval loop, then retries with
      // approved:true once it has verified the operator's decision JWS.
      return {
        policy_approval_required: true,
        item_id: itemId,
        resource_name: content.title,
        reason_kind: policy.reason_kind,
        reason_detail: policy.reason_detail,
        constraint_kind: policy.constraint_kind,
        require_approval_per_use: content.require_approval_per_use === true,
      };
    }
    const h = handles.mint({
      agentDid,
      itemId,
      shareId: content.share_id ?? null,
      wasApproved: req.approved === true,
      approvalId: typeof req.approval_id === 'string' ? req.approval_id : null,
    });
    recordUse?.('mint', h);
    return {
      ok: true,
      vault_handle: h.token,
      expires_at_ms: h.expiresAtMs,
      item_id: itemId,
      injection: injectionSummary(content.injection),
    };
  }

  if (op === 'http_fetch') {
    const token = typeof req.vault_handle === 'string' ? req.vault_handle : '';
    const h = handles.lookup(token, { agentDid });
    if (!h) return { error: 'handle_invalid', detail: 'handle missing, expired, or not yours' };

    const content = await resolveShare(h.itemId);
    if (!content) {
      handles.revoke(token);
      return { error: 'share_not_found', detail: 'share gone since the handle was minted' };
    }

    let injected;
    try {
      injected = applyInjection({
        injection: content.injection,
        secret: content.secret,
        url: req.url,
        headers: req.headers ?? {},
        item: content,
      });
    } catch (e) {
      handles.revoke(token); // single-use: consumed even on a bad spec
      recordUse?.('consume', h);
      return { error: 'inject_failed', detail: e?.message ?? String(e) };
    }

    try {
      const res = await fetchImpl(injected.url, {
        method: req.method ?? 'GET',
        headers: injected.headers,
        ...(req.body != null ? { body: req.body } : {}),
      });
      const status = typeof res?.status === 'number' ? res.status : 0;
      const rawBody = typeof res?.text === 'function' ? await res.text() : '';
      const truncated = rawBody.length > BODY_CAP;
      const body = truncated ? rawBody.slice(0, BODY_CAP) : rawBody;
      const headers = headersToObject(res?.headers);
      handles.revoke(token); // single-use
      recordUse?.('consume', h);
      return { ok: true, status, headers, body, truncated };
    } catch (e) {
      handles.revoke(token);
      recordUse?.('consume', h);
      return { error: 'fetch_failed', detail: e?.message ?? String(e) };
    }
  }

  return { error: 'unknown_op', detail: `unknown op '${op}'` };
}

function headersToObject(h) {
  const out = {};
  try {
    if (h && typeof h.forEach === 'function') {
      h.forEach((v, k) => {
        out[k] = v;
      });
    } else if (h && typeof h === 'object') {
      for (const [k, v] of Object.entries(h)) out[k] = String(v);
    }
  } catch {
    /* best-effort */
  }
  return out;
}

/** Start the vault IPC server in the listener. `deps` are passed to every
 *  request (see handleVaultRequest). Best-effort: a socket error never disrupts
 *  the listener's MLS/channel work. */
export async function startVaultServer({ scope = 'main', deps }) {
  const sockPath = vaultSocketPath(scope);
  await mkdir(dirname(sockPath), { recursive: true, mode: 0o700 });
  if (existsSync(sockPath)) {
    try {
      await unlink(sockPath);
    } catch {
      /* ignore */
    }
  }
  const server = createServer((conn) => {
    let buf = '';
    conn.on('error', () => {});
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let req;
        try {
          req = JSON.parse(line);
        } catch {
          conn.write(`${JSON.stringify({ error: 'bad_json' })}\n`);
          continue;
        }
        void handleVaultRequest(req, deps)
          .then((resp) => {
            if (!conn.destroyed) conn.write(`${JSON.stringify(resp)}\n`);
          })
          .catch((err) => {
            if (!conn.destroyed) {
              conn.write(`${JSON.stringify({ error: 'server_error', detail: err?.message ?? String(err) })}\n`);
            }
          });
      }
    });
  });
  server.on('error', (err) =>
    process.stderr.write(`[lastid-agent] vault server error: ${err.message}\n`),
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(sockPath, resolve);
  });
  return { status: 'listening', socket: sockPath, server };
}

/** Client (used by the MCP tool process): send one request, read one reply.
 *  Rejects if the listener socket isn't there (no listener running). */
export function vaultRequest(scope, req, { timeoutMs = 30_000 } = {}) {
  const sockPath = vaultSocketPath(scope);
  return new Promise((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error('vault IPC timeout'));
    }, timeoutMs);
    conn.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        try {
          resolve(JSON.parse(buf.slice(0, nl)));
        } catch (e) {
          reject(e);
        }
        conn.end();
      }
    });
    conn.write(`${JSON.stringify(req)}\n`);
  });
}
