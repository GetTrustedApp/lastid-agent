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
import { randomUUID } from 'node:crypto';
import { evalShareForUse, OUTCOME } from './vault-policy.js';
import { defaultRateTracker } from './vault-rate.js';
import { exchangeClientCredentials } from './oauth-exchange.js';
import { applyInjection, injectionSummary, buildEnvInjection } from './vault-inject.js';
import { usageContext, summarizeConstraints } from './vault-cache.js';
import { buildChildEnv, runChildStreaming, commandBinary } from './vault-exec.js';

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
  const { agentDid, resolveShare, resolveSecret, genHandleKeypair, handles, fetchImpl, recordUse, audit, now, rateTracker = defaultRateTracker } = deps;
  const clock = typeof now === 'function' ? now : () => Date.now();
  const op = req?.op;

  if (op === 'vault_use') {
    const itemId = typeof req.item_id === 'string' ? req.item_id : '';
    if (!itemId) return { error: 'bad_request', detail: 'item_id required' };
    const content = await resolveShare(itemId);
    if (!content) return { error: 'share_not_found', detail: 'no verified share for this item' };

    // The listener is the single point that sees every mint, so IT supplies the
    // authoritative recent-use count for rate_per_minute (the caller can't be
    // trusted to count its own uses). Overrides any client-sent value.
    const ctx = { ...(req.ctx ?? {}), uses_last_minute: rateTracker.count(itemId, 60_000, clock()) };
    const policy = evalShareForUse({ content, ctx });
    if (policy.outcome === OUTCOME.DENY) {
      return { error: 'policy_denied', reason_kind: policy.reason_kind, reason_detail: policy.reason_detail, constraint_kind: policy.constraint_kind };
    }
    if (policy.outcome === OUTCOME.APPROVAL && req.approved !== true) {
      // Single dispatch site for the cross-device approval loop. Callers
      // (MCP handleLocalVault, CLI cmdRun, anything future) just await
      // vault_use — they NEVER see `policy_approval_required`, never run
      // the loop themselves. Bedrock [mem_fdf4ae34b140437098c90399efcde299]:
      // ONE place to keep in sync. Previously the dispatch lived in
      // mcp-server.js AND cli.js — every caller had to re-implement the
      // "check signal → POST → poll → retry" dance, which is exactly the
      // bifurcation that caused the duplicate-approval bug.
      //
      // `approval_request` is the BODY runApprovalLoop POSTs to the IdP's
      // /v1/agent-use-approvals — every field below is required by the
      // IdP's CreateBody validator. share_id matches the desktop's
      // `compute_share_id` template (lastid-vc::decision_jws) so the
      // operator's decision JWS binds to a share_id the desktop will
      // recognize on the retry path.
      const purposeIn = typeof req.purpose === 'string' && req.purpose.length > 0
        ? req.purpose
        : null;
      const approvalRequest = {
        share_id: `share::${agentDid}::${itemId}`,
        resource_kind: 'credential',
        resource_ref: itemId,
        // The IdP rejects an empty string for resource_name but accepts
        // its absence — only include when the share has a title.
        ...(content.title ? { resource_name: content.title } : {}),
        ...(purposeIn ? { purpose: purposeIn } : {}),
        reason_kind: policy.reason_kind,
        // The `one_time_use_required` branch of vault-policy returns no
        // reason_detail (the share itself is the "why"). The IdP's
        // CreateBody validator REQUIRES a non-empty reason_detail, so
        // default to a human-readable summary when policy didn't carry
        // one. constraint_failed paths always provide their own detail.
        reason_detail:
          typeof policy.reason_detail === 'string' && policy.reason_detail.length > 0
            ? policy.reason_detail
            : 'Operator requires approval for each use of this share.',
        ...(policy.constraint_kind ? { constraint_kind: policy.constraint_kind } : {}),
        // session_id is a per-use anchor so a re-request after a denial
        // is a fresh row in the operator's history (not a re-decision on
        // the same approval). Per-vault_use UUID is the simplest fit; the
        // operator's audit chain stitches by approval_id, not session_id.
        session_id: randomUUID(),
      };
      // Run the loop inline. The listener (startVaultServer's caller in
      // cli.js cmdListen) MUST inject signingSeed/agentDid/vcCompact into
      // deps; we don't have any other source for the DPoP-signing material
      // in this process. Tests can inject `runApprovalLoop: <fn>` as a dep
      // override so a unit test doesn't hit the real IdP.
      if (!deps.signingSeed || !deps.vcCompact) {
        return {
          error: 'policy_approval_unavailable',
          reason_detail:
            'listener missing signing material — approval loop cannot run without signingSeed + vcCompact in deps',
        };
      }
      const runLoop = deps.runApprovalLoop
        ?? (await import('./use-approval-loop.js')).runApprovalLoop;
      let outcome;
      try {
        outcome = await runLoop({
          approvalBody: { approval_request: approvalRequest },
          originalArgs: { item_id: itemId },
          agentDid,
          vcCompact: deps.vcCompact,
          signingSeed: deps.signingSeed,
        });
      } catch (err) {
        return {
          error: 'policy_approval_failed',
          reason_detail: err?.message ?? String(err),
        };
      }
      if (outcome?.expired) {
        return {
          error: 'policy_approval_expired',
          reason_detail: 'operator did not decide within the pending window',
        };
      }
      if (outcome?.denied) {
        return {
          error: outcome.body?.error ?? 'policy_approval_denied',
          reason_detail: outcome.body?.reason_detail ?? 'operator denied the approval',
        };
      }
      if (!outcome?.retryArgs) {
        return {
          error: 'policy_approval_unexpected',
          reason_detail: 'approval loop returned no retryArgs',
        };
      }
      // Approved — flip the flag + carry the approval_id forward, then
      // fall through to the mint code below (req.approved !== true
      // gate no longer fires). The mint path runs unchanged.
      req.approved = true;
      req.approval_id = outcome.retryArgs.approval_id;
    }
    // Mint an ephemeral handle keypair: the public key goes to the holder to
    // wrap the released credential to; the private key stays here and opens the
    // wrap exactly once. Required — the secret is delivered wrapped to it.
    let kp;
    try {
      kp = await genHandleKeypair();
    } catch (e) {
      return { error: 'handle_keypair_failed', detail: e?.message ?? String(e) };
    }
    if (!kp || typeof kp.public_sec1_b64 !== 'string' || typeof kp.secret_sec1_b64 !== 'string') {
      return { error: 'handle_keypair_failed', detail: 'keypair generator returned no keys' };
    }
    const h = handles.mint({
      agentDid,
      itemId,
      shareId: content.share_id ?? null,
      wasApproved: req.approved === true,
      approvalId: typeof req.approval_id === 'string' ? req.approval_id : null,
      handlePubB64: kp.public_sec1_b64,
      handlePrivB64: kp.secret_sec1_b64,
    });
    // Count this mint toward the per-item rate window (only successful mints —
    // a denied/pending use must not consume rate budget).
    rateTracker.record(itemId, clock());
    recordUse?.('mint', h);
    return {
      ok: true,
      vault_handle: h.token,
      expires_at_ms: h.expiresAtMs,
      item_id: itemId,
      injection: injectionSummary(content.injection),
      // Usage context so the agent knows HOW to use this credential + the
      // limits it's operating under — never the secret value.
      usage: usageContext(content),
      docs_url: content.docs_url,
      constraints_summary: summarizeConstraints(content.constraints),
    };
  }

  if (op === 'http_fetch') {
    const token = typeof req.vault_handle === 'string' ? req.vault_handle : '';
    const h = handles.lookup(token, { agentDid });
    if (!h) return { error: 'handle_invalid', detail: 'handle missing, expired, or not yours' };

    // The cached share is METADATA only (the injection spec + usage). The
    // credential itself is fetched JUST-IN-TIME and lives only from here until
    // we zeroize it — never on disk, never beyond this one call.
    const content = await resolveShare(h.itemId);
    if (!content) {
      handles.revoke(token);
      return { error: 'share_not_found', detail: 'share gone since the handle was minted' };
    }

    let secretObj = null;
    let injected = null;
    let mintedToken = null;
    let response;
    try {
      try {
        // Pass the handle so the secret is fetched WRAPPED to its keypair and
        // opened with the in-memory private key (two-layer envelope).
        secretObj = await resolveSecret(h.itemId, h);
      } catch (e) {
        return { error: 'secret_unavailable', detail: e?.message ?? String(e) };
      }
      if (!secretObj || typeof secretObj.secret !== 'string') {
        return { error: 'secret_unavailable', detail: 'no credential released for this handle' };
      }

      // OAuth client_credentials: the sealed secret is the CLIENT SECRET, not a
      // bearer token (we never store a minted token — it would be stale). Mint a
      // fresh access token here, from the agent's machine (so IP-allowlisted
      // apps see the right source), and inject THAT. Other injections (incl. an
      // already-captured authorization_code token) inject the sealed value as-is.
      let injectSecret = secretObj.secret;
      const inj = content.injection;
      if (inj?.type === 'oauth_bearer' && inj.grant_type === 'client_credentials') {
        try {
          mintedToken = await exchangeClientCredentials(
            {
              tokenEndpoint: inj.token_endpoint,
              clientId: inj.client_id,
              clientSecret: secretObj.secret,
              scope: inj.scope,
            },
            fetchImpl,
          );
        } catch (e) {
          response = { error: 'oauth_exchange_failed', detail: e?.message ?? String(e) };
          return response;
        }
        injectSecret = mintedToken;
      }

      try {
        injected = applyInjection({
          injection: content.injection,
          secret: injectSecret,
          url: req.url,
          headers: req.headers ?? {},
          // Inject reads companion fields (basic_auth username, AWS secret) off
          // the item; merge the JIT secret(s) onto the metadata for this call.
          item: { ...content, secret: secretObj.secret, secret_secondary: secretObj.secret_secondary },
        });
      } catch (e) {
        response = { error: 'inject_failed', detail: e?.message ?? String(e) };
        return response;
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
        response = { ok: true, status, headers, body, truncated };
        return response;
      } catch (e) {
        response = { error: 'fetch_failed', detail: e?.message ?? String(e) };
        return response;
      }
    } finally {
      // Zeroize the decrypted secret the instant we're done, drop the injected
      // headers (they hold the secret string), consume the handle (single-use),
      // and record the two guardrail timings the front page surfaces:
      //   permissioned_ms  — how long the agent held a usable handle (mint→now)
      //   credentialed_ms  — the unencrypted-credential window (decrypt→zeroize)
      const consumeMs = clock();
      try {
        secretObj?.zeroize?.();
      } catch {
        /* best-effort */
      }
      injected = null;
      // Drop the minted access token reference too (a JS string can't be wiped
      // in place, same as the injected secret — but don't retain it past use).
      mintedToken = null;
      handles.revoke(token);
      // permissioned_ms = how long the agent held a usable handle (mint→now).
      // credentialed_ms = the TRUE unencrypted-credential window: from when the
      // secret was decrypted (secretObj.decryptedAtMs) to zeroize — sub-second
      // precision, NOT rounded up to a whole second. Surfaced on the response so
      // the caller (and the operator's audit) sees the real exposure per call.
      const metrics = {
        permissioned_ms: Math.max(0, consumeMs - (h.mintedAtMs ?? consumeMs)),
        credentialed_ms: secretObj?.decryptedAtMs
          ? Math.max(0, consumeMs - secretObj.decryptedAtMs)
          : 0,
      };
      if (response && typeof response === 'object') {
        response.permissioned_ms = metrics.permissioned_ms;
        response.credentialed_ms = metrics.credentialed_ms;
      }
      recordUse?.('consume', h, {
        ...metrics,
        status: response && 'status' in response ? response.status : null,
        outcome: response?.ok ? 'ok' : (response?.error ?? 'error'),
      });
      // Audit chain: a credential was injected at the network boundary (the
      // 'credential_use' class). Non-sensitive only — item id, destination host,
      // injection kind, HTTP status, outcome, and the credentialed window. NEVER
      // the secret. Gated + spooled by the injected audit() (audit-policy.js).
      try {
        let host = null;
        try {
          host = new URL(req.url).host;
        } catch {
          /* unparseable url → no host */
        }
        audit?.('AgentCredentialInjected', {
          item_id: h.itemId,
          host,
          injection: content?.injection?.type ?? null,
          status: response && 'status' in response ? response.status : null,
          outcome: response?.ok ? 'ok' : (response?.error ?? 'error'),
          credentialed_ms: metrics.credentialed_ms,
        });
      } catch {
        /* audit is best-effort — never disrupt the use path */
      }
    }
  }

  return { error: 'unknown_op', detail: `unknown op '${op}'` };
}

/**
 * Handle a STREAMING `exec` op (the CLI credential proxy): inject a vault secret
 * as env vars into a child process, stream its scrubbed stdout/stderr back as
 * frames via `sink`, and emit a terminal frame. Mirrors http_fetch's lifecycle
 * (resolve → inject → run → finally{ zeroize, revoke, metrics, audit }) but the
 * "work" is spawning a child and the injection is an env map. The secret lives
 * only in the listener + the child's env, never in the agent.
 *
 *   {op:'exec', vault_handle, argv:string[], cwd?}
 *     → frames: {stream:'stdout'|'stderr', b64}  (0+, as output arrives)
 *     → terminal: {ok, exit_code, signal, timed_out, truncated, permissioned_ms, credentialed_ms}
 *               | {error:'handle_invalid'|'binary_not_permitted'|'inject_failed'|...}
 *
 * @param {object} req
 * @param {object} deps  same as handleVaultRequest + spawnImpl
 * @param {(frame:object)=>void} sink  emits a frame to the client
 */
export async function handleVaultExec(req, deps, sink) {
  const { agentDid, resolveShare, resolveSecret, handles, recordUse, audit, now, spawnImpl } = deps;
  const clock = typeof now === 'function' ? now : () => Date.now();
  const emit = (f) => { try { sink(f); } catch { /* client gone */ } };

  const token = typeof req.vault_handle === 'string' ? req.vault_handle : '';
  const h = handles.lookup(token, { agentDid });
  if (!h) { emit({ error: 'handle_invalid', detail: 'handle missing, expired, or not yours' }); return; }

  // argv must be a clean non-empty string[]; anything else is a malformed request.
  const argv = Array.isArray(req.argv) ? req.argv : null;
  if (!argv || argv.length === 0 || !argv.every((a) => typeof a === 'string')) {
    handles.revoke(token);
    emit({ error: 'bad_request', detail: 'argv must be a non-empty string[]' });
    return;
  }
  const bin = commandBinary(argv);

  const content = await resolveShare(h.itemId);
  if (!content) {
    handles.revoke(token);
    emit({ error: 'share_not_found', detail: 'share gone since the handle was minted' });
    return;
  }

  // Binary binding + injectability checked BEFORE any secret resolution: a
  // mismatch (e.g. trying to wrap `printenv`/`env`/`sh`) never decrypts the
  // secret, and still consumes the single-use handle. Audited so the operator
  // sees the denied attempt in the same credentialed-access surface.
  if (content.injection?.type !== 'env') {
    handles.revoke(token);
    audit?.('AgentCredentialInjected', { item_id: h.itemId, host: null, binary: bin, injection: content.injection?.type ?? null, status: null, outcome: 'inject_failed', credentialed_ms: 0 });
    emit({ error: 'inject_failed', detail: 'not an env-injectable credential' });
    return;
  }
  const binaries = Array.isArray(content.binaries) ? content.binaries : [];
  if (!binaries.includes(bin)) {
    handles.revoke(token);
    audit?.('AgentCredentialInjected', { item_id: h.itemId, host: null, binary: bin, injection: 'env', status: null, outcome: 'binary_not_permitted', credentialed_ms: 0 });
    emit({ error: 'binary_not_permitted', detail: bin });
    return;
  }

  let secretObj = null;
  let injectedEnv = null;
  let terminal = null;
  try {
    try {
      secretObj = await resolveSecret(h.itemId, h);
    } catch (e) {
      terminal = { error: 'secret_unavailable', detail: e?.message ?? String(e) };
      return;
    }
    if (!secretObj || typeof secretObj.secret !== 'string') {
      terminal = { error: 'secret_unavailable', detail: 'no credential released for this handle' };
      return;
    }
    try {
      injectedEnv = buildEnvInjection({
        injection: content.injection,
        secret: secretObj.secret,
        secret_secondary: secretObj.secret_secondary,
      }).env;
    } catch (e) {
      terminal = { error: 'inject_failed', detail: e?.message ?? String(e) };
      return;
    }

    const childEnv = buildChildEnv(process.env, injectedEnv, { allowlist: content.env_allowlist });
    // Scrub BOTH secret values from the child's output, longest-first.
    const secrets = [secretObj.secret_secondary, secretObj.secret].filter(
      (s) => typeof s === 'string' && s.length > 0,
    );
    const result = await runChildStreaming({
      argv,
      cwd: typeof req.cwd === 'string' ? req.cwd : undefined,
      env: childEnv,
      secrets,
      ...(typeof content.exec_timeout_ms === 'number' ? { timeoutMs: content.exec_timeout_ms } : {}),
      spawnImpl,
      onStdout: (b) => emit({ stream: 'stdout', b64: b.toString('base64') }),
      onStderr: (b) => emit({ stream: 'stderr', b64: b.toString('base64') }),
    });
    terminal = result.spawn_error
      ? { error: 'spawn_failed', detail: result.spawn_error, binary: bin }
      : { ok: true, exit_code: result.exit_code, signal: result.signal, timed_out: result.timed_out, truncated: result.truncated };
    return;
  } finally {
    // Identical lifecycle to http_fetch: zeroize the secret, consume the handle,
    // record the two timings (permissioned_ms = handle lifetime; credentialed_ms
    // = decrypt → child-exit/scrub = the true credential-hold window), and audit
    // the credentialed use in the SAME 'AgentCredentialInjected' surface as the
    // network path — so all credentialed access is captured, CLI included.
    const consumeMs = clock();
    try { secretObj?.zeroize?.(); } catch { /* best-effort */ }
    injectedEnv = null;
    handles.revoke(token);
    const metrics = {
      permissioned_ms: Math.max(0, consumeMs - (h.mintedAtMs ?? consumeMs)),
      credentialed_ms: secretObj?.decryptedAtMs ? Math.max(0, consumeMs - secretObj.decryptedAtMs) : 0,
    };
    if (terminal && typeof terminal === 'object') {
      terminal.permissioned_ms = metrics.permissioned_ms;
      terminal.credentialed_ms = metrics.credentialed_ms;
    }
    recordUse?.('consume', h, {
      ...metrics,
      status: terminal?.exit_code ?? null,
      outcome: terminal?.ok ? 'ok' : (terminal?.error ?? 'error'),
    });
    try {
      audit?.('AgentCredentialInjected', {
        item_id: h.itemId,
        host: null,
        binary: bin,
        injection: 'env',
        status: terminal?.exit_code ?? null,
        outcome: terminal?.ok ? 'ok' : (terminal?.error ?? 'error'),
        credentialed_ms: metrics.credentialed_ms,
      });
    } catch { /* audit is best-effort */ }
    emit(terminal ?? { error: 'exec_failed', detail: 'no result' });
  }
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
        // `exec` streams MULTIPLE frames (output chunks + a terminal); route it
        // to the streaming handler which writes frames directly. All other ops
        // are single request → single reply.
        if (req && req.op === 'exec') {
          void handleVaultExec(req, deps, (frame) => {
            if (!conn.destroyed) conn.write(`${JSON.stringify(frame)}\n`);
          }).catch((err) => {
            if (!conn.destroyed) {
              conn.write(`${JSON.stringify({ error: 'server_error', detail: err?.message ?? String(err) })}\n`);
            }
          });
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
 *  Rejects if the listener socket isn't there (no listener running).
 *
 *  Default timeout is 10min to cover the full operator-approval window
 *  inside the listener — vault_use's approval loop blocks up to
 *  use-approval-loop's PENDING_TTL_MS (5min) waiting for the operator's
 *  decision JWS, plus headroom for cross-device propagation. Pre-fix the
 *  default was 30s; a slow operator-decision time produced a misleading
 *  "vault IPC timeout" while the listener was still happily polling, the
 *  operator's eventual approval landed against a dead client, and the
 *  whole flow looked broken when it was just impatient. */
export function vaultRequest(scope, req, { timeoutMs = 600_000 } = {}) {
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

/** Streaming client for the `exec` op (used by `lastid-agent run`): send the
 *  request, then read frames until the terminal one — calling onStdout/onStderr
 *  with the (already-scrubbed) raw output bytes as they arrive. Resolves with
 *  the terminal frame ({ok, exit_code, ...} or {error}). The secret never
 *  enters this process: the listener only ever sends scrubbed output. */
export function vaultExecStream(scope, req, { onStdout, onStderr, timeoutMs = 600_000 } = {}) {
  const sockPath = vaultSocketPath(scope);
  return new Promise((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    let done = false;
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error('vault exec IPC timeout'));
    }, timeoutMs);
    conn.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let frame;
        try {
          frame = JSON.parse(line);
        } catch {
          continue;
        }
        if (frame.stream === 'stdout' && typeof frame.b64 === 'string') {
          onStdout?.(Buffer.from(frame.b64, 'base64'));
          continue;
        }
        if (frame.stream === 'stderr' && typeof frame.b64 === 'string') {
          onStderr?.(Buffer.from(frame.b64, 'base64'));
          continue;
        }
        // Anything else is the terminal frame.
        done = true;
        clearTimeout(timer);
        resolve(frame);
        conn.end();
        return;
      }
    });
    conn.on('close', () => {
      if (!done) {
        clearTimeout(timer);
        reject(new Error('vault exec connection closed before terminal frame'));
      }
    });
    conn.write(`${JSON.stringify({ ...req, op: 'exec' })}\n`);
  });
}
