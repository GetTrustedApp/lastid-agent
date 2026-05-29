/**
 * Vault IPC handler (lib/vault-ipc.js::handleVaultRequest) — the local trusted
 * boundary. Tested with injected deps (no socket, no real fetch/crypto): the
 * allow/deny/approval gate, single-use handle consumption, injection at fetch,
 * and that an invalid/forged share or handle is refused. Plus an end-to-end
 * round-trip over the real unix socket.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';

import { EventEmitter } from 'node:events';
import { handleVaultRequest, handleVaultExec, startVaultServer, vaultRequest, vaultExecStream, vaultSocketPath } from '../lib/vault-ipc.js';
import { VaultHandleStore } from '../lib/vault-handle-store.js';
import { VaultRateTracker } from '../lib/vault-rate.js';

const AGENT = 'did:lastid:agent:zA';

// resolveShare returns METADATA only — the secret is fetched JIT via
// resolveSecret (the secret never sits in the cached share).
const SHARE = {
  item_id: 'vault_1',
  title: 'OpenAI key',
  injection: { type: 'header', name: 'Authorization', format: 'Bearer {value}' },
  constraints: [],
  on_violation: { type: 'deny' },
  require_approval_per_use: false,
  granted_actions: ['use'],
};

const SECRET = 'sk-SECRET-zzz';

function deps(over = {}) {
  return {
    agentDid: AGENT,
    handles: new VaultHandleStore(),
    resolveShare: async (id) => (id === 'vault_1' ? { ...SHARE } : null),
    // JIT secret release (now handle-aware): the secret is wrapped to the
    // handle's keypair, fetched + opened in resolveSecret.
    resolveSecret: async (id, _handle) =>
      id === 'vault_1' ? { secret: SECRET, zeroize: () => {} } : null,
    // Mints the ephemeral handle keypair at vault_use (wasm in prod).
    genHandleKeypair: async () => ({ public_sec1_b64: 'PUBKEY', secret_sec1_b64: 'PRIVKEY' }),
    fetchImpl: async () => ({ status: 200, text: async () => 'OK', headers: { 'content-type': 'text/plain' } }),
    now: () => Date.now(),
    ...over,
  };
}

test('vault_use (allow) mints a handle + returns injection summary, NEVER the secret', async () => {
  const d = deps();
  const r = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(r.ok, true);
  assert.ok(r.vault_handle);
  assert.deepEqual(r.injection, { type: 'header', name: 'Authorization', format: 'Bearer {value}' });
  assert.equal(JSON.stringify(r).includes('sk-SECRET-zzz'), false, 'secret never in vault_use reply');
})

test('vault_use on an unknown / unverifiable share → share_not_found', async () => {
  const r = await handleVaultRequest({ op: 'vault_use', item_id: 'nope' }, deps());
  assert.equal(r.error, 'share_not_found');
})

test('vault_use denied by policy → policy_denied (no handle)', async () => {
  const d = deps({ resolveShare: async () => ({ ...SHARE, constraints: [{ type: 'time_window', not_before: '2026-01-01T00:00:00Z', not_after: '2026-01-02T00:00:00Z' }] }) });
  const r = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1', ctx: { now_ms: 999999 } }, d);
  assert.equal(r.error, 'policy_denied');
  assert.equal(d.handles.size, 0);
})

test('vault_use needing approval → policy_approval_required until approved:true', async () => {
  const d = deps({ resolveShare: async () => ({ ...SHARE, require_approval_per_use: true }) });
  const r1 = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(r1.policy_approval_required, true);
  assert.equal(d.handles.size, 0, 'no handle until approved');
  const r2 = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1', approved: true, approval_id: 'ap_1' }, d);
  assert.equal(r2.ok, true);
  assert.ok(r2.vault_handle);
})

test('policy_approval_required carries an `approval_request` with EVERY IdP-required field', async () => {
  // Regression for the 2026-05-28 bug where the IdP rejected the POST
  // with "share_id required; resource_kind required; resource_ref
  // required; reason_kind required; reason_detail required; session_id
  // required" — vault-ipc returned the signal without an approval_request
  // and runApprovalLoop POSTed JSON.stringify(undefined).
  const d = deps({
    resolveShare: async () => ({
      ...SHARE,
      require_approval_per_use: true,
      title: 'LastID - IDP - AWS',
    }),
  });
  const r = await handleVaultRequest(
    { op: 'vault_use', item_id: 'vault_aws', purpose: 'fetch the last 5 CloudTrail events' },
    d,
  );
  assert.equal(r.policy_approval_required, true);
  assert.ok(r.approval_request, 'approval_request is present')
  // Every IdP CreateBody-required field is populated; share_id matches
  // the desktop's `compute_share_id` template (see
  // lastid-vc::decision_jws::compute_share_id) so the operator's
  // decision binds to a share_id the desktop will recognize.
  assert.match(r.approval_request.share_id, /^share::did:lastid:agent:.+::vault_aws$/);
  assert.equal(r.approval_request.resource_kind, 'credential');
  assert.equal(r.approval_request.resource_ref, 'vault_aws');
  assert.equal(r.approval_request.resource_name, 'LastID - IDP - AWS');
  assert.equal(r.approval_request.purpose, 'fetch the last 5 CloudTrail events');
  assert.ok(typeof r.approval_request.reason_kind === 'string' && r.approval_request.reason_kind.length > 0);
  assert.ok(typeof r.approval_request.reason_detail === 'string' && r.approval_request.reason_detail.length > 0);
  assert.match(r.approval_request.session_id, /^[0-9a-f-]{36}$/i);
})

test('approval_request omits resource_name + purpose when the share/call has neither (IdP rejects empty-string)', async () => {
  // The IdP's CreateBody validator rejects empty-string resource_name /
  // purpose. Construct the request with the field ABSENT (not
  // empty-string) when there's nothing to put there.
  const d = deps({
    resolveShare: async () => ({
      ...SHARE,
      require_approval_per_use: true,
      title: '', // simulate a share with no human-readable title
    }),
  });
  const r = await handleVaultRequest(
    { op: 'vault_use', item_id: 'vault_x' }, // no purpose
    d,
  );
  assert.equal(r.policy_approval_required, true);
  assert.equal('resource_name' in r.approval_request, false, 'resource_name absent, not empty-string');
  assert.equal('purpose' in r.approval_request, false, 'purpose absent, not empty-string');
})

test('http_fetch injects the secret, calls, and revokes (single-use)', async () => {
  let seen = null;
  const d = deps({
    fetchImpl: async (url, opts) => {
      seen = { url, headers: opts.headers };
      return { status: 200, text: async () => 'hello', headers: {} };
    },
  });
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  const r = await handleVaultRequest(
    { op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://api.openai.com/v1/models', headers: { Accept: 'application/json' } },
    d,
  );
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.body, 'hello');
  // The secret was attached to the OUTBOUND request only.
  assert.equal(seen.headers.Authorization, 'Bearer sk-SECRET-zzz');
  // Single-use: the handle is gone; a replay fails.
  const replay = await handleVaultRequest({ op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://x' }, d);
  assert.equal(replay.error, 'handle_invalid');
})

test('vault_use mints the handle WITH an ephemeral keypair (for the wrap)', async () => {
  const d = deps();
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  const h = d.handles.lookup(used.vault_handle, { agentDid: AGENT });
  assert.equal(h.handlePubB64, 'PUBKEY');
  assert.equal(h.handlePrivB64, 'PRIVKEY');
  // The keypair is internal — it must NOT be in the agent-facing reply.
  assert.equal(JSON.stringify(used).includes('PRIVKEY'), false);
})

test('vault_use fails closed if the handle keypair cannot be minted', async () => {
  const d = deps({ genHandleKeypair: async () => { throw new Error('wasm down'); } });
  const r = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(r.error, 'handle_keypair_failed');
  assert.equal(d.handles.size, 0, 'no handle minted without a keypair');
})

test('http_fetch fetches the secret JIT (wrapped to the handle), zeroizes, records timing', async () => {
  let zeroized = false;
  let resolvedSecretFor = null;
  let sawHandleKeypair = false;
  let metric = null;
  const d = deps({
    resolveSecret: async (id, handle) => {
      resolvedSecretFor = id;
      sawHandleKeypair = handle?.handlePubB64 === 'PUBKEY' && handle?.handlePrivB64 === 'PRIVKEY';
      return { secret: SECRET, zeroize: () => { zeroized = true; } };
    },
    recordUse: (kind, _h, m) => { if (kind === 'consume') metric = m; },
  });
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  const r = await handleVaultRequest(
    { op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://api.openai.com/v1/models' },
    d,
  );
  assert.equal(r.ok, true);
  assert.equal(resolvedSecretFor, 'vault_1', 'secret fetched JIT for this share');
  assert.equal(sawHandleKeypair, true, 'the handle (with its keypair) is passed to resolveSecret');
  assert.equal(zeroized, true, 'secret buffer zeroized after the call');
  // Timing captured for the guardrail metrics.
  assert.ok(metric && typeof metric.permissioned_ms === 'number');
  assert.ok(typeof metric.credentialed_ms === 'number');
  assert.equal(metric.outcome, 'ok');
  assert.equal(metric.status, 200);
})

test('http_fetch when no secret is released → secret_unavailable, handle consumed, no fetch', async () => {
  let called = false;
  const d = deps({
    resolveSecret: async () => null, // IdP released nothing (revoked / 404)
    fetchImpl: async () => ((called = true), { status: 200, text: async () => '' }),
  });
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  const r = await handleVaultRequest({ op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://x' }, d);
  assert.equal(r.error, 'secret_unavailable');
  assert.equal(called, false, 'never fetched without a credential');
  // Single-use: the handle is consumed even when the secret was unavailable.
  const replay = await handleVaultRequest({ op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://x' }, d);
  assert.equal(replay.error, 'handle_invalid');
})

test('http_fetch with a bogus / other-agent handle → handle_invalid (no fetch)', async () => {
  let called = false;
  const d = deps({ fetchImpl: async () => ((called = true), { status: 200, text: async () => '' }) });
  const r = await handleVaultRequest({ op: 'http_fetch', vault_handle: 'not-a-real-token', url: 'https://x' }, d);
  assert.equal(r.error, 'handle_invalid');
  assert.equal(called, false);
})

test('rate_per_minute enforces across calls — the listener supplies the count', async () => {
  // A shared tracker + fixed clock: max 1/min, so the 2nd use within the window
  // is denied. Proves the listener feeds uses_last_minute (previously always 0,
  // so the limit never tripped) and only counts successful mints.
  const rateTracker = new VaultRateTracker();
  const now = 1_000_000;
  const d = deps({
    rateTracker,
    now: () => now,
    resolveShare: async () => ({ ...SHARE, constraints: [{ type: 'rate_per_minute', max: 1 }] }),
  });
  const first = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(first.ok, true, 'first use under the limit is allowed + minted');
  const second = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(second.error, 'policy_denied');
  assert.equal(second.reason_kind, 'rate_limited');
  assert.equal(second.constraint_kind, 'rate_per_minute');
})

test('a denied use does not consume rate budget', async () => {
  // First use denied for a DIFFERENT reason (time window) must not record a mint,
  // so a later in-window use still has full budget.
  const rateTracker = new VaultRateTracker();
  const now = Date.parse('2026-03-01T12:00:00Z');
  const d = deps({
    rateTracker,
    now: () => now,
    resolveShare: async () => ({
      ...SHARE,
      constraints: [
        { type: 'time_window', not_before: '2026-01-01T00:00:00Z', not_after: '2026-02-01T00:00:00Z' }, // expired
        { type: 'rate_per_minute', max: 1 },
      ],
    }),
  });
  const denied = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(denied.error, 'policy_denied');
  assert.equal(rateTracker.count('vault_1', 60_000, now), 0, 'denied use recorded no mint');
})

test('oauth client_credentials: listener mints a token from the sealed secret and injects THAT (never the client_secret)', async () => {
  const TOKEN_ENDPOINT = 'https://idp.example.com/oauth/token';
  const CLIENT_SECRET = 'cs-DO-NOT-LEAK';
  let sentAuth = null;
  const d = deps({
    resolveShare: async () => ({
      ...SHARE,
      injection: {
        type: 'oauth_bearer',
        name: 'Authorization',
        format: 'Bearer {value}',
        grant_type: 'client_credentials',
        token_endpoint: TOKEN_ENDPOINT,
        client_id: 'cid',
        scope: 'read',
      },
    }),
    // The sealed secret IS the client secret, not a bearer token.
    resolveSecret: async () => ({ secret: CLIENT_SECRET, zeroize: () => {} }),
    fetchImpl: async (url, opts) => {
      if (url === TOKEN_ENDPOINT) {
        // The token exchange carries the client secret in its body...
        assert.match(opts.body, /client_secret=cs-DO-NOT-LEAK/);
        return { status: 200, json: async () => ({ access_token: 'minted-AT', token_type: 'Bearer' }) };
      }
      // ...but the OUTBOUND request must carry the MINTED token, not the secret.
      sentAuth = opts.headers.Authorization;
      return { status: 200, text: async () => 'OK', headers: {} };
    },
  });
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  assert.equal(used.ok, true);
  const r = await handleVaultRequest({ op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://api.example.com/x' }, d);
  assert.equal(r.ok, true);
  assert.equal(sentAuth, 'Bearer minted-AT', 'injected the minted token, not the client secret');
  assert.equal(JSON.stringify(r).includes(CLIENT_SECRET), false, 'client secret never in the response');
})

test('oauth client_credentials: a failed token exchange → oauth_exchange_failed, no outbound call', async () => {
  let outboundCalled = false;
  const d = deps({
    resolveShare: async () => ({
      ...SHARE,
      injection: { type: 'oauth_bearer', name: 'Authorization', format: 'Bearer {value}', grant_type: 'client_credentials', token_endpoint: 'https://idp/token', client_id: 'cid' },
    }),
    resolveSecret: async () => ({ secret: 'cs', zeroize: () => {} }),
    fetchImpl: async (url) => {
      if (url === 'https://idp/token') return { status: 401, json: async () => ({ error: 'invalid_client' }) };
      outboundCalled = true;
      return { status: 200, text: async () => 'OK', headers: {} };
    },
  });
  const used = await handleVaultRequest({ op: 'vault_use', item_id: 'vault_1' }, d);
  const r = await handleVaultRequest({ op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://api/x' }, d);
  assert.equal(r.error, 'oauth_exchange_failed');
  assert.equal(outboundCalled, false, 'never made the outbound call without a token');
})

test('round-trips over the real unix socket', async () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  const { server } = await startVaultServer({ scope, deps: deps() });
  try {
    const used = await vaultRequest(scope, { op: 'vault_use', item_id: 'vault_1' });
    assert.equal(used.ok, true);
    const fetched = await vaultRequest(scope, { op: 'http_fetch', vault_handle: used.vault_handle, url: 'https://x' });
    assert.equal(fetched.ok, true);
    assert.equal(fetched.status, 200);
  } finally {
    server.close();
    try { rmSync(vaultSocketPath(scope), { force: true }); } catch { /* ignore */ }
    rmSync(dir, { recursive: true, force: true });
  }
})

// ── exec op (CLI credential proxy) ────────────────────────────────────────────

const ENV_SHARE = {
  item_id: 'vault_env',
  title: 'GH token',
  injection: { type: 'env', env_map: [{ name: 'GH_TOKEN', field: 'secret' }] },
  binaries: ['gh'],
  constraints: [],
  on_violation: { type: 'deny' },
  granted_actions: ['use'],
};
const ENV_SECRET = 'ghp_TOPSECRET_TOKEN_value';

// A spawn fake: emits `stdout` then closes; captures the env it was handed.
function fakeSpawn({ stdout = '', exitCode = 0, onEnv, onSpawn } = {}) {
  return (_cmd, _args, opts) => {
    onSpawn?.();
    onEnv?.(opts?.env);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};
    setImmediate(() => {
      if (stdout) child.stdout.emit('data', Buffer.from(stdout));
      child.emit('close', exitCode, null);
    });
    return child;
  };
}

function execDeps(over = {}) {
  return {
    agentDid: AGENT,
    handles: new VaultHandleStore(),
    resolveShare: async (id) => (id === 'vault_env' ? { ...ENV_SHARE } : null),
    resolveSecret: async (id) => (id === 'vault_env' ? { secret: ENV_SECRET, decryptedAtMs: Date.now(), zeroize: () => {} } : null),
    genHandleKeypair: async () => ({ public_sec1_b64: 'P', secret_sec1_b64: 'S' }),
    now: () => Date.now(),
    spawnImpl: fakeSpawn({}),
    ...over,
  };
}

function collectSink() {
  const frames = [];
  return { frames, sink: (f) => frames.push(f), terminal: () => frames[frames.length - 1] };
}

async function mintHandle(d, itemId = 'vault_env') {
  const r = await handleVaultRequest({ op: 'vault_use', item_id: itemId }, d);
  return r.vault_handle;
}

test('exec: injects env into the child, streams SCRUBBED output, audits credentialed use', async () => {
  const audited = [];
  let zeroized = false;
  let seenEnv = null;
  const d = execDeps({
    spawnImpl: fakeSpawn({ stdout: `hello ${ENV_SECRET} bye`, onEnv: (e) => { seenEnv = e; } }),
    resolveSecret: async (id) => (id === 'vault_env' ? { secret: ENV_SECRET, decryptedAtMs: Date.now(), zeroize: () => { zeroized = true; } } : null),
    audit: (type, meta) => audited.push({ type, meta }),
  });
  const handle = await mintHandle(d);
  const c = collectSink();
  await handleVaultExec({ vault_handle: handle, argv: ['gh', 'api', 'user'] }, d, c.sink);

  assert.equal(seenEnv.GH_TOKEN, ENV_SECRET, 'credential reached the child env');
  const streamed = c.frames.filter((f) => f.stream).map((f) => Buffer.from(f.b64, 'base64').toString('utf8')).join('');
  assert.equal(streamed.includes(ENV_SECRET), false, 'secret scrubbed from streamed output');
  assert.ok(streamed.includes('[redacted]'));
  const term = c.terminal();
  assert.equal(term.ok, true);
  assert.equal(term.exit_code, 0);
  assert.equal(typeof term.credentialed_ms, 'number');
  assert.equal(JSON.stringify(c.frames).includes(ENV_SECRET), false, 'secret never in any frame');
  assert.ok(zeroized, 'secret zeroized');
  const ev = audited.find((a) => a.type === 'AgentCredentialInjected');
  assert.ok(ev, 'credentialed-access audit emitted');
  assert.equal(ev.meta.binary, 'gh');
  assert.equal(ev.meta.injection, 'env');
  assert.equal(typeof ev.meta.credentialed_ms, 'number');
  assert.equal(JSON.stringify(ev.meta).includes(ENV_SECRET), false, 'audit holds no secret');
})

test('exec: handle is single-use — replay refused, no second spawn', async () => {
  let spawnCount = 0;
  const d = execDeps({ spawnImpl: fakeSpawn({ stdout: 'ok', onSpawn: () => { spawnCount++; } }) });
  const handle = await mintHandle(d);
  await handleVaultExec({ vault_handle: handle, argv: ['gh', 'x'] }, d, collectSink().sink);
  const c = collectSink();
  await handleVaultExec({ vault_handle: handle, argv: ['gh', 'x'] }, d, c.sink);
  assert.equal(c.terminal().error, 'handle_invalid');
  assert.equal(spawnCount, 1, 'replay did not spawn');
})

test('exec: binary not in the share binding is denied BEFORE the secret is resolved', async () => {
  let resolved = false;
  let spawned = false;
  const d = execDeps({
    resolveSecret: async () => { resolved = true; return { secret: ENV_SECRET, decryptedAtMs: Date.now(), zeroize() {} }; },
    spawnImpl: fakeSpawn({ onSpawn: () => { spawned = true; } }),
  });
  const handle = await mintHandle(d);
  const c = collectSink();
  await handleVaultExec({ vault_handle: handle, argv: ['printenv', 'GH_TOKEN'] }, d, c.sink);
  assert.equal(c.terminal().error, 'binary_not_permitted');
  assert.equal(resolved, false, 'secret never resolved on a binary mismatch');
  assert.equal(spawned, false, 'child never spawned on a binary mismatch');
})

test('exec: a non-env (network) credential cannot be used as a CLI', async () => {
  const d = execDeps({ resolveShare: async () => ({ ...ENV_SHARE, injection: { type: 'header', name: 'Authorization' } }) });
  const handle = await mintHandle(d);
  const c = collectSink();
  await handleVaultExec({ vault_handle: handle, argv: ['gh', 'x'] }, d, c.sink);
  assert.equal(c.terminal().error, 'inject_failed');
})

test('exec: rejects an empty argv', async () => {
  const d = execDeps();
  const handle = await mintHandle(d);
  const c = collectSink();
  await handleVaultExec({ vault_handle: handle, argv: [] }, d, c.sink);
  assert.equal(c.terminal().error, 'bad_request');
})

test('exec: real unix-socket round-trip streams scrubbed output from a real child', async () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  const TOKEN = 'ghp_REALSOCKET_SECRET_xyz';
  const { spawn } = await import('node:child_process');
  let server;
  try {
    ({ server } = await startVaultServer({
      scope,
      deps: {
        agentDid: AGENT,
        handles: new VaultHandleStore(),
        resolveShare: async (id) => (id === 'vault_env'
          ? { item_id: 'vault_env', injection: { type: 'env', env_map: [{ name: 'GH_TOKEN', field: 'secret' }] }, binaries: ['node'], constraints: [], on_violation: { type: 'deny' }, granted_actions: ['use'] }
          : null),
        resolveSecret: async () => ({ secret: TOKEN, decryptedAtMs: Date.now(), zeroize() {} }),
        genHandleKeypair: async () => ({ public_sec1_b64: 'P', secret_sec1_b64: 'S' }),
        now: () => Date.now(),
        spawnImpl: spawn,
      },
    }));
    const used = await vaultRequest(scope, { op: 'vault_use', item_id: 'vault_env' });
    let out = '';
    const term = await vaultExecStream(
      scope,
      { vault_handle: used.vault_handle, argv: ['node', '-e', 'process.stdout.write("tok="+process.env.GH_TOKEN)'] },
      { onStdout: (b) => { out += b.toString('utf8'); }, onStderr: () => {} },
    );
    assert.equal(term.ok, true);
    assert.equal(term.exit_code, 0);
    assert.equal(out.includes(TOKEN), false, 'real child echoed the token but it returned scrubbed');
    assert.ok(out.includes('[redacted]'));
  } finally {
    try { server?.close(); } catch { /* ignore */ }
    try { rmSync(vaultSocketPath(scope), { force: true }); } catch { /* ignore */ }
    rmSync(dir, { recursive: true, force: true });
  }
})
