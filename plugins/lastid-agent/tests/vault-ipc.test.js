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

import { handleVaultRequest, startVaultServer, vaultRequest, vaultSocketPath } from '../lib/vault-ipc.js';
import { VaultHandleStore } from '../lib/vault-handle-store.js';

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
    // JIT secret release. zeroizeCalls lets a test assert the secret was wiped.
    resolveSecret: async (id) =>
      id === 'vault_1' ? { secret: SECRET, zeroize: () => {} } : null,
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

test('http_fetch fetches the secret JIT, zeroizes it after, and records timing', async () => {
  let zeroized = false;
  let resolvedSecretFor = null;
  let metric = null;
  const d = deps({
    resolveSecret: async (id) => {
      resolvedSecretFor = id;
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
