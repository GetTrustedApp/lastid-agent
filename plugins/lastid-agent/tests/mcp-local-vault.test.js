/**
 * Local vault dispatch (lib/mcp-server.js::handleLocalVault) — the SaaS /
 * no-desktop path that routes vault_use + http_fetch to the listener over the
 * vault unix socket. Before this, vault_use/http_fetch were only advertised
 * when a desktop published them, so the agent could never call them with no
 * desktop running. These lock the capability gate + the IPC routing (the
 * vaultRequest is injected; no real socket).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleLocalVault } from '../lib/mcp-server.js';

// A compact VC is `<header>.<payload>.<sig>`; decodeVcClaims only base64-decodes
// the payload, so we can craft one carrying exactly the capabilities we want.
function vc(caps) {
  const payload = Buffer.from(
    JSON.stringify({ capabilities: caps, sub: 'did:lastid:agent:zT', parent_human_did: 'did:lastid:zH' }),
  ).toString('base64url');
  return `eyJhbGciOiJFZERTQSJ9.${payload}.sig`;
}
const withVault = { agentDid: 'did:lastid:agent:zT', vcCompact: vc([{ resource: 'vault:use', actions: ['Use'] }]) };
const noVault = { agentDid: 'did:lastid:agent:zT', vcCompact: vc([{ resource: 'memory:read:global', actions: ['Read'] }]) };
const body = (res) => JSON.parse(res.content[0].text);

test('not provisioned → not_provisioned error, no IPC', async () => {
  let called = false;
  const r = await handleLocalVault({ name: 'vault_use', args: { item_id: 'v' }, scope: 'main', loadedAgent: null, vaultRequest: async () => ((called = true), {}) });
  assert.equal(r.isError, true);
  assert.match(body(r).error, /not_provisioned/);
  assert.equal(called, false);
});

test('without vault:use capability → capability_denied, no IPC', async () => {
  let called = false;
  const r = await handleLocalVault({ name: 'vault_use', args: { item_id: 'v' }, scope: 'main', loadedAgent: noVault, vaultRequest: async () => ((called = true), {}) });
  assert.equal(r.isError, true);
  assert.match(body(r).error, /capability_denied/);
  assert.equal(called, false, 'never reaches the listener without the capability');
});

test('vault_use routes op=vault_use to the listener and returns the handle (never a secret)', async () => {
  let seen = null;
  const r = await handleLocalVault({
    name: 'vault_use', args: { item_id: 'vault_1' }, scope: 'main', loadedAgent: withVault,
    vaultRequest: async (scope, req) => { seen = { scope, req }; return { ok: true, vault_handle: 'H1', item_id: 'vault_1', injection: { type: 'header' } }; },
  });
  assert.equal(seen.scope, 'main');
  assert.equal(seen.req.op, 'vault_use');
  assert.equal(seen.req.item_id, 'vault_1');
  assert.equal(body(r).vault_handle, 'H1');
  assert.equal(r.isError ?? false, false);
});

test('http_fetch forwards handle + url + method + body to the listener', async () => {
  let seen = null;
  const r = await handleLocalVault({
    name: 'http_fetch',
    args: { vault_handle: 'H1', url: 'https://api.tavily.com/search', method: 'POST', body: '{"query":"x"}' },
    scope: 'main', loadedAgent: withVault,
    vaultRequest: async (_scope, req) => { seen = req; return { ok: true, status: 200, body: '{}', headers: {}, truncated: false }; },
  });
  assert.equal(seen.op, 'http_fetch');
  assert.equal(seen.vault_handle, 'H1');
  assert.equal(seen.url, 'https://api.tavily.com/search');
  assert.equal(seen.method, 'POST');
  assert.equal(seen.body, '{"query":"x"}');
  assert.equal(body(r).status, 200);
});

test('a listener error (handle_invalid) surfaces as isError', async () => {
  const r = await handleLocalVault({
    name: 'http_fetch', args: { vault_handle: 'bad', url: 'https://x' }, scope: 'main', loadedAgent: withVault,
    vaultRequest: async () => ({ error: 'handle_invalid', detail: 'expired' }),
  });
  assert.equal(r.isError, true);
  assert.match(body(r).error, /handle_invalid/);
});
