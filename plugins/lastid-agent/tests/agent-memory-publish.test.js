/**
 * Tests for the agent memory write-through (lib/agent-memory-publish.js):
 * the LIVE POST to the IdP — content encrypted under the agent's slot_seed,
 * agent-tier→active with a self-copy, global→draft target, forget→revoke
 * tombstone. Uses a mock fetch (no network).
 */
import { test } from 'node:test';
import assert from 'node:assert';

import { publishAgentMemory, memorySyncContent, MEMORIES_PATH } from '../lib/agent-memory-publish.js';
import { decryptContent } from '../lib/agent-content-crypto.js';

const loaded = {
  agentDid: 'did:lastid:agent:zT',
  slotSeed: Buffer.alloc(32, 5),
  vcCompact: 'vc.jwt',
};
const idpUrl = 'https://idp.test';

function capture() {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, headers: opts.headers, body: JSON.parse(opts.body) });
    return { ok: true, status: 200 };
  };
  return { calls, fetchImpl };
}

test('memorySyncContent: durable fields, no embedding', () => {
  const c = memorySyncContent({
    kind: 'fact', subject: ['x'], claim: 'C', summary: 'S', bedrock: true,
    sensitivity: 'low', source: { kind: 'user_explicit' }, confidence: 0.95,
    decay: 'none', status: 'active', created_at: 't', embedding: [1, 2, 3],
  });
  assert.equal(c.claim, 'C');
  assert.equal(c.bedrock, true);
  assert.equal(c.source_kind, 'user_explicit');
  assert.equal(c.authored_by, 'agent');
  assert.equal(c.embedding, undefined, 'embedding is local-only, never synced');
});

test('publishAgentMemory: agent-tier active → POST to IdP /memories, self-copy, slot-encrypted', async () => {
  const { calls, fetchImpl } = capture();
  const memory = {
    id: 'mem_1', tier: 'agent', version: 1, kind: 'preference', subject: ['style'],
    claim: 'matt likes terse', bedrock: false, sensitivity: 'low',
    source: { kind: 'user_explicit' }, confidence: 0.95, decay: 'slow', status: 'active', created_at: 't',
  };
  const okv = await publishAgentMemory({ idpUrl, loaded, memory, status: 'active', fetchImpl });
  assert.equal(okv, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith(MEMORIES_PATH));
  assert.equal(calls[0].url, `${idpUrl}${MEMORIES_PATH}`);
  assert.equal(calls[0].headers.Authorization, 'Bearer vc.jwt');
  assert.ok(typeof calls[0].headers.DPoP === 'string' && calls[0].headers.DPoP.length > 0);
  const b = calls[0].body;
  assert.equal(b.target, loaded.agentDid, 'agent-tier targets the agent DID');
  assert.equal(b.status, 'active');
  assert.equal(b.copies.length, 1);
  assert.equal(b.copies[0].agent_did, loaded.agentDid, 'self-copy only');
  // The content decrypts under the agent's slot_seed back to the claim.
  const dec = JSON.parse(decryptContent(loaded.slotSeed, b.copies[0].enc_b64).toString('utf8'));
  assert.equal(dec.claim, 'matt likes terse');
});

test('publishAgentMemory: global → target=global (a draft the operator promotes)', async () => {
  const { calls, fetchImpl } = capture();
  const memory = { id: 'mem_2', tier: 'global', version: 1, kind: 'fact', subject: ['x'], claim: 'c', status: 'drafted', source: {} };
  await publishAgentMemory({ idpUrl, loaded, memory, status: 'active', fetchImpl });
  assert.equal(calls[0].body.target, 'global');
});

test('publishAgentMemory: revoke → content-less tombstone', async () => {
  const { calls, fetchImpl } = capture();
  const memory = { id: 'mem_3', tier: 'agent', version: 2 };
  await publishAgentMemory({ idpUrl, loaded, memory, status: 'revoked', version: 2, fetchImpl });
  const b = calls[0].body;
  assert.equal(b.status, 'revoked');
  assert.equal(b.version, 2);
  assert.equal(b.copies[0].enc_b64, undefined, 'no content on a tombstone');
});

test('publishAgentMemory: non-2xx → false', async () => {
  const memory = { id: 'mem_4', tier: 'agent', version: 1, kind: 'fact', subject: ['x'], claim: 'c', source: {} };
  const okv = await publishAgentMemory({ idpUrl, loaded, memory, status: 'active', fetchImpl: async () => ({ ok: false, status: 500 }) });
  assert.equal(okv, false);
});

test('publishAgentMemory: no slotSeed → false (cannot encrypt/sign)', async () => {
  const okv = await publishAgentMemory({ idpUrl, loaded: { agentDid: 'did:a', vcCompact: 'v' }, memory: { id: 'm', tier: 'agent', version: 1 }, fetchImpl: async () => ({ ok: true }) });
  assert.equal(okv, false);
});
