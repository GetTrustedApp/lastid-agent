/**
 * Tests for cross-session/host reconcile: memory-store.applySync (rebuild an
 * agent-authored memory from a synced copy, version-guarded, handle revokes)
 * and the syncAgentState routing (agent-authored memories → memory-store, not
 * operator-store; operator-authored → operator-store).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { MemoryStore } from '../lib/memory-store.js';
import { OperatorStore } from '../lib/operator-store.js';
import { syncAgentState } from '../lib/agent-state-sync.js';
import { encryptContent } from '../lib/agent-content-crypto.js';
import { deriveAgentEd25519Keypair } from '../lib/agent-provisioning.js';

function memStore() {
  return new MemoryStore('test', join(tmpdir(), `mem-${randomUUID()}.json`), {
    agentDid: 'did:lastid:agent:zT',
    parentHumanDid: 'did:lastid:zH',
  });
}

const content = (over = {}) => ({
  kind: 'fact', subject: ['x'], claim: 'reconciled claim', bedrock: false,
  sensitivity: 'low', source_kind: 'inferred', confidence: 0.5, decay: 'none',
  status: 'active', created_at: '2026-01-01T00:00:00Z', authored_by: 'agent', ...over,
});

// ── applySync units ────────────────────────────────────────────────

test('applySync: active agent record → rebuilds a MemoryObject', () => {
  const s = memStore();
  const changed = s.applySync({ id: 'mem_a', target: 'global', version: 1, status: 'active', content: content() }, 'agent');
  assert.equal(changed, true);
  const m = s.get('mem_a');
  assert.equal(m.claim, 'reconciled claim');
  assert.equal(m.tier, 'global');
  assert.equal(m.embedding, null, 're-embedded locally');
});

test('applySync: operator-authored active is ignored (lives in operator-store)', () => {
  const s = memStore();
  assert.equal(s.applySync({ id: 'mem_op', target: 'global', version: 1, status: 'active', content: content() }, 'operator'), false);
  assert.equal(s.get('mem_op'), null);
});

test('applySync: version guard — same/older version is a no-op (preserves embedding)', () => {
  const s = memStore();
  s.applySync({ id: 'mem_v', target: 'global', version: 2, status: 'active', content: content({ claim: 'v2' }) }, 'agent');
  s.get('mem_v').embedding = [0.1, 0.2]; // simulate a local embedding
  s.save();
  const changed = s.applySync({ id: 'mem_v', target: 'global', version: 2, status: 'active', content: content({ claim: 'v2-echo' }) }, 'agent');
  assert.equal(changed, false, 'same version not re-applied');
  assert.deepEqual(s.get('mem_v').embedding, [0.1, 0.2], 'embedding preserved');
  assert.equal(s.get('mem_v').claim, 'v2');
});

test('applySync: newer version supersedes', () => {
  const s = memStore();
  s.applySync({ id: 'mem_u', target: 'global', version: 1, status: 'active', content: content({ claim: 'old' }) }, 'agent');
  s.applySync({ id: 'mem_u', target: 'global', version: 2, status: 'active', content: content({ claim: 'new' }) }, 'agent');
  assert.equal(s.get('mem_u').claim, 'new');
});

test('applySync: revoke drops a present id (any author)', () => {
  const s = memStore();
  s.applySync({ id: 'mem_r', target: 'global', version: 1, status: 'active', content: content() }, 'agent');
  const changed = s.applySync({ id: 'mem_r', target: 'global', version: 2, status: 'revoked' }, 'operator');
  assert.equal(changed, true);
  assert.equal(s.get('mem_r'), null, 'forgotten by the revoke (e.g. an operator promote)');
});

// ── syncAgentState routing ─────────────────────────────────────────

test('sync routes an agent-authored memory to memory-store, NOT operator-store', async () => {
  const slotSeed = Buffer.alloc(32, 3);
  const { signingKey } = deriveAgentEd25519Keypair(slotSeed);
  const enc_b64 = encryptContent(slotSeed, Buffer.from(JSON.stringify(content({ claim: 'from another session' })), 'utf8')).toString('base64');
  const record = { id: 'mem_x', kind: 'memory', target: 'global', version: 1, status: 'active', author: 'agent', enc_b64, cursor: 1 };

  const fetchImpl = async (url) => ({
    ok: true,
    json: async () =>
      url.includes('/memories') ? { records: [record], cursor: 1 } : { records: [], cursor: 0 },
  });

  const operatorStore = new OperatorStore('test', join(tmpdir(), `op-${randomUUID()}.json`));
  const memoryStore = new MemoryStore('test', join(tmpdir(), `mem-${randomUUID()}.json`), {
    agentDid: 'did:lastid:agent:zT',
    parentHumanDid: 'did:lastid:zH',
  });

  const res = await syncAgentState({
    idpUrl: 'https://idp.test',
    agentDid: 'did:lastid:agent:zT',
    vcCompact: 'vc.jwt',
    signingKey,
    slotSeed,
    store: operatorStore,
    memoryStore,
    fetchImpl,
    verifyRecord: () => true, // memories verify-if-signed; bypass for the test
  });

  assert.equal(res.reconciled, 1);
  assert.equal(memoryStore.get('mem_x')?.claim, 'from another session', 'reconciled into memory-store');
  assert.equal(operatorStore.listMemories().length, 0, 'NOT in operator-store (no double-inject)');
});
