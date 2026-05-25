/**
 * Tests for the agent-state sync client (lib/agent-state-sync.js).
 *
 * Uses an injected fake fetch backed by a record dataset, with the REAL
 * agent-content-crypto producing each `enc_b64`, so every test is a true
 * encrypt -> fetch -> decrypt -> apply round-trip against a real
 * OperatorStore. Covers initial pull, incremental ?since, revocation,
 * the provenance gate, per-record decrypt-failure resilience, transport
 * errors, and the WS doorbell handler.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

import {
  syncAgentState,
  decodeRecord,
  makeDoorbellHandler,
} from '../lib/agent-state-sync.js';
import { OperatorStore } from '../lib/operator-store.js';
import { encryptJson } from '../lib/agent-content-crypto.js';
import {
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';

const SEED = Buffer.alloc(32, 0x5a);
const { signingKey, publicJwk } = deriveAgentEd25519Keypair(SEED);
const AGENT_DID = agentDidFromPublicJwk(publicJwk);

const auth = {
  idpUrl: 'http://idp.test',
  agentDid: AGENT_DID,
  vcCompact: 'eyJ.agent.vc',
  signingKey,
  slotSeed: SEED,
  // These tests exercise sync mechanics (fetch/decrypt/cursor); real
  // signature verification is covered in agent-sig-verify.test.js, so
  // bypass the provenance gate here. The provenance test overrides this.
  verifyRecord: () => ({ ok: true }),
};

function freshStore() {
  return new OperatorStore('test', join(tmpdir(), `sync-${randomUUID()}.json`));
}

function activeRecord(kind, id, content, cursor, version = 1) {
  return {
    id,
    kind,
    target: 'global',
    status: 'active',
    version,
    cursor,
    updated_at: '2026-01-01T00:00:00Z',
    tool: content.tool,
    enc_b64: encryptJson(SEED, content).toString('base64'),
  };
}
const rule = (id, content, cursor, v) => activeRecord('rule', id, content, cursor, v);
const memory = (id, content, cursor, v) => activeRecord('memory', id, content, cursor, v);
const revoked = (kind, id, cursor, version) => ({ id, kind, status: 'revoked', version, cursor });

function jsonResp(obj) {
  return { ok: true, status: 200, json: async () => obj, text: async () => '' };
}

/** Fake IdP: serves records with cursor > ?since per kind, plus the kind's high-water cursor. */
function makeFakeIdp({ rules = [], memories = [], failStatus = null }) {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    seen.push({ url, headers: opts.headers });
    if (failStatus) {
      return { ok: false, status: failStatus, json: async () => ({}), text: async () => 'server error' };
    }
    const u = new URL(url);
    const since = Number(u.searchParams.get('since')) || 0;
    const all = u.pathname.endsWith('/rules') ? rules : u.pathname.endsWith('/memories') ? memories : [];
    const records = all.filter((r) => r.cursor > since);
    const cursor = all.reduce((m, r) => Math.max(m, r.cursor), since);
    return jsonResp({ records, cursor });
  };
  return { fetchImpl, seen };
}

test('initial sync decrypts and applies rules + memories, advances cursor, sends Bearer + DPoP', async () => {
  const store = freshStore();
  const idp = makeFakeIdp({
    rules: [
      rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny', reason: 'no stash' }, 1),
      rule('r2', { tool: '*', pattern: 'rm -rf /', severity: 'deny' }, 2),
    ],
    memories: [memory('m1', { bedrock: true, claim: 'matt writes terse' }, 2)],
  });

  const res = await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  assert.equal(res.applied, 3);
  assert.equal(res.rejected, 0);
  assert.equal(store.cursor, 2);
  assert.equal(store.listRules().length, 2);
  assert.equal(store.listMemories().length, 1);
  assert.equal(store.bedrockMemories().length, 1);
  // The decrypted content round-tripped intact.
  assert.equal(store.matchRules('Bash', { command: 'git stash' }).matched.reason, 'no stash');

  // Auth headers present and well-formed on every request.
  assert.ok(idp.seen.length >= 2);
  for (const { headers } of idp.seen) {
    assert.match(headers.Authorization, /^Bearer eyJ\.agent\.vc$/);
    assert.equal(headers.DPoP.split('.').length, 3);
  }
});

test('incremental sync sends ?since=<cursor> and applies only newer records', async () => {
  const store = freshStore();
  const dataset = { rules: [rule('r1', { tool: 'Bash', pattern: 'a', severity: 'warn' }, 5)], memories: [] };
  const idp = makeFakeIdp(dataset);

  await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  assert.equal(store.cursor, 5);
  assert.equal(store.listRules().length, 1);

  // A new rule lands at a higher cursor.
  dataset.rules.push(rule('r2', { tool: 'Bash', pattern: 'b', severity: 'deny' }, 6));
  idp.seen.length = 0;
  const res = await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });

  assert.equal(res.applied, 1); // only the new one
  assert.equal(store.cursor, 6);
  assert.equal(store.listRules().length, 2);
  // The second round of requests carried ?since=5.
  for (const { url } of idp.seen) {
    assert.equal(new URL(url).searchParams.get('since'), '5');
  }
});

test('a revoked record removes the rule from the store', async () => {
  const store = freshStore();
  const dataset = { rules: [rule('r1', { tool: 'Bash', pattern: 'x', severity: 'deny' }, 1)], memories: [] };
  const idp = makeFakeIdp(dataset);
  await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  assert.equal(store.listRules().length, 1);

  dataset.rules.push(revoked('rule', 'r1', 2, 2));
  await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  assert.equal(store.listRules().length, 0);
  assert.equal(store.cursor, 2);
});

test('verifyRecord rejects records that fail the provenance gate', async () => {
  const store = freshStore();
  const idp = makeFakeIdp({
    rules: [
      rule('good', { tool: 'Bash', pattern: 'a', severity: 'warn' }, 1),
      rule('forged', { tool: 'Bash', pattern: 'b', severity: 'deny' }, 2),
    ],
    memories: [],
  });
  const rejected = [];
  const res = await syncAgentState({
    ...auth,
    store,
    fetchImpl: idp.fetchImpl,
    verifyRecord: (rec) => (rec.id === 'forged' ? { ok: false, reason: 'signature' } : { ok: true }),
    onReject: (rec, reason) => rejected.push([rec.id, reason]),
  });
  assert.equal(res.applied, 1);
  assert.equal(res.rejected, 1);
  assert.equal(store.listRules().length, 1);
  assert.equal(store.listRules()[0].id, 'good');
  assert.deepEqual(rejected, [['forged', 'signature']]);
  // The cursor still advances past the rejected record so it isn't re-fetched forever.
  assert.equal(store.cursor, 2);
});

test('an undecryptable record is skipped, the rest of the batch still applies', async () => {
  const store = freshStore();
  const good = rule('r1', { tool: 'Bash', pattern: 'a', severity: 'warn' }, 1);
  const corrupt = { ...rule('r2', { tool: 'Bash', pattern: 'b', severity: 'deny' }, 2), enc_b64: 'not-valid-ciphertext' };
  const idp = makeFakeIdp({ rules: [good, corrupt], memories: [] });
  const rejected = [];
  const res = await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl, onReject: (rec, reason) => rejected.push([rec.id, reason]) });
  assert.equal(res.applied, 1);
  assert.equal(store.listRules().length, 1);
  assert.equal(store.listRules()[0].id, 'r1');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0][0], 'r2');
  assert.match(rejected[0][1], /^decrypt:/);
  assert.equal(store.cursor, 2); // advanced past the bad record
});

test('a non-OK response throws', async () => {
  const store = freshStore();
  const idp = makeFakeIdp({ failStatus: 503 });
  await assert.rejects(
    syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl }),
    /fetch failed: 503/,
  );
});

test('decodeRecord: active decrypts (with bytes), revoked passes through', () => {
  const active = rule('r1', { tool: 'Bash', pattern: 'p', severity: 'deny' }, 1);
  const d = decodeRecord(active, SEED);
  assert.equal(d.storeRecord.status, 'active');
  assert.equal(d.storeRecord.content.pattern, 'p');
  assert.ok(Buffer.isBuffer(d.contentBytes));

  const rev = revoked('rule', 'r1', 2, 2);
  const d2 = decodeRecord(rev, SEED);
  assert.equal(d2.storeRecord.status, 'revoked');
  assert.equal(d2.contentBytes, null);
});

test('doorbell handler triggers a (debounced) sync on changed events and ignores others', async () => {
  let calls = 0;
  const onEvent = makeDoorbellHandler(() => { calls += 1; }, { debounceMs: 10 });

  assert.equal(onEvent({ type: 'group_chat.message' }), false); // not handled
  assert.equal(onEvent({ type: 'rules.changed', cursor: 7 }), true);
  assert.equal(onEvent({ type: 'memory.changed', cursor: 8 }), true); // collapses with the above
  await delay(40);
  assert.equal(calls, 1, 'burst of changes should debounce to a single sync');

  assert.equal(onEvent('agent_state.changed'), true); // string form
  await delay(40);
  assert.equal(calls, 2);
});
