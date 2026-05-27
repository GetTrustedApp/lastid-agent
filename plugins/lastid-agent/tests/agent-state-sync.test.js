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
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import crypto, { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

import {
  syncAgentState,
  decodeRecord,
  makeDoorbellHandler,
} from '../lib/agent-state-sync.js';
import { OperatorStore } from '../lib/operator-store.js';
import { encryptJson } from '../lib/agent-content-crypto.js';
import { sha256Hex } from '../lib/agent-sig-verify.js';
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
// A sealed vault share as the IdP serves it: enc_b64 is opaque to the sync
// (applyVaultRecords stores it without decrypting; the listener unfurls only at
// inject time), keyed by id in the local vault cache.
const vaultShare = (id, cursor, version = 1) => ({
  id,
  kind: 'vault',
  target: 'global',
  status: 'active',
  version,
  cursor,
  enc_b64: Buffer.from(`sealed-${id}`).toString('base64'),
});

function jsonResp(obj) {
  return { ok: true, status: 200, json: async () => obj, text: async () => '' };
}

/** Fake IdP: serves records with cursor > ?since per kind, plus the kind's high-water cursor. */
function makeFakeIdp({ rules = [], memories = [], vault = [], failStatus = null, failVault = false }) {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    seen.push({ url, headers: opts.headers });
    if (failStatus) {
      return { ok: false, status: failStatus, json: async () => ({}), text: async () => 'server error' };
    }
    const u = new URL(url);
    // Vault-ONLY transport failure (exercises the fail-soft path): rules /
    // memories still succeed while vault 503s.
    if (failVault && u.pathname.endsWith('/vault')) {
      return { ok: false, status: 503, json: async () => ({}), text: async () => 'vault down' };
    }
    const since = Number(u.searchParams.get('since')) || 0;
    const all = u.pathname.endsWith('/rules')
      ? rules
      : u.pathname.endsWith('/memories')
        ? memories
        : u.pathname.endsWith('/vault')
          ? vault
          : [];
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
  // The second round's RULES request carried ?since=5 — its OWN per-kind
  // cursor. Other kinds carry their own cursor independently (0 here: they had
  // no records, so they never advanced) — that independence is the fix.
  const ruleReq = idp.seen.find(({ url }) => new URL(url).pathname.endsWith('/rules'));
  assert.equal(new URL(ruleReq.url).searchParams.get('since'), '5');
  const memReq = idp.seen.find(({ url }) => new URL(url).pathname.endsWith('/memories'));
  assert.equal(new URL(memReq.url).searchParams.get('since'), '0');
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

// ── Trust-on-first-use pinning of the operator delegation key (#24/2) ──────
// The IdP supplies the delegation key embedded in the sync response. We pin it
// on the first sync and verify against the pinned key thereafter, so a later
// (compromised/forged) response can't swap the key and forge operator records.

const K1 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const K2 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwkOf = (kp) => {
  const j = kp.publicKey.export({ format: 'jwk' });
  return { x_b64u: j.x, y_b64u: j.y };
};

function mintEs256(claims, privateKey) {
  const h = Buffer.from(JSON.stringify({ typ: 'jwt+lastid-human-auth-v1', alg: 'ES256' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${sig.toString('base64url')}`;
}

function operatorSignedRule(id, content, cursor, privateKey) {
  const contentBytes = Buffer.from(JSON.stringify(content), 'utf8');
  const claims = { kind: 'rule', id, target: 'global', version: 1, status: 'active', content_sha256: sha256Hex(contentBytes) };
  return {
    id, kind: 'rule', target: 'global', status: 'active', version: 1, cursor,
    updated_at: '2026-01-01T00:00:00Z', tool: content.tool,
    enc_b64: encryptJson(SEED, content).toString('base64'),
    sig: mintEs256(claims, privateKey),
  };
}

function idpWithKey(rules, jwk) {
  return async (url) => {
    const u = new URL(url);
    const since = Number(u.searchParams.get('since')) || 0;
    const all = u.pathname.endsWith('/rules') ? rules : [];
    const records = all.filter((r) => r.cursor > since);
    const cursor = all.reduce((m, r) => Math.max(m, r.cursor), since);
    return jsonResp({ records, cursor, operator_delegation_jwk: jwk });
  };
}

const realAuth = { idpUrl: 'http://idp.test', agentDid: AGENT_DID, vcCompact: 'vc', signingKey, slotSeed: SEED };

test('TOFU: first sync pins the operator delegation key', async () => {
  const store = freshStore();
  const r1 = operatorSignedRule('rule_1', { tool: 'shell', pattern: 'tok-a', severity: 'deny' }, 1, K1.privateKey);
  const res = await syncAgentState({ ...realAuth, store, fetchImpl: idpWithKey([r1], jwkOf(K1)) });
  assert.equal(res.applied, 1, 'the signed rule applies');
  assert.deepEqual(store.pinnedDelegationJwk, jwkOf(K1), 'key pinned on first sync');
});

test('TOFU: a swapped delegation key is ignored — verification uses the PINNED key', async () => {
  const store = freshStore();
  const r1 = operatorSignedRule('rule_1', { tool: 'shell', pattern: 'tok-a', severity: 'deny' }, 1, K1.privateKey);
  await syncAgentState({ ...realAuth, store, fetchImpl: idpWithKey([r1], jwkOf(K1)) });

  // Second sync: the IdP now supplies K2 (swapped) and serves rule_2 signed by
  // the SWAPPED key (forgery) + rule_3 signed by the PINNED key.
  const forged = operatorSignedRule('rule_2', { tool: 'shell', pattern: 'tok-b', severity: 'deny' }, 2, K2.privateKey);
  const genuine = operatorSignedRule('rule_3', { tool: 'shell', pattern: 'tok-c', severity: 'deny' }, 3, K1.privateKey);
  await syncAgentState({ ...realAuth, store, fetchImpl: idpWithKey([forged, genuine], jwkOf(K2)) });

  assert.deepEqual(store.pinnedDelegationJwk, jwkOf(K1), 'pin not overwritten by the swapped key');
  assert.ok(store.listRules().some((r) => r.id === 'rule_3'), 'pinned-key record applies');
  assert.ok(!store.listRules().some((r) => r.id === 'rule_2'), 'swapped-key forgery rejected');
});

test('operator-store: pinDelegationJwk pins once and persists', () => {
  const path = join(tmpdir(), `pin-${randomUUID()}.json`);
  const s1 = new OperatorStore('test', path);
  assert.equal(s1.pinnedDelegationJwk, null);
  assert.equal(s1.pinDelegationJwk(jwkOf(K1)), true, 'pins first time');
  assert.equal(s1.pinDelegationJwk(jwkOf(K2)), false, 'no-op once pinned');
  assert.deepEqual(s1.pinnedDelegationJwk, jwkOf(K1));
  const s2 = new OperatorStore('test', path);
  assert.deepEqual(s2.pinnedDelegationJwk, jwkOf(K1));
});

// ── per-kind cursors: the vault-share stranding fix ───────────────────────
//
// The sync used to drive EVERY kind's `?since=` off one global cursor, so a
// fast kind (memories) advancing the high-water would skip a slower kind's
// (vault) record whose cursor sat below it — a credential silently never
// reached the agent. Each kind now tracks its own cursor.

test('POSITIVE: per-kind cursors advance independently; each kind fetches from its own ?since', async () => {
  const store = freshStore();
  const idp = makeFakeIdp({
    rules: [rule('r1', { tool: 'Bash', pattern: 'a', severity: 'warn' }, 3)],
    memories: [memory('m1', { claim: 'x' }, 7)],
  });
  await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  // Each kind tracked its OWN high-water; the global cursor is the max (only the
  // ever-synced gate), never reused as a per-kind since.
  assert.equal(store.cursorFor('rule'), 3);
  assert.equal(store.cursorFor('memory'), 7);
  assert.equal(store.cursor, 7);

  // Next sync: rules re-request from 3, memories from 7 — INDEPENDENTLY.
  idp.seen.length = 0;
  await syncAgentState({ ...auth, store, fetchImpl: idp.fetchImpl });
  const sinceFor = (seg) => {
    const req = idp.seen.find(({ url }) => new URL(url).pathname.endsWith(`/${seg}`));
    return new URL(req.url).searchParams.get('since');
  };
  assert.equal(sinceFor('rules'), '3');
  assert.equal(sinceFor('memories'), '7');
});

test('NEGATIVE: a failed vault fetch does NOT advance the vault cursor while other kinds do', async () => {
  const store = freshStore();
  const scope = `vault-fail-${randomUUID()}`;
  const vaultDir = join(homedir(), '.lastid-agent', scope);
  const idp = makeFakeIdp({
    memories: [memory('m1', { claim: 'x' }, 9)],
    vault: [vaultShare('v1', 4)],
    failVault: true, // vault 503s (fail-soft); rules/memories succeed
  });
  try {
    await syncAgentState({ ...auth, store, scope, fetchImpl: idp.fetchImpl });
    // Memory advanced to 9; vault stayed at 0 — NOT leapfrogged to the global
    // high-water — so the share is RE-FETCHABLE next sync, not stranded.
    assert.equal(store.cursorFor('memory'), 9);
    assert.equal(store.cursorFor('vault'), 0);
  } finally {
    rmSync(vaultDir, { recursive: true, force: true });
  }
});

test('REGRESSION: a vault share below the rules/memories high-water is still delivered (not stranded)', async () => {
  const store = freshStore();
  const scope = `vault-strand-${randomUUID()}`;
  const vaultDir = join(homedir(), '.lastid-agent', scope);
  const dataset = { memories: [memory('m1', { bedrock: true, claim: 'x' }, 10)], vault: [] };
  const idp = makeFakeIdp(dataset);
  try {
    // Sync 1: memories push the GLOBAL high-water to 10; vault is empty (cursor 0).
    await syncAgentState({ ...auth, store, scope, fetchImpl: idp.fetchImpl });
    assert.equal(store.cursor, 10);
    assert.equal(store.cursorFor('vault'), 0);

    // A vault share lands at cursor 5 — BELOW the global high-water of 10. Under
    // the OLD single-cursor sync the next pull used ?since=10 and skipped it
    // forever (the bug). Per-kind, the vault fetch uses its OWN since=0.
    dataset.vault.push(vaultShare('v1', 5));
    idp.seen.length = 0;
    await syncAgentState({ ...auth, store, scope, fetchImpl: idp.fetchImpl });

    const vaultReq = idp.seen.find(({ url }) => new URL(url).pathname.endsWith('/vault'));
    assert.equal(new URL(vaultReq.url).searchParams.get('since'), '0');
    // Vault cursor advanced INDEPENDENTLY to the delivered share's cursor.
    assert.equal(store.cursorFor('vault'), 5);
    // And the share actually reached the local vault cache — true delivery.
    const cached = JSON.parse(readFileSync(join(vaultDir, 'vault-shares.json'), 'utf8'));
    assert.ok(cached['v1'], 'vault share v1 reached the local vault cache (not stranded)');
  } finally {
    rmSync(vaultDir, { recursive: true, force: true });
  }
});

test('REGRESSION: a legacy single-cursor store re-pulls every kind from 0 (self-heal)', () => {
  // A store written by the OLD code: a global `cursor`, NO per-kind `cursors`.
  // It must report cursorFor(kind)=0 for every kind so the next sync re-pulls
  // from scratch and recovers anything the single cursor had stranded — while
  // still reading as "ever synced" (cursor>0) so the policy gate isn't reset.
  const path = join(tmpdir(), `legacy-${randomUUID()}.json`);
  writeFileSync(path, JSON.stringify({ version: 1, cursor: 233, records: {} }));
  const store = new OperatorStore('test', path);
  assert.equal(store.cursor, 233, 'legacy global cursor preserved (ever-synced)');
  assert.equal(store.cursorFor('vault'), 0, 'per-kind vault cursor heals to 0');
  assert.equal(store.cursorFor('memory'), 0);
  assert.equal(store.cursorFor('rule'), 0);
});
