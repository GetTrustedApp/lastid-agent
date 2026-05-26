/**
 * Tests for the agent memory audit chain (lib/memory-audit.js): per-AGENT
 * keying, genesis + chain_id, checkpoints, append + hash-link + Ed25519 sign +
 * verify + tamper detection + per-agent ship cursor, and the memory-tools
 * integration (write/update/forget append signed records; drafts do not).
 *
 * The chain is keyed PER AGENT within a scope: a scope can host two agents at
 * once, and a single per-scope chain would interleave their records (and two
 * writers would fork it), so each agent gets its own genesis-rooted file.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';

import {
  appendMemoryAudit,
  maybeCheckpoint,
  auditSelfCheck,
  readMemoryAudit,
  verifyMemoryAudit,
  publicKeyFor,
  canonicalJson,
  memoryAuditPath,
  agentChainSlug,
  listChainSlugs,
  unshippedEntries,
  shipUnshipped,
  CHECKPOINT_EVENT,
  CHECKPOINT_INTERVAL,
} from '../lib/memory-audit.js';
import { handleMemoryTool } from '../lib/memory-tools.js';
import { shipMemoryAudit } from '../lib/memory-audit-ship.js';
import { deriveAgentEd25519Keypair } from '../lib/agent-provisioning.js';

const AGENT = 'did:lastid:agent:zA';
const AGENT_B = 'did:lastid:agent:zB';

function freshScope() {
  const scope = `test-${randomUUID()}`;
  return { scope, dir: join(homedir(), '.lastid-agent', scope) };
}

const { privateKey, publicKey } = generateKeyPairSync('ed25519');

test('canonicalJson: deterministic key order', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ a: { y: 1, x: 2 } }), '{"a":{"x":2,"y":1}}');
});

test('integrity_hash is blake3 over canonicalJson(core) — cross-runtime vector', async () => {
  const { blake3 } = await import('@noble/hashes/blake3.js');
  const { bytesToHex } = await import('@noble/hashes/utils.js');
  // FIXED-CORE VECTOR — the console validator (TS, same @noble/hashes blake3
  // over the same canonicalJson, INCLUDING chain_id) MUST produce this identical
  // hash. If either side drifts (canonicalJson shape, hash algo, core fields),
  // this catches it. chain_id is fixed here so the vector is reproducible.
  const core = {
    chain_id: '0'.repeat(32),
    seq: 0,
    timestamp: '2026-01-01T00:00:00.000Z',
    agent_did: 'did:lastid:agent:zTEST',
    event_type: 'AgentMemoryWritten',
    memory_id: 'mem_1',
    metadata: { kind: 'fact' },
    prev_hash: null,
  };
  const hex = bytesToHex(blake3(Buffer.from(canonicalJson(core), 'utf-8')));
  assert.strictEqual(hex, '3faf18c7ff15e9ffd96482d13121e48772373fa21d30ce6d3f2114c85462ac17');

  // An appended record's integrity_hash is blake3 over its own core (proves the
  // chain uses blake3 over the chain_id-bearing core).
  const { scope, dir } = freshScope();
  try {
    const r = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm', metadata: {} });
    const rcore = {
      chain_id: r.chain_id,
      seq: r.seq,
      timestamp: r.timestamp,
      agent_did: r.agent_did,
      event_type: r.event_type,
      memory_id: r.memory_id,
      metadata: r.metadata,
      prev_hash: r.prev_hash,
    };
    assert.strictEqual(r.integrity_hash, bytesToHex(blake3(Buffer.from(canonicalJson(rcore), 'utf-8'))));
    assert.strictEqual(r.integrity_hash.length, 64, 'blake3-256 hex is 64 chars');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('genesis: an agent\'s first record is seq 0, prev_hash null, with a fresh chain_id', () => {
  const { scope, dir } = freshScope();
  try {
    const a = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'mem_1', metadata: { kind: 'fact' } });
    const b = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryUpdated', memoryId: 'mem_1', metadata: { fields_changed: 'claim' } });
    assert.equal(a.seq, 0);
    assert.equal(a.prev_hash, null, 'genesis has no predecessor');
    assert.ok(/^[0-9a-f]{32}$/.test(a.chain_id), 'genesis mints a chain_id');
    assert.equal(b.seq, 1);
    assert.equal(b.prev_hash, a.integrity_hash, 'b links to a');
    assert.equal(b.chain_id, a.chain_id, 'same generation inherits the chain_id');
    assert.ok(a.signature && b.signature, 'signed');

    const report = verifyMemoryAudit(scope, AGENT, publicKey);
    assert.equal(report.intact, true);
    assert.equal(report.total, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// THE REGRESSION for the operator's "all my chains are broken": two agents in
// ONE scope each get their own genesis-rooted, single-writer chain — so neither
// interleaves the other and each verifies independently.
test('per-agent isolation: two agents in one scope keep separate genesis-rooted chains', () => {
  const { scope, dir } = freshScope();
  const keyA = generateKeyPairSync('ed25519');
  const keyB = generateKeyPairSync('ed25519');
  try {
    // Interleave appends, exactly as two concurrent agents would.
    appendMemoryAudit({ scope, signingKey: keyA.privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'a1' });
    appendMemoryAudit({ scope, signingKey: keyB.privateKey, agentDid: AGENT_B, eventType: 'AgentMemoryWritten', memoryId: 'b1' });
    appendMemoryAudit({ scope, signingKey: keyA.privateKey, agentDid: AGENT, eventType: 'AgentMemoryUpdated', memoryId: 'a1' });
    appendMemoryAudit({ scope, signingKey: keyB.privateKey, agentDid: AGENT_B, eventType: 'AgentMemoryForgotten', memoryId: 'b1' });

    const chainA = readMemoryAudit(scope, AGENT);
    const chainB = readMemoryAudit(scope, AGENT_B);
    // Each agent's records are contiguous (seq 0,1) in ITS OWN file — not mixed.
    assert.deepEqual(chainA.map((r) => r.seq), [0, 1]);
    assert.deepEqual(chainB.map((r) => r.seq), [0, 1]);
    assert.notEqual(chainA[0].chain_id, chainB[0].chain_id, 'distinct generations');
    assert.notEqual(memoryAuditPath(scope, AGENT), memoryAuditPath(scope, AGENT_B), 'distinct files');

    // Each chain verifies against ITS OWN signing key, independently.
    assert.equal(verifyMemoryAudit(scope, AGENT, keyA.publicKey).intact, true);
    assert.equal(verifyMemoryAudit(scope, AGENT_B, keyB.publicKey).intact, true);

    // Both agents appear in the scope's chain listing (so shipping covers all).
    const slugs = listChainSlugs(scope);
    assert.ok(slugs.includes(agentChainSlug(AGENT)));
    assert.ok(slugs.includes(agentChainSlug(AGENT_B)));
    assert.equal(slugs.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify detects a tampered record', () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'mem_1' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryForgotten', memoryId: 'mem_1' });
    // Tamper: rewrite the file with a mutated metadata on entry 0.
    const path = memoryAuditPath(scope, AGENT);
    const lines = readMemoryAudit(scope, AGENT);
    lines[0].memory_id = 'mem_HACKED';
    writeFileSync(path, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
    const report = verifyMemoryAudit(scope, AGENT, publicKey);
    assert.equal(report.intact, false);
    assert.equal(report.firstFailure.seq, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('publicKeyFor: derives a verifying key from the private key', () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm' });
    const pub = publicKeyFor(privateKey);
    assert.ok(pub);
    assert.equal(verifyMemoryAudit(scope, AGENT, pub).intact, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── on-break self-heal ─────────────────────────────────────────────

test('self-heal: a corrupt tail re-roots a NEW generation instead of chaining onto it', () => {
  const { scope, dir } = freshScope();
  try {
    const a = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm0' });
    const b = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    // Tamper the TAIL record on disk (its integrity_hash no longer matches core).
    const path = memoryAuditPath(scope, AGENT);
    const lines = readMemoryAudit(scope, AGENT);
    lines[lines.length - 1].memory_id = 'm1_TAMPERED';
    writeFileSync(path, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');

    // Next append must NOT link onto the broken tail — it re-genesises.
    const healed = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm2' });
    assert.equal(healed.seq, 0, 're-rooted at a fresh genesis');
    assert.equal(healed.prev_hash, null, 'genesis has no predecessor');
    assert.notEqual(healed.chain_id, a.chain_id, 'a new generation');
    assert.equal(healed.metadata.healed_from_break, true, 'flagged as a heal');
    assert.equal(healed.metadata.broke_after_seq, b.seq);
    assert.ok(/^[0-9a-f]{32}$/.test(healed.chain_id), 'a fresh generation id');

    // The healed record links to nothing broken — its own hash recomputes
    // cleanly, so the new generation (segmented by chain_id console-side) is the
    // clean "verify from here" root, even though the file still holds the old
    // tampered record as broken history.
    const recomputed = (() => {
      const fresh = readMemoryAudit(scope, AGENT).find((r) => r.chain_id === healed.chain_id && r.seq === 0);
      return fresh.integrity_hash === healed.integrity_hash;
    })();
    assert.ok(recomputed, 'the healed genesis is persisted intact');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('auditSelfCheck: intact chain is a no-op (no reset record added)', () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm0' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    const before = readMemoryAudit(scope, AGENT).length;
    const r = auditSelfCheck({ scope, signingKey: privateKey, agentDid: AGENT, publicKey });
    assert.equal(r.intact, true);
    assert.equal(r.healed, undefined);
    assert.equal(readMemoryAudit(scope, AGENT).length, before, 'no record added when intact');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// THE DEEP-BREAK case the append-time tail-heal can't catch: a MIDDLE record is
// tampered (the tail still verifies). auditSelfCheck must detect it and re-root
// a clean generation via a genesis ChainCheckpoint, so future events chain off
// the reset, not the broken generation.
test('auditSelfCheck: a deep (middle) break → checkpoint + re-genesis reset', () => {
  const { scope, dir } = freshScope();
  try {
    const a = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm0' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm2' });
    // Tamper the MIDDLE record (seq 1); the tail (seq 2) still verifies on its own.
    const path = memoryAuditPath(scope, AGENT);
    const lines = readMemoryAudit(scope, AGENT);
    lines[1].memory_id = 'm1_TAMPERED';
    writeFileSync(path, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');

    const r = auditSelfCheck({ scope, signingKey: privateKey, agentDid: AGENT, publicKey });
    assert.equal(r.intact, false);
    assert.equal(r.healed, true);
    assert.equal(r.firstFailure.seq, 1, 'detected the middle break');

    // A genesis-rooted reset ChainCheckpoint was appended.
    const after = readMemoryAudit(scope, AGENT);
    const reset = after[after.length - 1];
    assert.equal(reset.event_type, CHECKPOINT_EVENT);
    assert.equal(reset.seq, 0, 'reset is a fresh genesis');
    assert.equal(reset.prev_hash, null);
    assert.notEqual(reset.chain_id, a.chain_id, 'a new generation');
    assert.equal(reset.metadata.chain_reset, true);
    assert.equal(reset.metadata.broke_at_seq, 1);

    // A subsequent append chains onto the clean reset (seq 1, same new chain_id).
    const next = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm3' });
    assert.equal(next.chain_id, reset.chain_id);
    assert.equal(next.seq, 1);
    assert.equal(next.prev_hash, reset.integrity_hash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── checkpoints ────────────────────────────────────────────────────

test('maybeCheckpoint: anchors the head with a signed, linked ChainCheckpoint', () => {
  const { scope, dir } = freshScope();
  try {
    const a = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    const b = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm2' });
    const cp = maybeCheckpoint({ scope, signingKey: privateKey, agentDid: AGENT });
    assert.equal(cp.event_type, CHECKPOINT_EVENT);
    assert.equal(cp.seq, 2, 'checkpoint links onto the head');
    assert.equal(cp.prev_hash, b.integrity_hash);
    assert.equal(cp.chain_id, a.chain_id, 'checkpoint stays in the generation');
    assert.equal(cp.metadata.anchored_seq, 1);
    assert.equal(cp.metadata.anchored_hash, b.integrity_hash);
    // The chain (incl. the checkpoint) still verifies end-to-end.
    assert.equal(verifyMemoryAudit(scope, AGENT, publicKey).intact, true);
    // No-op when there is nothing to anchor (a fresh agent's empty chain).
    assert.equal(maybeCheckpoint({ scope, signingKey: privateKey, agentDid: AGENT_B }), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('auto-checkpoint: crossing CHECKPOINT_INTERVAL stamps a ChainCheckpoint', () => {
  const { scope, dir } = freshScope();
  try {
    for (let i = 0; i < CHECKPOINT_INTERVAL; i += 1) {
      appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentToolInvoked', memoryId: `m${i}` });
    }
    const chain = readMemoryAudit(scope, AGENT);
    // INTERVAL data records + 1 auto-checkpoint stamped at the boundary.
    assert.equal(chain.length, CHECKPOINT_INTERVAL + 1);
    const last = chain[chain.length - 1];
    assert.equal(last.event_type, CHECKPOINT_EVENT);
    assert.equal(last.metadata.anchored_seq, CHECKPOINT_INTERVAL - 1);
    assert.equal(verifyMemoryAudit(scope, AGENT, publicKey).intact, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── ship cursor (per-agent) ────────────────────────────────────────

test('ship cursor: per-agent unshipped → ship advances → none left (cursors independent)', async () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm2' });
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT_B, eventType: 'AgentMemoryWritten', memoryId: 'b1' });
    assert.equal(unshippedEntries(scope, AGENT).length, 2);
    assert.equal(unshippedEntries(scope, AGENT_B).length, 1, 'B has its own cursor');

    let shippedBatch = null;
    const n = await shipUnshipped(scope, AGENT, async (records) => { shippedBatch = records; return true; });
    assert.equal(n, 2);
    assert.equal(shippedBatch.length, 2);
    assert.equal(unshippedEntries(scope, AGENT).length, 0, 'A cursor advanced');
    assert.equal(unshippedEntries(scope, AGENT_B).length, 1, 'B untouched by A\'s ship');

    // A failed post must NOT advance the cursor.
    appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentMemoryForgotten', memoryId: 'm1' });
    const n2 = await shipUnshipped(scope, AGENT, async () => false);
    assert.equal(n2, 0);
    assert.equal(unshippedEntries(scope, AGENT).length, 1, 'still pending after failed ship');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── IdP shipping ───────────────────────────────────────────────────

test('shipMemoryAudit: POSTs unshipped records to /audit + advances on 2xx', async () => {
  const { scope, dir } = freshScope();
  const { signingKey } = deriveAgentEd25519Keypair(Buffer.alloc(32, 9));
  try {
    appendMemoryAudit({ scope, signingKey, agentDid: AGENT, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    let posted = null;
    const okFetch = async (url, opts) => {
      posted = { url, headers: opts.headers, body: JSON.parse(opts.body) };
      return { ok: true, status: 200 };
    };
    const n = await shipMemoryAudit({ idpUrl: 'https://idp.example', scope, agentDid: AGENT, vcCompact: 'vc.jwt', signingKey, fetchImpl: okFetch });
    assert.equal(n, 1);
    assert.match(posted.url, /\/v1\/agent-state\/audit$/);
    assert.equal(posted.headers.Authorization, 'Bearer vc.jwt');
    assert.ok(typeof posted.headers.DPoP === 'string' && posted.headers.DPoP.length > 0, 'DPoP proof attached');
    assert.equal(posted.body.records.length, 1);
    assert.ok(posted.body.records[0].chain_id, 'shipped record carries chain_id for server-side segmentation');
    assert.equal(unshippedEntries(scope, AGENT).length, 0, 'cursor advanced');

    // A 500 must NOT advance the cursor.
    appendMemoryAudit({ scope, signingKey, agentDid: AGENT, eventType: 'AgentMemoryForgotten', memoryId: 'm1' });
    const n2 = await shipMemoryAudit({ idpUrl: 'https://idp.example', scope, agentDid: AGENT, vcCompact: 'vc.jwt', signingKey, fetchImpl: async () => ({ ok: false, status: 500 }) });
    assert.equal(n2, 0);
    assert.equal(unshippedEntries(scope, AGENT).length, 1, 'still pending after failed ship');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── memory-tools integration ───────────────────────────────────────

const loadedAgent = { agentDid: 'did:lastid:agent:zT', slotSeed: Buffer.alloc(32, 7), vcCompact: 'vc.jwt', idpUrl: 'https://idp.test' };
const claims = { sub: 'did:lastid:agent:zT', parent_human_did: 'did:lastid:zH' };
const okFetch = async () => ({ ok: true, status: 200 }); // live write-through succeeds w/o network

test('memory tools SPOOL audit records (write/update/forget); draft does NOT; listener drain chains them', async () => {
  const { scope, dir } = freshScope();
  const call = (name, args) => handleMemoryTool({ name, args, scope, loadedAgent, claims, fetchImpl: okFetch });
  const body = (r) => JSON.parse(r.content[0].text);
  try {
    const w = body(await call('lastid_memory_write', { kind: 'fact', subject: ['x'], claim: 'c1', source_kind: 'user_explicit' }));
    await call('lastid_memory_draft', { kind: 'fact', subject: ['x'], claim: 'a draft', source_kind: 'inferred', source_quote: 'q' });
    await call('lastid_memory_update', { id: w.memory.id, claim: 'c1 updated', reason: 'clarified' });
    await call('lastid_memory_forget', { id: w.memory.id, reason: 'obsolete' });

    // The MCP tool process only ENQUEUES — the signed chain is still empty
    // until the listener (single writer) drains the spool.
    assert.equal(readMemoryAudit(scope, loadedAgent.agentDid).length, 0, 'memory ops must not write the chain directly');

    const { signingKey } = deriveAgentEd25519Keypair(loadedAgent.slotSeed);
    const { drainAuditSpool } = await import('../lib/audit-spool.js');
    const chained = drainAuditSpool({ scope, signingKey, agentDid: loadedAgent.agentDid });
    assert.equal(chained, 3, 'three CUD events chained (draft excluded)');

    const chain = readMemoryAudit(scope, loadedAgent.agentDid);
    const types = chain.map((r) => r.event_type);
    assert.deepEqual(types, ['AgentMemoryWritten', 'AgentMemoryUpdated', 'AgentMemoryForgotten'], 'draft not chained');
    // signed with the agent's derived key → verifies
    assert.equal(verifyMemoryAudit(scope, loadedAgent.agentDid, publicKeyFor(signingKey)).intact, true);
    // metadata is non-sensitive (no claim leaked)
    assert.ok(!JSON.stringify(chain).includes('c1 updated'), 'claim text not in the audit chain');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// REGRESSION (PayloadTooLargeError / 0 records at the IdP): a large backlog used
// to ship in ONE POST that exceeded the IdP's 1mb body limit, so it 413'd, the
// cursor never advanced, and the backlog grew forever. shipUnshipped now drains
// in size-bounded chunks, advancing the cursor per chunk.
test('shipUnshipped drains a large backlog in size-bounded chunks (per-chunk cursor)', async () => {
  const { scope, dir } = freshScope();
  try {
    for (let i = 0; i < 250; i += 1) {
      appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentToolInvoked', memoryId: `m${i}`, metadata: { input: 'x'.repeat(3000) } });
    }
    const batchSizes = [];
    const shipped = await shipUnshipped(scope, AGENT, async (recs) => { batchSizes.push(recs.length); return true; }, { maxBatchBytes: 50 * 1024 });
    assert.equal(shipped, 250, 'all records drained');
    assert.ok(batchSizes.length > 1, 'drained across multiple chunks, not one oversized POST');
    assert.ok(Math.max(...batchSizes) <= 200, 'each chunk under the count cap');
    assert.equal(unshippedEntries(scope, AGENT).length, 0, 'cursor fully advanced — backlog cleared');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('shipUnshipped: a failed chunk stops + leaves the cursor (offline-safe, resumable)', async () => {
  const { scope, dir } = freshScope();
  try {
    for (let i = 0; i < 300; i += 1) {
      appendMemoryAudit({ scope, signingKey: privateKey, agentDid: AGENT, eventType: 'AgentToolInvoked', memoryId: `m${i}`, metadata: { input: 'x'.repeat(3000) } });
    }
    let call = 0;
    const shipped1 = await shipUnshipped(scope, AGENT, async () => (++call === 1), { maxBatchBytes: 50 * 1024 });
    assert.ok(shipped1 > 0 && shipped1 < 300, 'shipped only the first chunk, then stopped on the failure');
    assert.equal(shipped1 + unshippedEntries(scope, AGENT).length, 300, 'cursor left at the failed chunk; the rest is still pending');
    // Resume: everything succeeds → drains the remainder (no records lost or double-shipped).
    const shipped2 = await shipUnshipped(scope, AGENT, async () => true, { maxBatchBytes: 50 * 1024 });
    assert.equal(shipped1 + shipped2, 300);
    assert.equal(unshippedEntries(scope, AGENT).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
