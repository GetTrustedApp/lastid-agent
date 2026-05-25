/**
 * Tests for the agent memory audit chain (lib/memory-audit.js): append +
 * hash-link + Ed25519 sign + verify + tamper detection + ship cursor, and the
 * memory-tools integration (write/update/forget append signed records;
 * drafts do not).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';

import {
  appendMemoryAudit,
  readMemoryAudit,
  verifyMemoryAudit,
  publicKeyFor,
  canonicalJson,
  unshippedEntries,
  shipUnshipped,
} from '../lib/memory-audit.js';
import { handleMemoryTool } from '../lib/memory-tools.js';
import { shipMemoryAudit } from '../lib/memory-audit-ship.js';
import { deriveAgentEd25519Keypair } from '../lib/agent-provisioning.js';

function freshScope() {
  const scope = `test-${randomUUID()}`;
  return { scope, dir: join(homedir(), '.lastid-agent', scope) };
}

const { privateKey, publicKey } = generateKeyPairSync('ed25519');

test('canonicalJson: deterministic key order', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ a: { y: 1, x: 2 } }), '{"a":{"x":2,"y":1}}');
});

test('append builds a signed, hash-linked chain that verifies', () => {
  const { scope, dir } = freshScope();
  try {
    const a = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: 'did:a', eventType: 'AgentMemoryWritten', memoryId: 'mem_1', metadata: { kind: 'fact' } });
    const b = appendMemoryAudit({ scope, signingKey: privateKey, agentDid: 'did:a', eventType: 'AgentMemoryUpdated', memoryId: 'mem_1', metadata: { fields_changed: 'claim' } });
    assert.equal(a.seq, 0);
    assert.equal(a.prev_hash, null);
    assert.equal(b.seq, 1);
    assert.equal(b.prev_hash, a.integrity_hash, 'b links to a');
    assert.ok(a.signature && b.signature, 'signed');

    const report = verifyMemoryAudit(scope, publicKey);
    assert.equal(report.intact, true);
    assert.equal(report.total, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify detects a tampered record', () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryWritten', memoryId: 'mem_1' });
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryForgotten', memoryId: 'mem_1' });
    // Tamper: rewrite the file with a mutated metadata on entry 0.
    const path = join(homedir(), '.lastid-agent', scope, 'memory-audit.jsonl');
    const lines = readMemoryAudit(scope);
    lines[0].memory_id = 'mem_HACKED';
    writeFileSync(path, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
    const report = verifyMemoryAudit(scope, publicKey);
    assert.equal(report.intact, false);
    assert.equal(report.firstFailure.seq, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('publicKeyFor: derives a verifying key from the private key', () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryWritten', memoryId: 'm' });
    const pub = publicKeyFor(privateKey);
    assert.ok(pub);
    assert.equal(verifyMemoryAudit(scope, pub).intact, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ship cursor: unshipped → ship advances → none left', async () => {
  const { scope, dir } = freshScope();
  try {
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryWritten', memoryId: 'm2' });
    assert.equal(unshippedEntries(scope).length, 2);

    let shippedBatch = null;
    const n = await shipUnshipped(scope, async (records) => { shippedBatch = records; return true; });
    assert.equal(n, 2);
    assert.equal(shippedBatch.length, 2);
    assert.equal(unshippedEntries(scope).length, 0, 'cursor advanced');

    // A failed post must NOT advance the cursor.
    appendMemoryAudit({ scope, signingKey: privateKey, eventType: 'AgentMemoryForgotten', memoryId: 'm1' });
    const n2 = await shipUnshipped(scope, async () => false);
    assert.equal(n2, 0);
    assert.equal(unshippedEntries(scope).length, 1, 'still pending after failed ship');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── IdP shipping ───────────────────────────────────────────────────

test('shipMemoryAudit: POSTs unshipped records to /audit + advances on 2xx', async () => {
  const { scope, dir } = freshScope();
  const { signingKey } = deriveAgentEd25519Keypair(Buffer.alloc(32, 9));
  try {
    appendMemoryAudit({ scope, signingKey, agentDid: 'did:a', eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    let posted = null;
    const okFetch = async (url, opts) => {
      posted = { url, headers: opts.headers, body: JSON.parse(opts.body) };
      return { ok: true, status: 200 };
    };
    const n = await shipMemoryAudit({ idpUrl: 'https://idp.example', scope, agentDid: 'did:a', vcCompact: 'vc.jwt', signingKey, fetchImpl: okFetch });
    assert.equal(n, 1);
    assert.match(posted.url, /\/v1\/agent-state\/audit$/);
    assert.equal(posted.headers.Authorization, 'Bearer vc.jwt');
    assert.ok(typeof posted.headers.DPoP === 'string' && posted.headers.DPoP.length > 0, 'DPoP proof attached');
    assert.equal(posted.body.records.length, 1);
    assert.equal(unshippedEntries(scope).length, 0, 'cursor advanced');

    // A 500 must NOT advance the cursor.
    appendMemoryAudit({ scope, signingKey, agentDid: 'did:a', eventType: 'AgentMemoryForgotten', memoryId: 'm1' });
    const n2 = await shipMemoryAudit({ idpUrl: 'https://idp.example', scope, agentDid: 'did:a', vcCompact: 'vc.jwt', signingKey, fetchImpl: async () => ({ ok: false, status: 500 }) });
    assert.equal(n2, 0);
    assert.equal(unshippedEntries(scope).length, 1, 'still pending after failed ship');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── memory-tools integration ───────────────────────────────────────

const loadedAgent = { agentDid: 'did:lastid:agent:zT', slotSeed: Buffer.alloc(32, 7), vcCompact: 'vc.jwt', idpUrl: 'https://idp.test' };
const claims = { sub: 'did:lastid:agent:zT', parent_human_did: 'did:lastid:zH' };
const okFetch = async () => ({ ok: true, status: 200 }); // live write-through succeeds w/o network

test('memory tools append audit records (write/update/forget); draft does NOT', async () => {
  const { scope, dir } = freshScope();
  const call = (name, args) => handleMemoryTool({ name, args, scope, loadedAgent, claims, fetchImpl: okFetch });
  const body = (r) => JSON.parse(r.content[0].text);
  try {
    const w = body(await call('lastid_memory_write', { kind: 'fact', subject: ['x'], claim: 'c1', source_kind: 'user_explicit' }));
    await call('lastid_memory_draft', { kind: 'fact', subject: ['x'], claim: 'a draft', source_kind: 'inferred', source_quote: 'q' });
    await call('lastid_memory_update', { id: w.memory.id, claim: 'c1 updated', reason: 'clarified' });
    await call('lastid_memory_forget', { id: w.memory.id, reason: 'obsolete' });

    const chain = readMemoryAudit(scope);
    const types = chain.map((r) => r.event_type);
    assert.deepEqual(types, ['AgentMemoryWritten', 'AgentMemoryUpdated', 'AgentMemoryForgotten'], 'draft not chained');
    // signed with the agent's derived key → verifies
    const { deriveAgentEd25519Keypair } = await import('../lib/agent-provisioning.js');
    const { signingKey } = deriveAgentEd25519Keypair(loadedAgent.slotSeed);
    assert.equal(verifyMemoryAudit(scope, publicKeyFor(signingKey)).intact, true);
    // metadata is non-sensitive (no claim leaked)
    assert.ok(!JSON.stringify(chain).includes('c1 updated'), 'claim text not in the audit chain');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
