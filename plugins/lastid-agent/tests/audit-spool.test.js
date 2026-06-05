/**
 * Tests for the audit spool (lib/audit-spool.js) — the lock-free write side of
 * the signed audit chain. Writers enqueue; the listener (single chain writer)
 * drains in order. These lock: enqueue is atomic + parseable, drain preserves
 * order + chains + unlinks, a corrupt file can't wedge the drain, tool_use_id
 * survives for call↔result correlation, and an append failure is retryable
 * (no double-append).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { rmSync, writeFileSync, readdirSync } from 'node:fs';

import {
  enqueueAuditEvent,
  listSpooled,
  drainAuditSpool,
  auditSpoolDir,
} from '../lib/audit-spool.js';
import { readMemoryAudit, verifyMemoryAudit } from '../lib/memory-audit.js';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function freshScope() {
  const scope = `test-${randomUUID()}`;
  return { scope, dir: join(homedir(), '.lastid-agent', scope) };
}

test('enqueue writes a parseable spool file; nothing touches the chain yet', () => {
  const { scope, dir } = freshScope();
  try {
    const p = enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Bash' } });
    assert.ok(p && p.endsWith('.json'), 'returns the published path');
    const spooled = listSpooled(scope);
    assert.equal(spooled.length, 1);
    assert.equal(spooled[0].rec.event_type, 'tool_call');
    assert.equal(spooled[0].rec.metadata.tool, 'Bash');
    // The signed chain is untouched until a drain.
    assert.equal(readMemoryAudit(scope).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('drain chains spooled events IN ORDER, signs them, and unlinks the spool', () => {
  const { scope, dir } = freshScope();
  try {
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Read', n: 1 } });
    enqueueAuditEvent({ scope, eventType: 'tool_result', metadata: { tool: 'Read', n: 2 } });
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Edit', n: 3 } });

    const chained = drainAuditSpool({ scope, signingKey: privateKey, agentDid: 'did:a' });
    assert.equal(chained, 3);

    const chain = readMemoryAudit(scope, 'did:a');
    assert.deepEqual(chain.map((r) => r.metadata.n), [1, 2, 3], 'chained in enqueue order');
    assert.deepEqual(chain.map((r) => r.seq), [0, 1, 2], 'seq is contiguous');
    assert.equal(verifyMemoryAudit(scope, 'did:a', publicKey).intact, true, 'hash-linked + signature verifies');
    // Spool emptied.
    assert.equal(listSpooled(scope).length, 0);
    assert.equal(readdirSync(auditSpoolDir(scope)).filter((f) => f.endsWith('.json')).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('tool_use_id rides into the chain metadata so a result correlates to its call', () => {
  const { scope, dir } = freshScope();
  try {
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Bash' }, toolUseId: 'tu_42' });
    enqueueAuditEvent({ scope, eventType: 'tool_result', metadata: { tool: 'Bash', status: 'success' }, toolUseId: 'tu_42' });
    drainAuditSpool({ scope, signingKey: privateKey, agentDid: 'did:a' });
    const chain = readMemoryAudit(scope, 'did:a');
    assert.equal(chain[0].metadata.tool_use_id, 'tu_42');
    assert.equal(chain[1].metadata.tool_use_id, 'tu_42');
    assert.equal(chain[0].event_type, 'tool_call');
    assert.equal(chain[1].event_type, 'tool_result');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt spool file is dropped and never wedges the drain', () => {
  const { scope, dir } = freshScope();
  try {
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Read' } });
    // Drop a garbage file directly into the spool.
    writeFileSync(join(auditSpoolDir(scope), '000000000000001-bad.json'), '{not json');
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { tool: 'Edit' } });

    const chained = drainAuditSpool({ scope, signingKey: privateKey, agentDid: 'did:a' });
    assert.equal(chained, 2, 'the two valid events chain; the corrupt one is skipped');
    assert.equal(listSpooled(scope).length, 0, 'corrupt file removed too');
    assert.equal(verifyMemoryAudit(scope, 'did:a', publicKey).intact, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an append failure is retryable: chained-so-far are unlinked, the rest stay', () => {
  const { scope, dir } = freshScope();
  try {
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { n: 1 } });
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { n: 2 } });
    enqueueAuditEvent({ scope, eventType: 'tool_call', metadata: { n: 3 } });

    // Mock append that throws on the 2nd event.
    let calls = 0;
    const flakyAppend = () => {
      calls += 1;
      if (calls === 2) throw new Error('disk full');
    };
    const chained = drainAuditSpool({ scope, signingKey: privateKey, append: flakyAppend });
    assert.equal(chained, 1, 'stopped after the first success');
    assert.equal(listSpooled(scope).length, 2, 'failed + remaining left for retry — no double-append');

    // A second drain (now healthy, real append) finishes the job in order.
    const more = drainAuditSpool({ scope, signingKey: privateKey, agentDid: 'did:a' });
    assert.equal(more, 2);
    assert.deepEqual(readMemoryAudit(scope, 'did:a').map((r) => r.metadata.n), [2, 3]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('enqueue is best-effort: a bad arg returns null, never throws', () => {
  assert.equal(enqueueAuditEvent({ scope: 'x', eventType: '' }), null);
  assert.equal(enqueueAuditEvent(), null);
});
