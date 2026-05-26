/**
 * Tests for the audit policy (lib/audit-policy.js) + its SOURCE gating in the
 * audit spool. The operator's signed policy says which classes the agent
 * audits; a disabled class is never spooled (so never chained/shipped). Fail
 * OPEN — only an explicitly-disabled class is dropped; unmapped/integrity
 * events (ChainCheckpoint) are always audited.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync, mkdirSync, writeFileSync } from 'node:fs';

import {
  AUDIT_CLASSES,
  AUDIT_POLICY_KIND,
  AUDIT_POLICY_ID,
  classForEvent,
  defaultPolicyClasses,
  isAuditEnabled,
  loadAuditPolicy,
  __resetAuditPolicyCache,
} from '../lib/audit-policy.js';
import { enqueueAuditEvent, listSpooled } from '../lib/audit-spool.js';
import { operatorStatePath } from '../lib/operator-store.js';

function freshScope() {
  const scope = `test-${randomUUID()}`;
  return { scope, dir: join(homedir(), '.lastid-agent', scope) };
}

// Write an operator-state.json holding an audit_policy record with the given
// class map (mirrors what the sync applies after verifying the signed record).
function writePolicy(scope, classes) {
  const path = operatorStatePath(scope);
  mkdirSync(join(homedir(), '.lastid-agent', scope), { recursive: true });
  const state = {
    version: 1,
    cursor: 1,
    records: {
      [AUDIT_POLICY_ID]: {
        id: AUDIT_POLICY_ID,
        kind: AUDIT_POLICY_KIND,
        target: 'global',
        status: 'active',
        version: 1,
        content: { classes, version: 1 },
      },
    },
  };
  writeFileSync(path, JSON.stringify(state), { mode: 0o600 });
  __resetAuditPolicyCache();
}

test('classForEvent: maps known events, null for unmapped', () => {
  assert.equal(classForEvent('AgentToolInvoked'), 'tool_calls');
  assert.equal(classForEvent('AgentToolSucceeded'), 'tool_calls');
  assert.equal(classForEvent('AgentMemoryForgotten'), 'memory_writes');
  assert.equal(classForEvent('AgentMemoryRead'), 'memory_reads');
  assert.equal(classForEvent('AgentRuleFired'), 'rule_fires');
  assert.equal(classForEvent('ChainCheckpoint'), null, 'integrity events are unmapped → always audited');
  assert.equal(classForEvent('SomethingNew'), null);
});

test('taxonomy enumerates surfaces we do not emit yet (operator wants the toggles ready)', () => {
  const byKey = Object.fromEntries(AUDIT_CLASSES.map((c) => [c.key, c]));
  // Surfaces wired today.
  assert.equal(byKey.tool_calls.emitted, true);
  assert.equal(byKey.memory_writes.emitted, true);
  // Surfaces NOT emitted yet but present so a toggle exists + governs on wire-up.
  assert.equal(byKey.memory_reads.emitted, false);
  assert.equal(byKey.credential_use.emitted, false);
  assert.equal(byKey.messages.emitted, false);
  assert.equal(byKey.sub_agents.emitted, false);
  // Every class maps at least one event_type, and every event maps back.
  for (const c of AUDIT_CLASSES) {
    assert.ok(c.events.length > 0, `${c.key} has events`);
    for (const ev of c.events) assert.equal(classForEvent(ev), c.key);
  }
});

test('isAuditEnabled: no policy → taxonomy defaults; unmapped always on', () => {
  assert.equal(isAuditEnabled(null, 'AgentToolInvoked'), true); // default true
  assert.equal(isAuditEnabled(null, 'AgentMemoryRead'), false); // default false (high-volume)
  assert.equal(isAuditEnabled(null, 'ChainCheckpoint'), true); // unmapped → always
  assert.equal(isAuditEnabled({ classes: {} }, 'AgentMemoryRead'), false, 'empty policy → class default');
});

test('isAuditEnabled: explicit toggles win; missing class falls back to default', () => {
  const policy = { classes: { tool_calls: false, memory_reads: true } };
  assert.equal(isAuditEnabled(policy, 'AgentToolInvoked'), false, 'explicitly disabled');
  assert.equal(isAuditEnabled(policy, 'AgentMemoryRead'), true, 'explicitly enabled (overrides default)');
  assert.equal(isAuditEnabled(policy, 'AgentMemoryWritten'), true, 'unmentioned class → default true');
  assert.equal(isAuditEnabled(policy, 'ChainCheckpoint'), true);
});

test('defaultPolicyClasses: every class present with its default', () => {
  const d = defaultPolicyClasses();
  assert.equal(d.tool_calls, true);
  assert.equal(d.memory_reads, false);
  assert.equal(Object.keys(d).length, AUDIT_CLASSES.length);
});

test('loadAuditPolicy: reads the synced audit_policy record from operator-state', () => {
  const { scope, dir } = freshScope();
  try {
    assert.equal(loadAuditPolicy(scope), null, 'none before sync');
    writePolicy(scope, { tool_calls: false });
    const p = loadAuditPolicy(scope);
    assert.equal(p.classes.tool_calls, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    __resetAuditPolicyCache();
  }
});

// THE source-gating: a disabled class never reaches the spool.
test('enqueueAuditEvent honors the policy at the SOURCE (disabled class never spooled)', () => {
  const { scope, dir } = freshScope();
  try {
    writePolicy(scope, { tool_calls: false }); // disable tool calls only
    enqueueAuditEvent({ scope, eventType: 'AgentToolInvoked', metadata: { tool: 'Bash' } });
    enqueueAuditEvent({ scope, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    enqueueAuditEvent({ scope, eventType: 'ChainCheckpoint' });
    const spooled = listSpooled(scope).map((s) => s.rec.event_type).sort();
    assert.deepEqual(spooled, ['AgentMemoryWritten', 'ChainCheckpoint'], 'tool call dropped at source; the rest spool');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    __resetAuditPolicyCache();
  }
});

test('enqueueAuditEvent fails OPEN: no policy → everything spools (no silent audit loss)', () => {
  const { scope, dir } = freshScope();
  try {
    enqueueAuditEvent({ scope, eventType: 'AgentToolInvoked', metadata: { tool: 'Bash' } });
    enqueueAuditEvent({ scope, eventType: 'AgentMemoryWritten', memoryId: 'm1' });
    assert.equal(listSpooled(scope).length, 2, 'no policy → audit everything');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    __resetAuditPolicyCache();
  }
});
