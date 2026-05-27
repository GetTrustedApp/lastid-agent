/**
 * Agent self-protection (lib/self-protection.js + OperatorStore matcher): the
 * agent refuses to read LastID's OWN key material into context. Built-in +
 * ON by default; matched on the secret IDENTIFIERS (not the command) so it
 * catches every vector — running `security …`, writing a script that does it,
 * dumping the keychain. Disableable locally (env, for debugging LastID) or
 * remotely (a synced 'self_protection' opt-out record).
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';

import { OperatorStore, deriveOperatorStateMacKey } from '../lib/operator-store.js';
import {
  SELF_PROTECTION_RULES,
  selfProtectionRecords,
  selfProtectionDisabledByEnv,
  redactSelfProtected,
  selfProtectionAuditEvent,
} from '../lib/self-protection.js';

function freshStore() {
  const scope = `test-${randomUUID()}`;
  return { store: new OperatorStore(scope), dir: join(homedir(), '.lastid-agent', scope) };
}

// Clear the env override around each case (it's process-global).
function withEnv(value, fn) {
  const prev = process.env.LASTID_SELF_PROTECTION;
  if (value === undefined) delete process.env.LASTID_SELF_PROTECTION;
  else process.env.LASTID_SELF_PROTECTION = value;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.LASTID_SELF_PROTECTION;
    else process.env.LASTID_SELF_PROTECTION = prev;
  }
}

test('selfProtectionRecords: built-in deny rules, attributed to the self-protection pack', () => {
  const recs = selfProtectionRecords();
  assert.equal(recs.length, SELF_PROTECTION_RULES.length);
  for (const r of recs) {
    assert.equal(r.content.severity, 'deny');
    assert.equal(r.content.self_protection, true);
    assert.equal(r.content.pack, 'agent-self-protection');
    assert.equal(r.content.tool, '*'); // tool-agnostic → catches Bash AND Write
  }
});

test('selfProtectionDisabledByEnv: off-values disable, anything else does not', () => {
  for (const v of ['off', 'OFF', '0', 'false', 'disabled', 'no']) {
    assert.equal(selfProtectionDisabledByEnv({ LASTID_SELF_PROTECTION: v }), true, v);
  }
  assert.equal(selfProtectionDisabledByEnv({ LASTID_SELF_PROTECTION: 'on' }), false);
  assert.equal(selfProtectionDisabledByEnv({}), false); // default ON
});

test('DENIES reading LastID key material via security (default on, no synced rules)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      const d = store.matchRules('Bash', {
        command: 'security find-generic-password -a $USER -s lastid.co/agent-slot-seed:main -w',
      });
      assert.equal(d.allow, false);
      assert.equal(d.matched.severity, 'deny');
      assert.equal(d.matched.memory_id, 'selfprot:lastid-key-material');
      assert.equal(d.matched.self_protection, true); // tagged distinctly for the hook/console
      assert.equal(d.matched.pack, 'agent-self-protection');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The operator's "capture writes" case: writing a script that does it.
test('DENIES writing a script that reads the key material (tool-agnostic match)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      const d = store.matchRules('Write', {
        file_path: '/tmp/steal.sh',
        content: '#!/bin/sh\nsecret-tool lookup service lastid.co/agent-project-root-seed\n',
      });
      assert.equal(d.allow, false);
      assert.equal(d.matched.severity, 'deny');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('DENIES a full keychain dump (would sweep up LastID keys)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      const d = store.matchRules('Bash', { command: 'security dump-keychain -d' });
      assert.equal(d.allow, false);
      assert.equal(d.matched.memory_id, 'selfprot:keychain-dump');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ALLOWS reading a NON-LastID keychain item (the agent can help with the user\'s own keys)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      const d = store.matchRules('Bash', {
        command: 'security find-generic-password -s github.com/my-pat -w',
      });
      assert.equal(d.allow, true);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('LOCAL env override disables it (debugging LastID itself)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv('off', () => {
      const d = store.matchRules('Bash', {
        command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w',
      });
      assert.equal(d.allow, true, 'disabled via LASTID_SELF_PROTECTION=off');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// SECURITY (operator: "we can't let someone edit these settings on disk … has
// to be from signed package … signed package has to validate"). An UNSIGNED
// opt-out record sitting in operator-state.json — exactly what an attacker or
// the agent's own Write tool could append — must NOT disable self-protection.
// The only honored disable is the local env override (above) or a delegation-
// SIGNED, signature-VALIDATED opt-out (pending; never a raw file flag).
test('an UNSIGNED on-disk opt-out record is IGNORED (disable must be signed + validated)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      // Simulate a tampered/forged file: a self_protection record with no valid
      // delegation signature behind it.
      store.applyRecords([
        { id: 'self-protection', kind: 'self_protection', target: 'global', status: 'active', version: 1, content: { enabled: false } },
      ], 1);
      assert.equal(store.selfProtectionEnabled(), true, 'unsigned file flag does NOT disable');
      const d = store.matchRules('Bash', {
        command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w',
      });
      assert.equal(d.allow, false, 'still protected — a file edit cannot turn off the guard');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The CUSTOMER-FACING signed disable: a self_protection opt-out honored ONLY in
// an integrity-VERIFIED (keyed) store — the MAC proves it came via the
// delegation-verified sync, not a disk edit. A keyless store ignores it.
test('a MAC-verified signed opt-out DISABLES it; a keyless store IGNORES the same file', () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  const seed = Buffer.alloc(32, 3);
  try {
    withEnv(undefined, () => {
      // Operator's signed opt-out, written by the keyed (listener) store → MAC'd.
      const writer = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(seed) });
      writer.applyRecords(
        [{ id: 'agent-self-protection', kind: 'self_protection', target: 'global', status: 'active', version: 1, content: { enabled: false } }],
        1,
      );
      // Keyed reader (the rule enforcer) → verifies the MAC → honors the opt-out.
      const keyed = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(seed) });
      assert.equal(keyed.selfProtectionEnabled(), false, 'signed + verified opt-out disables');
      assert.equal(
        keyed.matchRules('Bash', { command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w' }).allow,
        true,
      );
      // Keyless reader → can't verify → ignores the opt-out → stays protected.
      const keyless = new OperatorStore(scope);
      assert.equal(keyless.selfProtectionEnabled(), true, 'keyless ignores the opt-out');
      assert.equal(
        keyless.matchRules('Bash', { command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w' }).allow,
        false,
      );
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('self-protection DENY wins over a synced operator warn (most-restrictive)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      // An operator warn that also matches the same command.
      store.applyRecords([
        { id: 'rule_warn', kind: 'rule', target: 'global', status: 'active', version: 1, updated_at: '2026-05-26T00:00:00Z', content: { tool: '*', pattern: 'security', is_regex: false, severity: 'warn', reason: 'heads up' } },
      ], 1);
      const d = store.matchRules('Bash', {
        command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w',
      });
      assert.equal(d.allow, false);
      assert.equal(d.matched.severity, 'deny'); // self-protection deny wins
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The guard's OWN source is off limits. Reading lib/self-protection.js or
// lib/keychain.js dumps the matcher patterns + the literal key-material service
// names into context — recon for evading this very guard. PreToolUse sees the
// tool INPUT, not the output, so a plain `cat keychain.js` would otherwise slip
// the names out. Tool-agnostic, so Read AND a Bash cat/sed both match; covers
// the .test.js fixtures, which embed the same names.
test('DENIES reading the self-protection / keychain source (recon for evading the guard)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      const attempts = [
        ['Read', { file_path: '/x/plugins/lastid-agent/lib/self-protection.js' }],
        ['Read', { file_path: '/x/plugins/lastid-agent/lib/keychain.js' }],
        ['Bash', { command: 'cat lib/keychain.js' }],
        ['Bash', { command: 'sed -n 1,80p lib/self-protection.js' }],
        ['Read', { file_path: '/x/plugins/lastid-agent/tests/self-protection.test.js' }],
      ];
      for (const [tool, input] of attempts) {
        const d = store.matchRules(tool, input);
        assert.equal(d.allow, false, JSON.stringify([tool, input]));
        assert.equal(d.matched.severity, 'deny');
        assert.equal(d.matched.memory_id, 'selfprot:lastid-self-source');
      }
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ALLOWS reading other plugin source (only the guard + keychain are off limits)', () => {
  const { store, dir } = freshStore();
  try {
    withEnv(undefined, () => {
      assert.equal(store.matchRules('Read', { file_path: '/x/plugins/lastid-agent/lib/rule-packs.js' }).allow, true);
      assert.equal(store.matchRules('Bash', { command: 'cat lib/operator-store.js' }).allow, true);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// OUTPUT-side net: PreToolUse blocks the obvious reads, but an obfuscated read
// can still emit protected material into a tool's OUTPUT. redactSelfProtected
// masks the key-material service-name tokens + the guard/keychain source
// filenames out of any text (tool output before it reaches the audit chain, and
// where the runtime allows, the model). The service literal here is built by
// concatenation so this source file never embeds it (which would itself be
// off limits).
test('redactSelfProtected: masks key-material service names + the guard source filenames', () => {
  const svc = 'lastid.co/agent-' + 'slot-seed:main';
  const r = redactSelfProtected(`found ${svc} and see lib/keychain.js for the rest`);
  assert.ok(!r.text.includes(svc), 'service token masked');
  assert.ok(!r.text.includes('keychain.js'), 'source filename masked');
  assert.equal(r.count, 2);
  assert.match(r.text, /REDACTED/);
});

test('redactSelfProtected: leaves unrelated output untouched (no false positives)', () => {
  const t = 'ordinary command output, nothing sensitive in here';
  const r = redactSelfProtected(t);
  assert.equal(r.text, t);
  assert.equal(r.count, 0);
});

// When self-protection FIRES the operator must see it in the audit chain.
// selfProtectionAuditEvent builds that event (ungated, a security signal).
test('selfProtectionAuditEvent: a self-protection input DENY becomes an audit event', () => {
  const ev = selfProtectionAuditEvent({
    matched: { self_protection: true, severity: 'deny', memory_id: 'selfprot:lastid-self-source', pack: 'agent-self-protection' },
    tool: 'Read',
    phase: 'input',
  });
  assert.equal(ev.eventType, 'AgentSelfProtectionTriggered');
  assert.equal(ev.metadata.phase, 'input');
  assert.equal(ev.metadata.rule, 'selfprot:lastid-self-source');
  assert.equal(ev.metadata.tool, 'Read');
});

test('selfProtectionAuditEvent: a NON-self-protection deny is not a self-protection event', () => {
  const ev = selfProtectionAuditEvent({
    matched: { self_protection: false, severity: 'deny', memory_id: 'rule_123' },
    tool: 'Bash',
    phase: 'input',
  });
  assert.equal(ev, null);
});

test('selfProtectionAuditEvent: key material flagged in OUTPUT becomes an audit event', () => {
  const ev = selfProtectionAuditEvent({ tool: 'Bash', phase: 'output' });
  assert.equal(ev.eventType, 'AgentSelfProtectionTriggered');
  assert.equal(ev.metadata.phase, 'output');
  assert.equal(ev.metadata.kind, 'key_material_in_output');
});
