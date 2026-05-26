/**
 * operator-state.json anti-tamper integrity (lib/operator-store.js).
 *
 * The operator's signed settings (rules, audit policy, …) are cached in a
 * plaintext file. The single writer (the listener) holds a MAC key derived from
 * the agent's slot_seed — which lives in the keychain, NOT in the file, and is
 * guarded by agent self-protection — and stamps a MAC over the state. A reader
 * holding the key (the policy-check rule enforcer) re-verifies on load; a
 * tampered, downgraded, or wrong-key file is REJECTED → safe defaults (no
 * spoofed rules). So an on-disk edit (the agent's own Write, or an fs attacker)
 * can't silently override what the operator signed.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync, readFileSync, writeFileSync } from 'node:fs';

import { OperatorStore, operatorStatePath, deriveOperatorStateMacKey } from '../lib/operator-store.js';

const SEED_A = Buffer.alloc(32, 7);
const SEED_B = Buffer.alloc(32, 9);

function fresh() {
  const scope = `test-${randomUUID()}`;
  return { scope, path: operatorStatePath(scope), dir: join(homedir(), '.lastid-agent', scope) };
}

const RULE = {
  id: 'rule_1',
  kind: 'rule',
  target: 'global',
  status: 'active',
  version: 1,
  updated_at: '2026-05-26T00:00:00Z',
  content: { tool: 'shell', pattern: 'rm -rf', is_regex: false, severity: 'deny', reason: 'no' },
};

function seedKeyed(scope, seed) {
  const s = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(seed) });
  s.applyRecords([RULE], 5); // writes the file WITH a MAC
  return s;
}

test('deriveOperatorStateMacKey: deterministic per seed, distinct across seeds, null for empty', () => {
  assert.ok(deriveOperatorStateMacKey(SEED_A).equals(deriveOperatorStateMacKey(SEED_A)));
  assert.ok(!deriveOperatorStateMacKey(SEED_A).equals(deriveOperatorStateMacKey(SEED_B)));
  assert.equal(deriveOperatorStateMacKey(Buffer.alloc(0)), null);
  assert.equal(deriveOperatorStateMacKey(null), null);
});

test('keyed save writes a MAC; a keyed reload with the right key loads the records', () => {
  const { scope, path, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    const onDisk = JSON.parse(readFileSync(path, 'utf8'));
    assert.ok(onDisk.integrity && typeof onDisk.integrity.mac === 'string', 'MAC stamped');

    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_A) });
    assert.equal(reader.listRules().length, 1, 'verified → records loaded');
    assert.equal(reader.cursor, 5);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TAMPER: editing a record on disk fails the check → safe defaults (no spoofed rules)', () => {
  const { scope, path, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    // Attacker edits the cached rule (e.g. flips deny→warn, or neuters the pattern).
    const f = JSON.parse(readFileSync(path, 'utf8'));
    f.records.rule_1.content.severity = 'warn';
    writeFileSync(path, JSON.stringify(f));

    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_A) });
    assert.equal(reader.listRules().length, 0, 'tampered state rejected → empty (not the edited rule)');
    assert.equal(reader.cursor, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TAMPER: ADDING a rule on disk is rejected (can\'t inject a rule by editing the file)', () => {
  const { scope, path, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    const f = JSON.parse(readFileSync(path, 'utf8'));
    f.records.injected = { ...RULE, id: 'injected', content: { ...RULE.content, severity: 'warn' } };
    writeFileSync(path, JSON.stringify(f));
    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_A) });
    assert.equal(reader.listRules().length, 0, 'injection rejected → empty');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('DOWNGRADE: stripping the integrity tag is rejected (can\'t just delete the MAC)', () => {
  const { scope, path, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    const f = JSON.parse(readFileSync(path, 'utf8'));
    delete f.integrity;
    writeFileSync(path, JSON.stringify(f));
    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_A) });
    assert.equal(reader.listRules().length, 0, 'un-MACed file rejected by a keyed reader');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('WRONG KEY: a file MACed under a different seed is rejected', () => {
  const { scope, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_B) });
    assert.equal(reader.listRules().length, 0, 'mismatched key → rejected');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a keyless reader loads best-effort (back-compat) — verification only when keyed', () => {
  const { scope, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A); // file has records + a MAC
    const keyless = new OperatorStore(scope); // no key → does not verify
    assert.equal(keyless.listRules().length, 1, 'keyless loads the records (ignores integrity)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The protection composes with self-protection: even a fully tampered file
// (rules wiped) leaves the BUILT-IN key guard intact.
test('self-protection survives a rejected file (built-in, not from the file)', () => {
  const { scope, path, dir } = fresh();
  try {
    seedKeyed(scope, SEED_A);
    writeFileSync(path, JSON.stringify({ cursor: 9, records: {} })); // tampered, no MAC
    const reader = new OperatorStore(scope, undefined, { macKey: deriveOperatorStateMacKey(SEED_A) });
    assert.equal(reader.listRules().length, 0, 'rejected → no synced rules');
    const d = reader.matchRules('Bash', {
      command: 'security find-generic-password -s lastid.co/agent-slot-seed:main -w',
    });
    assert.equal(d.allow, false, 'self-protection still denies reading the agent key');
    assert.equal(d.matched.self_protection, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
