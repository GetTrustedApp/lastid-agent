/**
 * Tests for the local operator-state store (lib/operator-store.js):
 * apply/version/revoke semantics, cursor monotonicity, persistence, and
 * the rule matcher whose output must be drop-in for the PreToolUse hook.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { OperatorStore } from '../lib/operator-store.js';

function freshStore() {
  return new OperatorStore('test', join(tmpdir(), `opstore-${randomUUID()}.json`));
}

function rule(id, content, over = {}) {
  return {
    id,
    kind: 'rule',
    target: 'global',
    status: 'active',
    version: 1,
    updated_at: '2026-01-01T00:00:00Z',
    content,
    ...over,
  };
}

test('upsert + listRules + bedrockMemories', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny', reason: 'no stash' }));
  s.upsert({ id: 'm1', kind: 'memory', status: 'active', version: 1, content: { bedrock: true, claim: 'matt writes terse' } });
  s.upsert({ id: 'm2', kind: 'memory', status: 'active', version: 1, content: { bedrock: false, claim: 'topical' } });
  assert.equal(s.listRules().length, 1);
  assert.equal(s.listMemories().length, 2);
  assert.equal(s.bedrockMemories().length, 1);
});

test('version downgrade is ignored', () => {
  const s = freshStore();
  s.upsert(rule('r1', { pattern: 'a', severity: 'warn' }, { version: 5 }));
  const changed = s.upsert(rule('r1', { pattern: 'b', severity: 'deny' }, { version: 3 }));
  assert.equal(changed, false);
  assert.equal(s.listRules()[0].content.pattern, 'a');
});

test('revoked status removes the record', () => {
  const s = freshStore();
  s.upsert(rule('r1', { pattern: 'a', severity: 'warn' }, { version: 1 }));
  assert.equal(s.listRules().length, 1);
  const changed = s.upsert(rule('r1', null, { version: 2, status: 'revoked' }));
  assert.equal(changed, true);
  assert.equal(s.listRules().length, 0);
});

test('applyRecords advances cursor, persists, and reload preserves state', () => {
  const path = join(tmpdir(), `opstore-${randomUUID()}.json`);
  const s = new OperatorStore('test', path);
  s.applyRecords(
    [rule('r1', { tool: 'Bash', pattern: 'rm -rf /', severity: 'deny', reason: 'nope' })],
    42,
  );
  assert.equal(s.cursor, 42);

  const reloaded = new OperatorStore('test', path);
  assert.equal(reloaded.cursor, 42);
  assert.equal(reloaded.listRules().length, 1);
  assert.equal(reloaded.listRules()[0].content.pattern, 'rm -rf /');
});

test('cursor is monotonic (a lower cursor is ignored)', () => {
  const s = freshStore();
  s.setCursor(10);
  s.setCursor(5);
  assert.equal(s.cursor, 10);
  s.setCursor(11);
  assert.equal(s.cursor, 11);
});

test('matchRules: deny match returns the hook-compatible shape', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny', reason: 'never stash' }));
  const d = s.matchRules('Bash', { command: 'git stash && make' });
  assert.equal(d.allow, false);
  assert.equal(d.matched.severity, 'deny');
  assert.equal(d.matched.memory_id, 'r1');
  assert.equal(d.matched.tool, 'bash');
  assert.equal(d.matched.reason, 'never stash');
});

test('matchRules: no match → allow', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny' }));
  assert.deepEqual(s.matchRules('Bash', { command: 'git status' }), { allow: true });
});

test('matchRules: rewrite carries the replacement', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'npm install', severity: 'rewrite', replacement: 'sfw npm install', reason: 'sandbox' }));
  const d = s.matchRules('Bash', { command: 'npm install left-pad' });
  assert.equal(d.matched.severity, 'rewrite');
  assert.equal(d.matched.replacement, 'sfw npm install');
});

test('matchRules: tool scoping', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'secret', severity: 'deny' }));
  // wrong tool → no match
  assert.deepEqual(s.matchRules('Edit', { command: 'secret' }), { allow: true });
  // a wildcard-tool rule matches any tool
  s.upsert(rule('r2', { tool: '*', pattern: 'secret', severity: 'warn' }));
  assert.equal(s.matchRules('Edit', { file_text: 'has secret in it' }).allow, false);
});

test('matchRules: regex pattern via is_regex flag and regex: prefix', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: '\\b(npm|yarn|pnpm)\\b', is_regex: true, severity: 'warn' }));
  assert.equal(s.matchRules('Bash', { command: 'yarn add x' }).allow, false);
  assert.equal(s.matchRules('Bash', { command: 'cargo build' }).allow, true);

  const s2 = freshStore();
  s2.upsert(rule('r2', { tool: 'Bash', pattern: 'regex:rm\\s+-rf', severity: 'deny' }));
  assert.equal(s2.matchRules('Bash', { command: 'rm   -rf /tmp' }).allow, false);
});

test('matchRules: deny wins over warn when both match', () => {
  const s = freshStore();
  s.upsert(rule('warn1', { tool: 'Bash', pattern: 'deploy', severity: 'warn' }));
  s.upsert(rule('deny1', { tool: 'Bash', pattern: 'deploy', severity: 'deny', reason: 'prod freeze' }));
  const d = s.matchRules('Bash', { command: 'deploy prod' });
  assert.equal(d.matched.severity, 'deny');
  assert.equal(d.matched.memory_id, 'deny1');
});

test('matchRules: tool-only rule (empty pattern) matches any use of that tool; empty+empty is a no-op', () => {
  const s = freshStore();
  s.upsert(rule('toolonly', { tool: 'WebFetch', pattern: '', severity: 'warn', reason: 'no outbound' }));
  assert.equal(s.matchRules('WebFetch', { url: 'https://x' }).allow, false);
  assert.equal(s.matchRules('Bash', { command: 'ls' }).allow, true);

  s.upsert(rule('noop', { tool: '', pattern: '', severity: 'deny' }));
  // The no-op rule must not start blocking everything.
  assert.equal(s.matchRules('Read', { file_path: '/etc/hosts' }).allow, true);
});

test('malformed regex fails closed (no match, no throw)', () => {
  const s = freshStore();
  s.upsert(rule('bad', { tool: 'Bash', pattern: 'regex:(unclosed', severity: 'deny' }));
  assert.doesNotThrow(() => s.matchRules('Bash', { command: 'anything' }));
  assert.equal(s.matchRules('Bash', { command: 'anything' }).allow, true);
});

test('policyDecision: a fired rule is returned regardless of sync state', () => {
  const s = freshStore();
  s.upsert(rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny', reason: 'no' }));
  const d = s.policyDecision('Bash', { command: 'git stash' });
  assert.equal(d.allow, false);
  assert.equal(d.matched.memory_id, 'r1');
});

test('policyDecision: synced with no match → authoritative allow', () => {
  const s = freshStore();
  s.applyRecords([rule('r1', { tool: 'Bash', pattern: 'git stash', severity: 'deny' })], 5);
  assert.ok(s.cursor > 0);
  assert.deepEqual(s.policyDecision('Bash', { command: 'git status' }), { allow: true });
});

test('policyDecision: never synced (cursor 0) → null, defer to desktop fallback', () => {
  const s = freshStore();
  assert.equal(s.cursor, 0);
  assert.equal(s.policyDecision('Bash', { command: 'anything' }), null);
});

test('matchRules: canonical tool categories match across runtime names', () => {
  // A rule authored against the canonical "shell" category matches
  // Claude's `Bash` AND a Codex-style `local_shell` — no name mismatch.
  const shellStore = freshStore();
  shellStore.upsert(rule('r_shell', { tool: 'shell', pattern: 'git stash', severity: 'deny' }));
  assert.equal(shellStore.matchRules('Bash', { command: 'git stash' }).allow, false);
  assert.equal(shellStore.matchRules('local_shell', { command: 'git stash' }).allow, false);

  // "file_edit" covers Edit + MultiEdit, but not Read (file_read).
  const editStore = freshStore();
  editStore.upsert(rule('r_edit', { tool: 'file_edit', pattern: 'secret', severity: 'warn' }));
  assert.equal(editStore.matchRules('Edit', { file_text: 'secret' }).allow, false);
  assert.equal(editStore.matchRules('MultiEdit', { file_text: 'secret' }).allow, false);
  assert.equal(editStore.matchRules('Read', { file_path: 'secret.txt' }).allow, true);

  // "search" covers Grep + Glob.
  const searchStore = freshStore();
  searchStore.upsert(rule('r_search', { tool: 'search', pattern: 'pw', severity: 'warn' }));
  assert.equal(searchStore.matchRules('Grep', { pattern: 'pw' }).allow, false);
  assert.equal(searchStore.matchRules('Glob', { pattern: 'pw' }).allow, false);

  // "subagent" covers Claude's `Agent` (NOT `Task`) and Codex's `spawn_agent`.
  const subagentStore = freshStore();
  subagentStore.upsert(rule('r_sub', { tool: 'subagent', pattern: 'x', severity: 'deny' }));
  assert.equal(subagentStore.matchRules('Agent', { x: 'x' }).allow, false);
  assert.equal(subagentStore.matchRules('spawn_agent', { x: 'x' }).allow, false);

  // Any MCP tool collapses to "mcp".
  const mcpStore = freshStore();
  mcpStore.upsert(rule('r_mcp', { tool: 'mcp', pattern: 'x', severity: 'warn' }));
  assert.equal(mcpStore.matchRules('mcp__pencil__batch_design', { x: 'x' }).allow, false);

  // A legacy raw-name rule ("bash") still matches its literal name.
  const legacyStore = freshStore();
  legacyStore.upsert(rule('r_legacy', { tool: 'Bash', pattern: 'rm', severity: 'deny' }));
  assert.equal(legacyStore.matchRules('Bash', { command: 'rm -rf' }).allow, false);
});
