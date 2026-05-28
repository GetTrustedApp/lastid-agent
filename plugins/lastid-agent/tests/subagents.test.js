/**
 * Subagents module (lib/subagents.js):
 *   PURE: agent.md parse + format round-trip, spawn arg construction,
 *         stream-json result extraction, scope name derivation.
 *   FS:   stub install → index write → list → invoke (mocked spawn).
 *
 * The spawn itself (real `claude` subprocess) is integration-tested manually
 * — too costly + flaky in unit tests. Everything else has tight coverage.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  subagentScopeName,
  parseAgentMd,
  formatAgentMd,
  buildSpawnArgs,
  parseStreamJsonResult,
  sha256Hex,
  readIndex,
  addToIndex,
  removeFromIndex,
  installStubSub,
  listSubagents,
  uninstallSub,
  invokeSubagent,
  applySubagentRecord,
} from '../lib/subagents.js';

// ── Pure layer ────────────────────────────────────────────────────────

test('subagentScopeName: parent+slug → parent-slug', () => {
  assert.equal(subagentScopeName('main', 'echobot'), 'main-echobot');
  assert.equal(subagentScopeName('verifier', 'kyc-check'), 'verifier-kyc-check');
});

test('subagentScopeName: NEGATIVE — missing parts throws', () => {
  assert.throws(() => subagentScopeName('', 'slug'), /parentScope \+ slug required/);
  assert.throws(() => subagentScopeName('parent', ''), /parentScope \+ slug required/);
});

test('parseAgentMd / formatAgentMd: round-trip preserves frontmatter + body', () => {
  const fm = {
    lastid_version: 1,
    id: '01HKABC',
    name: 'Echo',
    slug: 'echobot',
    mode: 'stub',
    claude_tools: { allowed: ['Read'], disallowed: ['WebFetch'] },
    mcp_allowed: [],
  };
  const body = 'You are Echo bot.\nRepeat the user input verbatim.';
  const raw = formatAgentMd(fm, body);
  const parsed = parseAgentMd(raw);
  assert.deepEqual(parsed.frontmatter, fm);
  assert.equal(parsed.body.trim(), body.trim());
});

test('parseAgentMd: NEGATIVE — missing fences fails clearly', () => {
  assert.throws(() => parseAgentMd('no fences here'), /missing leading `---`/);
  assert.throws(() => parseAgentMd('---\nfoo: bar\n'), /missing closing `---`/);
});

test('parseAgentMd: hand-written YAML frontmatter parses', () => {
  const raw = `---
name: Echo
slug: echobot
mode: stub
---
You are Echo bot.
`;
  const parsed = parseAgentMd(raw);
  assert.equal(parsed.frontmatter.name, 'Echo');
  assert.equal(parsed.frontmatter.slug, 'echobot');
  assert.equal(parsed.frontmatter.mode, 'stub');
  assert.match(parsed.body, /You are Echo bot\./);
});

test('buildSpawnArgs: produces the right argv + scope env (input via stdin, NOT argv)', () => {
  const out = buildSpawnArgs({
    subagent: {
      slug: 'echobot',
      scope: 'main-echobot',
      claude_tools: { allowed: ['Read', 'Bash(echo:*)'], disallowed: ['WebFetch'] },
    },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: { PATH: '/usr/bin', SOMETHING_ELSE: 'kept' },
  });
  assert.equal(out.cmd, 'claude');
  assert.deepEqual(out.args, [
    '--print',
    '--verbose',
    '--system-prompt-file',
    '/tmp/sys.md',
    '--output-format',
    'stream-json',
    '--allowed-tools',
    'Read,Bash(echo:*)',
    '--disallowed-tools',
    'WebFetch',
  ]);
  // SECURITY GUARD: input must NEVER appear in argv (would enable flag
  // smuggling — an input of "--dangerously-skip-permissions" would flip
  // that flag on). Input is piped to stdin by invokeSubagent.
  assert.ok(
    !out.args.some((a) => a.startsWith('--dangerously')),
    'no dangerous flags from any source',
  );
  assert.equal(out.env.LASTID_AGENT_SCOPE, 'main-echobot');
  assert.equal(out.env.PATH, '/usr/bin'); // parent env carried through
  assert.equal(out.env.SOMETHING_ELSE, 'kept');
});

test('buildSpawnArgs: omits tool flags when arrays are empty/missing', () => {
  const out = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: { allowed: [], disallowed: [] } },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  assert.equal(out.args.includes('--allowed-tools'), false);
  assert.equal(out.args.includes('--disallowed-tools'), false);
});

test('parseStreamJsonResult: extracts final result event', () => {
  const stdout = [
    '{"type":"system","subtype":"init"}',
    '{"type":"assistant","message":{"content":[{"type":"text","text":"thinking..."}]}}',
    '{"type":"result","subtype":"success","is_error":false,"result":"ECHO: hello"}',
  ].join('\n');
  const r = parseStreamJsonResult(stdout);
  assert.deepEqual(r, { ok: true, error: null, text: 'ECHO: hello' });
});

test('parseStreamJsonResult: NEGATIVE — is_error:true → not ok', () => {
  const stdout = '{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Boom"}';
  const r = parseStreamJsonResult(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.error, 'Boom');
});

test('parseStreamJsonResult: NEGATIVE — no result event → not ok', () => {
  const stdout = '{"type":"system","subtype":"init"}\n{"type":"assistant"}';
  const r = parseStreamJsonResult(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.error, 'no_result_event');
});

test('parseStreamJsonResult: tolerates malformed lines', () => {
  const stdout = [
    '{"type":"system"}',
    'not-json-at-all',
    '{"type":"result","subtype":"success","is_error":false,"result":"ok"}',
    '',
  ].join('\n');
  const r = parseStreamJsonResult(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.text, 'ok');
});

test('sha256Hex: deterministic + hex-shaped', () => {
  const h = sha256Hex('hello');
  assert.match(h, /^[a-f0-9]{64}$/);
  assert.equal(h, sha256Hex('hello'));
  assert.notEqual(h, sha256Hex('world'));
});

// ── FS-backed (uses temp HOME) ────────────────────────────────────────

let tmpHome;
let prevHome;

before(async () => {
  prevHome = process.env.HOME;
  tmpHome = await mkdtemp(join(tmpdir(), 'lastid-subagents-'));
  process.env.HOME = tmpHome;
});
after(async () => {
  process.env.HOME = prevHome;
  await rm(tmpHome, { recursive: true, force: true });
});

test('readIndex: empty when missing', async () => {
  const map = await readIndex('main-fresh');
  assert.deepEqual(map, {});
});

test('addToIndex → readIndex round-trip', async () => {
  const entry = { slug: 'echobot', name: 'Echo', scope: 'main-echobot', mode: 'stub' };
  await addToIndex('main', entry);
  const map = await readIndex('main');
  assert.deepEqual(map.echobot, entry);
  // file is JSON v1
  const raw = await readFile(join(tmpHome, '.lastid-agent', 'main', 'subagents.json'), 'utf-8');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.version, 1);
  assert.ok(parsed.subagents.echobot);
});

test('removeFromIndex: drops the slug, leaves others', async () => {
  await addToIndex('main', { slug: 'a', name: 'A', scope: 'main-a', mode: 'stub' });
  await addToIndex('main', { slug: 'b', name: 'B', scope: 'main-b', mode: 'stub' });
  await removeFromIndex('main', 'a');
  const map = await readIndex('main');
  assert.equal(map.a, undefined);
  assert.ok(map.b);
});

test('installStubSub: writes scope dir + agent.md + index entry', async () => {
  const entry = await installStubSub({
    parentScope: 'main',
    slug: 'echoinstall',
    name: 'Echo Install',
    body: 'You are Echo Install bot. Echo input verbatim.',
    claudeTools: { allowed: ['Read'], disallowed: ['WebFetch'] },
    mcpAllowed: [],
  });
  assert.equal(entry.scope, 'main-echoinstall');
  assert.equal(entry.mode, 'stub');
  assert.match(entry.body_sha256, /^[a-f0-9]{64}$/);
  // agent.md is on disk
  const raw = await readFile(entry.agent_md_path, 'utf-8');
  const parsed = parseAgentMd(raw);
  assert.equal(parsed.frontmatter.slug, 'echoinstall');
  assert.equal(parsed.frontmatter.mode, 'stub');
  assert.match(parsed.body, /Echo Install bot/);
  // index updated
  const list = await listSubagents('main');
  const found = list.find((s) => s.slug === 'echoinstall');
  assert.ok(found, 'subagent listed under parent');
});

test('installStubSub: NEGATIVE — bad slug rejected', async () => {
  await assert.rejects(
    installStubSub({ parentScope: 'main', slug: 'BadSlug', name: 'x', body: 'y' }),
    /slug must be lowercase/,
  );
  await assert.rejects(
    installStubSub({ parentScope: 'main', slug: '123abc', name: 'x', body: 'y' }),
    /slug must be lowercase/,
  );
});

test('installStubSub: NEGATIVE — missing required field rejected', async () => {
  await assert.rejects(
    installStubSub({ parentScope: 'main', slug: 'ok', name: '', body: 'y' }),
    /name required/,
  );
  await assert.rejects(
    installStubSub({ parentScope: 'main', slug: 'ok', name: 'X', body: '' }),
    /body required/,
  );
});

test('uninstallSub: removes from index + deletes scope dir', async () => {
  await installStubSub({
    parentScope: 'main',
    slug: 'gonebot',
    name: 'Gone',
    body: 'temp',
  });
  const r = await uninstallSub({ parentScope: 'main', slug: 'gonebot' });
  assert.equal(r.ok, true);
  assert.equal(r.removed.scope, 'main-gonebot');
  const list = await listSubagents('main');
  assert.equal(list.find((s) => s.slug === 'gonebot'), undefined);
  // scope dir gone (best-effort; just confirm readIndex returns nothing for it)
  const subMap = await readIndex('main-gonebot');
  assert.deepEqual(subMap, {});
});

test('uninstallSub: NEGATIVE — unknown slug returns not_found', async () => {
  const r = await uninstallSub({ parentScope: 'main', slug: 'nobody' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'not_found');
});

test('invokeSubagent: NEGATIVE — empty/non-string input rejected at the boundary', async () => {
  // input_required is the contract; no spawn should happen.
  let r = await invokeSubagent({ parentScope: 'main', slug: 'anything', input: '' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'input_required');
  r = await invokeSubagent({ parentScope: 'main', slug: 'anything', input: undefined });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'input_required');
  r = await invokeSubagent({ parentScope: 'main', slug: 'anything', input: 42 });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'input_required');
});

test('invokeSubagent: NEGATIVE — unknown slug returns not_found_or_revoked', async () => {
  const r = await invokeSubagent({
    parentScope: 'main',
    slug: 'never-installed',
    input: 'hello',
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'not_found_or_revoked');
});

test('listSubagents: sorted by slug', async () => {
  // fresh parent so we don't fight earlier tests' entries
  const p = 'main-listing';
  await installStubSub({ parentScope: p, slug: 'charlie', name: 'C', body: 'c' });
  await installStubSub({ parentScope: p, slug: 'alpha', name: 'A', body: 'a' });
  await installStubSub({ parentScope: p, slug: 'bravo', name: 'B', body: 'b' });
  const list = await listSubagents(p);
  assert.deepEqual(list.map((s) => s.slug), ['alpha', 'bravo', 'charlie']);
});

// ── Doorbell-driven install: applySubagentRecord ──────────────────────
// The console publishes a subagent → IdP fans out a sealed record → the
// listener's agent-state-sync decrypts → calls applySubagentRecord to
// materialize the scope on disk. No human "install" step. These tests
// stand in for the sync-side dispatch (which is itself end-to-end exercised
// by agent-state-sync.test.js — the disk-write IS the contract here).

test('applySubagentRecord: ACTIVE record writes scope dir + index entry (mode=published)', async () => {
  const parentScope = 'main-published';
  const entry = await applySubagentRecord({
    scope: parentScope,
    storeRecord: {
      id: 'subagent-record-1',
      kind: 'subagent',
      status: 'active',
      content: {
        slug: 'echopub',
        name: 'Echo (Published)',
        body: 'You are Echo Published. Echo input verbatim.',
        claude_tools: { allowed: ['Read'], disallowed: ['WebFetch'] },
        mcp_allowed: ['lastid_react'],
      },
    },
  });
  assert.equal(entry.scope, 'main-published-echopub');
  assert.equal(entry.mode, 'published');
  // The record id is stable across re-applies (IdP-assigned).
  assert.equal(entry.id, 'subagent-record-1');
  // agent.md on disk reflects the published mode.
  const raw = await readFile(entry.agent_md_path, 'utf-8');
  const parsed = parseAgentMd(raw);
  assert.equal(parsed.frontmatter.slug, 'echopub');
  assert.equal(parsed.frontmatter.mode, 'published');
  assert.equal(parsed.frontmatter.id, 'subagent-record-1');
  assert.match(parsed.body, /Echo Published/);
  // Parent index lists it.
  const list = await listSubagents(parentScope);
  assert.ok(list.find((s) => s.slug === 'echopub'));
});

test('applySubagentRecord: REVOKED record removes scope dir + index entry', async () => {
  const parentScope = 'main-revoke';
  // First, install via active record.
  await applySubagentRecord({
    scope: parentScope,
    storeRecord: {
      id: 'rec-2',
      kind: 'subagent',
      status: 'active',
      content: {
        slug: 'goingaway',
        name: 'Going Away',
        body: 'soon to be revoked',
      },
    },
  });
  // Confirm present.
  let list = await listSubagents(parentScope);
  assert.ok(list.find((s) => s.slug === 'goingaway'));
  // Now revoke.
  const r = await applySubagentRecord({
    scope: parentScope,
    storeRecord: { id: 'rec-2', kind: 'subagent', status: 'revoked', content: { slug: 'goingaway' } },
  });
  assert.equal(r.ok, true);
  list = await listSubagents(parentScope);
  assert.equal(list.find((s) => s.slug === 'goingaway'), undefined);
});

test('applySubagentRecord: re-apply ACTIVE updates body + preserves stable id (idempotent)', async () => {
  const parentScope = 'main-idem';
  const e1 = await applySubagentRecord({
    scope: parentScope,
    storeRecord: {
      id: 'stable-id',
      kind: 'subagent',
      status: 'active',
      content: { slug: 'idem', name: 'Idem', body: 'v1 body' },
    },
  });
  const e2 = await applySubagentRecord({
    scope: parentScope,
    storeRecord: {
      id: 'stable-id',
      kind: 'subagent',
      status: 'active',
      content: { slug: 'idem', name: 'Idem', body: 'v2 body' },
    },
  });
  assert.equal(e1.id, 'stable-id');
  assert.equal(e2.id, 'stable-id');
  // Body sha changed; entry was updated in place.
  assert.notEqual(e1.body_sha256, e2.body_sha256);
  const list = await listSubagents(parentScope);
  // Still exactly one entry for that slug.
  assert.equal(list.filter((s) => s.slug === 'idem').length, 1);
});

test('applySubagentRecord: NEGATIVE — malformed slug rejected', async () => {
  await assert.rejects(
    applySubagentRecord({
      scope: 'main',
      storeRecord: { id: 'x', kind: 'subagent', status: 'active', content: { slug: 'BadSlug', name: 'X', body: 'y' } },
    }),
    /slug missing or malformed/,
  );
  await assert.rejects(
    applySubagentRecord({
      scope: 'main',
      storeRecord: { id: 'x', kind: 'subagent', status: 'active', content: { name: 'X', body: 'y' } },
    }),
    /slug missing or malformed/,
  );
});

test('applySubagentRecord: NEGATIVE — active record without body rejected', async () => {
  await assert.rejects(
    applySubagentRecord({
      scope: 'main',
      storeRecord: { id: 'x', kind: 'subagent', status: 'active', content: { slug: 'ok', name: 'X' } },
    }),
    /body required/,
  );
});

test('applySubagentRecord: NEGATIVE — missing scope/storeRecord rejected', async () => {
  await assert.rejects(
    applySubagentRecord({ storeRecord: { kind: 'subagent', content: { slug: 'x', body: 'y' } } }),
    /scope required/,
  );
  await assert.rejects(applySubagentRecord({ scope: 'main' }), /storeRecord required/);
});
