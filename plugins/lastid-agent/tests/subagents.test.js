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
  mcpConfigForSubagent,
  readSubagentInvocation,
  listRunningSubagentInvocations,
  appendInvocationProgress,
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
    // mcp__lastid-agent is ALWAYS prepended so Claude's auto-mode classifier
    // never gates our own MCP tools (the agent must always be able to reply).
    'mcp__lastid-agent,Read,Bash(echo:*)',
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

test('buildSpawnArgs: injects --mcp-config + --strict-mcp-config when mcpConfigPath given', () => {
  const out = buildSpawnArgs({
    subagent: { slug: 'echobot', scope: 'main-echobot', claude_tools: {} },
    systemPromptPath: '/tmp/sys.md',
    mcpConfigPath: '/tmp/mcp-123.json',
    parentEnv: {},
  });
  const i = out.args.indexOf('--mcp-config');
  assert.notEqual(i, -1, '--mcp-config flag present');
  assert.equal(out.args[i + 1], '/tmp/mcp-123.json');
  assert.ok(
    out.args.includes('--strict-mcp-config'),
    '--strict-mcp-config present so only the injected server is loaded',
  );
});

test('buildSpawnArgs: omits MCP flags when mcpConfigPath is missing/empty', () => {
  const out = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: {} },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  assert.equal(out.args.includes('--mcp-config'), false);
  assert.equal(out.args.includes('--strict-mcp-config'), false);

  const outEmpty = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: {} },
    systemPromptPath: '/tmp/sys.md',
    mcpConfigPath: '',
    parentEnv: {},
  });
  assert.equal(outEmpty.args.includes('--mcp-config'), false);
  assert.equal(outEmpty.args.includes('--strict-mcp-config'), false);
});

test('mcpConfigForSubagent: returns the canonical lastid-agent server entry', () => {
  const cfg = mcpConfigForSubagent();
  assert.ok(cfg.mcpServers, 'has mcpServers map');
  assert.ok(cfg.mcpServers['lastid-agent'], 'registers lastid-agent server');
  const srv = cfg.mcpServers['lastid-agent'];
  assert.equal(srv.command, 'node');
  assert.equal(srv.type, 'stdio');
  assert.ok(Array.isArray(srv.args), 'args is array');
  assert.equal(srv.args.length, 2);
  // First arg = absolute path to bin/lastid-agent.js; second arg = 'serve'.
  assert.match(srv.args[0], /bin\/lastid-agent\.js$/);
  assert.equal(srv.args[1], 'serve');
});

test('buildSpawnArgs: --allowed-tools always present (mcp__lastid-agent injected); --disallowed-tools omitted when empty/missing', () => {
  const out = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: { allowed: [], disallowed: [] } },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  // New contract: --allowed-tools is ALWAYS present because we always inject
  // mcp__lastid-agent — with no user tools, its value is exactly that.
  const i = out.args.indexOf('--allowed-tools');
  assert.notEqual(i, -1, '--allowed-tools always present');
  assert.equal(out.args[i + 1], 'mcp__lastid-agent');
  // --disallowed-tools still omitted when the disallowed array is empty.
  assert.equal(out.args.includes('--disallowed-tools'), false);
});

test('buildSpawnArgs: --allowed-tools always whitelists mcp__lastid-agent (auto-classifier bypass for our own MCP tools)', () => {
  // Pin the contract explicitly so future drift trips this test rather than
  // a live sub-agent: mcp__lastid-agent is the FIRST entry in --allowed-tools
  // regardless of what (if any) user tools are configured.

  // Case 1: no claude_tools at all.
  const bare = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: {} },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  const bi = bare.args.indexOf('--allowed-tools');
  assert.notEqual(bi, -1, '--allowed-tools present with no user tools');
  assert.equal(bare.args[bi + 1], 'mcp__lastid-agent');

  // Case 2: claude_tools.allowed missing entirely.
  const missing = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x' },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  const mi = missing.args.indexOf('--allowed-tools');
  assert.notEqual(mi, -1, '--allowed-tools present when claude_tools absent');
  assert.equal(missing.args[mi + 1], 'mcp__lastid-agent');

  // Case 3: with user tools, mcp__lastid-agent is prepended (first entry).
  const withTools = buildSpawnArgs({
    subagent: { slug: 'x', scope: 'main-x', claude_tools: { allowed: ['Read', 'Bash(echo:*)'] } },
    systemPromptPath: '/tmp/sys.md',
    parentEnv: {},
  });
  const wi = withTools.args.indexOf('--allowed-tools');
  assert.notEqual(wi, -1, '--allowed-tools present with user tools');
  assert.equal(withTools.args[wi + 1], 'mcp__lastid-agent,Read,Bash(echo:*)');
  assert.equal(
    withTools.args[wi + 1].split(',')[0],
    'mcp__lastid-agent',
    'mcp__lastid-agent is always the first whitelisted tool',
  );
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

// ── Backgrounded-invocation state files ──────────────────────────────
//
// readSubagentInvocation / listRunningSubagentInvocations operate on
// `~/.lastid-agent/<parent-scope>/subagent-invocations/<id>.json`. The
// tmpHome fixture above redirects $HOME so these tests don't touch the
// operator's real agent dir. We seed state files directly (no real
// spawn) so we can assert listing/filtering/pruning behavior cleanly.

import { mkdir as fsMkdir, writeFile as fsWriteFile } from 'node:fs/promises';

async function seedInvocation(scope, id, state) {
  const dir = join(tmpHome, '.lastid-agent', scope, 'subagent-invocations');
  await fsMkdir(dir, { recursive: true });
  await fsWriteFile(join(dir, `${id}.json`), JSON.stringify(state, null, 2), 'utf-8');
}

test('readSubagentInvocation: returns the state when the file exists', async () => {
  await seedInvocation('main', 'bg-1', {
    status: 'running',
    invocation_id: 'bg-1',
    slug: 'testy',
    started_at: new Date().toISOString(),
  });
  const state = await readSubagentInvocation({ parentScope: 'main', invocationId: 'bg-1' });
  assert.equal(state?.status, 'running');
  assert.equal(state?.invocation_id, 'bg-1');
  assert.equal(state?.slug, 'testy');
});

test('readSubagentInvocation: NEGATIVE — null when missing (unknown id / pruned)', async () => {
  const state = await readSubagentInvocation({
    parentScope: 'main',
    invocationId: 'nonexistent',
  });
  assert.equal(state, null);
});

test('readSubagentInvocation: NEGATIVE — required args throw', async () => {
  await assert.rejects(
    readSubagentInvocation({ invocationId: 'x' }),
    /parentScope \+ invocationId required/,
  );
  await assert.rejects(
    readSubagentInvocation({ parentScope: 'main' }),
    /parentScope \+ invocationId required/,
  );
});

test('listRunningSubagentInvocations: empty when no directory yet', async () => {
  const items = await listRunningSubagentInvocations({ parentScope: 'never-spawned' });
  assert.deepEqual(items, []);
});

test('listRunningSubagentInvocations: returns ONLY running by default', async () => {
  const now = new Date().toISOString();
  await seedInvocation('main-filter', 'r-1', {
    status: 'running', invocation_id: 'r-1', slug: 'a', started_at: now,
  });
  await seedInvocation('main-filter', 'r-2', {
    status: 'running', invocation_id: 'r-2', slug: 'b', started_at: now,
  });
  await seedInvocation('main-filter', 'done-1', {
    status: 'completed', invocation_id: 'done-1', slug: 'c', started_at: now,
    audit: { completed_at: now },
  });
  const running = await listRunningSubagentInvocations({ parentScope: 'main-filter' });
  assert.equal(running.length, 2);
  assert.ok(running.every((r) => r.status === 'running'));
});

test('listRunningSubagentInvocations: include_all also returns terminal', async () => {
  const now = new Date().toISOString();
  await seedInvocation('main-all', 'r-1', {
    status: 'running', invocation_id: 'r-1', slug: 'a', started_at: now,
  });
  await seedInvocation('main-all', 'done-1', {
    status: 'completed', invocation_id: 'done-1', slug: 'b', started_at: now,
    audit: { completed_at: now },
  });
  const all = await listRunningSubagentInvocations({
    parentScope: 'main-all',
    includeAll: true,
  });
  assert.equal(all.length, 2);
});

test('listRunningSubagentInvocations: prunes terminal files older than 24h', async () => {
  const fresh = new Date().toISOString();
  const stale = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
  await seedInvocation('main-prune', 'r-1', {
    status: 'running', invocation_id: 'r-1', slug: 'a', started_at: fresh,
  });
  await seedInvocation('main-prune', 'old-1', {
    status: 'completed', invocation_id: 'old-1', slug: 'b', started_at: stale,
    audit: { completed_at: stale },
  });
  // The default-running listing skips terminal entries anyway — but the
  // pruning happens BEFORE the filter, and we can observe via include_all
  // that the stale file is gone on the next read.
  await listRunningSubagentInvocations({ parentScope: 'main-prune' });
  const all = await listRunningSubagentInvocations({
    parentScope: 'main-prune',
    includeAll: true,
  });
  // old-1 pruned; only r-1 remains.
  assert.equal(all.length, 1);
  assert.equal(all[0].invocation_id, 'r-1');
});

test('listRunningSubagentInvocations: NEGATIVE — missing parentScope throws', async () => {
  await assert.rejects(
    listRunningSubagentInvocations({}),
    /parentScope required/,
  );
});

// ── appendInvocationProgress — backgrounded sub-agent progress channel ──
//
// The child sub-agent's `lastid_progress` MCP tool streams stage updates
// into the running invocation's state file so the parent sees "still
// alive, here's what I'm doing" between the spawn and the completion push.
// We seed state files with the same seedInvocation() helper the listing
// tests use — no real spawn — and assert the read-modify-write semantics,
// the MAX_PROGRESS_ENTRIES cap, and the silent no-op guards.

test('appendInvocationProgress: POSITIVE — one entry lands, status stays running', async () => {
  await seedInvocation('main-prog', 'p-1', {
    status: 'running', invocation_id: 'p-1', slug: 'a',
    started_at: new Date().toISOString(),
  });
  await appendInvocationProgress({
    parentScope: 'main-prog', invocationId: 'p-1', stage: 'fetching',
  });
  const state = await readSubagentInvocation({ parentScope: 'main-prog', invocationId: 'p-1' });
  assert.equal(state.status, 'running');
  assert.ok(Array.isArray(state.progress));
  assert.equal(state.progress.length, 1);
  assert.equal(state.progress[0].stage, 'fetching');
  assert.match(state.progress[0].at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(state.progress[0].detail, undefined);
});

test('appendInvocationProgress: POSITIVE — two entries land in order with detail preserved', async () => {
  await seedInvocation('main-prog', 'p-2', {
    status: 'running', invocation_id: 'p-2', slug: 'a',
    started_at: new Date().toISOString(),
  });
  await appendInvocationProgress({
    parentScope: 'main-prog', invocationId: 'p-2', stage: 'step-1', detail: 'reading config',
  });
  await appendInvocationProgress({
    parentScope: 'main-prog', invocationId: 'p-2', stage: 'step-2', detail: 'writing output',
  });
  const state = await readSubagentInvocation({ parentScope: 'main-prog', invocationId: 'p-2' });
  assert.equal(state.progress.length, 2);
  assert.deepEqual(state.progress.map((p) => p.stage), ['step-1', 'step-2']);
  assert.equal(state.progress[0].detail, 'reading config');
  assert.equal(state.progress[1].detail, 'writing output');
});

test('appendInvocationProgress: EDGE — capped at MAX_PROGRESS_ENTRIES (60 → last 50, FIFO)', async () => {
  await seedInvocation('main-prog', 'p-cap', {
    status: 'running', invocation_id: 'p-cap', slug: 'a',
    started_at: new Date().toISOString(),
  });
  for (let i = 1; i <= 60; i++) {
    await appendInvocationProgress({
      parentScope: 'main-prog', invocationId: 'p-cap', stage: `stage-${i}`,
    });
  }
  const state = await readSubagentInvocation({ parentScope: 'main-prog', invocationId: 'p-cap' });
  // Bounded to 50; the oldest 10 (stage-1 … stage-10) drop off the front.
  assert.equal(state.progress.length, 50);
  assert.equal(state.progress[0].stage, 'stage-11');
  assert.equal(state.progress[49].stage, 'stage-60');
});

test('appendInvocationProgress: NEGATIVE — unknown invocation file is a silent no-op', async () => {
  let result;
  await assert.doesNotReject(async () => {
    result = await appendInvocationProgress({
      parentScope: 'main-prog', invocationId: 'never-spawned', stage: 'x',
    });
  });
  assert.equal(result, undefined);
  // Nothing was created on disk.
  const state = await readSubagentInvocation({ parentScope: 'main-prog', invocationId: 'never-spawned' });
  assert.equal(state, null);
});

test('appendInvocationProgress: NEGATIVE — terminal invocation drops the append', async () => {
  const now = new Date().toISOString();
  await seedInvocation('main-prog', 'p-done', {
    status: 'completed', invocation_id: 'p-done', slug: 'a', started_at: now,
    progress: [{ stage: 'earlier', at: now }],
    audit: { completed_at: now },
  });
  await appendInvocationProgress({
    parentScope: 'main-prog', invocationId: 'p-done', stage: 'too-late',
  });
  const state = await readSubagentInvocation({ parentScope: 'main-prog', invocationId: 'p-done' });
  // Unchanged: the completed snapshot keeps only its original progress entry.
  assert.equal(state.progress.length, 1);
  assert.equal(state.progress[0].stage, 'earlier');
});

test('appendInvocationProgress: NEGATIVE — missing args / empty stage throw clearly', async () => {
  await assert.rejects(
    appendInvocationProgress({ invocationId: 'p-1', stage: 'x' }),
    /parentScope \+ invocationId required/,
  );
  await assert.rejects(
    appendInvocationProgress({ parentScope: 'main-prog', stage: 'x' }),
    /parentScope \+ invocationId required/,
  );
  await assert.rejects(
    appendInvocationProgress({ parentScope: 'main-prog', invocationId: 'p-1', stage: '' }),
    /stage required/,
  );
});
