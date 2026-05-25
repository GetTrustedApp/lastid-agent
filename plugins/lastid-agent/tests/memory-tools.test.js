/**
 * Tests for the memory MCP tool dispatch (lib/memory-tools.js): handleMemoryTool
 * write/draft/get/list/search/update/forget against a throwaway scope, plus the
 * keyword search ranking. The capability gate lives in mcp-server.js (the
 * existing, separately-tested mechanism); these tests exercise the tool logic
 * assuming the gate passed.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';

import {
  handleMemoryTool,
  searchMemories,
  keywordScore,
  MEMORY_TOOL_NAMES,
} from '../lib/memory-tools.js';
import { MemoryStore } from '../lib/memory-store.js';

// slot seed present so the live write-through can encrypt + sign.
const loadedAgent = {
  agentDid: 'did:lastid:agent:zTEST',
  slotSeed: Buffer.alloc(32, 7),
  vcCompact: 'vc.jwt',
  idpUrl: 'https://idp.test',
};
const claims = { sub: 'did:lastid:agent:zTEST', parent_human_did: 'did:lastid:zHUMAN' };
// Mock IdP: writes "succeed"/"fail" without touching the network.
const okFetch = async () => ({ ok: true, status: 200 });
const failFetch = async () => ({ ok: false, status: 503 });

function withScope() {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  return { scope, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function call(name, args, scope, fetchImpl = okFetch) {
  return handleMemoryTool({ name, args, scope, loadedAgent, claims, fetchImpl });
}
function body(res) {
  return JSON.parse(res.content[0].text);
}

test('MEMORY_TOOL_NAMES covers the 7 tools', () => {
  for (const n of [
    'lastid_memory_write',
    'lastid_memory_draft',
    'lastid_memory_get',
    'lastid_memory_list',
    'lastid_memory_search',
    'lastid_memory_update',
    'lastid_memory_forget',
  ]) {
    assert.ok(MEMORY_TOOL_NAMES.has(n), n);
  }
});

test('write → list → get round-trip', async () => {
  const { scope, cleanup } = withScope();
  try {
    const w = body(
      await call('lastid_memory_write', {
        kind: 'preference',
        subject: ['workflow'],
        claim: 'matt wants regression tests on every bug',
        source_kind: 'user_explicit',
      }, scope),
    );
    assert.equal(w.ok, true);
    assert.ok(w.memory.id.startsWith('mem_'));
    assert.equal(w.memory.status, 'active');
    assert.equal(w.memory.embedding, undefined, 'raw embedding not echoed to the agent');

    const list = body(await call('lastid_memory_list', {}, scope));
    assert.equal(list.memories.length, 1);

    const got = body(await call('lastid_memory_get', { id: w.memory.id }, scope));
    assert.equal(got.memory.claim, 'matt wants regression tests on every bug');
  } finally {
    cleanup();
  }
});

test('draft is not active and not listed by default', async () => {
  const { scope, cleanup } = withScope();
  try {
    const d = body(
      await call('lastid_memory_draft', {
        kind: 'fact',
        subject: ['tooling'],
        claim: 'matt uses RTK token killer',
        source_kind: 'inferred',
        source_quote: 'rtk gain',
      }, scope),
    );
    assert.equal(d.status, 'drafted');
    const list = body(await call('lastid_memory_list', {}, scope)); // status active default
    assert.equal(list.memories.length, 0);
    const drafts = body(await call('lastid_memory_list', { status: 'drafted' }, scope));
    assert.equal(drafts.memories.length, 1);
  } finally {
    cleanup();
  }
});

test('search (keyword) finds by query term and honors exclude_bedrock', async () => {
  const { scope, cleanup } = withScope();
  try {
    await call('lastid_memory_write', {
      kind: 'preference', subject: ['deploy'], claim: 'use socketfirewall for package installs',
      source_kind: 'user_explicit', bedrock: true,
    }, scope);
    await call('lastid_memory_write', {
      kind: 'fact', subject: ['testing'], claim: 'jest runs via npm test for global mocks',
      source_kind: 'user_explicit',
    }, scope);

    const hits = body(await call('lastid_memory_search', { query: 'how do I install packages safely' }, scope));
    assert.ok(hits.hits.length >= 1);
    assert.ok(hits.hits.some((h) => /socketfirewall/.test(h.claim)));

    const noBedrock = body(
      await call('lastid_memory_search', { query: 'install packages', exclude_bedrock: true }, scope),
    );
    assert.ok(!noBedrock.hits.some((h) => /socketfirewall/.test(h.claim)), 'bedrock excluded');
  } finally {
    cleanup();
  }
});

test('update changes claim; forget soft-deletes', async () => {
  const { scope, cleanup } = withScope();
  try {
    const w = body(await call('lastid_memory_write', {
      kind: 'decision', subject: ['arch'], claim: 'use MLS for transport',
      source_kind: 'user_explicit',
    }, scope));
    const u = body(await call('lastid_memory_update', {
      id: w.memory.id, claim: 'use MLS for real-time transport', reason: 'clarified',
    }, scope));
    assert.equal(u.memory.claim, 'use MLS for real-time transport');

    const f = body(await call('lastid_memory_forget', { id: w.memory.id, reason: 'obsolete' }, scope));
    assert.equal(f.ok, true);
    const got = body(await call('lastid_memory_get', { id: w.memory.id }, scope));
    assert.equal(got.memory.status, 'forgotten');
  } finally {
    cleanup();
  }
});

test('get/update/forget on a missing id return an error result', async () => {
  const { scope, cleanup } = withScope();
  try {
    const g = await call('lastid_memory_get', { id: 'mem_NOPE' }, scope);
    assert.equal(g.isError, true);
    const u = await call('lastid_memory_update', { id: 'mem_NOPE', reason: 'x' }, scope);
    assert.equal(u.isError, true);
  } finally {
    cleanup();
  }
});

test('write validation surfaces as an error result (not a throw)', async () => {
  const { scope, cleanup } = withScope();
  try {
    const r = await call('lastid_memory_write', { kind: 'fact', subject: [], claim: '', source_kind: 'user_explicit' }, scope);
    assert.equal(r.isError, true);
    assert.match(body(r).error, /subject|claim/);
  } finally {
    cleanup();
  }
});

// ── ranking helpers ────────────────────────────────────────────────

// ── live write-through: IdP is authoritative, rollback on failure ──

test('LIVE: write fails when the IdP write fails — nothing kept locally', async () => {
  const { scope, cleanup } = withScope();
  try {
    const r = await call('lastid_memory_write', {
      kind: 'fact', subject: ['x'], claim: 'should not persist', source_kind: 'user_explicit',
    }, scope, failFetch);
    assert.equal(r.isError, true);
    assert.match(body(r).error, /NOT saved/);
    const list = body(await call('lastid_memory_list', {}, scope));
    assert.equal(list.memories.length, 0, 'rolled back — no local-only copy');
  } finally {
    cleanup();
  }
});

test('LIVE: update rolls back to the prior value when the IdP write fails', async () => {
  const { scope, cleanup } = withScope();
  try {
    const w = body(await call('lastid_memory_write', { kind: 'fact', subject: ['x'], claim: 'original', source_kind: 'user_explicit' }, scope));
    const u = await call('lastid_memory_update', { id: w.memory.id, claim: 'changed', reason: 'r' }, scope, failFetch);
    assert.equal(u.isError, true);
    const got = body(await call('lastid_memory_get', { id: w.memory.id }, scope));
    assert.equal(got.memory.claim, 'original', 'reverted on failed server write');
  } finally {
    cleanup();
  }
});

test('LIVE: forget does NOT drop locally when the IdP revoke fails', async () => {
  const { scope, cleanup } = withScope();
  try {
    const w = body(await call('lastid_memory_write', { kind: 'fact', subject: ['x'], claim: 'keep me', source_kind: 'user_explicit' }, scope));
    const f = await call('lastid_memory_forget', { id: w.memory.id, reason: 'r' }, scope, failFetch);
    assert.equal(f.isError, true);
    const got = body(await call('lastid_memory_get', { id: w.memory.id }, scope));
    assert.equal(got.memory.status, 'active', 'still active — revoke never reached the server');
  } finally {
    cleanup();
  }
});

test('keywordScore: fraction of query terms present', () => {
  const m = { claim: 'use socketfirewall for npm installs', subject: ['deploy'] };
  assert.ok(keywordScore('socketfirewall installs', m) === 1);
  assert.ok(keywordScore('kubernetes helm', m) === 0);
});

test('searchMemories: ranks higher-overlap first', async () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  try {
    const store = new MemoryStore(scope, undefined, { agentDid: 'did:a', parentHumanDid: 'did:h' });
    store.write({ kind: 'fact', subject: ['x'], claim: 'alpha beta gamma', source_kind: 'inferred' });
    store.write({ kind: 'fact', subject: ['x'], claim: 'alpha only', source_kind: 'inferred' });
    const hits = await searchMemories(store, 'alpha beta', { limit: 5 });
    assert.equal(hits[0].claim, 'alpha beta gamma', 'more overlap ranks first');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
