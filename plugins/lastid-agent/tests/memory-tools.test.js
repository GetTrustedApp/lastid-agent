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

// REGRESSION (project_root_seed stale-bundle bug): a long-lived MCP server
// cached a pre-reprovision agent bundle with projectRootSeed=null, so every
// project-tier write failed at publishAgentMemory's seed guard and surfaced the
// misleading generic "server write failed" — which read like an IdP problem.
// The fix: mcp-server reloads the bundle when the seed is missing, and the tool
// refuses a seedless project write with the REAL reason. These lock the refusal.
test('REGRESSION: project-tier write WITHOUT a project_root_seed refuses with the real reason', async () => {
  const { scope, cleanup } = withScope();
  try {
    const res = await call('lastid_memory_draft', {
      kind: 'fact', subject: ['x'], claim: 'c', source_kind: 'inferred',
      tier: 'project', project_key: 'github.com/acme/widgets',
    }, scope);
    assert.equal(res.isError, true);
    const b = body(res);
    assert.match(b.error, /project_root_seed/);
    assert.doesNotMatch(b.error, /server write failed/); // not the misleading generic one
  } finally {
    cleanup();
  }
});

test('a project-tier write WITH a project_root_seed passes the seed guard and proceeds', async () => {
  const { scope, cleanup } = withScope();
  const seeded = { ...loadedAgent, projectRootSeed: Buffer.alloc(32, 9) };
  try {
    const res = await handleMemoryTool({
      name: 'lastid_memory_write',
      args: { kind: 'fact', subject: ['x'], claim: 'c', source_kind: 'inferred', tier: 'project', project_key: 'github.com/acme/widgets' },
      scope, loadedAgent: seeded, claims, fetchImpl: okFetch,
    });
    assert.equal(res.isError ?? false, false);
    assert.equal(body(res).ok, true);
  } finally {
    cleanup();
  }
});

// REGRESSION (made-up repos / bifurcation): the agent used to supply project_key
// and HALLUCINATED it (github.com/LastID/lastid.co vs the real
// github.com/GetTrustedApp/lastid.co); the old "pass project_key" error invited
// it to invent one on retry. The repo MUST be tool-derived from the filesystem
// (the git remote), never the agent. These lock that.
test('REGRESSION: an agent-supplied project_key is IGNORED — the repo is derived, never the agent', async () => {
  const { scope, cleanup } = withScope();
  const seeded = { ...loadedAgent, projectRootSeed: Buffer.alloc(32, 9) };
  try {
    const res = await handleMemoryTool({
      name: 'lastid_memory_draft',
      args: {
        kind: 'decision', subject: ['vault'], claim: 'handle envelope is HPKE base mode',
        source_kind: 'inferred', tier: 'project',
        project_key: 'github.com/LastID/lastid.co', // ← the agent's HALLUCINATED repo
      },
      scope, loadedAgent: seeded, claims, fetchImpl: okFetch,
      resolveRepo: () => 'github.com/gettrustedapp/lastid.co', // the REAL git remote
    });
    assert.equal(res.isError ?? false, false);
    const b = body(res);
    assert.equal(b.memory.tier, 'project');
    assert.equal(b.memory.project_key, 'github.com/gettrustedapp/lastid.co', 'derived repo wins');
    assert.notEqual(b.memory.project_key, 'github.com/LastID/lastid.co', 'made-up repo never stored');
  } finally {
    cleanup();
  }
});

test('repo work with NO explicit tier defaults to project, scoped to the DERIVED repo', async () => {
  const { scope, cleanup } = withScope();
  const seeded = { ...loadedAgent, projectRootSeed: Buffer.alloc(32, 9) };
  try {
    const res = await handleMemoryTool({
      name: 'lastid_memory_draft',
      args: { kind: 'fact', subject: ['x'], claim: 'a repo fact', source_kind: 'inferred' }, // no tier, no project_key
      scope, loadedAgent: seeded, claims, fetchImpl: okFetch,
      resolveRepo: () => 'github.com/gettrustedapp/lastid.co',
    });
    const b = body(res);
    assert.equal(b.memory.tier, 'project');
    assert.equal(b.memory.project_key, 'github.com/gettrustedapp/lastid.co');
  } finally {
    cleanup();
  }
});

test('tier=project with NO repo in context refuses WITHOUT inviting a made-up key', async () => {
  const { scope, cleanup } = withScope();
  const seeded = { ...loadedAgent, projectRootSeed: Buffer.alloc(32, 9) };
  try {
    const res = await handleMemoryTool({
      name: 'lastid_memory_draft',
      args: { kind: 'fact', subject: ['x'], claim: 'c', source_kind: 'inferred', tier: 'project' },
      scope, loadedAgent: seeded, claims, fetchImpl: okFetch,
      resolveRepo: () => null, // no repo derivable from the filesystem
    });
    assert.equal(res.isError, true);
    const b = body(res);
    assert.match(b.error, /no repo is in context/);
    assert.doesNotMatch(b.error, /pass project_key/); // must NOT tell the agent to supply one
  } finally {
    cleanup();
  }
});

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

test('searchMemories: includeDrafts surfaces a draft (tagged), excluded by default', async () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  try {
    const store = new MemoryStore(scope, undefined, { agentDid: 'did:a', parentHumanDid: 'did:h' });
    store.draft({ kind: 'fact', subject: ['x'], claim: 'kafka topic naming convention', source_kind: 'inferred' });
    // Default: drafts are NOT in topical search.
    assert.equal((await searchMemories(store, 'kafka topic', { limit: 5 })).length, 0);
    // Opt-in: the draft surfaces, tagged so the renderer marks it.
    const hits = await searchMemories(store, 'kafka topic', { limit: 5, includeDrafts: true });
    assert.equal(hits.length, 1);
    assert.equal(hits[0].claim, 'kafka topic naming convention');
    assert.equal(hits[0].draft, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
