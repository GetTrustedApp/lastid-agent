/**
 * Project-tier injection behavior (the "memories follow the work" feature).
 *
 * A project memory is scoped to one git remote (project_key) and must inject
 * ONLY when the agent is working in that repo — never for unrelated work, and
 * never leaking across repos. These tests lock that: matching repo surfaces it
 * (bedrock always, topical when relevant); a different repo or no repo excludes
 * it; global/agent memories are unaffected.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MemoryStore } from '../lib/memory-store.js';
import { retrievePacket } from '../lib/memory-retrieve.js';
import { searchMemories } from '../lib/memory-tools.js';

const IDP = 'github.com/gettrustedapp/gettrusted-idp';
const SDK = 'github.com/gettrustedapp/lastid-sdk';

const DIR = mkdtempSync(join(tmpdir(), 'lastid-projtier-'));
after(() => {
  try {
    rmSync(DIR, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
});

let n = 0;
function freshStore() {
  const s = new MemoryStore('main', join(DIR, `mem-${n++}.json`), {
    agentDid: 'did:lastid:agent:test',
    parentHumanDid: 'did:lastid:human:test',
  });
  return s;
}

function seed(store) {
  store.write({ kind: 'preference', subject: ['style'], claim: 'global topical: prefer terse answers', source_kind: 'user_explicit' });
  store.write({ kind: 'rule', subject: ['workflow'], claim: 'global bedrock: always write a regression test', source_kind: 'user_explicit', bedrock: true });
  // Project memories for two distinct repos.
  store.write({ kind: 'fact', subject: ['listener'], claim: 'IDP bedrock: the listener is the single MLS writer per scope', source_kind: 'tool_observation', tier: 'project', project_key: IDP, bedrock: true });
  store.write({ kind: 'fact', subject: ['cursor'], claim: 'IDP topical: agent-state sync advances a shared since-cursor', source_kind: 'tool_observation', tier: 'project', project_key: IDP });
  store.write({ kind: 'fact', subject: ['wasm'], claim: 'SDK bedrock: build mls-wasm via build-and-copy script', source_kind: 'tool_observation', tier: 'project', project_key: SDK, bedrock: true });
  return store;
}

// ── validation ─────────────────────────────────────────────────────

test('tier=project requires a project_key', () => {
  const s = freshStore();
  assert.throws(
    () => s.write({ kind: 'fact', subject: ['x'], claim: 'no key', source_kind: 'inferred', tier: 'project' }),
    /project_key is required/,
  );
});

test('project memory persists its project_key + null agent_did', () => {
  const s = freshStore();
  const m = s.write({ kind: 'fact', subject: ['x'], claim: 'scoped', source_kind: 'inferred', tier: 'project', project_key: IDP });
  assert.equal(m.tier, 'project');
  assert.equal(m.project_key, IDP);
  assert.equal(m.agent_did, null); // shared, not bound to one agent
});

// ── bedrock split ──────────────────────────────────────────────────

test('bedrockMemories EXCLUDES project bedrock (no dilution of unrelated work)', () => {
  const s = seed(freshStore());
  const ids = s.bedrockMemories().map((m) => m.claim);
  assert.ok(ids.some((c) => c.startsWith('global bedrock')));
  assert.ok(!ids.some((c) => c.includes('IDP bedrock')), 'project bedrock must not be in the global always-inject set');
  assert.ok(!ids.some((c) => c.includes('SDK bedrock')));
});

test('projectBedrockMemories returns only the matching repo', () => {
  const s = seed(freshStore());
  assert.deepEqual(s.projectBedrockMemories(IDP).map((m) => m.subject[0]), ['listener']);
  assert.deepEqual(s.projectBedrockMemories(SDK).map((m) => m.subject[0]), ['wasm']);
  assert.deepEqual(s.projectBedrockMemories(null), []);
});

// ── retrieval packet (the turn-start injection) ────────────────────

test('POSITIVE: retrievePacket in repo IDP injects IDP project bedrock, not SDK', async () => {
  const s = seed(freshStore());
  const { markdown } = await retrievePacket({ store: s, prompt: 'what about the listener', projectKey: IDP });
  assert.match(markdown, /IDP bedrock: the listener/);
  assert.doesNotMatch(markdown, /SDK bedrock/);
  assert.match(markdown, /global bedrock/); // global still always injects
});

test('NEGATIVE: retrievePacket with NO project injects neither repo, only global/agent', async () => {
  const s = seed(freshStore());
  const { markdown } = await retrievePacket({ store: s, prompt: 'the listener and the cursor', projectKey: null });
  assert.doesNotMatch(markdown, /IDP bedrock/);
  assert.doesNotMatch(markdown, /SDK bedrock/);
  assert.doesNotMatch(markdown, /IDP topical/);
  assert.match(markdown, /global bedrock/);
});

test('NEGATIVE: retrievePacket in repo SDK does NOT leak IDP memories', async () => {
  const s = seed(freshStore());
  const { markdown } = await retrievePacket({ store: s, prompt: 'the listener cursor mls', projectKey: SDK });
  assert.doesNotMatch(markdown, /IDP bedrock/);
  assert.doesNotMatch(markdown, /IDP topical/);
  assert.match(markdown, /SDK bedrock/);
});

// ── topical search scoping ─────────────────────────────────────────

test('searchMemories: project topical eligible only in its repo', async () => {
  const s = seed(freshStore());
  // Keyword path (no embedder): query mentions "cursor" (an IDP topical memory).
  const inIdp = await searchMemories(s, 'cursor sync', { projectKey: IDP });
  assert.ok(inIdp.some((h) => h.claim.includes('IDP topical')), 'IDP topical surfaces in IDP');

  const inSdk = await searchMemories(s, 'cursor sync', { projectKey: SDK });
  assert.ok(!inSdk.some((h) => h.claim.includes('IDP topical')), 'IDP topical must NOT surface in SDK');

  const noProject = await searchMemories(s, 'cursor sync', { projectKey: null });
  assert.ok(!noProject.some((h) => h.claim.includes('IDP topical')), 'IDP topical must NOT surface with no project');
});
