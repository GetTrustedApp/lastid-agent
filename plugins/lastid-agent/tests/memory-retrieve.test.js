/**
 * Tests for local memory retrieval / packet composition (lib/memory-retrieve.js):
 * bedrock + topical packet for UserPromptSubmit, ambient block for PreToolUse,
 * operator-store bedrock inclusion, and last_confirmed_at bumping on inject.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { MemoryStore } from '../lib/memory-store.js';
import { retrievePacket, retrieveSearchBlock } from '../lib/memory-retrieve.js';

function freshStore() {
  return new MemoryStore('test', join(tmpdir(), `mem-${randomUUID()}.json`), {
    agentDid: 'did:lastid:agent:zT',
    parentHumanDid: 'did:lastid:zH',
  });
}

test('retrievePacket: composes bedrock + topical, cites ids', async () => {
  const s = freshStore();
  const bed = s.write({
    kind: 'preference', subject: ['style'], claim: 'matt writes terse', source_kind: 'user_explicit', bedrock: true,
  });
  s.write({
    kind: 'fact', subject: ['deploy'], claim: 'use socketfirewall for npm installs', source_kind: 'user_explicit',
  });
  const { markdown, injectedIds } = await retrievePacket({ prompt: 'how to install npm packages', store: s });
  assert.match(markdown, /<lastid-memory>/);
  assert.match(markdown, /## Bedrock/);
  assert.match(markdown, /## Relevant to this turn/);
  assert.match(markdown, new RegExp(`\\[${bed.id}\\] matt writes terse`));
  assert.match(markdown, /socketfirewall/);
  assert.ok(injectedIds.includes(bed.id));
});

test('retrievePacket: empty store → empty markdown', async () => {
  const s = freshStore();
  const { markdown, injectedIds } = await retrievePacket({ prompt: 'anything', store: s });
  assert.equal(markdown, '');
  assert.equal(injectedIds.length, 0);
});

test('retrievePacket: bumps last_confirmed_at on injected bedrock', async () => {
  const s = freshStore();
  const m = s.write({ kind: 'fact', subject: ['x'], claim: 'ground truth', source_kind: 'user_explicit', bedrock: true });
  const before = s.get(m.id).last_confirmed_at;
  await new Promise((r) => setTimeout(r, 2));
  await retrievePacket({ prompt: 'unrelated', store: s });
  assert.notEqual(s.get(m.id).last_confirmed_at, before);
});

test('retrievePacket: includes operator-store bedrock memories', async () => {
  const s = freshStore();
  const operatorStore = {
    listMemories: () => [
      { id: 'mem_op1', content: { bedrock: true, claim: 'operator says never force push' } },
      { id: 'mem_op2', content: { bedrock: false, claim: 'non-bedrock, should be skipped' } },
    ],
  };
  const { markdown } = await retrievePacket({ prompt: 'x', store: s, operatorStore });
  assert.match(markdown, /\[mem_op1\] operator says never force push/);
  assert.doesNotMatch(markdown, /should be skipped/);
});

test('retrievePacket: operator non-bedrock memories surface topically (keyword)', async () => {
  const s = freshStore()
  const operatorStore = {
    listMemories: () => [
      { id: "mem_opA", content: { bedrock: false, claim: "deploy with kubernetes helm charts", subject: ["deploy"] } },
      { id: "mem_opB", content: { bedrock: true, claim: "always inject this", subject: [] } },
    ],
  }
  const { markdown } = await retrievePacket({ prompt: "kubernetes helm", store: s, operatorStore })
  assert.match(markdown, /## Relevant to this turn/)
  assert.match(markdown, /\[mem_opA\] deploy with kubernetes helm/)
  // the bedrock operator memory goes in the Bedrock section, not topical
  assert.match(markdown, /\[mem_opB\] always inject this/)
})

test('retrieveSearchBlock: ambient hits, excludes bedrock', async () => {
  const s = freshStore();
  s.write({ kind: 'fact', subject: ['deploy'], claim: 'socketfirewall scans packages', source_kind: 'user_explicit', bedrock: true });
  s.write({ kind: 'fact', subject: ['deploy'], claim: 'pnpm is the package manager', source_kind: 'user_explicit' });
  const block = await retrieveSearchBlock({ query: 'package manager', store: s, excludeBedrock: true });
  assert.match(block, /source="ambient"/);
  assert.match(block, /pnpm is the package manager/);
  assert.doesNotMatch(block, /socketfirewall/, 'bedrock excluded from ambient');
});

test('retrieveSearchBlock: nothing relevant → empty string', async () => {
  const s = freshStore();
  s.write({ kind: 'fact', subject: ['x'], claim: 'alpha', source_kind: 'inferred' });
  const block = await retrieveSearchBlock({ query: 'kubernetes helm charts', store: s });
  assert.equal(block, '');
});
