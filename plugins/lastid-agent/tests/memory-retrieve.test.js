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
import {
  retrievePacket,
  retrieveSearchBlock,
  gateInjectedHits,
  INJECT_FLOOR,
  INJECT_GAP,
} from '../lib/memory-retrieve.js';

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
  assert.match(markdown, new RegExp(`\\[${bed.id}\\] \\(agent\\) matt writes terse`));
  assert.match(markdown, /socketfirewall/);
  assert.ok(injectedIds.includes(bed.id));
});

test('retrievePacket: labels each line with its tier so collective (global/project) vs private (agent) is legible', async () => {
  const s = freshStore();
  const REPO = 'github.com/acme/widgets';
  s.write({ kind: 'fact', subject: ['install'], claim: 'use pnpm for installs', source_kind: 'user_explicit', tier: 'global', bedrock: true });
  s.write({ kind: 'fact', subject: ['build'], claim: 'this repo builds with turbo', source_kind: 'user_explicit', tier: 'project', project_key: REPO, bedrock: true });
  const { markdown } = await retrievePacket({ prompt: 'how do installs work', store: s, projectKey: REPO });
  assert.match(markdown, /\(global\)/, 'global ground truth tagged');
  assert.match(markdown, /\(project\)/, 'this repo\'s ground truth tagged');
});

test('retrievePacket: empty store → empty markdown', async () => {
  const s = freshStore();
  const { markdown, injectedIds } = await retrievePacket({ prompt: 'anything', store: s });
  assert.equal(markdown, '');
  assert.equal(injectedIds.length, 0);
});

test('retrievePacket: surfaces THIS repo\'s project draft, marked "(draft)", with fetch-full guidance', async () => {
  const s = freshStore();
  const REPO = 'github.com/lastid/lastid.co';
  s.draft({
    kind: 'decision', subject: ['vault'], claim: 'handle envelope is HPKE base mode',
    source_kind: 'inferred', tier: 'project', project_key: REPO,
  });
  const { markdown } = await retrievePacket({ prompt: 'how does the handle envelope work', store: s, projectKey: REPO });
  assert.match(markdown, /handle envelope is HPKE base mode/);
  assert.match(markdown, /\(project, draft\)/); // tier + unverified marker
  assert.match(markdown, /lastid_memory_get/); // told it can fetch the full memory by id
});

test('retrievePacket: a project draft for a DIFFERENT repo is not surfaced', async () => {
  const s = freshStore();
  s.draft({
    kind: 'decision', subject: ['vault'], claim: 'a different repos draft secret',
    source_kind: 'inferred', tier: 'project', project_key: 'github.com/lastid/other-repo',
  });
  const { markdown } = await retrievePacket({ prompt: 'draft secret', store: s, projectKey: 'github.com/lastid/lastid.co' });
  assert.equal(markdown.includes('a different repos draft secret'), false);
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
  assert.match(markdown, /\[mem_op1\] \(operator\) operator says never force push/);
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
  assert.match(markdown, /\[mem_opA\] \(operator\) deploy with kubernetes helm/)
  // the bedrock operator memory goes in the Bedrock section, not topical
  assert.match(markdown, /\[mem_opB\] \(operator\) always inject this/)
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

// ── Injection relevance gate (gateInjectedHits) ──────────────────────────────

test('gateInjectedHits: empty / unscored input → empty', () => {
  assert.deepEqual(gateInjectedHits([]), []);
  assert.deepEqual(gateInjectedHits(undefined), []);
  assert.deepEqual(gateInjectedHits([{ memory_id: 'a' }]), []); // no numeric score
});

test('gateInjectedHits: a strong cluster is kept whole', () => {
  const hits = [{ score: 0.5 }, { score: 0.42 }, { score: 0.4 }]; // all within INJECT_GAP of top
  assert.equal(gateInjectedHits(hits).length, 3);
});

test('gateInjectedHits: a weak tail riding behind one strong hit is dropped', () => {
  // 0.30 clears the floor but is > INJECT_GAP below the 0.5 top → cut.
  const kept = gateInjectedHits([{ score: 0.5, memory_id: 'top' }, { score: 0.3, memory_id: 'tail' }]);
  assert.equal(kept.length, 1);
  assert.equal(kept[0].memory_id, 'top');
});

test('gateInjectedHits: an all-weak set (top below the floor) injects nothing', () => {
  // The "meta turn" case — everything is only loosely on-topic.
  assert.deepEqual(gateInjectedHits([{ score: 0.25 }, { score: 0.24 }]), []);
});

test('gateInjectedHits: a hit exactly at the floor is kept', () => {
  assert.equal(gateInjectedHits([{ score: INJECT_FLOOR }]).length, 1);
  // sanity: the constants are the documented values (tuned 2026-05-27 from
  // live observation — bumped floor 0.28→0.30 and tightened gap 0.12→0.10
  // to cut the thin 0.29-0.34 tail that still survived the original gate).
  assert.equal(INJECT_FLOOR, 0.3);
  assert.equal(INJECT_GAP, 0.1);
});

// ── Compact topical/ambient rendering ────────────────────────────────────────

test('retrievePacket: a topical hit WITH a summary renders summary-only (full claim omitted)', async () => {
  const s = freshStore();
  s.write({
    kind: 'fact', subject: ['deploy'], source_kind: 'user_explicit',
    claim: 'the kubernetes helm pipeline rolls out via argocd using a gitops_unique_marker flow',
    summary: 'deploy via argocd',
  });
  const { markdown } = await retrievePacket({ prompt: 'kubernetes helm', store: s });
  assert.match(markdown, /## Relevant to this turn/);
  assert.match(markdown, /deploy via argocd/, 'short summary is shown');
  assert.doesNotMatch(markdown, /gitops_unique_marker/, 'full claim body is not injected for topical');
});

test('retrievePacket: a long topical claim with NO summary is truncated with an ellipsis', async () => {
  const s = freshStore();
  s.write({
    kind: 'fact', subject: ['k8s'], source_kind: 'user_explicit',
    claim: `kubernetes ${'y'.repeat(300)} END_OF_CLAIM_MARKER`, // > the topical cap
  });
  const { markdown } = await retrievePacket({ prompt: 'kubernetes', store: s });
  assert.match(markdown, /…/, 'truncation ellipsis present');
  assert.doesNotMatch(markdown, /END_OF_CLAIM_MARKER/, 'tail of the long claim is cut');
});

test('retrievePacket: a weak topical hit is gated out (bedrock still injects)', async () => {
  const s = freshStore();
  s.write({ kind: 'fact', subject: ['x'], claim: 'always inject this ground truth', source_kind: 'user_explicit', bedrock: true });
  // 1 of 5 query terms present → keyword score 0.2, below INJECT_FLOOR.
  s.write({ kind: 'fact', subject: ['x'], claim: 'alpha only here, nothing else', source_kind: 'inferred' });
  const { markdown } = await retrievePacket({ prompt: 'alpha beta gamma delta epsilon', store: s });
  assert.match(markdown, /## Bedrock/);
  assert.match(markdown, /always inject this ground truth/);
  assert.doesNotMatch(markdown, /## Relevant to this turn/, 'weak topical set → no topical section');
  assert.doesNotMatch(markdown, /alpha only here/);
});

test('retrieveSearchBlock: hit with a summary renders summary-only', async () => {
  const s = freshStore();
  s.write({
    kind: 'fact', subject: ['deploy'], source_kind: 'user_explicit',
    claim: 'pnpm install runs behind socketfirewall_unique_marker scanning every package',
    summary: 'pnpm is the package manager',
  });
  const block = await retrieveSearchBlock({ query: 'package manager', store: s, excludeBedrock: true });
  assert.match(block, /pnpm is the package manager/);
  assert.doesNotMatch(block, /socketfirewall_unique_marker/, 'full claim omitted for ambient rows');
});
