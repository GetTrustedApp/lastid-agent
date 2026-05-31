/**
 * Tests for the local agent memory store (lib/memory-store.js) — the JS port
 * of the desktop Rust MemoryStore: CRUD, defaults, validation, the draft
 * lifecycle, filtering/sorting, sensitivity escalation, and expiry.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  MemoryStore,
  escalateSensitivity,
  memoryEmbeddingText,
  isExpired,
} from '../lib/memory-store.js';

function freshStore() {
  return new MemoryStore('test', join(tmpdir(), `mem-${randomUUID()}.json`), {
    agentDid: 'did:lastid:agent:zTEST',
    parentHumanDid: 'did:lastid:zHUMAN',
  });
}

const baseWrite = {
  kind: 'preference',
  subject: ['workflow'],
  claim: 'matt prefers terse answers',
  source_kind: 'user_explicit',
};

// ── write + defaults ───────────────────────────────────────────────

test('write: defaults confidence by source_kind, decay by kind, ids + timestamps', () => {
  const s = freshStore();
  const m = s.write(baseWrite);
  assert.ok(m.id.startsWith('mem_'));
  assert.equal(m.status, 'active');
  assert.equal(m.tier, 'agent'); // default
  assert.equal(m.agent_did, 'did:lastid:agent:zTEST');
  assert.equal(m.parent_human_did, 'did:lastid:zHUMAN');
  assert.equal(m.confidence, 0.95); // user_explicit
  assert.equal(m.decay, 'slow'); // preference
  assert.deepEqual(m.allowed_uses, ['reasoning', 'style']);
  assert.equal(m.bedrock, false);
  assert.ok(m.created_at && m.updated_at && m.last_confirmed_at);
  assert.equal(m.embedding, null);
});

test('write: global tier leaves agent_did null', () => {
  const s = freshStore();
  const m = s.write({ ...baseWrite, tier: 'global', bedrock: true });
  assert.equal(m.tier, 'global');
  assert.equal(m.agent_did, null);
  assert.equal(m.bedrock, true);
});

// ── claim sanitization (the </claim> tool-framing leak) ────────────

test('write: strips a leaked tool-call framing tail from the claim (the </claim> glitch)', () => {
  const s = freshStore();
  const m = s.write({
    ...baseWrite,
    claim: 'Real content here.</claim>\n<parameter name="source_kind">conversation',
  });
  assert.equal(m.claim, 'Real content here.');
});

test('write: strips a leaked <parameter name= tail with no closing tag', () => {
  const s = freshStore();
  const m = s.write({ ...baseWrite, claim: 'Just the claim. <parameter name="summary">junk' });
  assert.equal(m.claim, 'Just the claim.');
});

test('write: leaves a clean claim untouched', () => {
  const s = freshStore();
  const clean = 'A normal claim with no markup at all.';
  assert.equal(s.write({ ...baseWrite, claim: clean }).claim, clean);
});

test('update: sanitizes a leaked framing tail on a claim edit too', () => {
  const s = freshStore();
  const m = s.write(baseWrite);
  const u = s.update(m.id, { claim: 'Edited claim.</claim>\n<parameter name="summary">x' });
  assert.equal(u.claim, 'Edited claim.');
});

test('write: confidence default for inferred/tool_observation', () => {
  const s = freshStore();
  assert.equal(s.write({ ...baseWrite, source_kind: 'inferred' }).confidence, 0.5);
  assert.equal(s.write({ ...baseWrite, source_kind: 'tool_observation' }).confidence, 0.7);
  assert.equal(s.write({ ...baseWrite, source_kind: 'imported' }).confidence, 0.6);
});

test('write: validation rejects empty subject / claim / bad kind', () => {
  const s = freshStore();
  assert.throws(() => s.write({ ...baseWrite, subject: [] }), /subject/);
  assert.throws(() => s.write({ ...baseWrite, claim: '   ' }), /claim/);
  assert.throws(() => s.write({ ...baseWrite, kind: 'nonsense' }), /kind/);
  assert.throws(() => s.write({ ...baseWrite, source_kind: 'nope' }), /source_kind/);
  assert.throws(() => s.write({ ...baseWrite, claim: 'x'.repeat(4001) }), /4000/);
});

test('write: an over-long summary is CLAMPED to 600, never rejected (footgun fix)', () => {
  const s = freshStore();
  // 700-char summary must NOT throw — it's an optional convenience field.
  const m = s.write({ ...baseWrite, summary: 'y'.repeat(700) });
  assert.equal(m.summary.length, 600, 'summary clamped to 600');
});

test('update: an over-long summary is CLAMPED, not rejected', () => {
  const s = freshStore();
  const m = s.write(baseWrite);
  const u = s.update(m.id, { summary: 'z'.repeat(900) });
  assert.equal(u.summary.length, 600, 'updated summary clamped to 600');
  // a whitespace-only summary clears it (not stored)
  const u2 = s.update(m.id, { summary: '   ' });
  assert.equal(u2.summary, undefined);
});

// ── sensitivity escalation ─────────────────────────────────────────

test('escalateSensitivity: raises to high on credential-ish content, never downgrades', () => {
  assert.equal(escalateSensitivity('low', 'my api key is abc'), 'high');
  assert.equal(escalateSensitivity('low', 'remember the password is hunter2'), 'high');
  assert.equal(escalateSensitivity('restricted', 'nothing secret'), 'restricted'); // no downgrade
  assert.equal(escalateSensitivity('low', 'just a normal preference'), 'low');
});

test('write: auto-escalates sensitivity from the claim', () => {
  const s = freshStore();
  const m = s.write({ ...baseWrite, claim: 'the prod database password is set in vault', sensitivity: 'low' });
  assert.equal(m.sensitivity, 'high');
});

// ── draft lifecycle ────────────────────────────────────────────────

test('draft: status=drafted, excluded from active/bedrock', () => {
  const s = freshStore();
  const d = s.draft({ ...baseWrite, bedrock: true });
  assert.equal(d.status, 'drafted');
  assert.equal(s.activeMemories().length, 0);
  assert.equal(s.bedrockMemories().length, 0);
});

test('promoteDraft: drafted → active; rejectDraft → forgotten', () => {
  const s = freshStore();
  const d = s.draft(baseWrite);
  const p = s.promoteDraft(d.id);
  assert.equal(p.status, 'active');
  assert.equal(s.activeMemories().length, 1);

  const d2 = s.draft(baseWrite);
  const r = s.rejectDraft(d2.id);
  assert.equal(r.status, 'forgotten');
  assert.equal(s.promoteDraft(d2.id), null); // not draftable anymore
});

// ── update ─────────────────────────────────────────────────────────

test('update: claim change invalidates embedding + bumps updated_at', async () => {
  const s = freshStore();
  const m = s.write(baseWrite);
  m.embedding = [0.1, 0.2];
  m.embedding_model_version = 'all-MiniLM-L6-v2';
  s.save();
  const before = m.updated_at;
  await new Promise((r) => setTimeout(r, 2));
  const u = s.update(m.id, { claim: 'matt prefers VERY terse answers' });
  assert.equal(u.claim, 'matt prefers VERY terse answers');
  assert.equal(u.embedding, null, 'embedding cleared on claim change');
  assert.notEqual(u.updated_at, before);
});

test('update: status only accepts active|deprecated (not forgotten/drafted)', () => {
  const s = freshStore();
  const m = s.write(baseWrite);
  s.update(m.id, { status: 'forgotten' });
  assert.equal(s.get(m.id).status, 'active', 'forgotten not allowed via update');
  s.update(m.id, { status: 'deprecated' });
  assert.equal(s.get(m.id).status, 'deprecated');
});

// ── forget ─────────────────────────────────────────────────────────

test('forget: soft keeps the row (forgotten), hard wipes it', () => {
  const s = freshStore();
  const a = s.write(baseWrite);
  s.forget(a.id);
  assert.equal(s.get(a.id).status, 'forgotten');
  const b = s.write(baseWrite);
  s.forget(b.id, { hard: true });
  assert.equal(s.get(b.id), null);
});

// ── list ───────────────────────────────────────────────────────────

test('list: filters by kind/bedrock/subject + sorts by confidence', () => {
  const s = freshStore();
  s.write({ ...baseWrite, kind: 'fact', claim: 'c1', source_kind: 'inferred' }); // conf .5
  s.write({ ...baseWrite, kind: 'fact', claim: 'c2', source_kind: 'user_explicit', bedrock: true }); // conf .95
  s.write({ ...baseWrite, kind: 'decision', claim: 'c3', subject: ['arch'] });
  const facts = s.list({ kinds: ['fact'] });
  assert.equal(facts.length, 2);
  assert.equal(facts[0].claim, 'c2', 'higher confidence first');
  assert.equal(s.list({ bedrock_only: true }).length, 1);
  assert.equal(s.list({ subject_includes: ['arch'] }).length, 1);
  assert.equal(s.list({ kinds: ['fact'], limit: 1 }).length, 1);
});

test('list: sensitivity_max gates restricted out', () => {
  const s = freshStore();
  s.write({ ...baseWrite, claim: 'the api key is sk-xyz' }); // → high
  s.write({ ...baseWrite, claim: 'plain preference' }); // low
  assert.equal(s.list({ sensitivity_max: 'low' }).length, 1);
  assert.equal(s.list({ sensitivity_max: 'high' }).length, 2);
});

// ── expiry ─────────────────────────────────────────────────────────

test('expiry: expired active memory drops out of active/bedrock', () => {
  const s = freshStore();
  const past = new Date(Date.now() - 1000).toISOString();
  const m = s.write({ ...baseWrite, bedrock: true, expires_at: past });
  assert.ok(isExpired(m));
  assert.equal(s.activeMemories().length, 0);
  assert.equal(s.bedrockMemories().length, 0);
});

// ── persistence ────────────────────────────────────────────────────

test('persistence: reload restores records', () => {
  const path = join(tmpdir(), `mem-${randomUUID()}.json`);
  const s1 = new MemoryStore('test', path, { agentDid: 'did:a', parentHumanDid: 'did:h' });
  const m = s1.write(baseWrite);
  const s2 = new MemoryStore('test', path);
  assert.equal(s2.get(m.id).claim, baseWrite.claim);
});

// ── embedding text ─────────────────────────────────────────────────

test('memoryEmbeddingText: claim + summary + subject tags', () => {
  const t = memoryEmbeddingText({ claim: 'C', summary: 'S', subject: ['a', 'b'] });
  assert.equal(t, 'C\nS\na, b');
  assert.equal(memoryEmbeddingText({ claim: 'C', subject: [] }), 'C');
});

// ── usableDrafts: the opt-out draft model (used immediately, marked) ─────

const REPO = 'github.com/lastid/lastid.co';

test('usableDrafts: own agent draft + this-repo project draft surface; other-repo + global drafts do not', () => {
  const s = freshStore();
  const a = s.draft({ ...baseWrite, claim: 'my agent note' }); // agent tier (default)
  const p = s.draft({ ...baseWrite, claim: 'repo note', tier: 'project', project_key: REPO });
  const other = s.draft({ ...baseWrite, claim: 'other repo', tier: 'project', project_key: 'github.com/lastid/other' });
  const g = s.draft({ ...baseWrite, claim: 'global note', tier: 'global' }); // high bar — stays gated

  const ids = s.usableDrafts(REPO).map((m) => m.id).sort();
  assert.deepEqual(ids, [a.id, p.id].sort());
  assert.equal(s.usableDrafts(REPO).some((m) => m.id === other.id), false, 'other repo excluded');
  assert.equal(s.usableDrafts(REPO).some((m) => m.id === g.id), false, 'global draft stays review-gated');
});

test('usableDrafts: active, forgotten, and expired drafts are all excluded', () => {
  const s = freshStore();
  const live = s.draft({ ...baseWrite, claim: 'live draft' });
  const exp = s.draft({ ...baseWrite, claim: 'expired', expires_at: '2000-01-01T00:00:00Z' });
  const rej = s.draft({ ...baseWrite, claim: 'rejected' });
  s.rejectDraft(rej.id); // → forgotten
  s.write({ ...baseWrite, claim: 'active, not a draft' });
  assert.deepEqual(s.usableDrafts(null).map((m) => m.id), [live.id]);
  assert.equal(exp.status, 'drafted'); // still drafted, just expired → excluded by isExpired
});
