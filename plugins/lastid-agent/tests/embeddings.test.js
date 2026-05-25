/**
 * Tests for local embeddings (lib/embeddings.js).
 *
 * cosine() is pure and always tested. The model-backed tests (makeEmbedder,
 * embedMemory, semantic search) require the opt-in @xenova/transformers
 * dependency; they run when it's installed (local dev after `memory-setup`)
 * and SKIP cleanly where it isn't (CI / fresh installs), since embeddings are
 * an optional enhancement over keyword fallback.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  cosine,
  makeEmbedder,
  backfillEmbeddings,
  embeddingsInstalled,
  EMBED_DIM,
} from '../lib/embeddings.js';
import { MemoryStore } from '../lib/memory-store.js';
import { searchMemories } from '../lib/memory-tools.js';

const HAS_EMB = await embeddingsInstalled();

function freshStore() {
  return new MemoryStore('test', join(tmpdir(), `mem-${randomUUID()}.json`), {
    agentDid: 'did:a',
    parentHumanDid: 'did:h',
  });
}

// ── cosine (pure, always) ──────────────────────────────────────────

test('cosine: identical=1, orthogonal=0, mismatched length=0', () => {
  assert.ok(Math.abs(cosine([1, 0, 0], [1, 0, 0]) - 1) < 1e-9);
  assert.ok(Math.abs(cosine([1, 0], [0, 1])) < 1e-9);
  assert.equal(cosine([1, 2, 3], [1, 2]), 0);
  assert.equal(cosine([0, 0], [0, 0]), 0);
});

// ── model-backed (skip if dep absent) ──────────────────────────────

test('makeEmbedder: 384-dim + separates relevant from irrelevant', { skip: !HAS_EMB }, async () => {
  const embed = makeEmbedder();
  const q = await embed('how do I install packages safely');
  const rel = await embed('use socketfirewall to scan npm packages before install');
  const irr = await embed('the weather in paris is nice today');
  assert.equal(q.length, EMBED_DIM);
  assert.ok(cosine(q, rel) > cosine(q, irr), 'relevant scores higher than irrelevant');
  assert.ok(cosine(q, rel) > 0.2, 'relevant clears the semantic floor');
});

test('embedMemory + backfill: persists vectors on the records', { skip: !HAS_EMB }, async () => {
  const s = freshStore();
  const m = s.write({ kind: 'fact', subject: ['deploy'], claim: 'socketfirewall guards installs', source_kind: 'user_explicit' });
  assert.equal(s.get(m.id).embedding, null);
  const n = await backfillEmbeddings(s);
  assert.equal(n, 1);
  assert.equal(s.get(m.id).embedding.length, EMBED_DIM);
  assert.equal(s.get(m.id).embedding_model_version, 'all-MiniLM-L6-v2');
});

test('searchMemories: semantic match finds a paraphrase keyword would miss', { skip: !HAS_EMB }, async () => {
  const s = freshStore();
  s.write({ kind: 'fact', subject: ['deploy'], claim: 'scan dependencies for malware before installing them', source_kind: 'user_explicit' });
  s.write({ kind: 'fact', subject: ['style'], claim: 'matt likes short replies', source_kind: 'user_explicit' });
  // Query shares NO content words with the relevant claim — keyword would score 0.
  const hits = await searchMemories(s, 'supply chain security for packages', { embedder: makeEmbedder(), limit: 3 });
  assert.ok(hits.length >= 1, 'semantic search returns a hit');
  assert.match(hits[0].claim, /scan dependencies/, 'the relevant memory ranks first');
});
