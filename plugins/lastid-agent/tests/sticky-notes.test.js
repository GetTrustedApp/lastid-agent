/**
 * Sticky notes — the file-anchored working/RAM memory layer (v1).
 * See docs/sticky-notes-spec.md + mem_01KSX20E.
 *
 * Phase 1 (store layer): the new `sticky` kind, its repo-relative `anchor`,
 * the JIT path lookup the Read hook uses, and the invariant that sticky notes
 * are EXCLUDED from semantic recall (they surface only via the anchor).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { MemoryStore } from '../lib/memory-store.js';
import { searchMemories } from '../lib/memory-tools.js';
import { anchorForPath } from '../lib/project-key.js';
import { memorySyncContent } from '../lib/agent-memory-publish.js';

function freshStore() {
  return new MemoryStore('test', join(tmpdir(), `sticky-${randomUUID()}.json`), {
    agentDid: 'did:lastid:agent:zTest',
    parentHumanDid: 'did:lastid:zOperator',
  });
}

const REPO = 'github.com/GetTrustedApp/lastid-agent';
const REL = 'plugins/lastid-agent/lib/memory-store.js';

function stickyInput(overrides = {}) {
  return {
    kind: 'sticky',
    tier: 'agent',
    source_kind: 'inferred',
    subject: ['sticky'],
    claim: 'left off at the KP purge; next: live reconcile',
    anchor: { repo_key: REPO, rel_path: REL },
    ...overrides,
  };
}

test('sticky note stores its repo-relative anchor (not an absolute path)', () => {
  const s = freshStore();
  const m = s.write(stickyInput());
  assert.equal(m.kind, 'sticky');
  assert.deepEqual(m.anchor, { repo_key: REPO, rel_path: REL });
});

test('stickyNotesForAnchor returns OPEN notes for the matching path, newest first', () => {
  const s = freshStore();
  const a = s.write(stickyInput({ claim: 'older note' }));
  const b = s.write(stickyInput({ claim: 'newer note' }));
  const hits = s.stickyNotesForAnchor(REPO, REL);
  assert.equal(hits.length, 2);
  assert.equal(hits[0].id, b.id); // newest first (v1 stickiness = recency)
  assert.equal(hits[1].id, a.id);
});

test('stickyNotesForAnchor: repo_key matches when both carry one; mismatch excluded; rel_path must match', () => {
  const s = freshStore();
  s.write(stickyInput());
  // Different repo (both carry a key) → excluded.
  assert.equal(s.stickyNotesForAnchor('github.com/other/repo', REL).length, 0);
  // Missing repo_key on the query side is permissive → still matches.
  assert.equal(s.stickyNotesForAnchor(null, REL).length, 1);
  // Different file → none.
  assert.equal(s.stickyNotesForAnchor(REPO, 'plugins/lastid-agent/lib/other.js').length, 0);
});

test('resolving (forget) a sticky note rips it up — no longer surfaced', () => {
  const s = freshStore();
  const m = s.write(stickyInput());
  assert.equal(s.stickyNotesForAnchor(REPO, REL).length, 1);
  s.forget(m.id); // "rip up" — soft-forget flips status off active
  assert.equal(s.stickyNotesForAnchor(REPO, REL).length, 0);
});

test('a NON-sticky memory carrying the same path is NOT surfaced by stickyNotesForAnchor', () => {
  const s = freshStore();
  s.write({ ...stickyInput(), kind: 'fact' });
  assert.equal(s.stickyNotesForAnchor(REPO, REL).length, 0);
});

// ── folder anchors (surface for anything under the folder) ─────────

test('stickyNotesForAnchor: a FOLDER-anchored sticky surfaces for any file under it', () => {
  const s = freshStore();
  const FOLDER = 'plugins/lastid-agent/lib';
  s.write(stickyInput({ anchor: { repo_key: REPO, rel_path: FOLDER }, claim: 'area note' }));
  assert.equal(s.stickyNotesForAnchor(REPO, `${FOLDER}/memory-store.js`).length, 1); // direct child
  assert.equal(s.stickyNotesForAnchor(REPO, `${FOLDER}/sub/deep.js`).length, 1); // deeper
  assert.equal(s.stickyNotesForAnchor(REPO, FOLDER).length, 1); // the folder itself (exact)
});

test('stickyNotesForAnchor: a folder anchor does NOT leak to a prefix-sharing sibling', () => {
  const s = freshStore();
  s.write(stickyInput({ anchor: { repo_key: REPO, rel_path: 'lib' }, claim: 'lib note' }));
  assert.equal(s.stickyNotesForAnchor(REPO, 'library/x.js').length, 0); // "lib" must not match "library/…"
  assert.equal(s.stickyNotesForAnchor(REPO, 'lib/x.js').length, 1); // a real file under lib does
});

test('stickyNotesForAnchor: a FILE anchor stays effectively exact (no subtree leak)', () => {
  const s = freshStore();
  s.write(stickyInput()); // anchored to the REL file
  assert.equal(s.stickyNotesForAnchor(REPO, REL).length, 1);
  assert.equal(s.stickyNotesForAnchor(REPO, 'plugins/lastid-agent/lib/other.js').length, 0);
});

test('sticky notes are EXCLUDED from semantic recall (searchMemories), facts are not', async () => {
  const s = freshStore();
  const sticky = s.write(stickyInput({ claim: 'reconcile KP purge eligibility note' }));
  const fact = s.write({
    kind: 'fact',
    tier: 'agent',
    source_kind: 'inferred',
    subject: ['reconcile'],
    claim: 'reconcile KP purge eligibility fact',
  });
  const hits = await searchMemories(s, 'reconcile KP purge eligibility', { limit: 8 });
  const ids = hits.map((h) => h.memory_id);
  assert.ok(!ids.includes(sticky.id), 'the sticky note is NOT in semantic results');
  assert.ok(ids.includes(fact.id), 'the fact IS recalled');
});

test('anchorForPath resolves a repo file to a repo-RELATIVE anchor (posix, portable)', () => {
  const self = fileURLToPath(import.meta.url);
  const a = anchorForPath(self);
  assert.ok(a && typeof a.repo_key === 'string' && a.repo_key.length > 0, 'repo_key present');
  assert.ok(!a.rel_path.startsWith('/'), 'rel_path is relative, not absolute');
  assert.ok(!a.rel_path.includes('\\'), 'rel_path uses posix separators');
  assert.ok(a.rel_path.endsWith('tests/sticky-notes.test.js'), 'rel_path points at this file');
});

test('anchorForPath on a non-repo path → null repo_key + absolute rel_path', () => {
  const a = anchorForPath('/tmp/lastid-nonrepo-xyz-0000/foo.txt');
  assert.equal(a.repo_key, null);
  assert.equal(a.rel_path, '/tmp/lastid-nonrepo-xyz-0000/foo.txt');
});

test('a sticky note round-trips its anchor through sync (memorySyncContent → applySync)', () => {
  const s = freshStore();
  const m = s.write(stickyInput());
  const content = memorySyncContent(m);
  assert.deepEqual(content.anchor, { repo_key: REPO, rel_path: REL }, 'anchor rides in synced content');
  // Simulate a sync-down on a FRESH store (another session / device / console).
  const s2 = freshStore();
  const applied = s2.applySync(
    { id: m.id, target: s2.agentDid, version: 1, status: 'active', content },
    'agent',
  );
  assert.equal(applied, true);
  assert.deepEqual(s2.get(m.id).anchor, { repo_key: REPO, rel_path: REL }, 're-hydrated anchor');
  const hits = s2.stickyNotesForAnchor(REPO, REL);
  assert.equal(hits.length, 1, 'synced-down sticky surfaces on its anchor');
  assert.equal(hits[0].id, m.id);
});
