/**
 * The injected memory guidance must make LastID memory the PREFERRED store and
 * actively steer the agent away from recording durable facts in markdown files
 * (the runtime's own memory prompt would otherwise encourage MEMORY.md/CLAUDE.md).
 * These lock the load-bearing phrasing so a future edit can't quietly drop it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  memoryGuidanceLines,
  hostMemoryWritePath,
  hostMemoryWriteWarning,
} from '../lib/memory-guidance.js';

const text = () => memoryGuidanceLines().join('\n');

test('leads with the action: save to the memory tools, not files', () => {
  const t = text();
  // The very first content line is a verb-first instruction (per the lead-with-
  // a-verb rule), naming the tools.
  const firstContent = memoryGuidanceLines().find((l) => l.trim().length > 0 && !l.startsWith('#'));
  assert.match(firstContent, /^Save /);
  assert.match(t, /lastid_memory_write/);
  assert.match(t, /lastid_memory_draft/);
});

test('explicitly steers OFF markdown-file memory', () => {
  const t = text();
  assert.match(t, /NOT to MEMORY\.md/);
  assert.match(t, /CLAUDE\.md/);
  assert.match(t, /markdown\/notes file/);
  // And the corrective nudge for the failure mode.
  assert.match(t, /about to record something durable in a file, write it\s+here instead/);
});

test('names the why as support (provable, synced, governed, injected)', () => {
  const t = text();
  assert.match(t, /cryptographically provable/);
  assert.match(t, /synced to every device and session/);
  assert.match(t, /governed by your operator/);
  assert.match(t, /auto-injected/);
});

test('documents all three tiers incl. the new project tier', () => {
  const t = text();
  assert.match(t, /`agent` \(default\)/);
  assert.match(t, /`project` — shared with all your operator's agents/);
  assert.match(t, /injected only when\s+you're working in that repo/);
  assert.match(t, /`global` — all the operator's agents/);
  assert.match(t, /high bar/);
});

test('preserves the write-vs-draft distinction', () => {
  const t = text();
  assert.match(t, /EXPLICITLY asked you to/);
  assert.match(t, /YOU inferred something durable/);
  assert.match(t, /source_quote/);
});

test('asserts precedence over the host file memory', () => {
  const t = text();
  assert.match(t, /machine-local scratch/i);
  assert.match(t, /never LastID/i);
  assert.match(t, /THIS WINS/);
});

test('makes drafting the reflex for inferred durable facts', () => {
  const t = text();
  assert.match(t, /REFLEX/);
  assert.match(t, /every time/);
});

test('makes CURATION (search → update → forget) a reflex, not just collection', () => {
  const t = text();
  assert.match(t, /CURATE, don't collect/);
  // Names the curation tools the agent must use, not just write/draft.
  assert.match(t, /lastid_memory_search/);
  assert.match(t, /lastid_memory_update/);
  assert.match(t, /lastid_memory_forget/);
  // Search-before-write, and edit the canonical memory rather than duplicate it.
  assert.match(t, /BEFORE every write\/draft/);
  assert.match(t, /do NOT write a parallel near-duplicate/);
  // Fix-or-forget a now-stale memory in the SAME turn (the reported failure mode).
  assert.match(t, /now wrong or\s+stale/);
  assert.match(t, /SAME\s+turn/);
});

test('forbids storing transient task state as durable memory', () => {
  const t = text();
  assert.match(t, /NEVER store transient TASK STATE/);
  assert.match(t, /stable fact\/decision\/rule/);
});

test('nudges ToolSearch to close the tool-loading friction gap', () => {
  const t = text();
  assert.match(t, /ToolSearch/);
});

// ── host file-memory write warning (warn, never block) ─────────────

const MEM = '/Users/matt/.claude/projects/-Users-matt/memory/foo.md';
const MEM_INDEX = '/Users/matt/.claude/projects/-Users-matt/memory/MEMORY.md';
const REPO_FILE = '/Users/matt/Documents/GitHub/LastID/lastid.co/src/lib/x.ts';

test('flags a Write to the host memory dir + names the LastID tool', () => {
  assert.equal(hostMemoryWritePath('Write', { file_path: MEM }), MEM);
  const w = hostMemoryWriteWarning('Write', { file_path: MEM });
  assert.ok(w);
  assert.match(w, /lastid_memory_draft/);
  assert.match(w, /Proceeding with the write/); // it WARNS, does not block
});

test('flags Edit/MultiEdit/NotebookEdit to the host memory store', () => {
  assert.ok(hostMemoryWriteWarning('Edit', { file_path: MEM_INDEX }));
  assert.ok(hostMemoryWriteWarning('MultiEdit', { file_path: MEM }));
  assert.ok(hostMemoryWriteWarning('NotebookEdit', { notebook_path: MEM.replace('.md', '.ipynb') }));
});

test('does NOT flag normal repo files, .claude config, CLAUDE.md, or non-write tools', () => {
  assert.equal(hostMemoryWritePath('Write', { file_path: REPO_FILE }), null);
  // Under .claude but not the memory store.
  assert.equal(hostMemoryWritePath('Write', { file_path: '/Users/matt/.claude/settings.json' }), null);
  // CLAUDE.md is legit project instructions, not a memory record — left alone.
  assert.equal(hostMemoryWritePath('Edit', { file_path: '/Users/matt/Documents/GitHub/LastID/CLAUDE.md' }), null);
  // Non-write tools and missing paths.
  assert.equal(hostMemoryWritePath('Bash', { command: 'echo hi' }), null);
  assert.equal(hostMemoryWritePath('Write', {}), null);
  assert.equal(hostMemoryWriteWarning('Read', { file_path: MEM }), null);
});
