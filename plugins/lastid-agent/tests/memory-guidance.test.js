/**
 * The injected memory guidance must make LastID memory the PREFERRED store and
 * actively steer the agent away from recording durable facts in markdown files
 * (the runtime's own memory prompt would otherwise encourage MEMORY.md/CLAUDE.md).
 * These lock the load-bearing phrasing so a future edit can't quietly drop it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryGuidanceLines } from '../lib/memory-guidance.js';

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
