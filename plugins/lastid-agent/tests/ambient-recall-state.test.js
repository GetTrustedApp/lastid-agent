import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_THROTTLE_MS,
  extractMemoryIds,
  nextStateAfterInject,
  nextStateAfterSkip,
  shouldInjectBlock,
  shouldRunAmbientRecall,
} from '../lib/ambient-recall-state.js';

// ─── shouldRunAmbientRecall ────────────────────────────────────────────────

test('shouldRunAmbientRecall is true on first call (no prior inject)', () => {
  assert.equal(shouldRunAmbientRecall({ last_inject_at: 0 }), true);
  assert.equal(shouldRunAmbientRecall({}), true);
  assert.equal(shouldRunAmbientRecall(null), true);
});

test('shouldRunAmbientRecall is false while inside the throttle window', () => {
  const now = 1_000_000;
  const state = { last_inject_at: now - 5_000 }; // 5s ago, well inside 30s
  assert.equal(shouldRunAmbientRecall(state, { now, throttleMs: DEFAULT_THROTTLE_MS }), false);
});

test('shouldRunAmbientRecall is true once the throttle window has elapsed', () => {
  const now = 1_000_000;
  const state = { last_inject_at: now - DEFAULT_THROTTLE_MS - 1 };
  assert.equal(shouldRunAmbientRecall(state, { now }), true);
});

test('shouldRunAmbientRecall honors a custom throttleMs override', () => {
  const now = 1_000_000;
  assert.equal(
    shouldRunAmbientRecall({ last_inject_at: now - 1_000 }, { now, throttleMs: 500 }),
    true,
  );
  assert.equal(
    shouldRunAmbientRecall({ last_inject_at: now - 100 }, { now, throttleMs: 500 }),
    false,
  );
});

// ─── extractMemoryIds ──────────────────────────────────────────────────────

test('extractMemoryIds pulls every mem_* token, dedupes, and sorts', () => {
  const block = '- [mem_01XYZ] foo - [mem_01ABC] bar - [mem_01XYZ] dup';
  assert.deepEqual(extractMemoryIds(block), ['mem_01ABC', 'mem_01XYZ']);
});

test('extractMemoryIds returns [] on empty / non-string input', () => {
  assert.deepEqual(extractMemoryIds(''), []);
  assert.deepEqual(extractMemoryIds(null), []);
  assert.deepEqual(extractMemoryIds('no memory ids in here'), []);
});

// ─── shouldInjectBlock ─────────────────────────────────────────────────────

test('shouldInjectBlock is true on first injection (no prior ids)', () => {
  assert.equal(shouldInjectBlock({ last_memory_ids: [] }, ['mem_a']), true);
  assert.equal(shouldInjectBlock({}, ['mem_a']), true);
});

test('shouldInjectBlock is false when the new id set is byte-equal to the previous', () => {
  const state = { last_memory_ids: ['mem_a', 'mem_b'] };
  assert.equal(shouldInjectBlock(state, ['mem_a', 'mem_b']), false);
});

test('shouldInjectBlock is true when ids changed (added/removed/different)', () => {
  const state = { last_memory_ids: ['mem_a', 'mem_b'] };
  assert.equal(shouldInjectBlock(state, ['mem_a']), true); // removed
  assert.equal(shouldInjectBlock(state, ['mem_a', 'mem_b', 'mem_c']), true); // added
  assert.equal(shouldInjectBlock(state, ['mem_a', 'mem_x']), true); // swapped
});

test('shouldInjectBlock is false when retrieved ids are empty (no signal)', () => {
  assert.equal(shouldInjectBlock({ last_memory_ids: ['mem_a'] }, []), false);
});

// ─── state transitions ────────────────────────────────────────────────────

test('nextStateAfterInject stamps the inject time + ids and resets skip_count', () => {
  const next = nextStateAfterInject(
    { last_inject_at: 1000, last_memory_ids: ['mem_old'], skip_count: 7 },
    { now: 5000, memoryIds: ['mem_new', 'mem_other'] },
  );
  assert.equal(next.last_inject_at, 5000);
  assert.deepEqual(next.last_memory_ids, ['mem_new', 'mem_other']);
  assert.equal(next.skip_count, 0);
});

test('nextStateAfterSkip preserves inject time + ids and increments skip_count', () => {
  const next = nextStateAfterSkip({
    last_inject_at: 5000,
    last_memory_ids: ['mem_a'],
    skip_count: 2,
  });
  assert.equal(next.last_inject_at, 5000);
  assert.deepEqual(next.last_memory_ids, ['mem_a']);
  assert.equal(next.skip_count, 3);
});

test('nextStateAfterSkip degrades cleanly from a corrupt/empty state', () => {
  const next = nextStateAfterSkip(null);
  assert.equal(next.last_inject_at, 0);
  assert.deepEqual(next.last_memory_ids, []);
  assert.equal(next.skip_count, 1);
});
