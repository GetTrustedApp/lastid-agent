/**
 * VaultRateTracker (lib/vault-rate.js) — the per-item sliding window that feeds
 * uses_last_minute so a rate_per_minute constraint actually enforces. The
 * count must exclude mints older than the window and be per-item.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VaultRateTracker } from '../lib/vault-rate.js';

test('count is 0 for an item with no recorded mints', () => {
  const t = new VaultRateTracker();
  assert.equal(t.count('v1', 60_000, 1_000), 0);
});

test('count reflects mints inside the window and is per-item', () => {
  const t = new VaultRateTracker();
  t.record('v1', 1_000);
  t.record('v1', 2_000);
  t.record('v2', 1_500);
  assert.equal(t.count('v1', 60_000, 3_000), 2);
  assert.equal(t.count('v2', 60_000, 3_000), 1);
  assert.equal(t.count('other', 60_000, 3_000), 0);
});

test('mints older than the window are pruned out of the count', () => {
  const t = new VaultRateTracker();
  t.record('v1', 1_000); // t=1s
  t.record('v1', 2_000); // t=2s
  // window 60s. At now=61_999 → cutoff=1_999: the 1s mint is pruned (<= cutoff),
  // the 2s mint stays (> cutoff).
  assert.equal(t.count('v1', 60_000, 61_999), 1);
  // At now=62_001 → cutoff=2_001: both mints are at/under the cutoff → 0.
  assert.equal(t.count('v1', 60_000, 62_001), 0);
});

test('a mint exactly at the cutoff is excluded (cutoff = now - window, <= drops)', () => {
  const t = new VaultRateTracker();
  t.record('v1', 1_000);
  // now=61_000, window=60_000 → cutoff=1_000; the 1_000 mint is <= cutoff → dropped.
  assert.equal(t.count('v1', 60_000, 61_000), 0);
});
