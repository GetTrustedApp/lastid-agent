/**
 * Tests for lib/active-scope.js — the ambient per-process scope used by the
 * FORK1 broker dispatch. Module-level state is per test-file (node --test runs
 * each file in its own process), so the "unset" case must be asserted first.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { setActiveScope, getActiveScope } from '../lib/active-scope.js';

test('getActiveScope: defaults to resolveScope() (main) when unset', () => {
  delete process.env.LASTID_AGENT_SCOPE;
  assert.equal(getActiveScope(), 'main');
});

test('getActiveScope: env LASTID_AGENT_SCOPE wins when nothing set explicitly', () => {
  process.env.LASTID_AGENT_SCOPE = 'fromenv';
  assert.equal(getActiveScope(), 'fromenv');
  delete process.env.LASTID_AGENT_SCOPE;
});

test('setActiveScope: an explicit scope overrides the env/default', () => {
  process.env.LASTID_AGENT_SCOPE = 'fromenv';
  setActiveScope('explicit');
  assert.equal(getActiveScope(), 'explicit');
  delete process.env.LASTID_AGENT_SCOPE;
});

test('setActiveScope: ignores empty/blank (keeps the last good value)', () => {
  setActiveScope('keepme');
  setActiveScope('');
  setActiveScope('   ');
  setActiveScope(null);
  assert.equal(getActiveScope(), 'keepme');
});
