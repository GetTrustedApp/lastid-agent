/**
 * scope-cleanup — wipes the local scope dir + keychain entries when a
 * sub-agent's VC has been revoked at the IdP. The fix shipped to stop
 * a stale listener (dev-testy-mctestface, attempt #871 observed live
 * 2026-05-29) from hammering prod /v1/ws with a dead VC forever after
 * an edit-caps revoke + reissue cycle orphaned its scope.
 *
 * Pure + dependency-injected so we don't actually touch keychain or
 * disk in these tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { cleanupRevokedScope, scopeDataDir } from '../lib/scope-cleanup.js';

test('scopeDataDir: joins homedir + .lastid-agent + scope', () => {
  const out = scopeDataDir('dev-testy-mctestface', () => '/Users/alice');
  assert.equal(out, '/Users/alice/.lastid-agent/dev-testy-mctestface');
});

test('scopeDataDir: rejects empty / non-string scope', () => {
  assert.throws(() => scopeDataDir(''));
  assert.throws(() => scopeDataDir('   '));
  // @ts-expect-error — passing non-string is the negative path
  assert.throws(() => scopeDataDir(null));
});

test('cleanupRevokedScope: HAPPY — wipes the dir + deletes keychain entries + returns summary', async () => {
  const calls = [];
  const summary = await cleanupRevokedScope('lastid-orphan', {
    rmDir: async (p) => { calls.push(['rmDir', p]); },
    deleteVc: async (s) => { calls.push(['deleteVc', s]); },
    logger: () => {},
    homedirFn: () => '/Users/alice',
  });
  assert.deepEqual(calls, [
    ['rmDir', '/Users/alice/.lastid-agent/lastid-orphan'],
    ['deleteVc', 'lastid-orphan'],
  ]);
  assert.equal(summary.scope, 'lastid-orphan');
  assert.equal(summary.dataDirRemoved, true);
  assert.equal(summary.dataDirError, null);
  assert.equal(summary.keychainCleared, true);
  assert.equal(summary.keychainError, null);
});

test('cleanupRevokedScope: dir wipe failure does NOT skip keychain (log-and-continue)', async () => {
  // Real-world failure mode: scope dir is held open by a stuck file
  // handle (rare) or already partially gone. Must still tear down the
  // keychain half — otherwise the operator has dead keychain entries
  // forever AND the next time anything pokes them gets confused state.
  const calls = [];
  const summary = await cleanupRevokedScope('lastid-orphan', {
    rmDir: async () => { throw new Error('EBUSY: device or resource busy'); },
    deleteVc: async (s) => { calls.push(['deleteVc', s]); },
    logger: () => {},
    homedirFn: () => '/Users/alice',
  });
  assert.equal(summary.dataDirRemoved, false);
  assert.match(summary.dataDirError, /EBUSY/);
  assert.deepEqual(calls, [['deleteVc', 'lastid-orphan']], 'keychain delete STILL ran');
  assert.equal(summary.keychainCleared, true);
});

test('cleanupRevokedScope: keychain failure does NOT abort the dir wipe (dir runs first)', async () => {
  const calls = [];
  const summary = await cleanupRevokedScope('lastid-orphan', {
    rmDir: async (p) => { calls.push(['rmDir', p]); },
    deleteVc: async () => { throw new Error('Keychain locked'); },
    logger: () => {},
    homedirFn: () => '/Users/alice',
  });
  assert.equal(summary.dataDirRemoved, true);
  assert.equal(summary.keychainCleared, false);
  assert.match(summary.keychainError, /Keychain locked/);
  assert.equal(calls.length, 1, 'rmDir ran exactly once even though keychain blew up after');
});

test('cleanupRevokedScope: logger receives a line per phase, prefixed with [lastid-agent]', async () => {
  const lines = [];
  await cleanupRevokedScope('lastid-orphan', {
    rmDir: async () => {},
    deleteVc: async () => {},
    logger: (line) => lines.push(line),
    homedirFn: () => '/Users/alice',
  });
  assert.equal(lines.length, 2);
  for (const line of lines) {
    assert.match(line, /^\[lastid-agent\] scope-cleanup:/);
  }
});
