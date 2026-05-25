/**
 * resolveScope (lib/scope.js) — picks this session's agent scope so one host
 * can run several distinct agents. Order: explicit --scope flag → the
 * LASTID_AGENT_SCOPE env → 'main'. ("default no scope = main", per the operator.)
 */
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { resolveScope } from '../lib/scope.js';

const ORIG = process.env.LASTID_AGENT_SCOPE;
afterEach(() => {
  if (ORIG === undefined) delete process.env.LASTID_AGENT_SCOPE;
  else process.env.LASTID_AGENT_SCOPE = ORIG;
});

test('defaults to main when nothing is set', () => {
  delete process.env.LASTID_AGENT_SCOPE;
  assert.equal(resolveScope(), 'main');
  assert.equal(resolveScope({}), 'main');
});

test('uses LASTID_AGENT_SCOPE when set', () => {
  process.env.LASTID_AGENT_SCOPE = 'lastid';
  assert.equal(resolveScope(), 'lastid');
  assert.equal(resolveScope({}), 'lastid');
});

test('an explicit --scope flag wins over the env', () => {
  process.env.LASTID_AGENT_SCOPE = 'lastid';
  assert.equal(resolveScope({ scope: 'work' }), 'work');
});

test('a boolean / empty flag is ignored (falls through to env, then main)', () => {
  process.env.LASTID_AGENT_SCOPE = 'lastid';
  assert.equal(resolveScope({ scope: true }), 'lastid'); // `--scope` with no value
  assert.equal(resolveScope({ scope: '' }), 'lastid');
  delete process.env.LASTID_AGENT_SCOPE;
  assert.equal(resolveScope({ scope: true }), 'main');
});

test('trims whitespace; blank env falls back to main', () => {
  process.env.LASTID_AGENT_SCOPE = '  lastid  ';
  assert.equal(resolveScope(), 'lastid');
  process.env.LASTID_AGENT_SCOPE = '   ';
  assert.equal(resolveScope(), 'main');
  assert.equal(resolveScope({ scope: '  work ' }), 'work');
});
