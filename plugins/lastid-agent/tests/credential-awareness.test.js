/**
 * credential-awareness (lib/credential-awareness.js) — surfaces WHICH vault
 * items the operator shared so the agent knows its access up front. The pure
 * formatters must never leak a secret (they only ever see the secret-free
 * compact view) and must render '' when empty (so the hooks inject nothing),
 * and the seen-marker diff must only fire on genuinely-new shares.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  compactCredential,
  formatCredentialBlock,
  diffNewCredentials,
  formatCredentialDelta,
  seenCredsPath,
  readSeenCreds,
  writeSeenCreds,
} from '../lib/credential-awareness.js';

// A vaultListView-shaped object (secret already dropped upstream).
const VIEW = {
  id: 'vault_tavily',
  title: 'Tavily Search',
  service: 'tavily',
  host: 'api.tavily.com',
  injection: { type: 'header', name: 'Authorization' },
  usage: 'service: tavily · attached as the Authorization header',
  constraints_summary: 'max 10/min; scoped to git_remote=github.com/x/y',
  // fields that must NOT ride into the compact view:
  has_secret: true,
  key_label: 'API key',
};

test('compactCredential keeps only the awareness fields + flattens injection type', () => {
  const c = compactCredential(VIEW);
  assert.deepEqual(c, {
    id: 'vault_tavily',
    title: 'Tavily Search',
    service: 'tavily',
    host: 'api.tavily.com',
    injection: 'header',
    usage: 'service: tavily · attached as the Authorization header',
    constraints: 'max 10/min; scoped to git_remote=github.com/x/y',
  });
  // No secret-bearing keys leak through.
  assert.equal('has_secret' in c, false);
  assert.equal('key_label' in c, false);
});

test('compactCredential falls back to service/id for a missing title', () => {
  assert.equal(compactCredential({ id: 'v1', service: 'svc' }).title, 'svc');
  assert.equal(compactCredential({ id: 'v1' }).title, 'v1');
  assert.equal(compactCredential({}).title, 'credential');
});

test('formatCredentialBlock returns "" for an empty/missing list (no empty heading)', () => {
  assert.equal(formatCredentialBlock([]), '');
  assert.equal(formatCredentialBlock(null), '');
  assert.equal(formatCredentialBlock([{ title: 'x' }]), ''); // no id → filtered out
});

test('formatCredentialBlock lists the credential with id, detail, limits + the use directive', () => {
  const block = formatCredentialBlock([compactCredential(VIEW)]);
  assert.match(block, /## Credentials shared with you right now/);
  assert.match(block, /vault_use\(item_id\)/); // tells the agent how to use it
  assert.match(block, /\*\*Tavily Search\*\* \(`vault_tavily`\)/);
  assert.match(block, /tavily · api\.tavily\.com · inject: header/);
  assert.match(block, /limits: max 10\/min/);
  // Never the secret.
  assert.doesNotMatch(block, /API key/);
});

test('diffNewCredentials returns only ids not already seen', () => {
  const items = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  assert.deepEqual(diffNewCredentials(['a', 'c'], items), [{ id: 'b' }]);
  assert.deepEqual(diffNewCredentials([], items), items); // all new
  assert.deepEqual(diffNewCredentials(['a', 'b', 'c'], items), []); // nothing new
  assert.deepEqual(diffNewCredentials(null, null), []); // null-safe
});

test('formatCredentialDelta returns "" when nothing new, else a compact note', () => {
  assert.equal(formatCredentialDelta([]), '');
  const one = formatCredentialDelta([{ id: 'v1', title: 'Stripe', service: 'stripe' }]);
  assert.match(one, /<lastid-vault>/);
  assert.match(one, /New credential now available/);
  assert.match(one, /\*\*Stripe\*\* \(stripe\)/);
  assert.match(one, /vault_use\(item_id\)/);
  // Pluralizes for >1.
  const two = formatCredentialDelta([{ id: 'v1', title: 'A' }, { id: 'v2', title: 'B' }]);
  assert.match(two, /New credentials now available/);
  assert.match(two, /access them/);
});

test('seen marker round-trips (isolated scope, never touches the real "main")', () => {
  const scope = '__test_credaware__';
  try {
    assert.deepEqual(readSeenCreds(scope), []); // unset → empty
    writeSeenCreds(scope, ['a', 'b', 'b', 'a']); // dedupes
    assert.deepEqual(readSeenCreds(scope).sort(), ['a', 'b']);
    writeSeenCreds(scope, ['c']);
    assert.deepEqual(readSeenCreds(scope), ['c']); // overwrites
  } finally {
    // Clean up the isolated scope dir we created.
    try {
      rmSync(dirname(seenCredsPath(scope)), { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
});
