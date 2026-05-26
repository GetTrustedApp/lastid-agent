/**
 * Vault cache (lib/vault-cache.js). The headline guarantee: shares are stored
 * SEALED (never decrypted at rest) and `vaultListView` NEVER emits the secret —
 * a leak here would put a credential in the agent's reasoning. Also: revokes
 * drop the entry; malformed records are ignored.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync, readFileSync } from 'node:fs';

import {
  applyVaultRecords,
  listVaultCache,
  getVaultShare,
  vaultListView,
  vaultCachePath,
} from '../lib/vault-cache.js';

function freshScope() {
  const scope = `test-${randomUUID()}`;
  return { scope, dir: join(homedir(), '.lastid-agent', scope) };
}

test('applyVaultRecords stores the SEALED blob (never decrypts at rest)', () => {
  const { scope, dir } = freshScope();
  try {
    const n = applyVaultRecords(scope, [
      { id: 'vault_1', version: 1, status: 'active', enc_b64: 'SEALEDBLOB==', for_agent_did: 'did:agent:z1' },
    ]);
    assert.equal(n, 1);
    const cached = getVaultShare(scope, 'vault_1');
    assert.equal(cached.enc_b64, 'SEALEDBLOB==');
    assert.equal(cached.for_agent_did, 'did:agent:z1');
    // On-disk file holds only the sealed blob — no plaintext secret anywhere.
    const raw = readFileSync(vaultCachePath(scope), 'utf8');
    assert.equal(raw.includes('secret'), false, 'no plaintext secret on disk');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a revoked record drops the entry; active upserts a new version', () => {
  const { scope, dir } = freshScope();
  try {
    applyVaultRecords(scope, [{ id: 'v', version: 1, status: 'active', enc_b64: 'A' }]);
    applyVaultRecords(scope, [{ id: 'v', version: 2, status: 'active', enc_b64: 'B' }]);
    assert.equal(getVaultShare(scope, 'v').enc_b64, 'B');
    assert.equal(getVaultShare(scope, 'v').version, 2);

    const dropped = applyVaultRecords(scope, [{ id: 'v', version: 3, status: 'revoked' }]);
    assert.equal(dropped, 1);
    assert.equal(getVaultShare(scope, 'v'), null);
    assert.equal(listVaultCache(scope).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('malformed records (no id / no enc_b64 on active) are skipped', () => {
  const { scope, dir } = freshScope();
  try {
    const n = applyVaultRecords(scope, [
      { version: 1, status: 'active', enc_b64: 'X' }, // no id
      { id: 'v2', status: 'active' }, // no enc_b64
      null,
    ]);
    assert.equal(n, 0);
    assert.equal(listVaultCache(scope).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('vaultListView DROPS the secret and reports has_secret — the leak guard', () => {
  const decoded = {
    item_id: 'vault_1',
    title: 'OpenAI key',
    kind: 'api_key',
    service: 'OpenAI',
    injection: { type: 'header', name: 'Authorization', format: 'Bearer {value}' },
    constraints: [],
    granted_actions: ['use'],
    secret: 'sk-SUPER-SECRET-zzz',
  };
  const view = vaultListView(decoded);
  assert.equal(view.title, 'OpenAI key');
  assert.equal(view.id, 'vault_1');
  assert.deepEqual(view.injection, { type: 'header', name: 'Authorization', format: 'Bearer {value}' });
  assert.equal(view.has_secret, true);
  // THE guarantee: no secret, anywhere in the serialized view.
  assert.equal('secret' in view, false);
  assert.equal(JSON.stringify(view).includes('sk-SUPER-SECRET-zzz'), false);
});

test('vaultListView: a bundle with no secret reports has_secret=false (no crash)', () => {
  const view = vaultListView({ item_id: 'x', title: 'T' });
  assert.equal(view.has_secret, false);
  assert.equal('secret' in view, false);
});
