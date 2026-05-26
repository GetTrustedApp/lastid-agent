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
  resolveVaultShare,
  vaultListView,
  usageContext,
  summarizeConstraints,
  vaultCachePath,
} from '../lib/vault-cache.js';
import { encryptContent } from '../lib/agent-content-crypto.js';

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

test('vaultListView DROPS the companion secret + acl (AWS/OAuth), reports has_secondary_secret', () => {
  const decoded = {
    item_id: 'vault_aws',
    title: 'AWS prod',
    kind: 'api_key',
    service: 'aws',
    key_label: 'Access key ID',
    secondary_key_label: 'Secret access key',
    injection: { type: 'header', name: 'Authorization' },
    secret: 'AKIA-PRIMARY',
    secret_secondary: 'SECRET-ACCESS-zzz',
    acl: { share_signature: 'sig', kid: 'device-key' },
  };
  const view = vaultListView(decoded);
  assert.equal(view.has_secret, true);
  assert.equal(view.has_secondary_secret, true);
  // Neither secret nor the signing blob rides along.
  assert.equal('secret' in view, false);
  assert.equal('secret_secondary' in view, false);
  assert.equal('acl' in view, false);
  const json = JSON.stringify(view);
  assert.equal(json.includes('SECRET-ACCESS-zzz'), false);
  assert.equal(json.includes('AKIA-PRIMARY'), false);
});

test('usageContext: builds a how-to-use line from share metadata (no secret)', () => {
  const u = usageContext({
    service: 'openai',
    account: 'acme-prod',
    key_label: 'API key',
    injection: { type: 'oauth_bearer' },
    docs_url: 'https://docs.openai.com',
  });
  assert.match(u, /service: openai/);
  assert.match(u, /account: acme-prod/);
  assert.match(u, /OAuth bearer/);
  assert.match(u, /docs: https:\/\/docs\.openai\.com/);
});

test('summarizeConstraints: renders recurring schedule + rate in plain language', () => {
  const s = summarizeConstraints([
    { type: 'recurring_schedule', days: [0, 1, 2, 3, 4], start_minute: 540, end_minute: 1020, utc_offset_minutes: 0 },
    { type: 'rate_per_minute', max: 10 },
  ]);
  assert.match(s, /Mon\/Tue\/Wed\/Thu\/Fri 09:00–17:00 UTC/);
  assert.match(s, /max 10\/min/);
  assert.equal(summarizeConstraints([]), undefined);
  assert.equal(summarizeConstraints(undefined), undefined);
});

// resolveVaultShare — the decrypt + operator-signature gate. The negative
// paths are the security-critical ones: anything not provably the operator's
// must resolve to null so neither vault_list nor inject can use it.
const SLOT = Buffer.alloc(32, 9);

test('resolveVaultShare: missing share → null', () => {
  const { scope, dir } = freshScope();
  try {
    assert.equal(resolveVaultShare(scope, 'nope', { slotSeed: SLOT, operatorJwk: null }), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveVaultShare: undecryptable blob (wrong slot_seed) → null + onReject', () => {
  const { scope, dir } = freshScope();
  try {
    applyVaultRecords(scope, [{ id: 'v', version: 1, status: 'active', enc_b64: 'bm90LXNlYWxlZA==', sig: 'x', target: 'did:a' }]);
    let rejected = null;
    const r = resolveVaultShare(scope, 'v', { slotSeed: SLOT, operatorJwk: null, onReject: (_id, why) => (rejected = why) });
    assert.equal(r, null);
    assert.match(rejected, /undecryptable/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveVaultShare: decrypts but UNSIGNED → null (fails the operator-sig gate)', () => {
  const { scope, dir } = freshScope();
  try {
    // A real slot_seed-sealed bundle (decrypt will succeed)…
    const bundle = { item_id: 'v', title: 'k', secret: 'sk-zzz', injection: { type: 'header', name: 'A' } };
    const enc_b64 = encryptContent(SLOT, Buffer.from(JSON.stringify(bundle), 'utf8')).toString('base64');
    // …but stored with NO signature → must be rejected (provenance unproven).
    applyVaultRecords(scope, [{ id: 'v', version: 1, status: 'active', enc_b64, sig: null, target: 'did:a' }]);
    let rejected = null;
    const r = resolveVaultShare(scope, 'v', { slotSeed: SLOT, operatorJwk: { x_b64u: 'x', y_b64u: 'y' }, onReject: (_id, why) => (rejected = why) });
    assert.equal(r, null, 'unsigned share must not resolve');
    assert.match(rejected, /unverified/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
