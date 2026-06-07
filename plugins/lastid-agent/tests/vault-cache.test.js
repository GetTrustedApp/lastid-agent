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
  resolveVaultSecret,
  vaultListView,
  usageContext,
  summarizeConstraints,
  vaultCachePath,
  decryptedVaultViews,
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

test('resolveVaultShare: missing share → null', async () => {
  const { scope, dir } = freshScope();
  try {
    assert.equal(await resolveVaultShare(scope, 'nope', { slotSeed: SLOT, operatorJwk: null }), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveVaultShare: undecryptable blob (wrong slot_seed) → null + onReject', async () => {
  const { scope, dir } = freshScope();
  try {
    applyVaultRecords(scope, [{ id: 'v', version: 1, status: 'active', enc_b64: 'bm90LXNlYWxlZA==', sig: 'x', target: 'did:a' }]);
    let rejected = null;
    const r = await resolveVaultShare(scope, 'v', { slotSeed: SLOT, operatorJwk: null, onReject: (_id, why) => (rejected = why) });
    assert.equal(r, null);
    assert.match(rejected, /undecryptable/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveVaultShare: decrypts but UNSIGNED → null (fails the operator-sig gate)', async () => {
  const { scope, dir } = freshScope();
  try {
    // A real slot_seed-sealed bundle (decrypt will succeed)…
    const bundle = { item_id: 'v', title: 'k', secret: 'sk-zzz', injection: { type: 'header', name: 'A' } };
    const enc_b64 = encryptContent(SLOT, Buffer.from(JSON.stringify(bundle), 'utf8')).toString('base64');
    // …but stored with NO signature → must be rejected (provenance unproven).
    applyVaultRecords(scope, [{ id: 'v', version: 1, status: 'active', enc_b64, sig: null, target: 'did:a' }]);
    let rejected = null;
    const r = await resolveVaultShare(scope, 'v', { slotSeed: SLOT, operatorJwk: { x_b64u: 'x', y_b64u: 'y' }, onReject: (_id, why) => (rejected = why) });
    assert.equal(r, null, 'unsigned share must not resolve');
    assert.match(rejected, /unverified/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// resolveVaultSecret — the TWO-LAYER JIT release: fetch wrapped → open the
// handle wrap (outer) → unseal with slot_seed (inner) → bind to the share id →
// zeroize. The negative paths (no release, bad unwrap, undecryptable, wrong
// share) must all fail closed.
const HANDLE = { token: 'h1', handlePubB64: 'PUB', handlePrivB64: 'PRIV' };
// The INNER blob the IdP wrapped: the secret JSON sealed to the slot_seed. In
// the live path the IdP wraps this to the handle; here openWithHandle hands it
// back directly (the wrap/open round-trip is covered by the SDK's own tests).
const innerSealed = (obj) => encryptContent(SLOT, Buffer.from(JSON.stringify(obj), 'utf8'));

test('resolveVaultSecret: opens the wrap, unseals, returns the secret bound to the id', async () => {
  const inner = innerSealed({ item_id: 'v', secret: 'sk-zzz', secret_secondary: 'refresh-q' });
  let sentPub = null;
  let sentHandleId = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async (_id, pub, hid) => {
      sentPub = pub;
      sentHandleId = hid;
      return 'WRAPPED-b64';
    },
    openWithHandle: (priv, hid, wrapped) => {
      assert.equal(priv, 'PRIV');
      assert.equal(hid, 'h1');
      assert.equal(wrapped, 'WRAPPED-b64');
      return inner;
    },
  });
  assert.equal(sentPub, 'PUB', 'sends the handle public key to be wrapped to');
  assert.equal(sentHandleId, 'h1', 'binds to the handle token');
  assert.equal(out.secret, 'sk-zzz');
  assert.equal(out.secret_secondary, 'refresh-q');
  assert.equal(typeof out.zeroize, 'function');
  out.zeroize(); // wipes the decrypted buffers; must not throw
});

test('resolveVaultSecret: BROKER-NATIVE (null seed) unseals the inner layer via the broker', async () => {
  // The handle unwrap (outer) stays node-side — the handle private key lives in
  // the listener, never the broker. Only the INNER slot-sealed layer routes to
  // the broker (it holds the seed). Assert the inner Buffer is forwarded with the
  // no-seed posture, and the released secret is returned + id-bound as usual.
  const innerBuf = Buffer.from('inner-slot-sealed-bytes');
  let sawSeed = 'unset';
  let sawScope = null;
  let sawEnv = null;
  const out = await resolveVaultSecret('v', {
    scope: 'sc',
    slotSeed: null, // broker-native
    handle: HANDLE,
    fetchWrappedSecret: async () => 'WRAPPED-b64',
    openWithHandle: () => innerBuf,
    _decrypt: async (s, seed, env) => {
      sawScope = s;
      sawSeed = seed;
      sawEnv = env;
      return Buffer.from(JSON.stringify({ item_id: 'v', secret: 'sk-broker' }), 'utf8');
    },
  });
  assert.equal(sawScope, 'sc');
  assert.equal(sawSeed, null, 'inner unseal forwarded the no-seed posture (→ broker)');
  assert.ok(Buffer.isBuffer(sawEnv) && sawEnv.equals(innerBuf), 'the handle-unwrapped inner bytes are what the broker unseals');
  assert.equal(out.secret, 'sk-broker');
  assert.equal(typeof out.zeroize, 'function');
  out.zeroize();
});

test('resolveVaultSecret: a handle with no keypair cannot unwrap → null', async () => {
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: { token: 'h1' }, // no handlePubB64 / handlePrivB64
    fetchWrappedSecret: async () => 'WRAPPED',
    openWithHandle: () => Buffer.from('x'),
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null);
  assert.match(why, /keypair/);
});

test('resolveVaultSecret: no secret released (404 → null) → null + onReject', async () => {
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async () => null,
    openWithHandle: () => Buffer.from('x'),
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null);
  assert.match(why, /no secret released/);
});

test('resolveVaultSecret: a failed handle unwrap (wrong key/id/tamper) → null', async () => {
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async () => 'WRAPPED',
    openWithHandle: () => {
      throw new Error('handle_id in envelope does not match');
    },
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null);
  assert.match(why, /unwrap failed/);
});

test('resolveVaultSecret: an undecryptable inner blob (wrong slot_seed / corrupt) → null', async () => {
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async () => 'WRAPPED',
    openWithHandle: () => Buffer.from('not-a-sealed-envelope'),
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null);
  assert.match(why, /undecryptable/);
});

test('resolveVaultSecret: an inner sealed for a DIFFERENT share is rejected (item_id bind)', async () => {
  const inner = innerSealed({ item_id: 'OTHER', secret: 'sk-zzz' });
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async () => 'WRAPPED',
    openWithHandle: () => inner,
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null, 'a relay serving the wrong share-secret must fail closed');
  assert.match(why, /item_id mismatch/);
});

test('resolveVaultSecret: an empty released secret → null', async () => {
  const inner = innerSealed({ item_id: 'v', secret: '' });
  let why = null;
  const out = await resolveVaultSecret('v', {
    slotSeed: SLOT,
    handle: HANDLE,
    fetchWrappedSecret: async () => 'WRAPPED',
    openWithHandle: () => inner,
    onReject: (_id, w) => (why = w),
  });
  assert.equal(out, null);
  assert.match(why, /empty/);
});

// decryptedVaultViews — the choke point that drives `vault_list` and the
// CLI binding refresh. Before 2026-05-28 it returned a bare array and
// silently swallowed every decrypt failure, which is how the sub-agent
// slot-0-sentinel seal-key bug went unnoticed for so long: a share landed
// on disk, decrypt failed AEAD, the catch was empty, vault_list returned
// 0 items. The shape is now `{ items, undecryptable }` so the count of
// open-failures is visible at every caller.

test('decryptedVaultViews returns {items, undecryptable} (shape contract)', async () => {
  const { scope, dir } = freshScope();
  try {
    // Empty store: items=[], undecryptable=[].
    const out = await decryptedVaultViews(scope, SLOT);
    assert.deepEqual(out.items, []);
    assert.deepEqual(out.undecryptable, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('decryptedVaultViews surfaces undecryptable shares (the wrong-key-bug guard)', async () => {
  const { scope, dir } = freshScope();
  try {
    // Seal a bundle under WRONG_SLOT, store it, then try to read it back
    // under the agent's (different) SLOT. This is the exact shape of the
    // 2026-05-28 sub-agent seal-key-mismatch bug: ciphertext on disk, the
    // wrong key in the decrypt loop. Pre-fix this counted as "0 items, no
    // signal." Post-fix it shows up in `undecryptable`.
    const WRONG_SLOT = Buffer.alloc(32, 0xaa);
    const bundle = JSON.stringify({ item_id: 'v-mismatch', service: 'aws' });
    const enc = encryptContent(WRONG_SLOT, Buffer.from(bundle, 'utf8'))
      .toString('base64');
    applyVaultRecords(scope, [
      { id: 'v-mismatch', version: 1, status: 'active', enc_b64: enc, sig: 'x', target: 'did:a' },
    ]);
    const out = await decryptedVaultViews(scope, SLOT);
    assert.equal(out.items.length, 0);
    assert.equal(out.undecryptable.length, 1);
    assert.equal(out.undecryptable[0].id, 'v-mismatch');
    assert.ok(typeof out.undecryptable[0].reason === 'string');
    assert.ok(out.undecryptable[0].reason.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('decryptedVaultViews mixes openable + unopenable correctly', async () => {
  const { scope, dir } = freshScope();
  try {
    const good = JSON.stringify({ item_id: 'v-ok', service: 'github' });
    const goodEnc = encryptContent(SLOT, Buffer.from(good, 'utf8')).toString('base64');
    const WRONG = Buffer.alloc(32, 0xbb);
    const bad = JSON.stringify({ item_id: 'v-bad', service: 'aws' });
    const badEnc = encryptContent(WRONG, Buffer.from(bad, 'utf8')).toString('base64');
    applyVaultRecords(scope, [
      { id: 'v-ok', version: 1, status: 'active', enc_b64: goodEnc, sig: 'x', target: 'did:a' },
      { id: 'v-bad', version: 1, status: 'active', enc_b64: badEnc, sig: 'x', target: 'did:a' },
    ]);
    const out = await decryptedVaultViews(scope, SLOT);
    assert.equal(out.items.length, 1);
    assert.equal(out.items[0].id, 'v-ok');
    assert.equal(out.undecryptable.length, 1);
    assert.equal(out.undecryptable[0].id, 'v-bad');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── BROKER-NATIVE vault decrypt (broker-credential-custody Phase 3 — 2026-06-07)
// A broker-native agent has NO slot seed in node (slotSeed null/undefined). The
// vault shares are sealed under the slot-seed KEK; the signed broker — which
// holds the seed — opens them via its decrypt_agent_content op. The vault path
// must route the no-seed case to the broker (same plaintext) instead of failing.

test('decryptedVaultViews: BROKER-NATIVE (null seed) decrypts via the broker, returns items', async () => {
  const { scope, dir } = freshScope();
  try {
    // The cached enc_b64 is opaque to node here (no seed). The broker returns the
    // plaintext bundle bytes; we mock it to assert the wiring + the args it gets.
    const bundle = { item_id: 'v-broker', service: 'aws', injection: { type: 'env' } };
    const plaintext = Buffer.from(JSON.stringify(bundle), 'utf8');
    let sawArgs = null;
    const brokerDecrypt = async (args) => {
      sawArgs = args;
      return plaintext;
    };
    applyVaultRecords(scope, [
      { id: 'v-broker', version: 1, status: 'active', enc_b64: 'c2VhbGVkLW9wYXF1ZQ==', sig: 'x', target: 'did:a' },
    ]);
    // slotSeed null → the helper must take the broker branch.
    const out = await decryptedVaultViews(scope, null, { brokerDecrypt });
    assert.equal(out.undecryptable.length, 0, 'broker decrypt succeeded → nothing undecryptable');
    assert.equal(out.items.length, 1);
    assert.equal(out.items[0].id, 'v-broker');
    // Wiring contract: the broker got the scope + the standard-base64 envelope.
    assert.equal(sawArgs.scope, scope);
    assert.equal(sawArgs.envelopeB64, 'c2VhbGVkLW9wYXF1ZQ==');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('decryptedVaultViews: BROKER-NATIVE broker failure is SURFACED (undecryptable), never swallowed', async () => {
  const { scope, dir } = freshScope();
  try {
    // Broker down / wrong agent / tamper → throw. Must surface as undecryptable
    // (the wrong-key-bug guard applies to the broker path too), not a silent 0.
    const brokerDecrypt = async () => {
      throw new Error('decrypt_agent_content failed: broker upstream_unavailable');
    };
    applyVaultRecords(scope, [
      { id: 'v-down', version: 1, status: 'active', enc_b64: 'c2VhbGVk', sig: 'x', target: 'did:a' },
    ]);
    const out = await decryptedVaultViews(scope, null, { brokerDecrypt });
    assert.equal(out.items.length, 0);
    assert.equal(out.undecryptable.length, 1);
    assert.equal(out.undecryptable[0].id, 'v-down');
    assert.match(out.undecryptable[0].reason, /broker/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveVaultShare: BROKER-NATIVE forwards the no-seed posture to the decrypt layer', async () => {
  const { scope, dir } = freshScope();
  try {
    applyVaultRecords(scope, [
      { id: 'v', version: 1, status: 'active', enc_b64: 'c2VhbGVk', sig: 'x', target: 'did:a' },
    ]);
    let sawSeed = 'unset';
    let sawScope = null;
    // Inject the decrypt layer to assert resolveVaultShare passes (scope, null, env)
    // through unchanged — that null seed is what makes the real helper pick the
    // broker. Return a valid-but-UNSIGNED bundle so the security gate still fires
    // (proves the broker path doesn't bypass the operator-signature check).
    const _decrypt = async (s, seed, env) => {
      sawScope = s;
      sawSeed = seed;
      assert.equal(env, 'c2VhbGVk');
      return Buffer.from(JSON.stringify({ item_id: 'v', secret: 'x' }), 'utf8');
    };
    let rejected = null;
    const r = await resolveVaultShare(scope, 'v', {
      slotSeed: null,
      operatorJwk: { x_b64u: 'x', y_b64u: 'y' },
      onReject: (_id, why) => (rejected = why),
      _decrypt,
    });
    assert.equal(sawScope, scope);
    assert.equal(sawSeed, null, 'no-seed posture forwarded to the decrypt layer (→ broker)');
    assert.equal(r, null, 'unsigned share still rejected on the broker path');
    assert.match(rejected, /unverified/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
