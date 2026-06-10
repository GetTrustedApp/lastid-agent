/**
 * credentialedUseBody (lib/vault-use-metrics.js) — maps a vault handle + timing
 * into the IdP credentialed-use row. The 'consumed' row's credentialed_secs is
 * the actual UNENCRYPTED window (decrypt→zeroize) that drives the operator's
 * guardrail metric, so getting this mapping right is what makes the sell honest.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { credentialedUseBody, publishCredentialedUse } from '../lib/vault-use-metrics.js';
import { generateKeyPairSync } from 'node:crypto';

const HANDLE = {
  itemId: 'vault_1',
  shareId: 'share_1',
  wasApproved: false,
  approvalId: null,
  mintedAtMs: Date.parse('2026-05-26T12:00:00.000Z'),
  ttlMs: 300_000, // 5 min handle TTL
};

test('mint row: minted status, ttl in seconds, auto_allow, no consumed/credentialed fields', () => {
  const b = credentialedUseBody('mint', HANDLE);
  assert.equal(b.status, 'minted');
  assert.equal(b.item_id, 'vault_1');
  assert.equal(b.share_id, 'share_1');
  assert.equal(b.decision_kind, 'auto_allow');
  assert.equal(b.ttl_secs, 300);
  assert.equal(b.minted_at, '2026-05-26T12:00:00.000Z');
  assert.equal('consumed_at' in b, false);
  assert.equal('credentialed_secs' in b, false);
});

test('consume row: consumed status + credentialed_secs as FRACTIONAL seconds (ms precision)', () => {
  const b = credentialedUseBody('consume', HANDLE, { credentialed_ms: 1600 });
  assert.equal(b.status, 'consumed');
  assert.ok(b.consumed_at, 'consumed_at stamped');
  assert.equal(b.credentialed_secs, 1.6); // 1600ms → 1.6s, not rounded to 2
  assert.equal(b.ttl_secs, 300);
});

test('consume row: a sub-second window stays sub-second (NOT floored to 1s)', () => {
  assert.equal(credentialedUseBody('consume', HANDLE, { credentialed_ms: 180 }).credentialed_secs, 0.18);
  assert.equal(credentialedUseBody('consume', HANDLE, { credentialed_ms: 42 }).credentialed_secs, 0.042);
});

test('an approved handle records decision_kind=approval + the approval_id', () => {
  const b = credentialedUseBody('mint', { ...HANDLE, wasApproved: true, approvalId: 'ap_1' });
  assert.equal(b.decision_kind, 'approval');
  assert.equal(b.approval_id, 'ap_1');
});

// REGRESSION — broker-native (ES256) agent shipped nothing because the shipper
// bailed on a null signingKey (no seed in node by custody design); the broker
// covers auth/seal/sign. publishCredentialedUse must REACH authedIdpFetch with a
// null signingKey, not bail.
test('publishCredentialedUse: broker-native (null signingKey) reaches authedIdpFetch', async () => {
  let reached = null;
  await publishCredentialedUse({
    idpUrl: 'https://idp.test',
    agentDid: 'did:lastid:agent:zDn',
    vcCompact: 'vc.jwt',
    signingKey: null, // broker-native: no key in node
    kind: 'mint',
    handle: HANDLE,
    _authedIdpFetch: async (opts) => { reached = opts; return {}; },
  });
  assert.ok(reached, 'authedIdpFetch WAS called (did not bail on null signingKey)');
  assert.equal(reached.signingKey, null);
  assert.ok(reached.path.includes('/credentialed-use'));
  assert.equal(reached.body.item_id, 'vault_1');
});

test('publishCredentialedUse: missing vcCompact still bails WITHOUT calling authedIdpFetch (no regression)', async () => {
  let called = false;
  await publishCredentialedUse({
    idpUrl: 'https://idp.test',
    agentDid: 'did:a',
    vcCompact: '', // missing VC → bail
    signingKey: null,
    kind: 'mint',
    handle: HANDLE,
    _authedIdpFetch: async () => { called = true; return {}; },
  });
  assert.equal(called, false, 'never reached the IdP call');
});

test('publishCredentialedUse: missing handle.itemId still bails WITHOUT calling authedIdpFetch (no regression)', async () => {
  let called = false;
  await publishCredentialedUse({
    idpUrl: 'https://idp.test',
    agentDid: 'did:a',
    vcCompact: 'vc.jwt',
    signingKey: null,
    kind: 'mint',
    handle: { itemId: '' }, // no item → bail
    _authedIdpFetch: async () => { called = true; return {}; },
  });
  assert.equal(called, false, 'never reached the IdP call');
});

test('publishCredentialedUse: legacy path unchanged — a real signingKey still reaches authedIdpFetch', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  let reached = null;
  await publishCredentialedUse({
    idpUrl: 'https://idp.test',
    agentDid: 'did:a',
    vcCompact: 'vc.jwt',
    signingKey: privateKey,
    kind: 'mint',
    handle: HANDLE,
    _authedIdpFetch: async (opts) => { reached = opts; return {}; },
  });
  assert.equal(reached.signingKey, privateKey, 'legacy signingKey forwarded unchanged');
});
