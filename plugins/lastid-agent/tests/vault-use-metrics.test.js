/**
 * credentialedUseBody (lib/vault-use-metrics.js) — maps a vault handle + timing
 * into the IdP credentialed-use row. The 'consumed' row's credentialed_secs is
 * the actual UNENCRYPTED window (decrypt→zeroize) that drives the operator's
 * guardrail metric, so getting this mapping right is what makes the sell honest.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { credentialedUseBody } from '../lib/vault-use-metrics.js';

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
