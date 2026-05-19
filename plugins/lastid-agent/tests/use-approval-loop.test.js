/**
 * Tests for the plugin-side use-approval orchestrator.
 *
 * The full create→poll→retry loop hits the IdP and isn't unit-testable
 * here; that path is exercised end-to-end against a live IdP. The
 * pieces we DO cover:
 *
 *   - parseApprovalRequiredResult correctly recognises a structured
 *     vault_use rejection and ignores other shapes.
 *   - The wasm bridge exposes computeShareId / verifyDecisionJws and
 *     round-trips against a freshly-signed decision claim, including
 *     the optional bind-check arguments.
 *
 * Together these confirm the orchestrator's hot path (detect, verify
 * locally, plan the retry) is wired against the canonical Rust
 * primitives.
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';

import { parseApprovalRequiredResult } from '../lib/use-approval-loop.js';
import { initializeSdkBindings } from '../lib/sdk-bindings.js';

test('parseApprovalRequiredResult recognises the structured rejection', () => {
  const result = {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'policy_approval_required',
          reason_kind: 'constraint_failed',
          reason_detail: 'amount cap',
          approval_request: {
            agent_did: 'did:lastid:agent:zABC',
            parent_human_did: 'did:lastid:zHUMAN',
            share_id: 'share::did:lastid:agent:zABC::item-1',
            resource_kind: 'item',
            resource_ref: 'item-1',
            reason_kind: 'constraint_failed',
            reason_detail: 'amount cap',
            session_id: 'session-1',
          },
        }),
      },
    ],
    isError: true,
  };
  const parsed = parseApprovalRequiredResult(result);
  assert.ok(parsed);
  assert.equal(parsed.approval_request.agent_did, 'did:lastid:agent:zABC');
});

test('parseApprovalRequiredResult returns null for ordinary success', () => {
  const result = {
    content: [
      { type: 'text', text: JSON.stringify({ vault_handle: 'tok' }) },
    ],
  };
  assert.equal(parseApprovalRequiredResult(result), null);
});

test('parseApprovalRequiredResult returns null for unrelated errors', () => {
  const result = {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ error: 'policy_denied', reason_kind: 'expired' }),
      },
    ],
    isError: true,
  };
  assert.equal(parseApprovalRequiredResult(result), null);
});

test('computeShareId is callable through the sdk bridge', async () => {
  const sdk = await initializeSdkBindings();
  const shareId = sdk.computeShareId({
    agentDid: 'did:lastid:agent:zABC',
    itemId: 'item-1',
  });
  assert.equal(shareId, 'share::did:lastid:agent:zABC::item-1');
});

// Sign a tiny ES256 JWS from Node so we can round-trip through wasm.
async function signDecisionJws({ payload, privateKey, header }) {
  const headerB64 = Buffer.from(JSON.stringify(header), 'utf-8').toString(
    'base64url',
  );
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf-8').toString(
    'base64url',
  );
  const signingInput = `${headerB64}.${payloadB64}`;
  const derSig = nodeSign('sha256', Buffer.from(signingInput, 'utf-8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  const sigB64 = Buffer.from(derSig).toString('base64url');
  return `${signingInput}.${sigB64}`;
}

test('verifyDecisionJws round-trips an ES256 approval JWS', async () => {
  const { webcrypto } = await import('node:crypto');
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privatePkcs8 = await webcrypto.subtle.exportKey(
    'pkcs8',
    keyPair.privateKey,
  );
  const privateKey = createPrivateKey({
    key: Buffer.from(privatePkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'did:lastid:zHUMAN',
    approval_id: '11111111-2222-4333-8444-555555555555',
    decision: 'approved',
    agent_did: 'did:lastid:agent:zABC',
    share_id: 'share::did:lastid:agent:zABC::item-1',
    iat: now,
    ttl_secs: 300,
    jti: 'urn:uuid:decision-1',
  };
  const jws = await signDecisionJws({
    payload,
    privateKey,
    header: { typ: 'jwt+lastid-decision-v1', alg: 'ES256' },
  });

  const sdk = await initializeSdkBindings();
  const claims = sdk.verifyDecisionJws({
    jwsCompact: jws,
    operatorJwkXB64u: jwk.x,
    operatorJwkYB64u: jwk.y,
    nowEpochSec: now + 5,
    expectedApprovalId: payload.approval_id,
    expectedParentHumanDid: payload.iss,
    expectedAgentDid: payload.agent_did,
    expectedShareId: payload.share_id,
  });
  assert.equal(claims.decision, 'approved');
  assert.equal(claims.approval_id, payload.approval_id);
  assert.equal(claims.ttl_secs, 300);
});

test('verifyDecisionJws rejects a JWS whose share_id does not match', async () => {
  const { webcrypto } = await import('node:crypto');
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privatePkcs8 = await webcrypto.subtle.exportKey(
    'pkcs8',
    keyPair.privateKey,
  );
  const privateKey = createPrivateKey({
    key: Buffer.from(privatePkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'did:lastid:zHUMAN',
    approval_id: '11111111-2222-4333-8444-555555555555',
    decision: 'approved',
    agent_did: 'did:lastid:agent:zABC',
    share_id: 'share::did:lastid:agent:zABC::item-1',
    iat: now,
    ttl_secs: 300,
    jti: 'urn:uuid:decision-2',
  };
  const jws = await signDecisionJws({
    payload,
    privateKey,
    header: { typ: 'jwt+lastid-decision-v1', alg: 'ES256' },
  });

  const sdk = await initializeSdkBindings();
  assert.throws(() =>
    sdk.verifyDecisionJws({
      jwsCompact: jws,
      operatorJwkXB64u: jwk.x,
      operatorJwkYB64u: jwk.y,
      nowEpochSec: now + 5,
      expectedShareId: 'share::did:lastid:agent:zABC::item-OTHER',
    }),
  );
});
