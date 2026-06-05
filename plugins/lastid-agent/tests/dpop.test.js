/**
 * Unit tests for the DPoP minter. The agent's identity is dual-algo:
 * existing agents are Ed25519 (EdDSA), new agents are P-256 (ES256).
 * `mintDpopJwt` feature-detects from the supplied KeyObject and MUST
 * produce a verifiable JWT for both — the no-flag-day backward-compat
 * contract. A wrong alg header (the regression) makes the IdP reject the
 * proof with "agent VC requires EdDSA, got ES256".
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';

import { mintDpopJwt } from '../lib/dpop.js';

function fromB64url(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

test('mintDpopJwt signs EdDSA for an Ed25519 key and verifies', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwt = mintDpopJwt({
    agentDid: 'did:lastid:agent:z6MkExampleEd25519',
    httpMethod: 'POST',
    httpUri: 'https://idp.example.com/v1/mls/keypackages',
    signingKey: privateKey,
  });
  const parts = jwt.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  const payload = JSON.parse(fromB64url(parts[1]).toString('utf-8'));
  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.kid, 'did:lastid:agent:z6MkExampleEd25519');
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, 'https://idp.example.com/v1/mls/keypackages');
  assert.ok(typeof payload.jti === 'string' && payload.jti.length > 0);
  // EdDSA raw 64-byte signature → verify with algorithm `null`.
  const sig = fromB64url(parts[2]);
  const ok = cryptoVerify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf-8'),
    publicKey,
    sig,
  );
  assert.equal(ok, true);
});

test('mintDpopJwt signs ES256 for a P-256 key and verifies', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const jwt = mintDpopJwt({
    agentDid: 'did:lastid:agent:zDnExampleP256',
    httpMethod: 'GET',
    httpUri: 'https://idp.example.com/v1/mls/keypackages/me',
    signingKey: privateKey,
  });
  const parts = jwt.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'ES256');
  assert.equal(header.kid, 'did:lastid:agent:zDnExampleP256');
  // ES256 raw r||s signature → verify with sha256 + ieee-p1363.
  const sig = fromB64url(parts[2]);
  const ok = cryptoVerify(
    'sha256',
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf-8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    sig,
  );
  assert.equal(ok, true);
});
