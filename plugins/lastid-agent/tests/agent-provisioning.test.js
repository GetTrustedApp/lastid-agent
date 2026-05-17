/**
 * Unit tests for the agent-side provisioning client. Covers the local
 * cryptographic pieces (keypair, proof JWT, offer parsing) — the
 * network calls are exercised end-to-end against the IdP at test
 * time, not stubbed here.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateAgentKeypair,
  mintProofJwt,
  parseCredentialOffer,
} from '../lib/agent-provisioning.js';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

function fromB64url(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

test('generateAgentKeypair produces an Ed25519 OKP JWK with the expected sizes', () => {
  const kp = generateAgentKeypair();
  assert.equal(kp.publicJwk.kty, 'OKP');
  assert.equal(kp.publicJwk.crv, 'Ed25519');
  // Ed25519 public is 32 bytes → 43-char base64url (no padding).
  assert.equal(kp.publicJwk.x.length, 43);
  // PKCS8 final 32 bytes is the raw private seed.
  assert.equal(kp.seed.length, 32);
});

test('mintProofJwt produces a valid EdDSA JWT verifiable against the embedded jwk', () => {
  const kp = generateAgentKeypair();
  const proof = mintProofJwt({
    credentialIssuer: 'https://idp.example.com',
    cNonce: 'nonce-abc',
    agentDid: 'did:lastid:agent:zABCDEF',
    agentPubkeyJwk: kp.publicJwk,
    privateKey: kp.privateKey,
  });
  const parts = proof.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  const payload = JSON.parse(fromB64url(parts[1]).toString('utf-8'));
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'openid4vci-proof+jwt');
  assert.deepEqual(header.jwk, kp.publicJwk);
  assert.equal(payload.iss, 'did:lastid:agent:zABCDEF');
  assert.equal(payload.aud, 'https://idp.example.com');
  assert.equal(payload.nonce, 'nonce-abc');

  const signingInput = `${parts[0]}.${parts[1]}`;
  const sig = fromB64url(parts[2]);
  const pubKeyObj = createPublicKey({ key: kp.publicJwk, format: 'jwk' });
  const ok = cryptoVerify(null, Buffer.from(signingInput, 'utf-8'), pubKeyObj, sig);
  assert.equal(ok, true);
});

test('parseCredentialOffer extracts the pre-authorized code from an inline offer URI', () => {
  const offer = {
    credential_issuer: 'https://idp.example.com',
    credential_configuration_ids: ['LastID.Agent.Base'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'pre-auth-123',
      },
    },
  };
  const uri = `openid-credential-offer://?credential_offer=${encodeURIComponent(
    JSON.stringify(offer),
  )}`;
  const parsed = parseCredentialOffer(uri);
  assert.equal(parsed.credentialIssuer, 'https://idp.example.com');
  assert.deepEqual(parsed.credentialConfigurationIds, ['LastID.Agent.Base']);
  assert.equal(parsed.preAuthorizedCode, 'pre-auth-123');
});

test('parseCredentialOffer rejects offers missing the pre-authorized-code grant', () => {
  const offer = {
    credential_issuer: 'https://idp.example.com',
    credential_configuration_ids: ['LastID.Agent.Base'],
    grants: {},
  };
  const uri = `openid-credential-offer://?credential_offer=${encodeURIComponent(
    JSON.stringify(offer),
  )}`;
  assert.throws(() => parseCredentialOffer(uri), /pre-authorized_code/);
});
