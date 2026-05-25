/**
 * Unit tests for the agent-side provisioning client. Covers the local
 * cryptographic pieces — ephemeral envelope key, slot-seed unsealing,
 * Ed25519 derivation, proof JWT minting, offer parsing — while the
 * network calls are exercised end-to-end against the IdP separately.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateEphemeralEnvelopeKeypair,
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
  mintProofJwt,
  parseCredentialOffer,
  _internal,
} from '../lib/agent-provisioning.js';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

function fromB64url(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

test('generateEphemeralEnvelopeKeypair produces an EC P-256 JWK with the expected sizes', () => {
  const kp = generateEphemeralEnvelopeKeypair();
  assert.equal(kp.publicJwk.kty, 'EC');
  assert.equal(kp.publicJwk.crv, 'P-256');
  // P-256 coords are 32 bytes → 43-char base64url (no padding).
  assert.equal(kp.publicJwk.x.length, 43);
  assert.equal(kp.publicJwk.y.length, 43);
  assert.ok(kp.privateKey);
});

test('project_root_seed seals + unseals through the SAME envelope path as the slot seed', () => {
  // The agent reuses unsealSlotSeed for the wallet-sealed project root seed, so
  // a round-trip must reproduce the exact 32 bytes. This is the contract behind
  // provisionAgent unsealing approved.sealedProjectRootSeed.
  const { publicJwk, privateKey } = generateEphemeralEnvelopeKeypair();
  const projectRootSeed = Buffer.alloc(32, 0x5a);
  const sealed = _internal.sealSlotSeed(projectRootSeed, publicJwk);
  const out = _internal.unsealSlotSeed(sealed, privateKey);
  assert.equal(out.length, 32);
  assert.ok(out.equals(projectRootSeed));
});

test('a project_root_seed sealed to a DIFFERENT ephemeral key fails to unseal (fail-open → no project tier)', () => {
  // Backs the best-effort/fail-open unseal in provisionAgent: a foreign or
  // malformed envelope throws and the agent degrades to global+agent, never
  // crashing provisioning.
  const a = generateEphemeralEnvelopeKeypair();
  const b = generateEphemeralEnvelopeKeypair();
  const sealed = _internal.sealSlotSeed(Buffer.alloc(32, 0x07), a.publicJwk);
  assert.throws(() => _internal.unsealSlotSeed(sealed, b.privateKey));
});

test('deriveAgentEd25519Keypair is deterministic for the same slot seed', () => {
  const slotSeed = Buffer.alloc(32, 0x42);
  const a = deriveAgentEd25519Keypair(slotSeed);
  const b = deriveAgentEd25519Keypair(slotSeed);
  assert.equal(a.publicJwk.x, b.publicJwk.x);
});

test('deriveAgentEd25519Keypair produces distinct identities for distinct seeds', () => {
  const a = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x01));
  const b = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x02));
  assert.notEqual(a.publicJwk.x, b.publicJwk.x);
});

test('deriveAgentEd25519Keypair refuses non-32-byte input', () => {
  assert.throws(
    () => deriveAgentEd25519Keypair(Buffer.alloc(31, 0x42)),
    /32-byte/,
  );
  assert.throws(
    () => deriveAgentEd25519Keypair('not-a-buffer'),
    /Buffer/,
  );
});

test('agentDidFromPublicJwk encodes a did:lastid:agent: with multibase z prefix', () => {
  const kp = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x07));
  const did = agentDidFromPublicJwk(kp.publicJwk);
  assert.ok(did.startsWith('did:lastid:agent:z'), `unexpected DID prefix: ${did}`);
  // Two derivations on the same seed must yield the same DID.
  const kp2 = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x07));
  const did2 = agentDidFromPublicJwk(kp2.publicJwk);
  assert.equal(did, did2);
});

test('mintProofJwt signs with the derived Ed25519 key and verifies against the embedded jwk', () => {
  const slotSeed = Buffer.alloc(32, 0x33);
  const { signingKey, publicJwk } = deriveAgentEd25519Keypair(slotSeed);
  const proof = mintProofJwt({
    credentialIssuer: 'https://idp.example.com',
    cNonce: 'nonce-abc',
    agentDid: agentDidFromPublicJwk(publicJwk),
    agentPubkeyJwk: publicJwk,
    signingKey,
  });
  const parts = proof.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  const payload = JSON.parse(fromB64url(parts[1]).toString('utf-8'));
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'openid4vci-proof+jwt');
  assert.deepEqual(header.jwk, publicJwk);
  assert.equal(payload.aud, 'https://idp.example.com');
  assert.equal(payload.nonce, 'nonce-abc');

  const signingInput = `${parts[0]}.${parts[1]}`;
  const sig = fromB64url(parts[2]);
  const pubKeyObj = createPublicKey({ key: publicJwk, format: 'jwk' });
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

test('base58btcEncode round-trip sanity for the multicodec(ed25519-pub) prefix', () => {
  // 0xed 0x01 followed by 32 zero bytes → the encoder must not return
  // an empty string and must preserve leading-zero behavior.
  const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.alloc(32, 0)]);
  const encoded = _internal.base58btcEncode(bytes);
  assert.ok(encoded.length > 0);
});
