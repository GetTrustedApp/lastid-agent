/**
 * Unit tests for the agent-side provisioning client. Covers the local
 * cryptographic pieces — ephemeral envelope key, slot-seed unsealing,
 * P-256 (ES256) identity derivation, proof JWT minting, offer parsing —
 * while the network calls are exercised end-to-end against the IdP
 * separately.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateEphemeralEnvelopeKeypair,
  deriveAgentP256Keypair,
  deriveAgentEd25519Keypair,
  deriveAgentKeypair,
  agentKeyTypeFromDid,
  deriveAgentDeviceId,
  agentDidFromPublicJwk,
  mintProofJwt,
  signParentAuthorization,
  parseCredentialOffer,
  _internal,
} from '../lib/agent-provisioning.js';
import {
  createPublicKey,
  verify as cryptoVerify,
  generateKeyPairSync,
} from 'node:crypto';

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

test('deriveAgentP256Keypair is deterministic for the same slot seed', () => {
  const slotSeed = Buffer.alloc(32, 0x42);
  const a = deriveAgentP256Keypair(slotSeed);
  const b = deriveAgentP256Keypair(slotSeed);
  assert.equal(a.publicJwk.x, b.publicJwk.x);
  assert.equal(a.publicJwk.y, b.publicJwk.y);
  assert.equal(a.agentDid, b.agentDid);
});

test('deriveAgentP256Keypair produces an EC/P-256 holder JWK + a did:lastid:agent DID', () => {
  const kp = deriveAgentP256Keypair(Buffer.alloc(32, 0x42));
  assert.equal(kp.publicJwk.kty, 'EC');
  assert.equal(kp.publicJwk.crv, 'P-256');
  // P-256 coords are 32 bytes → 43-char base64url (no padding).
  assert.equal(kp.publicJwk.x.length, 43);
  assert.equal(kp.publicJwk.y.length, 43);
  assert.equal(kp.signingSeed.length, 32);
  assert.ok(kp.agentDid.startsWith('did:lastid:agent:z'));
});

test('deriveAgentP256Keypair produces distinct identities for distinct seeds', () => {
  const a = deriveAgentP256Keypair(Buffer.alloc(32, 0x01));
  const b = deriveAgentP256Keypair(Buffer.alloc(32, 0x02));
  assert.notEqual(a.publicJwk.x, b.publicJwk.x);
  assert.notEqual(a.agentDid, b.agentDid);
});

test('deriveAgentP256Keypair refuses non-32-byte input', () => {
  assert.throws(
    () => deriveAgentP256Keypair(Buffer.alloc(31, 0x42)),
    /32-byte/,
  );
  assert.throws(
    () => deriveAgentP256Keypair('not-a-buffer'),
    /Buffer/,
  );
});

// ── PINNED KAT — cross-system contract. The IdP's agent device-id
//    derivation MUST reproduce this DID → ad-id pair byte-for-byte for
//    seed [42;32]; if they diverge, agent↔operator MLS membership
//    silently breaks. This vector is the source of truth.
test('KAT: seed [42;32] → pinned P-256 DID, holder JWK, and device-id', () => {
  const seed = Buffer.alloc(32, 42);
  const kp = deriveAgentP256Keypair(seed);
  assert.equal(
    kp.agentDid,
    'did:lastid:agent:zDnaeycdPRAMt7QPrLLcYHLiY2wnf1bVMMU1Aqvg4724k8ToE',
  );
  assert.equal(kp.publicJwk.kty, 'EC');
  assert.equal(kp.publicJwk.crv, 'P-256');
  assert.equal(kp.publicJwk.x, '7QzUQKKfT8idSUWe6yEMhAhyCylEwH4BI1AUWsn4TAk');
  assert.equal(kp.publicJwk.y, 'CFK9En0kVMCifo6MSOiM7TKaVuLj62Kiyh7j_fHKvdU');
  // device-id = `ad-` + first 32 hex of SHA-256 over the RFC7638 canonical
  // EC JWK `{"crv":"P-256","kty":"EC","x":..,"y":..}`.
  assert.equal(deriveAgentDeviceId(seed), 'ad-1ef73378e49013f06656bc0a223f46ad');
});

test('agentDidFromPublicJwk round-trips the keypair DID and rejects non-EC JWKs', () => {
  const kp = deriveAgentP256Keypair(Buffer.alloc(32, 0x07));
  const did = agentDidFromPublicJwk(kp.publicJwk);
  assert.ok(did.startsWith('did:lastid:agent:z'), `unexpected DID prefix: ${did}`);
  // Must agree with the DID the WASM derivation already returned.
  assert.equal(did, kp.agentDid);
  // Two derivations on the same seed must yield the same DID.
  const kp2 = deriveAgentP256Keypair(Buffer.alloc(32, 0x07));
  assert.equal(did, agentDidFromPublicJwk(kp2.publicJwk));
  // A JWK that is neither EC/P-256 nor OKP/Ed25519 is rejected.
  assert.throws(
    () => agentDidFromPublicJwk({ kty: 'RSA', n: 'x', e: 'AQAB' }),
    /EC\/P-256 or OKP\/Ed25519/,
  );
});

test('mintProofJwt signs ES256 with the derived P-256 key and verifies against the embedded jwk', () => {
  const slotSeed = Buffer.alloc(32, 0x33);
  const { signingSeed, publicJwk, agentDid } = deriveAgentP256Keypair(slotSeed);
  const proof = mintProofJwt({
    credentialIssuer: 'https://idp.example.com',
    cNonce: 'nonce-abc',
    agentDid,
    agentPubkeyJwk: publicJwk,
    signingSeed,
  });
  const parts = proof.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  const payload = JSON.parse(fromB64url(parts[1]).toString('utf-8'));
  assert.equal(header.alg, 'ES256');
  assert.equal(header.typ, 'openid4vci-proof+jwt');
  // The WASM embeds the EC P-256 holder JWK derived from the scalar.
  assert.equal(header.jwk.kty, 'EC');
  assert.equal(header.jwk.crv, 'P-256');
  assert.equal(header.jwk.x, publicJwk.x);
  assert.equal(header.jwk.y, publicJwk.y);
  assert.equal(payload.iss, agentDid);
  assert.equal(payload.aud, 'https://idp.example.com');
  assert.equal(payload.nonce, 'nonce-abc');

  const signingInput = `${parts[0]}.${parts[1]}`;
  const sig = fromB64url(parts[2]);
  const pubKeyObj = createPublicKey({ key: publicJwk, format: 'jwk' });
  // ES256 raw r||s → verify with ieee-p1363 + sha256.
  const ok = cryptoVerify(
    'sha256',
    Buffer.from(signingInput, 'utf-8'),
    { key: pubKeyObj, dsaEncoding: 'ieee-p1363' },
    sig,
  );
  assert.equal(ok, true);
});

// Regression: subagent-provisioning derives a P-256 keypair and calls
// mintProofJwt with BOTH the KeyObject (`signingKey`) and the raw scalar
// (`signingSeed`). The Ed25519-feature-detect at the top of mintProofJwt
// is keyed to `asymmetricKeyType === 'ed25519'`, so a P-256 KeyObject
// MUST fall through to the WASM ES256 path — which needs the raw
// scalar. If the caller drops `signingSeed`, mintProofJwt throws
// `signingSeed must be the raw P-256 scalar bytes`, surfacing in the
// listener as `subagent self-heal failed: ... mintProofJwt: signingSeed
// must be the raw P-256 scalar bytes`. Lock in the call shape.
test('mintProofJwt accepts the subagent-provisioning shape (P-256 KeyObject + signingSeed) and signs ES256', () => {
  const slotSeed = Buffer.alloc(32, 0x77);
  const { signingKey, signingSeed, publicJwk, agentDid } =
    deriveAgentP256Keypair(slotSeed);
  const proof = mintProofJwt({
    credentialIssuer: 'https://idp.example.com',
    cNonce: 'sub-nonce',
    agentDid,
    agentPubkeyJwk: publicJwk,
    signingKey, // a P-256 KeyObject — MUST not trip the Ed25519 branch
    signingSeed, // raw scalar — required by the ES256 / WASM path
  });
  const header = JSON.parse(fromB64url(proof.split('.')[0]).toString('utf-8'));
  assert.equal(header.alg, 'ES256');
  assert.equal(header.typ, 'openid4vci-proof+jwt');
});

test('mintProofJwt throws the operator-visible error when a P-256 KeyObject is passed WITHOUT signingSeed', () => {
  // The exact regression that landed in production as
  //   `subagent self-heal failed: ... mintProofJwt: signingSeed must be the raw P-256 scalar bytes`
  const slotSeed = Buffer.alloc(32, 0x77);
  const { signingKey, publicJwk, agentDid } = deriveAgentP256Keypair(slotSeed);
  assert.throws(
    () =>
      mintProofJwt({
        credentialIssuer: 'https://idp.example.com',
        cNonce: 'sub-nonce',
        agentDid,
        agentPubkeyJwk: publicJwk,
        signingKey, // no signingSeed → P-256 path explodes
      }),
    /signingSeed must be the raw P-256 scalar bytes/,
  );
});

// ── Ed25519 BACKWARD-COMPAT (existing agents). The no-flag-day path:
//    existing agents have an Ed25519 identity (`did:lastid:agent:z6Mk…`)
//    and MUST keep deriving Ed25519 + signing EdDSA + an Ed25519 device-id.

test('deriveAgentEd25519Keypair is deterministic and yields an OKP/Ed25519 JWK', () => {
  const slotSeed = Buffer.alloc(32, 0x42);
  const a = deriveAgentEd25519Keypair(slotSeed);
  const b = deriveAgentEd25519Keypair(slotSeed);
  assert.equal(a.publicJwk.kty, 'OKP');
  assert.equal(a.publicJwk.crv, 'Ed25519');
  // Ed25519 pubkey is 32 bytes → 43-char base64url (no padding).
  assert.equal(a.publicJwk.x.length, 43);
  assert.equal(a.signingSeed.length, 32);
  // Deterministic for the same seed.
  assert.equal(a.publicJwk.x, b.publicJwk.x);
});

test('deriveAgentEd25519Keypair produces distinct identities for distinct seeds', () => {
  const a = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x01));
  const b = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x02));
  assert.notEqual(a.publicJwk.x, b.publicJwk.x);
});

test('deriveAgentEd25519Keypair refuses non-32-byte input', () => {
  assert.throws(() => deriveAgentEd25519Keypair(Buffer.alloc(31, 0x42)), /32-byte/);
  assert.throws(() => deriveAgentEd25519Keypair('not-a-buffer'), /Buffer/);
});

test('agentDidFromPublicJwk encodes an Ed25519 OKP JWK as a z6Mk did:lastid:agent', () => {
  const kp = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x07));
  const did = agentDidFromPublicJwk(kp.publicJwk);
  // multicodec(0xed01) || pubkey base58btc-encodes to the canonical z6Mk prefix.
  assert.ok(did.startsWith('did:lastid:agent:z6Mk'), `unexpected DID: ${did}`);
  // Same seed → same DID.
  const kp2 = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x07));
  assert.equal(did, agentDidFromPublicJwk(kp2.publicJwk));
});

test('agentKeyTypeFromDid feature-detects ed25519 (z6Mk) vs p256 (zDn)', () => {
  // Real Ed25519 agent DID (z6Mk prefix from a derived keypair).
  const edDid = agentDidFromPublicJwk(
    deriveAgentEd25519Keypair(Buffer.alloc(32, 0x07)).publicJwk,
  );
  assert.ok(edDid.startsWith('did:lastid:agent:z6Mk'));
  assert.equal(agentKeyTypeFromDid(edDid), 'ed25519');
  // Real P-256 agent DID (zDn prefix from the pinned KAT).
  const p256Did = deriveAgentP256Keypair(Buffer.alloc(32, 42)).agentDid;
  assert.ok(p256Did.startsWith('did:lastid:agent:zDn'));
  assert.equal(agentKeyTypeFromDid(p256Did), 'p256');
  // Garbage / missing prefix defaults to p256 (new-agent default).
  assert.equal(agentKeyTypeFromDid('not-a-did'), 'p256');
  assert.equal(agentKeyTypeFromDid(undefined), 'p256');
});

test('deriveAgentKeypair dispatches Ed25519 for a z6Mk DID and P-256 otherwise', () => {
  const slotSeed = Buffer.alloc(32, 0x07);
  const edDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
  const ed = deriveAgentKeypair(slotSeed, edDid);
  assert.equal(ed.publicJwk.kty, 'OKP');
  assert.equal(ed.publicJwk.crv, 'Ed25519');
  assert.equal(ed.signingKey.asymmetricKeyType, 'ed25519');
  // The dispatcher attaches the passed-in DID for the Ed25519 path.
  assert.equal(ed.agentDid, edDid);
  // It must match the standalone Ed25519 derivation byte-for-byte.
  assert.equal(ed.publicJwk.x, deriveAgentEd25519Keypair(slotSeed).publicJwk.x);

  const p256Did = deriveAgentP256Keypair(slotSeed).agentDid;
  const p = deriveAgentKeypair(slotSeed, p256Did);
  assert.equal(p.publicJwk.kty, 'EC');
  assert.equal(p.publicJwk.crv, 'P-256');
  assert.equal(p.signingKey.asymmetricKeyType, 'ec');
  assert.equal(p.agentDid, p256Did);
});

test('deriveAgentDeviceId feature-detects: Ed25519 DID → Ed25519 device-id ≠ P-256 device-id', () => {
  const slotSeed = Buffer.alloc(32, 0x42);
  const edDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
  const edId = deriveAgentDeviceId(slotSeed, edDid);
  const p256Id = deriveAgentDeviceId(slotSeed); // no DID → P-256 (default)
  assert.ok(edId.startsWith('ad-'));
  assert.ok(p256Id.startsWith('ad-'));
  // Same seed, different algo → different device-id. The Ed25519 path must
  // NOT silently produce the P-256 id (that was the regression).
  assert.notEqual(edId, p256Id);
  // Passing a P-256 DID is equivalent to passing nothing.
  const p256Did = deriveAgentP256Keypair(slotSeed).agentDid;
  assert.equal(deriveAgentDeviceId(slotSeed, p256Did), p256Id);
});

test('mintProofJwt signs EdDSA for an Ed25519 key and verifies against the embedded jwk', () => {
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
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'openid4vci-proof+jwt');
  assert.deepEqual(header.jwk, publicJwk);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const sig = fromB64url(parts[2]);
  const pubKeyObj = createPublicKey({ key: publicJwk, format: 'jwk' });
  // EdDSA raw 64-byte signature → verify with algorithm `null`.
  const ok = cryptoVerify(null, Buffer.from(signingInput, 'utf-8'), pubKeyObj, sig);
  assert.equal(ok, true);
});

test('base58btcEncode round-trip sanity for the multicodec(ed25519-pub) prefix', () => {
  // 0xed 0x01 followed by 32 zero bytes → the encoder must not return an
  // empty string and must preserve leading-zero behavior.
  const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.alloc(32, 0)]);
  const encoded = _internal.base58btcEncode(bytes);
  assert.ok(encoded.length > 0);
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

test('agentDidFromPublicJwk agrees with the WASM-owned DID encoding (no JS drift)', () => {
  // The DID encoding (did:key P-256 multicodec + base58btc) is owned by the
  // Rust SDK via the WASM. Re-encoding the keypair's own JWK must reproduce
  // exactly the DID the WASM derivation already returned — the trip-wire that
  // catches the JS-side reconstruction drifting from the single source.
  const kp = deriveAgentP256Keypair(Buffer.alloc(32, 0x5e));
  assert.equal(agentDidFromPublicJwk(kp.publicJwk), kp.agentDid);
});

// ── parent_authorization (sub-agent delegation). DUAL-ALGO on both sides:
//    the IdP's verifyParentAuthorization feature-detects the expected alg from
//    the parent's cnf pubkey (Ed25519 OKP → EdDSA, P-256 EC → ES256) and
//    requires header.alg to match. So an existing Ed25519 parent signs EdDSA
//    and a new P-256 parent signs ES256 — both accepted. Pure-JS signer.

function sampleParentClaims(parentDid) {
  return JSON.stringify({
    iss: parentDid,
    sub: 'did:lastid:agent:z6MkSUB',
    sub_agent_class: 'echo',
    sub_agent_index: 0,
    agent_pubkey_jwk_thumb: 'thumb',
    capabilities: [],
    may_delegate: false,
    iat: 1_700_000_000,
    exp: 1_700_003_600,
    jti: 'urn:uuid:test',
  });
}

test('signParentAuthorization: Ed25519 parent → EdDSA JWS the IdP verifier accepts', () => {
  const parent = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x42));
  const parentDid = agentDidFromPublicJwk(parent.publicJwk);
  const claimsJson = sampleParentClaims(parentDid);
  const jws = signParentAuthorization(parent.signingKey, claimsJson);
  const parts = jws.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  // The exact header shape the IdP's verifyParentAuthorization requires.
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'jwt+lastid-parent-auth-v1');
  // Payload is the verbatim claims bytes (no re-serialization).
  assert.equal(fromB64url(parts[1]).toString('utf-8'), claimsJson);
  // Verify EdDSA against the parent's Ed25519 pubkey — mirrors the IdP's
  // jose.compactVerify(jws, importJWK(okpJwk, 'EdDSA')).
  const pubKeyObj = createPublicKey({ key: parent.publicJwk, format: 'jwk' });
  const sig = fromB64url(parts[2]);
  assert.equal(sig.length, 64); // raw Ed25519 signature
  const ok = cryptoVerify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf-8'),
    pubKeyObj,
    sig,
  );
  assert.equal(ok, true);
});

test('signParentAuthorization: P-256 parent → ES256 JWS the IdP verifier accepts', () => {
  const parent = deriveAgentP256Keypair(Buffer.alloc(32, 0x42));
  const parentDid = parent.agentDid;
  const claimsJson = sampleParentClaims(parentDid);
  const jws = signParentAuthorization(parent.signingKey, claimsJson);
  const parts = jws.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(fromB64url(parts[0]).toString('utf-8'));
  // P-256 parent → ES256 header (what the IdP derives from a P-256 cnf JWK).
  assert.equal(header.alg, 'ES256');
  assert.equal(header.typ, 'jwt+lastid-parent-auth-v1');
  // Payload is the verbatim claims bytes (no re-serialization).
  assert.equal(fromB64url(parts[1]).toString('utf-8'), claimsJson);
  // Verify ES256 against the parent's P-256 pubkey — mirrors the IdP's
  // jose.compactVerify(jws, importJWK(ecJwk, 'ES256')): raw r||s, ieee-p1363.
  const pubKeyObj = createPublicKey({ key: parent.publicJwk, format: 'jwk' });
  const sig = fromB64url(parts[2]);
  assert.equal(sig.length, 64); // raw r||s P-256 signature
  const ok = cryptoVerify(
    'sha256',
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf-8'),
    { key: pubKeyObj, dsaEncoding: 'ieee-p1363' },
    sig,
  );
  assert.equal(ok, true);
});

test('signParentAuthorization: rejects a key that is neither Ed25519 nor P-256', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(
    () => signParentAuthorization(privateKey, '{}'),
    /Ed25519 or P-256/,
  );
});

test('signParentAuthorization: optional kid lands in the header (both algos)', () => {
  const ed = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x42));
  const edHeader = JSON.parse(
    fromB64url(signParentAuthorization(ed.signingKey, '{}', 'parent-ed').split('.')[0]).toString('utf-8'),
  );
  assert.equal(edHeader.kid, 'parent-ed');
  const p = deriveAgentP256Keypair(Buffer.alloc(32, 0x42));
  const pHeader = JSON.parse(
    fromB64url(signParentAuthorization(p.signingKey, '{}', 'parent-p256').split('.')[0]).toString('utf-8'),
  );
  assert.equal(pHeader.kid, 'parent-p256');
});
