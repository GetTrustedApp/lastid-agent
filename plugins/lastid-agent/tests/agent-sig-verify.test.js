/**
 * Tests for agent-state signature verification (lib/agent-sig-verify.js).
 *
 * Mints real ES256 (P-256) JWS the same way the operator's
 * sign_human_authorization does (header typ "jwt+lastid-human-auth-v1",
 * alg ES256; payload = claims verbatim; sig = raw r||s, base64url), then
 * checks the agent's pure-node:crypto verifier accepts good records and
 * rejects forged/tampered/unbound/unsigned ones — fail-closed for rules,
 * verify-if-signed for memories.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';

import {
  verifyRecordSignature,
  sha256Hex,
  signAgentRecordJws,
  agentEd25519PublicKeyFromDid,
  verifyAgentRecordJws,
} from '../lib/agent-sig-verify.js';
import {
  deriveAgentP256Keypair,
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';

const b64url = (x) => Buffer.from(x).toString('base64url');

// One operator delegation_authority key for the suite.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pubJwk = publicKey.export({ format: 'jwk' });
const OPERATOR_JWK = { x_b64u: pubJwk.x, y_b64u: pubJwk.y };

// A different key, to forge with.
const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

// A real agent P-256 keypair + its did:lastid:agent DID (the agent-authored
// path). signAgentRecordJws signs with the raw 32-byte scalar via the WASM.
const agentKp = deriveAgentP256Keypair(Buffer.alloc(32, 0x11));
const AGENT_DID = agentKp.agentDid;

function mintJws(claims, { typ = 'jwt+lastid-human-auth-v1', key = privateKey } = {}) {
  const h = b64url(JSON.stringify({ typ, alg: 'ES256' }));
  const p = b64url(JSON.stringify(claims));
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`, 'utf8'), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return `${h}.${p}.${sig.toString('base64url')}`;
}

const CONTENT = Buffer.from(JSON.stringify({ pattern: 'git stash', severity: 'deny' }), 'utf8');

function signedRule(over = {}) {
  const base = { kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active' };
  const rec = { ...base, ...over };
  const claims = {
    kind: rec.kind,
    id: rec.id,
    target: rec.target,
    version: rec.version,
    status: rec.status,
    content_sha256: sha256Hex(CONTENT),
  };
  return { ...rec, sig: mintJws(claims) };
}

test('accepts a correctly-signed rule with a matching content hash', () => {
  assert.deepEqual(verifyRecordSignature(signedRule(), CONTENT, OPERATOR_JWK), { ok: true });
});

test('rejects a rule signed by the wrong key', () => {
  const claims = {
    kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active',
    content_sha256: sha256Hex(CONTENT),
  };
  const rec = { kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active', sig: mintJws(claims, { key: other.privateKey }) };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /signature/);
});

test('rejects when the decrypted content does not match the signed hash', () => {
  const v = verifyRecordSignature(signedRule(), Buffer.from('tampered content'), OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /content hash/);
});

test('rejects a signature that does not bind this record (id swap)', () => {
  const rec = signedRule(); // sig binds id rule_1
  rec.id = 'rule_2'; // ...but the wire record claims rule_2
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /bind/);
});

test('rejects a wrong-typ JWS', () => {
  const claims = {
    kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active',
    content_sha256: sha256Hex(CONTENT),
  };
  const rec = { kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active', sig: mintJws(claims, { typ: 'jwt' }) };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /typ/);
});

test('rules are fail-closed: unsigned rule is rejected', () => {
  const rec = { kind: 'rule', id: 'rule_1', target: 'global', version: 1, status: 'active' };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /no signature/);
});

test('rules are fail-closed: no operator key → rejected even if signed', () => {
  const v = verifyRecordSignature(signedRule(), CONTENT, null);
  assert.equal(v.ok, false);
  assert.match(v.reason, /no operator delegation key/);
});

test('memories are FAIL-CLOSED: an unsigned memory is rejected', () => {
  const rec = { kind: 'memory', id: 'mem_1', target: 'global', version: 1, status: 'active' };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false, 'no path in without a verified signature');
  assert.match(v.reason, /no signature/);
});

// ── agent-authored memories (EdDSA over the agent's Ed25519 key) ────────

function signedAgentMemory(over = {}) {
  const base = {
    kind: 'memory', id: 'mem_a1', target: 'global', version: 1, status: 'active',
    author: 'agent', author_agent_did: AGENT_DID,
  };
  const rec = { ...base, ...over };
  const claims = {
    kind: rec.kind, id: rec.id, target: rec.target, version: rec.version, status: rec.status,
    content_sha256: sha256Hex(CONTENT),
  };
  return { ...rec, sig: signAgentRecordJws(claims, agentKp.signingSeed) };
}

test('accepts an agent-signed memory verified against the author DID', () => {
  assert.deepEqual(verifyRecordSignature(signedAgentMemory(), CONTENT, OPERATOR_JWK), { ok: true });
});

test('agent self-copy: verifies against the syncing agent DID when no author_agent_did', () => {
  const rec = signedAgentMemory({ author_agent_did: undefined });
  assert.deepEqual(
    verifyRecordSignature(rec, CONTENT, OPERATOR_JWK, { agentDid: AGENT_DID }),
    { ok: true },
  );
});

test('rejects an agent memory signed by a DIFFERENT agent key', () => {
  // A different agent identity (different seed → different P-256 scalar) but
  // the record still CLAIMS AGENT_DID — the sig must fail to verify.
  const otherAgent = deriveAgentP256Keypair(Buffer.alloc(32, 0x22));
  const claims = {
    kind: 'memory', id: 'mem_a1', target: 'global', version: 1, status: 'active',
    content_sha256: sha256Hex(CONTENT),
  };
  const rec = {
    kind: 'memory', id: 'mem_a1', target: 'global', version: 1, status: 'active',
    author: 'agent', author_agent_did: AGENT_DID, sig: signAgentRecordJws(claims, otherAgent.signingSeed),
  };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /signature/);
});

test('rejects an agent memory with tampered content', () => {
  const v = verifyRecordSignature(signedAgentMemory(), Buffer.from('tampered'), OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /content hash/);
});

test('rejects an agent memory whose sig binds a different record (replay)', () => {
  const rec = signedAgentMemory();
  rec.id = 'mem_other';
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /bind/);
});

test('a signed revoke (no content) verifies on its claims', () => {
  const claims = { kind: 'rule', id: 'rule_1', target: 'global', version: 2, status: 'revoked' };
  const rec = { kind: 'rule', id: 'rule_1', target: 'global', version: 2, status: 'revoked', sig: mintJws(claims) };
  assert.deepEqual(verifyRecordSignature(rec, null, OPERATOR_JWK), { ok: true });
});

// ── Ed25519 BACKWARD-COMPAT (existing agents author records with EdDSA) ──
//    An existing Ed25519 agent (`did:lastid:agent:z6Mk…`) signs its memory
//    records EdDSA, NOT ES256. The dual-algo signer/verifier MUST round-trip
//    those AND keep rejecting cross-alg / wrong-key / tampered records.

const edAgentKp = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x33));
const ED_AGENT_DID = agentDidFromPublicJwk(edAgentKp.publicJwk);

function signedEdAgentMemory(over = {}) {
  const base = {
    kind: 'memory', id: 'mem_ed1', target: 'global', version: 1, status: 'active',
    author: 'agent', author_agent_did: ED_AGENT_DID,
  };
  const rec = { ...base, ...over };
  const claims = {
    kind: rec.kind, id: rec.id, target: rec.target, version: rec.version, status: rec.status,
    content_sha256: sha256Hex(CONTENT),
  };
  // Pass { signingKey, signingSeed } — the Ed25519 KeyObject selects EdDSA.
  return {
    ...rec,
    sig: signAgentRecordJws(claims, {
      signingKey: edAgentKp.signingKey,
      signingSeed: edAgentKp.signingSeed,
    }),
  };
}

test('Ed25519 agent: signAgentRecordJws emits an EdDSA header', () => {
  const rec = signedEdAgentMemory();
  const header = JSON.parse(
    Buffer.from(rec.sig.split('.')[0], 'base64url').toString('utf8'),
  );
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'jwt+lastid-agent-auth-v1');
});

test('Ed25519 agent: its DID is the z6Mk multibase form', () => {
  assert.ok(ED_AGENT_DID.startsWith('did:lastid:agent:z6Mk'), ED_AGENT_DID);
  // The DID decodes back to the keypair's raw Ed25519 pubkey.
  const pub = agentEd25519PublicKeyFromDid(ED_AGENT_DID);
  assert.equal(Buffer.from(pub).toString('base64url'), edAgentKp.publicJwk.x);
});

test('accepts an Ed25519 agent-signed memory verified against the author DID', () => {
  assert.deepEqual(
    verifyRecordSignature(signedEdAgentMemory(), CONTENT, OPERATOR_JWK),
    { ok: true },
  );
});

test('Ed25519 agent self-copy: verifies against the syncing agent DID', () => {
  const rec = signedEdAgentMemory({ author_agent_did: undefined });
  assert.deepEqual(
    verifyRecordSignature(rec, CONTENT, OPERATOR_JWK, { agentDid: ED_AGENT_DID }),
    { ok: true },
  );
});

test('rejects an Ed25519 agent memory signed by a DIFFERENT Ed25519 key', () => {
  const otherEd = deriveAgentEd25519Keypair(Buffer.alloc(32, 0x44));
  const claims = {
    kind: 'memory', id: 'mem_ed1', target: 'global', version: 1, status: 'active',
    content_sha256: sha256Hex(CONTENT),
  };
  const rec = {
    kind: 'memory', id: 'mem_ed1', target: 'global', version: 1, status: 'active',
    author: 'agent', author_agent_did: ED_AGENT_DID,
    sig: signAgentRecordJws(claims, {
      signingKey: otherEd.signingKey,
      signingSeed: otherEd.signingSeed,
    }),
  };
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /signature/);
});

test('rejects an Ed25519 agent memory with tampered content', () => {
  const v = verifyRecordSignature(signedEdAgentMemory(), Buffer.from('tampered'), OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /content hash/);
});

test('cross-alg: an EdDSA record verified with ONLY a P-256 key is rejected', () => {
  const rec = signedEdAgentMemory();
  // Hand the verifier only a P-256 key — it must refuse (no Ed25519 key).
  assert.throws(
    () => verifyAgentRecordJws(rec.sig, { es256: agentKp.publicJwk }),
    /no Ed25519 key/,
  );
});

test('cross-alg: an ES256 record verified with ONLY an Ed25519 key is rejected', () => {
  const claims = {
    kind: 'memory', id: 'mem_x', target: 'global', version: 1, status: 'active',
    content_sha256: sha256Hex(CONTENT),
  };
  // P-256 agent signs ES256.
  const es256Sig = signAgentRecordJws(claims, agentKp.signingSeed);
  assert.throws(
    () => verifyAgentRecordJws(es256Sig, { ed25519: agentEd25519PublicKeyFromDid(ED_AGENT_DID) }),
    /no P-256 key/,
  );
});

test('tampered Ed25519 sig (flipped signature byte) fails to verify', () => {
  const rec = signedEdAgentMemory();
  const parts = rec.sig.split('.');
  const sigBytes = Buffer.from(parts[2], 'base64url');
  sigBytes[0] ^= 0xff;
  rec.sig = `${parts[0]}.${parts[1]}.${sigBytes.toString('base64url')}`;
  const v = verifyRecordSignature(rec, CONTENT, OPERATOR_JWK);
  assert.equal(v.ok, false);
  assert.match(v.reason, /signature/);
});
