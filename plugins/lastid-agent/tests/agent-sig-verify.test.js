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

import { verifyRecordSignature, sha256Hex } from '../lib/agent-sig-verify.js';

const b64url = (x) => Buffer.from(x).toString('base64url');

// One operator delegation_authority key for the suite.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pubJwk = publicKey.export({ format: 'jwk' });
const OPERATOR_JWK = { x_b64u: pubJwk.x, y_b64u: pubJwk.y };

// A different key, to forge with.
const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

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

test('memories are verify-if-signed: unsigned memory is allowed', () => {
  const rec = { kind: 'memory', id: 'mem_1', target: 'global', version: 1, status: 'active' };
  assert.deepEqual(verifyRecordSignature(rec, CONTENT, OPERATOR_JWK), { ok: true });
  // ...but a signed memory with a bad sig is rejected.
  const claims = { kind: 'memory', id: 'mem_1', target: 'global', version: 1, status: 'active', content_sha256: sha256Hex(CONTENT) };
  const bad = { ...rec, sig: mintJws(claims, { key: other.privateKey }) };
  assert.equal(verifyRecordSignature(bad, CONTENT, OPERATOR_JWK).ok, false);
});

test('a signed revoke (no content) verifies on its claims', () => {
  const claims = { kind: 'rule', id: 'rule_1', target: 'global', version: 2, status: 'revoked' };
  const rec = { kind: 'rule', id: 'rule_1', target: 'global', version: 2, status: 'revoked', sig: mintJws(claims) };
  assert.deepEqual(verifyRecordSignature(rec, null, OPERATOR_JWK), { ok: true });
});
