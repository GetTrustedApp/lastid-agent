/**
 * Tests for the slot_seed content crypto (lib/agent-content-crypto.js).
 *
 * The wire format is the canonical LastID envelope, SymmetricOnly suite
 * (0x0003) — the operator side produces it via the Rust
 * `lastid-envelope::envelope_encrypt`, and this Node peer reads it. These
 * tests:
 *   1. lock the content-KEK derivation (HKDF-SHA512 off the slot_seed),
 *   2. lock the Node envelope output for a fixed (dek, nonces) vector so
 *      the format can't silently drift,
 *   3. cover round-trip + the safety surface (wrong key, tamper, truncation).
 *
 * Cross-language interop (decrypt a Rust-`envelope_encrypt`-produced
 * envelope) is anchored alongside the WASM export that emits it.
 *
 * Locked vectors (seed = 32 bytes of 0x07):
 *   contentKey = 7143c0f24a4736a7d31d3d3b508e171da3e923319c38211acce7486b439aa6f0
 */
import { test } from 'node:test';
import assert from 'node:assert';

import {
  deriveContentKey,
  encryptContent,
  decryptContent,
  encryptJson,
  decryptJson,
} from '../lib/agent-content-crypto.js';

const SEED7 = Buffer.alloc(32, 7);
const SEED8 = Buffer.alloc(32, 8);

const KAT_KEY_HEX =
  '7143c0f24a4736a7d31d3d3b508e171da3e923319c38211acce7486b439aa6f0';
const KAT_PLAINTEXT = '{"hello":"world"}';
// Deterministic envelope for SEED7 / content above with dek=32×0xAB,
// payloadNonce=12×0x00, wrapNonce=12×0x00. Locks the Node LIDE
// SymmetricOnly serialization.
const KAT_DET = { dek: Buffer.alloc(32, 0xab), payloadNonce: Buffer.alloc(12, 0), wrapNonce: Buffer.alloc(12, 0) };
const KAT_ENVELOPE_B64 =
  'TElERQEAAwAAASEAAAAEEABhZ2VudC1jb250ZW50L3YxTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxW3WcPc3MyX4/W3wQmZKueCm60ugkCz7RTphOYqlcpsKGDnMen1GjDJCN0yylJXvAAAAAAAAAAAAAAAAih88ILboNA9tcyRaZ5P/bCjlz5IcULzfYH1VozkBTD1b';

test('deriveContentKey is deterministic, 32 bytes, and matches the locked vector', () => {
  const k1 = deriveContentKey(SEED7);
  assert.equal(k1.length, 32);
  assert.ok(k1.equals(deriveContentKey(SEED7)));
  assert.equal(k1.toString('hex'), KAT_KEY_HEX, 'content-KEK derivation drifted');
});

test('deriveContentKey rejects a non-32-byte seed', () => {
  assert.throws(() => deriveContentKey(Buffer.alloc(16, 1)));
  assert.throws(() => deriveContentKey('not a buffer'));
});

test('different slot seeds derive different keys', () => {
  assert.ok(!deriveContentKey(SEED7).equals(deriveContentKey(SEED8)));
});

test('round-trips a string', () => {
  const msg = 'never run `git stash`';
  assert.equal(decryptContent(SEED7, encryptContent(SEED7, msg)).toString('utf8'), msg);
});

test('round-trips a JSON object', () => {
  const obj = { type: 'rule', pattern: 'git stash', severity: 'deny' };
  assert.deepEqual(decryptJson(SEED7, encryptJson(SEED7, obj)), obj);
});

test('emits a LIDE SymmetricOnly envelope (suite 0x0003, Symmetric recipient 0x04)', () => {
  const env = encryptContent(SEED7, 'x');
  assert.equal(env.subarray(0, 4).toString('ascii'), 'LIDE');
  assert.equal(env.readUInt16LE(4), 1); // version
  assert.equal(env.readUInt16LE(6), 0x0003); // SymmetricOnly
  assert.equal(env[9], 1); // recipient_count
  assert.equal(env[14], 0x04); // first recipient type = Symmetric
});

test('KAT: deterministic encrypt reproduces the locked envelope (format lock)', () => {
  const env = encryptContent(SEED7, KAT_PLAINTEXT, KAT_DET);
  assert.equal(env.toString('base64'), KAT_ENVELOPE_B64, 'envelope format drifted');
});

test('KAT: decrypts the locked envelope', () => {
  assert.equal(decryptContent(SEED7, KAT_ENVELOPE_B64).toString('utf8'), KAT_PLAINTEXT);
});

test('decrypt with the wrong slot seed is rejected', () => {
  const env = encryptContent(SEED7, 'secret-ish content');
  assert.throws(() => decryptContent(SEED8, env));
});

test('tampering with the payload is rejected (auth tag)', () => {
  const env = Buffer.from(encryptContent(SEED7, 'integrity matters'));
  env[env.length - 1] ^= 0x01; // flip a byte in the payload GCM tag
  assert.throws(() => decryptContent(SEED7, env));
});

test('a non-LIDE / truncated buffer is rejected', () => {
  assert.throws(() => decryptContent(SEED7, Buffer.alloc(8, 0)));
  assert.throws(() => decryptContent(SEED7, Buffer.from('not an envelope', 'utf8')));
});

test('random dek/nonces make repeated encryptions differ but both decrypt', () => {
  const a = encryptContent(SEED7, 'same plaintext');
  const b = encryptContent(SEED7, 'same plaintext');
  assert.ok(!a.equals(b), 'fresh dek/nonce per message');
  assert.equal(decryptContent(SEED7, a).toString('utf8'), 'same plaintext');
  assert.equal(decryptContent(SEED7, b).toString('utf8'), 'same plaintext');
});
