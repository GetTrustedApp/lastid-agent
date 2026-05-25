/**
 * Tests for the slot_seed content crypto (lib/agent-content-crypto.js).
 *
 * Two jobs:
 *   1. Correctness + safety of the Node encrypt/decrypt path.
 *   2. LOCK the cross-language interop vectors. The operator side
 *      (Rust/WASM via lastid-envelope) must reproduce these exact bytes
 *      from the same inputs, or browser-authored content won't decrypt
 *      on the agent. If you change the KDF/cipher params and these
 *      vectors move, the Rust side must move in lockstep.
 *
 * Locked vectors (seed = 32 bytes of 0x07):
 *   contentKey = 7143c0f24a4736a7d31d3d3b508e171da3e923319c38211acce7486b439aa6f0
 *   encrypt(seed, "{\"hello\":\"world\"}", nonce = 12 bytes of 0x00)
 *     = base64 "AAAAAAAAAAAAAAAAFeQVvjDw96xpdLE0m6GFMDZWvMElO+mI4elmXzwslRq8"
 */
import { test } from 'node:test';
import assert from 'node:assert';

import {
  deriveContentKey,
  encryptContent,
  decryptContent,
  encryptJson,
  decryptJson,
  NONCE_LEN,
  TAG_LEN,
} from '../lib/agent-content-crypto.js';

const SEED7 = Buffer.alloc(32, 7);
const SEED8 = Buffer.alloc(32, 8);

const KAT_KEY_HEX =
  '7143c0f24a4736a7d31d3d3b508e171da3e923319c38211acce7486b439aa6f0';
const KAT_PLAINTEXT = '{"hello":"world"}';
const KAT_PACKED_B64 =
  'AAAAAAAAAAAAAAAAFeQVvjDw96xpdLE0m6GFMDZWvMElO+mI4elmXzwslRq8';

test('deriveContentKey is deterministic, 32 bytes, and matches the locked vector', () => {
  const k1 = deriveContentKey(SEED7);
  const k2 = deriveContentKey(SEED7);
  assert.equal(k1.length, 32);
  assert.ok(k1.equals(k2), 'derivation must be deterministic');
  assert.equal(k1.toString('hex'), KAT_KEY_HEX, 'interop vector drifted');
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
  const packed = encryptContent(SEED7, msg);
  assert.equal(decryptContent(SEED7, packed).toString('utf8'), msg);
});

test('round-trips a JSON object', () => {
  const obj = { type: 'rule', pattern: 'git stash', severity: 'deny' };
  const packed = encryptJson(SEED7, obj);
  assert.deepEqual(decryptJson(SEED7, packed), obj);
});

test('KAT: decrypts the locked cross-language ciphertext', () => {
  // The interop anchor — the Rust/WASM operator side must produce this
  // exact base64 for (seed=32x07, nonce=0, plaintext=KAT_PLAINTEXT).
  const out = decryptContent(SEED7, KAT_PACKED_B64);
  assert.equal(out.toString('utf8'), KAT_PLAINTEXT);
});

test('encrypt with a fixed nonce reproduces the locked ciphertext', () => {
  const packed = encryptContent(SEED7, KAT_PLAINTEXT, { nonce: Buffer.alloc(NONCE_LEN, 0) });
  assert.equal(packed.toString('base64'), KAT_PACKED_B64);
});

test('wire layout is nonce(12) || ciphertext || tag(16)', () => {
  const nonce = Buffer.from('0123456789ab', 'utf8'); // 12 bytes
  const pt = 'abc';
  const packed = encryptContent(SEED7, pt, { nonce });
  assert.equal(packed.length, NONCE_LEN + Buffer.byteLength(pt) + TAG_LEN);
  assert.ok(packed.subarray(0, NONCE_LEN).equals(nonce));
});

test('decrypt with the wrong slot seed is rejected', () => {
  const packed = encryptContent(SEED7, 'secret-ish content');
  assert.throws(() => decryptContent(SEED8, packed));
});

test('tampering with the ciphertext is rejected (auth tag)', () => {
  const packed = encryptContent(SEED7, 'integrity matters');
  const tampered = Buffer.from(packed);
  tampered[NONCE_LEN] ^= 0x01; // flip a ciphertext byte
  assert.throws(() => decryptContent(SEED7, tampered));
});

test('truncated input is rejected', () => {
  assert.throws(() => decryptContent(SEED7, Buffer.alloc(NONCE_LEN + TAG_LEN - 1, 0)));
});

test('random nonces make repeated encryptions of the same plaintext differ', () => {
  const a = encryptContent(SEED7, 'same plaintext');
  const b = encryptContent(SEED7, 'same plaintext');
  assert.ok(!a.equals(b), 'nonce must be random per message');
  // ...but both still decrypt.
  assert.equal(decryptContent(SEED7, a).toString('utf8'), 'same plaintext');
  assert.equal(decryptContent(SEED7, b).toString('utf8'), 'same plaintext');
});

test('AAD mismatch is rejected', () => {
  const packed = encryptContent(SEED7, 'bound to aad', { aad: 'ctx-A' });
  assert.equal(decryptContent(SEED7, packed, { aad: 'ctx-A' }).toString('utf8'), 'bound to aad');
  assert.throws(() => decryptContent(SEED7, packed, { aad: 'ctx-B' }));
  assert.throws(() => decryptContent(SEED7, packed)); // missing aad
});
