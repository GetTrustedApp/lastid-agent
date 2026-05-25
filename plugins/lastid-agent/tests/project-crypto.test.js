/**
 * Tests for project-tier content crypto (lib/project-crypto.js, Option B).
 *
 * Defining properties:
 *  - All an operator's agents share one project_root_seed, so any of them can
 *    read/write a repo's project memories; an outsider (different seed) cannot.
 *  - The content key is keyed by the public routing_id, NOT the repo name — so
 *    a reader who has only a synced record (routing_id) can decrypt it and
 *    recover project_key from inside (breaks the circular dependency).
 *  - The IdP, holding no seed, learns neither the content nor the repo name.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';

import {
  deriveProjectContentKey,
  deriveProjectRoutingId,
  encryptProjectContent,
  decryptProjectContent,
  encryptProjectJson,
  decryptProjectJson,
} from '../lib/project-crypto.js';

const SEED_A = crypto.createHash('sha256').update('operator-project-root-seed').digest(); // 32B
const SEED_B = crypto.createHash('sha256').update('a-DIFFERENT-operator').digest();
const IDP = 'github.com/gettrustedapp/gettrusted-idp';
const SDK = 'github.com/gettrustedapp/lastid-sdk';

const rid = (seed, projectKey) => deriveProjectRoutingId(seed, projectKey);

// ── routing id (privacy) ───────────────────────────────────────────

test('deriveProjectRoutingId: deterministic + per-project, leaks no repo name', () => {
  const r1 = rid(SEED_A, IDP);
  assert.equal(r1, rid(SEED_A, IDP), 'every agent recomputes the same id');
  assert.notEqual(r1, rid(SEED_A, SDK), 'distinct per repo');
  assert.match(r1, /^[0-9a-f]{64}$/, 'opaque sha256 hex');
  assert.ok(!r1.includes('github') && !r1.includes('idp'), 'no repo name in the id');
  assert.notEqual(rid(SEED_A, IDP), rid(SEED_B, IDP), 'distinct per operator');
});

// ── content key (keyed by routing id) ──────────────────────────────

test('deriveProjectContentKey: deterministic, 32 bytes, keyed by routing id', () => {
  const r = rid(SEED_A, IDP);
  const k1 = deriveProjectContentKey(SEED_A, r);
  const k2 = deriveProjectContentKey(SEED_A, r);
  assert.equal(k1.length, 32);
  assert.ok(k1.equals(k2));
});

test('deriveProjectContentKey: different routing id / seed → different key', () => {
  assert.ok(!deriveProjectContentKey(SEED_A, rid(SEED_A, IDP)).equals(deriveProjectContentKey(SEED_A, rid(SEED_A, SDK))));
  assert.ok(!deriveProjectContentKey(SEED_A, rid(SEED_A, IDP)).equals(deriveProjectContentKey(SEED_B, rid(SEED_A, IDP))));
});

test('deriveProjectContentKey: negative — bad seed / empty routing id rejected', () => {
  assert.throws(() => deriveProjectContentKey(Buffer.alloc(16), rid(SEED_A, IDP)), /32-byte/);
  assert.throws(() => deriveProjectContentKey(SEED_A, ''), /non-empty/);
});

// ── round-trip + the circular-break read path ──────────────────────

test('encrypt/decrypt: round-trips under the routing-id-keyed content key', () => {
  const r = rid(SEED_A, IDP);
  const env = encryptProjectContent(SEED_A, r, 'the idp listener is the single MLS writer');
  assert.equal(decryptProjectContent(SEED_A, r, env).toString('utf8'), 'the idp listener is the single MLS writer');
});

test('READ PATH: a reader with ONLY the routing_id decrypts and recovers project_key from inside', () => {
  // Writer: knows project_key → routing_id → encrypts content that CONTAINS
  // project_key (so the reader can scope it locally after decrypting).
  const writerRid = rid(SEED_A, IDP);
  const env = encryptProjectJson(SEED_A, writerRid, { project_key: IDP, claim: 'single MLS writer per scope' });
  // Reader: has the seed + the record's plaintext routing_id ONLY (no repo
  // name). Derives the key from routing_id, decrypts, THEN learns project_key.
  const recovered = decryptProjectJson(SEED_A, writerRid, env);
  assert.equal(recovered.project_key, IDP, 'project_key recovered from inside the ciphertext');
  assert.equal(recovered.claim, 'single MLS writer per scope');
});

test('POSITIVE (point of B): a DIFFERENT agent with the SAME seed reads it (recomputing routing_id)', () => {
  const env = encryptProjectJson(SEED_A, rid(SEED_A, IDP), { project_key: IDP, claim: 'shared' });
  // Agent #2: same operator seed, recomputes routing_id from the repo it's in.
  const seedForAgent2 = Buffer.from(SEED_A);
  assert.deepEqual(decryptProjectJson(seedForAgent2, rid(seedForAgent2, IDP), env), { project_key: IDP, claim: 'shared' });
});

// ── negatives: confidentiality boundaries ──────────────────────────

test('NEGATIVE: a DIFFERENT repo routing id cannot decrypt (no cross-repo read)', () => {
  const env = encryptProjectContent(SEED_A, rid(SEED_A, IDP), 'idp-only secret');
  assert.throws(() => decryptProjectContent(SEED_A, rid(SEED_A, SDK), env), /Unsupported state|tag|decrypt/i);
});

test('NEGATIVE: a different operator seed cannot decrypt (other tenant)', () => {
  const r = rid(SEED_A, IDP);
  const env = encryptProjectContent(SEED_A, r, 'operator A project memory');
  // SEED_B can't derive the same content key even with the same routing id.
  assert.throws(() => decryptProjectContent(SEED_B, r, env), /Unsupported state|tag|decrypt/i);
});

test('NEGATIVE: tampered ciphertext fails the GCM tag', () => {
  const r = rid(SEED_A, IDP);
  const env = encryptProjectContent(SEED_A, r, 'integrity-protected');
  env[env.length - 1] ^= 0xff;
  assert.throws(() => decryptProjectContent(SEED_A, r, env), /Unsupported state|tag|decrypt/i);
});
