/**
 * Seed-custody invariant (mem_01KTQK1E): node may hold/use slot-seed material ONLY
 * for a legacy Ed25519 (z6Mk) agent. EVERY P-256/ES256 (zDn) agent is broker-sole
 * custody — node NEVER uses its seed, even if a stale copy is physically present in
 * the keychain.
 *
 * Regression for the live bug (test-logdiver agent zDnaetPg, 2026-06-09): the
 * operator's vault share was undecryptable ("Unsupported state or unable to
 * authenticate data" — node:crypto AES-GCM tag failure) because loadAgentVc keyed
 * custody off `slotSeed === null` (seed-PRESENCE), so a P-256 agent that still had
 * a leftover keychain seed was mis-classified as a legacy node agent and the vault
 * decrypt ran in node with a STALE key instead of routing to the broker.
 *
 * deriveSeedCustody is the pure load-bearing decision (no keychain mock needed).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveSeedCustody, seedAlgoFromDid } from '../lib/keychain.js';
import { agentKeyTypeFromDid } from '../lib/agent-provisioning.js';

const ED25519_DID = 'did:lastid:agent:z6Mkr42bS9SV2ffKGH2AsMDnkPYx5qDmXPicfwBDx5BSPke2';
const P256_DID = 'did:lastid:agent:zDnaetPgXJw4WJFeJoJKzsyjNbf36QPQpTkKdBuLkXXCKauef';
const SEED = Buffer.alloc(32, 0x07);
const PRS = Buffer.alloc(32, 0x09);

// ── The headline regression: a P-256 agent NEVER uses a node seed ──────────────

test('P-256 agent with a STALE keychain seed → slotSeed dropped, broker-native', () => {
  // The exact failing shape: a zDn agent that still has 32 seed bytes sitting in
  // the keychain. Before the fix this returned the seed (node path → stale key →
  // AEAD failure). It MUST now be dropped so vault/content decrypt routes to the
  // broker (the sole correct seed holder).
  const c = deriveSeedCustody(P256_DID, SEED, PRS);
  assert.equal(c.algo, 'p256');
  assert.equal(c.slotSeed, null, 'P-256 node seed must be dropped even when present');
  assert.equal(c.projectRootSeed, null, 'P-256 project seed must be dropped too');
  assert.equal(c.brokerNative, true);
});

test('P-256 agent with no keychain seed → broker-native, null seeds', () => {
  const c = deriveSeedCustody(P256_DID, null, null);
  assert.equal(c.slotSeed, null);
  assert.equal(c.projectRootSeed, null);
  assert.equal(c.brokerNative, true);
});

// ── Legacy Ed25519 agents are unchanged (node keeps the seed) ──────────────────

test('Ed25519 agent with a keychain seed → keeps node seed, NOT broker-native', () => {
  const c = deriveSeedCustody(ED25519_DID, SEED, PRS);
  assert.equal(c.algo, 'ed25519');
  assert.equal(Buffer.isBuffer(c.slotSeed), true);
  assert.equal(c.slotSeed.equals(SEED), true);
  assert.equal(c.projectRootSeed.equals(PRS), true);
  assert.equal(c.brokerNative, false);
});

test('Ed25519 agent with no project seed → slot seed kept, project null', () => {
  const c = deriveSeedCustody(ED25519_DID, SEED, null);
  assert.equal(c.slotSeed.equals(SEED), true);
  assert.equal(c.projectRootSeed, null);
  assert.equal(c.brokerNative, false);
});

// ── DID-absent fallback (very old bundles) keys off seed-presence ──────────────

test('no DID + a seed present → treated as legacy Ed25519 (keeps seed)', () => {
  const c = deriveSeedCustody(null, SEED, null);
  assert.equal(c.algo, 'ed25519');
  assert.equal(c.slotSeed.equals(SEED), true);
  assert.equal(c.brokerNative, false);
});

test('no DID + no seed → broker-native', () => {
  const c = deriveSeedCustody(null, null, null);
  assert.equal(c.algo, 'p256');
  assert.equal(c.slotSeed, null);
  assert.equal(c.brokerNative, true);
});

// ── The discriminator itself, and it must never drift from the canonical one ───

test('seedAlgoFromDid: z6Mk → ed25519, zDn → p256, junk → p256 (fail safe to broker)', () => {
  assert.equal(seedAlgoFromDid(ED25519_DID), 'ed25519');
  assert.equal(seedAlgoFromDid(P256_DID), 'p256');
  assert.equal(seedAlgoFromDid('did:lastid:agent:zSomethingElse'), 'p256');
  assert.equal(seedAlgoFromDid(''), 'p256');
  assert.equal(seedAlgoFromDid(null), 'p256');
  assert.equal(seedAlgoFromDid(undefined), 'p256');
});

test('seedAlgoFromDid never drifts from the canonical agentKeyTypeFromDid', () => {
  // keychain.js keeps its own inline copy to avoid a backwards dep on the heavy
  // provisioning module; this asserts the two agree so they can never silently
  // diverge (a drift would re-open the mis-classification bug).
  for (const did of [
    ED25519_DID,
    P256_DID,
    'did:lastid:agent:z6MkAnotherEd25519',
    'did:lastid:agent:zDnAnotherP256',
    'did:lastid:agent:zUnknownPrefix',
    'not-a-did',
    '',
  ]) {
    assert.equal(
      seedAlgoFromDid(did),
      agentKeyTypeFromDid(did),
      `drift for ${JSON.stringify(did)}`,
    );
  }
});
