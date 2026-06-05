/**
 * L5 — the MLS device_id is PINNED at provisioning, with the legacy `ad-`
 * derivation as the no-flag-day fallback.
 *
 * Gates locked here:
 *   1. EXISTING AGENTS WORKING (no-flag-day) — an agent with no persisted
 *      device_id resolves to byte-for-byte the SAME `ad-` it derives today,
 *      for both the P-256 and the Ed25519 (legacy) fleet. Until an agent is
 *      reissued machine-bound, nothing about its device_id changes.
 *   2. PINNED md- WINS — a reissued machine-bound agent uses the persisted
 *      `md-…` verbatim, even though the same slot seed would derive a
 *      different `ad-…`.
 *   3. SINGLE SOURCE / AGREEMENT — KeyPackage publish stamps the device_id it
 *      reads from the MLS handle (`mls.deviceId`), never an independent
 *      re-derivation, so the KP and the credential cannot disagree (the
 *      multi-device two-sources class, mem_01KST27).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import {
  resolveAgentDeviceId,
  deriveAgentDeviceId,
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';
import { machineDeviceIdFromP256Jwk } from '../lib/agent-device-id.js';
import { publishAgentKeyPackage } from '../lib/mls-publish.js';

const P256_KAT_DID = 'did:lastid:agent:zDnaeycdPRAMt7QPrLLcYHLiY2wnf1bVMMU1Aqvg4724k8ToE';
const MACHINE_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '7QzUQKKfT8idSUWe6yEMhAhyCylEwH4BI1AUWsn4TAk',
  y: 'CFK9En0kVMCifo6MSOiM7TKaVuLj62Kiyh7j_fHKvdU',
};

// ── GATE 1: existing agents working (no-flag-day) ─────────────────────────

test('GATE: a P-256 agent with NO persisted device_id resolves to today\'s ad- byte-for-byte', () => {
  const slotSeed = Buffer.alloc(32, 42);
  const resolved = resolveAgentDeviceId({
    persistedDeviceId: null,
    slotSeed,
    agentDid: P256_KAT_DID,
  });
  assert.equal(resolved, deriveAgentDeviceId(slotSeed, P256_KAT_DID));
  assert.ok(resolved.startsWith('ad-'));
});

test('GATE: an existing Ed25519 agent with NO persisted device_id keeps its Ed25519 ad-', () => {
  const slotSeed = Buffer.alloc(32, 0x42);
  const edDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
  assert.ok(edDid.startsWith('did:lastid:agent:z6Mk'));
  const resolved = resolveAgentDeviceId({ persistedDeviceId: null, slotSeed, agentDid: edDid });
  // Byte-for-byte the legacy Ed25519 device-id — the no-flag-day seam for the
  // existing fleet (mem_01KTAGN9: existing live agents are Ed25519).
  assert.equal(resolved, deriveAgentDeviceId(slotSeed, edDid));
  assert.ok(resolved.startsWith('ad-'));
});

test('empty-string persisted device_id is treated as absent → legacy fallback', () => {
  const slotSeed = Buffer.alloc(32, 7);
  assert.equal(
    resolveAgentDeviceId({ persistedDeviceId: '', slotSeed, agentDid: P256_KAT_DID }),
    deriveAgentDeviceId(slotSeed, P256_KAT_DID),
  );
});

// ── GATE 2: pinned md- wins ───────────────────────────────────────────────

test('GATE: a persisted md- is used verbatim, overriding the seed-derived ad-', () => {
  const slotSeed = Buffer.alloc(32, 42);
  const machineMd = machineDeviceIdFromP256Jwk(MACHINE_JWK); // md-1ef73378…
  const resolved = resolveAgentDeviceId({
    persistedDeviceId: machineMd,
    slotSeed,
    agentDid: P256_KAT_DID,
  });
  assert.equal(resolved, machineMd);
  assert.ok(resolved.startsWith('md-'));
  // The pin overrides derivation: this seed's ad- is a DIFFERENT value.
  assert.notEqual(resolved, deriveAgentDeviceId(slotSeed, P256_KAT_DID));
});

// ── GATE 3: single source — KP publish reads the device_id from the handle ─

test('GATE: publishAgentKeyPackage stamps the KP device_id from the handle, not a re-derivation', async () => {
  const slotSeed = Buffer.alloc(32, 42);
  // A machine-bound handle reports an md- that is NOT what this seed derives as
  // ad-. If publish re-derived (the old two-sources bug) the KP would carry the
  // wrong ad- id; reading mls.deviceId is the single source that prevents it.
  const HANDLE_MD = machineDeviceIdFromP256Jwk(MACHINE_JWK);
  assert.notEqual(HANDLE_MD, deriveAgentDeviceId(slotSeed, P256_KAT_DID));

  const fakeMls = {
    deviceId: HANDLE_MD,
    generateKeyPackage: async () => 'kp-b64',
    persist: async () => {},
  };
  let capturedBody = null;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    capturedBody = JSON.parse(init.body);
    return { ok: true, json: async () => ({ refs: ['r1'] }), text: async () => '' };
  };
  try {
    await publishAgentKeyPackage({
      idpUrl: 'http://idp.test',
      agentDid: P256_KAT_DID,
      vcCompact: 'vc-compact',
      slotSeed,
      scope: 'main',
      mls: fakeMls,
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  const kps = capturedBody?.key_packages ?? [];
  assert.ok(kps.length >= 2, 'expected regular + last-resort KeyPackages');
  for (const kp of kps) {
    assert.equal(kp.device_id, HANDLE_MD, 'every KP device_id must equal mls.deviceId');
    assert.equal(kp.cred_version, 2);
  }
});
