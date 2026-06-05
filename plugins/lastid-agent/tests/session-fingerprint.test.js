/**
 * Tests for the SessionFingerprint plugin path.
 *
 * Covers the wire-shape contract the desktop's /session handler reads
 * (snake_case fields, optional parent_session_id) plus end-to-end sign
 * + verify against the canonical Rust signer via the wasm bridge.
 */
import { test } from 'node:test';
import assert from 'node:assert';

import { initializeSdkBindings } from '../lib/sdk-bindings.js';
import {
  buildUnsignedSessionFingerprint,
  computeProjectFingerprint,
} from '../lib/session-fingerprint.js';
import {
  deriveAgentP256Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';

function fixtureAgent() {
  const slotSeed = Buffer.alloc(32, 7);
  const { signingSeed, publicJwk } = deriveAgentP256Keypair(slotSeed);
  return {
    agentDid: agentDidFromPublicJwk(publicJwk),
    signingSeed,
  };
}

test('computeProjectFingerprint always returns cwd_hash and host_machine_id', () => {
  const fp = computeProjectFingerprint(process.cwd());
  assert.equal(typeof fp.cwd_hash, 'string');
  assert.equal(typeof fp.host_machine_id, 'string');
  assert.ok(fp.cwd_hash.length > 0);
  assert.ok(fp.host_machine_id.length > 0);
});

test('buildUnsignedSessionFingerprint has the wire shape the desktop expects', () => {
  const { agentDid } = fixtureAgent();
  const unsigned = buildUnsignedSessionFingerprint({ agentDid, cwd: process.cwd() });
  assert.ok(/^[0-9a-f-]{36}$/.test(unsigned.session_id));
  assert.equal(unsigned.agent_did, agentDid);
  assert.equal(typeof unsigned.started_at_ms, 'number');
  assert.equal(typeof unsigned.signed_at_ms, 'number');
  assert.equal(unsigned.parent_session_id, null);
  assert.equal(unsigned.signature, '');
  assert.equal(typeof unsigned.project.cwd_hash, 'string');
  assert.equal(typeof unsigned.project.host_machine_id, 'string');
});

test('signSessionFingerprint produces a sig that verifySessionFingerprint accepts', async () => {
  const { agentDid, signingSeed } = fixtureAgent();
  const unsigned = buildUnsignedSessionFingerprint({ agentDid, cwd: process.cwd() });
  const sdk = await initializeSdkBindings();
  const signed = sdk.signSessionFingerprint(signingSeed, unsigned);
  assert.equal(signed.agent_did, agentDid);
  assert.ok(typeof signed.signature === 'string' && signed.signature.length > 0);
  assert.equal(sdk.verifySessionFingerprint(signed), true);
});

test('tampered session_id is rejected by verifySessionFingerprint', async () => {
  const { agentDid, signingSeed } = fixtureAgent();
  const unsigned = buildUnsignedSessionFingerprint({ agentDid, cwd: process.cwd() });
  const sdk = await initializeSdkBindings();
  const signed = sdk.signSessionFingerprint(signingSeed, unsigned);
  const tampered = { ...signed, session_id: '00000000-0000-0000-0000-000000000000' };
  assert.throws(() => sdk.verifySessionFingerprint(tampered));
});

test('tampered project hash is rejected by verifySessionFingerprint', async () => {
  const { agentDid, signingSeed } = fixtureAgent();
  const unsigned = buildUnsignedSessionFingerprint({ agentDid, cwd: process.cwd() });
  const sdk = await initializeSdkBindings();
  const signed = sdk.signSessionFingerprint(signingSeed, unsigned);
  const tampered = {
    ...signed,
    project: { ...signed.project, cwd_hash: 'AAAA' },
  };
  assert.throws(() => sdk.verifySessionFingerprint(tampered));
});

test('two distinct agents produce distinguishable signatures over the same payload', async () => {
  const a = fixtureAgent();
  const b = (() => {
    const slotSeed = Buffer.alloc(32, 8);
    const { signingSeed, publicJwk } = deriveAgentP256Keypair(slotSeed);
    return { agentDid: agentDidFromPublicJwk(publicJwk), signingSeed };
  })();
  assert.notEqual(a.agentDid, b.agentDid);

  const sdk = await initializeSdkBindings();
  // Sign the same nominal session under each identity's view of itself.
  const unsignedA = buildUnsignedSessionFingerprint({ agentDid: a.agentDid, cwd: process.cwd() });
  const unsignedB = buildUnsignedSessionFingerprint({ agentDid: b.agentDid, cwd: process.cwd() });
  const signedA = sdk.signSessionFingerprint(a.signingSeed, unsignedA);
  const signedB = sdk.signSessionFingerprint(b.signingSeed, unsignedB);

  assert.equal(sdk.verifySessionFingerprint(signedA), true);
  assert.equal(sdk.verifySessionFingerprint(signedB), true);

  // Crossing: A's signature on B's payload (different agent_did) must fail
  // because the embedded agent_did won't match the signing key.
  const crossed = { ...signedB, signature: signedA.signature };
  assert.throws(() => sdk.verifySessionFingerprint(crossed));
});
