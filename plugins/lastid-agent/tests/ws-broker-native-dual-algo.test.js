/**
 * DUAL-ALGO WS-CONNECT parity — the reason a broker-native P-256 (`zDn…`)
 * agent goes dark on group-chat while an Ed25519 (`z6Mk…`) agent works.
 *
 * The inbound DECRYPT path (MlsDispatcher → wasm) is dual-algo clean — proven
 * in tests/mls-dual-algo-inbound.test.js (Ed25519, P-256, and cross-algo all
 * decrypt). So a P-256 agent that never "receives group-chat events" is NOT
 * failing at decrypt; it never gets the frames because its WEBSOCKET never
 * opens.
 *
 * The branch that decides how the WS upgrade is authenticated:
 *
 *   cli.js cmdListen:
 *     brokerNative      → signingKey = null   (seed lives only in the broker)
 *     legacy / Ed25519  → signingKey = deriveAgentKeypair(...).signingKey
 *     brokerWs = brokerWsEligible({ brokerNative, agentDid })   // true ONLY for
 *                                                                // zDn + native
 *   ws-client.js #openSocket (per connect):
 *     if (brokerWs && brokerSocketExistsSync(scope))  → broker mints the auth
 *     else                                            → mintDpopJwt({ signingKey })
 *
 * THE TRAP: when `brokerWs` is true but the broker socket is NOT up at connect
 * time (broker still starting, crashed, or never installed), `#openSocket`
 * falls through to `mintDpopJwt({ signingKey: null })`. `mintDpopJwt`
 * feature-detects the algo from the key and, on a null key, takes the ES256
 * `else` branch → `crypto.sign('sha256', …, { key: null })` THROWS. The throw
 * propagates out of `#openSocket`; the socket never opens; no `group_chat.*`
 * frame ever reaches the dispatcher. The agent is dark — exactly the reported
 * symptom — and the cause is the connection auth branch, not decrypt.
 *
 * An Ed25519 agent is never broker-native (the broker is P-256-only) so it
 * always has a real node `signingKey` and mints its DPoP fine.
 *
 * This test reproduces the asymmetry against the REAL helpers
 * (`brokerWsEligible`, `mintDpopJwt`) and the REAL cli.js signingKey-selection
 * rule, with the broker treated as DOWN (the hermetic default — no broker
 * socket exists for a random scope).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { brokerWsEligible } from '../lib/ws-client.js';
import { mintDpopJwt } from '../lib/dpop.js';
import { brokerSocketExistsSync } from '../lib/broker-ipc.js';
import {
  deriveAgentKeypair,
  deriveAgentEd25519Keypair,
  deriveAgentP256Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';

/**
 * Mirror cli.js cmdListen's signingKey selection EXACTLY:
 *   brokerNative ⇒ null (seed only in the broker); else derive from the seed.
 * (cli.js:1200-1208 / 1375-1386.)
 */
function listenerSigningKey({ brokerNative, slotSeed, agentDid }) {
  if (brokerNative) return null;
  return deriveAgentKeypair(slotSeed, agentDid).signingKey;
}

/**
 * Mirror ws-client.js #openSocket's connect-auth decision. Returns the minted
 * DPoP proof for the node path, or the sentinel 'BROKER' when the broker path
 * is taken. THROWS exactly where the real #openSocket throws — when it falls
 * through to mintDpopJwt with a null key.
 */
function openSocketAuth({ brokerWs, scope, agentDid, signingKey }) {
  if (brokerWs && brokerSocketExistsSync(scope)) return 'BROKER';
  // else → node mints the upgrade DPoP (this is the real line ws-client.js:266)
  return mintDpopJwt({
    agentDid,
    httpMethod: 'GET',
    httpUri: 'https://human.lastid.co/v1/ws',
    signingKey,
  });
}

const seed = (b) => Buffer.alloc(32, b);
// A scope with no broker socket → brokerSocketExistsSync(scope) === false.
const NO_BROKER_SCOPE = `dual-algo-test-${process.pid}-${Date.now()}`;

test('sanity: no broker socket exists for the test scope (broker is DOWN)', () => {
  assert.equal(brokerSocketExistsSync(NO_BROKER_SCOPE), false);
});

test('Ed25519 (z6Mk…) agent: never broker-native → mints a real DPoP, WS opens', () => {
  const slotSeed = seed(0x11);
  const agentDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
  assert.ok(agentDid.startsWith('did:lastid:agent:z6Mk'));

  // Ed25519 can't be served by the P-256-only broker → brokerNative false.
  const brokerNative = false;
  const signingKey = listenerSigningKey({ brokerNative, slotSeed, agentDid });
  assert.ok(signingKey, 'Ed25519 agent must have a node signing key');

  const brokerWs = brokerWsEligible({ brokerNative, agentDid });
  assert.equal(brokerWs, false, 'Ed25519 agent must NOT be eligible for the broker WS');

  // #openSocket mints a DPoP and proceeds — the WS connects, frames flow.
  const proof = openSocketAuth({ brokerWs, scope: NO_BROKER_SCOPE, agentDid, signingKey });
  assert.match(proof, /^[\w-]+\.[\w-]+\.[\w-]+$/, 'expected a 3-part DPoP JWT');
  // Header alg is EdDSA for the Ed25519 key.
  const header = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString('utf-8'));
  assert.equal(header.alg, 'EdDSA');
});

test('REPRO: broker-native P-256 (zDn…) agent with broker DOWN → WS connect THROWS (agent goes dark)', () => {
  const slotSeed = seed(0x22);
  const agentDid = deriveAgentP256Keypair(slotSeed).agentDid;
  assert.ok(agentDid.startsWith('did:lastid:agent:zDn'));

  // Broker-native: seed lives only in the broker, node holds NO signing key.
  const brokerNative = true;
  const signingKey = listenerSigningKey({ brokerNative, slotSeed, agentDid });
  assert.equal(signingKey, null, 'broker-native agent must have NO node signing key');

  const brokerWs = brokerWsEligible({ brokerNative, agentDid });
  assert.equal(brokerWs, true, 'broker-native P-256 agent IS eligible for the broker WS');

  // Broker is DOWN at connect time → #openSocket falls through to
  // mintDpopJwt({ signingKey: null }) → ES256 sign with a null key → THROWS.
  // The socket never opens; the dispatcher never sees a single group_chat
  // frame. THIS is the reproduced dual-algo defect.
  assert.throws(
    () => openSocketAuth({ brokerWs, scope: NO_BROKER_SCOPE, agentDid, signingKey }),
    (err) => {
      // The throw is the null-key crypto failure inside mintDpopJwt's ES256
      // branch — NOT a clean "broker down, retry later" classification.
      assert.ok(err instanceof Error, `expected an Error, got ${err}`);
      return true;
    },
    'broker-native P-256 WS connect should throw on the null-key DPoP mint',
  );
});

test('CONTRAST: the SAME P-256 agent, if node held the seed, would mint a DPoP fine', () => {
  // Proves the failure is the null signingKey (custody/branch), not anything
  // intrinsic to P-256 — a seed-in-node P-256 agent mints an ES256 DPoP and
  // connects. So the fix is to never reach mintDpopJwt with a null key on the
  // broker-native path (e.g. block/await the broker, or surface a clean
  // broker-down retry instead of a crash).
  const slotSeed = seed(0x22);
  const agentDid = deriveAgentP256Keypair(slotSeed).agentDid;
  const signingKey = deriveAgentKeypair(slotSeed, agentDid).signingKey; // node holds it
  assert.ok(signingKey);
  const proof = openSocketAuth({
    brokerWs: false, // seed-in-node ⇒ legacy direct WS
    scope: NO_BROKER_SCOPE,
    agentDid,
    signingKey,
  });
  const header = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString('utf-8'));
  assert.equal(header.alg, 'ES256', 'P-256 key mints an ES256 DPoP');
});
