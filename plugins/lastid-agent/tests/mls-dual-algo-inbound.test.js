/**
 * DUAL-ALGO inbound group-chat parity — drive a REAL MLS welcome + message
 * through the REAL inbound handler (MlsDispatcher.onEvent → MlsClient →
 * vendored wasm) once for an Ed25519 (`z6Mk…`) agent and once for a P-256
 * (`zDn…`) agent.
 *
 * The operator suspects the inbound WS-message handler falls into the Ed25519
 * case (or a silently-failing ES256 case) so broker-native (P-256) agents
 * never receive/decrypt group-chat events. This test builds the actual flow:
 *
 *   operator MLS client  --createGroup--> add agent's KeyPackage
 *        |                                       |
 *     welcome_b64 + commit                   message ciphertext
 *        |                                       |
 *        v                                       v
 *   agent's MlsDispatcher.onEvent('group_chat.welcome')  (REAL handler)
 *   agent's MlsDispatcher.onEvent('group_chat.message')  (REAL handler)
 *        |
 *        v
 *   ~/.lastid-agent/<scope>/operator-inbox.jsonl  (decrypted envelope landed?)
 *
 * Pass condition: the operator's plaintext envelope decrypts and lands in the
 * agent's inbox. If the P-256 case fails where the Ed25519 case passes, the
 * dual-algo bug is reproduced at the exact hop.
 *
 * Hermetic: HOME is pointed at a per-test temp dir so each agent's sealed
 * mls-state.b64 is isolated; the real vendored wasm does the crypto; no IdP
 * network, no broker.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { MlsClient } from '../lib/mls-client.js';
import { MlsDispatcher, operatorInboxPath } from '../lib/mls-dispatch.js';
import {
  deriveAgentEd25519Keypair,
  deriveAgentP256Keypair,
  agentDidFromPublicJwk,
} from '../lib/agent-provisioning.js';

const ORIG_HOME = process.env.HOME;

// Distinct 32-byte seeds so the operator and the agent never collide on the
// sealed-state path (path is HOME/.lastid-agent/<scope>/mls-state.b64 and we
// give each role its own scope too).
function seed(byte) {
  return Buffer.alloc(32, byte);
}

/**
 * Reserve a fresh openmls group id (16 bytes, base64). Mirrors what the
 * console/agent does before createGroup.
 */
function freshGroupIdB64() {
  return Buffer.from(randomUUID().replace(/-/g, ''), 'hex').toString('base64');
}

/**
 * One full inbound run for a given operator DID + agent DID pair. Builds a real
 * group on the operator's wasm client, adds the agent via its real KeyPackage,
 * then feeds the resulting welcome + an encrypted application message through
 * the agent's REAL MlsDispatcher. Returns the parsed inbox lines the dispatcher
 * wrote (the decrypted envelopes the operator would have received).
 */
async function runInbound({ home, operatorDid, agentDid, operatorSeed, agentSeed }) {
  process.env.HOME = home;
  const operatorScope = 'operator';
  const agentScope = 'agent';

  // Real wasm-backed clients sealed to isolated temp paths.
  const operator = await MlsClient.open({
    agentDid: operatorDid,
    slotSeed: operatorSeed,
    scope: operatorScope,
  });
  const agent = await MlsClient.open({
    agentDid,
    slotSeed: agentSeed,
    scope: agentScope,
  });

  // Agent publishes a KeyPackage (its inbound identity for the group).
  const agentKpB64 = await agent.generateKeyPackage();

  // Operator authors a group and adds the agent in one commit → welcome.
  const groupIdB64 = freshGroupIdB64();
  await operator.createGroup(groupIdB64);
  const added = await operator.addMember(groupIdB64, agentKpB64);
  assert.equal(typeof added.welcome_b64, 'string', 'operator did not produce a welcome');

  // Operator encrypts an application message for the group.
  const envelope = { t: 'text', body: 'ping from operator', v: 1 };
  const plaintextB64 = Buffer.from(JSON.stringify(envelope), 'utf-8').toString('base64');
  const messageB64 = await operator.encryptApplicationMessage(groupIdB64, plaintextB64);
  assert.equal(typeof messageB64, 'string', 'operator did not produce a ciphertext');

  // Wire the agent's REAL dispatcher (the same class cli.js cmdListen uses).
  const logs = [];
  const idpGroupId = randomUUID();
  const dispatcher = new MlsDispatcher({
    mls: agent,
    scope: agentScope,
    log: (l) => logs.push(l),
    requestSend: () => {}, // swallow fetch_queue requests
  });

  // Drive the ACTUAL inbound entry point: onEvent, exactly the WS frames the
  // IdP would fan out — welcome first, then the live message.
  await dispatcher.onEvent({
    type: 'group_chat.welcome',
    payload: {
      mls_welcome: added.welcome_b64,
      group_id: idpGroupId,
      inviter_did: operatorDid,
    },
  });
  await dispatcher.onEvent({
    type: 'group_chat.message',
    payload: {
      mls_message: messageB64,
      group_id: idpGroupId,
      sender_did: operatorDid,
    },
  });

  // Read what the dispatcher decrypted into the agent's inbox.
  const inboxFile = operatorInboxPath(agentScope);
  let lines = [];
  try {
    const raw = await readFile(inboxFile, 'utf-8');
    lines = raw
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  operator.free();
  agent.free();
  return { lines, logs, idpGroupId };
}

test('DUAL-ALGO: Ed25519 (z6Mk…) agent decrypts an operator group_chat.message', async () => {
  const home = await mkdtemp(join(tmpdir(), 'lastid-ed25519-'));
  try {
    const operatorSeed = seed(11);
    const agentSeed = seed(22);
    // Operator + agent both Ed25519 identities (the working legacy fleet).
    const operatorDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(operatorSeed).publicJwk);
    const agentDid = agentDidFromPublicJwk(deriveAgentEd25519Keypair(agentSeed).publicJwk);
    assert.ok(operatorDid.startsWith('did:lastid:agent:z6Mk'), 'operator DID not Ed25519');
    assert.ok(agentDid.startsWith('did:lastid:agent:z6Mk'), 'agent DID not Ed25519');

    const { lines, logs } = await runInbound({
      home,
      operatorDid,
      agentDid,
      operatorSeed,
      agentSeed,
    });

    assert.equal(
      lines.length,
      1,
      `Ed25519 agent inbox should have exactly 1 decrypted message, got ${lines.length}. logs:\n${logs.join('\n')}`,
    );
    assert.equal(lines[0].envelope.t, 'text');
    assert.equal(lines[0].envelope.body, 'ping from operator');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('DUAL-ALGO: P-256 (zDn…) agent decrypts an operator group_chat.message', async () => {
  const home = await mkdtemp(join(tmpdir(), 'lastid-p256-'));
  try {
    const operatorSeed = seed(33);
    const agentSeed = seed(44);
    // Operator + agent both P-256 identities (broker-native fleet).
    const operatorDid = deriveAgentP256Keypair(operatorSeed).agentDid;
    const agentDid = deriveAgentP256Keypair(agentSeed).agentDid;
    assert.ok(operatorDid.startsWith('did:lastid:agent:zDn'), 'operator DID not P-256');
    assert.ok(agentDid.startsWith('did:lastid:agent:zDn'), 'agent DID not P-256');

    const { lines, logs } = await runInbound({
      home,
      operatorDid,
      agentDid,
      operatorSeed,
      agentSeed,
    });

    assert.equal(
      lines.length,
      1,
      `P-256 agent inbox should have exactly 1 decrypted message, got ${lines.length}. logs:\n${logs.join('\n')}`,
    );
    assert.equal(lines[0].envelope.t, 'text');
    assert.equal(lines[0].envelope.body, 'ping from operator');
  } finally {
    process.env.HOME = ORIG_HOME;
    await rm(home, { recursive: true, force: true });
  }
});

test.after(() => {
  process.env.HOME = ORIG_HOME;
});
