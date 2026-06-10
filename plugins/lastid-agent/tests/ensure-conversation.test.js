/**
 * ensureConversation (lib/ensure-conversation.js) — the agent-initiated
 * self-heal, now a thin wrapper over the shared wasm `MlsOrchestrator`.
 * Locks the contract:
 *   - reuse an existing group with the operator (never fork),
 *   - else delegate to the orchestrator (startDirectChat) and persist
 *     the IdP UUID ↔ openmls id mapping so the send path resolves it,
 *   - bubble a clear error when the orchestrator returns no group ids,
 *   - require an operatorDid.
 *
 * Phase C2: the per-device addMember loop moved into the wasm core; the
 * old tests for "addMember-per-device" + "no key packages" are now
 * covered by the Rust unit tests for `commit_ops::*`. Here we only
 * lock the JS-side glue.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ensureConversation } from '../lib/ensure-conversation.js';

const BASE = {
  scope: 'main',
  agentDid: 'did:lastid:agent:zAgent',
  operatorDid: 'did:lastid:zOperator',
  idpUrl: 'https://idp.test',
  vcCompact: 'vc',
  signingKey: {},
};

/** Build a fake orchestrator + capture every call against it. */
function fakeOrchestrator(result, calls = {}) {
  return {
    async startDirectChat(peerDid) {
      calls.startDirectChat = { peerDid };
      if (result instanceof Error) throw result;
      return result;
    },
    async reconcileMemberDevices() {
      throw new Error('reconcileMemberDevices should not be called here');
    },
  };
}

test('reuses an existing group with the operator (never forks)', async () => {
  const existing = { idpGroupId: 'g-existing', groupIdB64: 'gid', operatorDid: BASE.operatorDid };
  const orchestratorCalls = {};
  const out = await ensureConversation({
    ...BASE,
    deps: {
      resolveActiveGroupForOperator: async () => existing,
      // Orchestrator + recordGroup must NOT be touched on the reuse path.
      getOrchestrator: async () => fakeOrchestrator({}, orchestratorCalls),
      recordGroup: async () => assert.fail('should not record'),
    },
  });
  assert.deepEqual(out, existing);
  assert.deepEqual(orchestratorCalls, {}); // never even constructed the orchestrator
});

test('delegates to the orchestrator + records the mapping when no group exists', async () => {
  const orchestratorCalls = {};
  let recordArgs;
  const out = await ensureConversation({
    ...BASE,
    deps: {
      resolveActiveGroupForOperator: async () => null,
      getOrchestrator: async () =>
        fakeOrchestrator(
          {
            idp_group_id: 'idp-uuid-1',
            local_group_id: 'NEWGID',
            member_count: 2,
            epoch: 1,
            peer_device_ids: ['devA', 'devB'],
          },
          orchestratorCalls,
        ),
      recordGroup: async (a) => {
        recordArgs = a;
      },
    },
  });

  assert.deepEqual(out, {
    idpGroupId: 'idp-uuid-1',
    groupIdB64: 'NEWGID',
    operatorDid: BASE.operatorDid,
  });
  // The orchestrator was driven once, with the operator did.
  assert.deepEqual(orchestratorCalls.startDirectChat, { peerDid: BASE.operatorDid });
  // The IdP UUID ↔ openmls mapping was persisted (the send path resolves
  // against this) — operator-scoped, with the device ids the orchestrator
  // surfaced.
  assert.equal(recordArgs.idpGroupId, 'idp-uuid-1');
  assert.equal(recordArgs.groupIdB64, 'NEWGID');
  assert.equal(recordArgs.operatorDid, BASE.operatorDid);
  assert.deepEqual(recordArgs.deviceIds, ['devA', 'devB']);
});

test('throws when the orchestrator returns no group ids', async () => {
  await assert.rejects(
    () =>
      ensureConversation({
        ...BASE,
        deps: {
          resolveActiveGroupForOperator: async () => null,
          getOrchestrator: async () => fakeOrchestrator({ /* no ids */ }),
          recordGroup: async () => assert.fail('should not record without ids'),
        },
      }),
    /no group ids/,
  );
});

test('requires an operatorDid', async () => {
  await assert.rejects(
    () => ensureConversation({ ...BASE, operatorDid: '', deps: {} }),
    /operatorDid required/,
  );
});

// ── Broker-native branch (G2): the agent-initiated self-heal for a
//    brokerNative && zDn agent routes THROUGH THE BROKER and NEVER builds a
//    node wasm orchestrator (a second openmls instance over the same sealed
//    keystore = state corruption). Detected via ctx.useBrokerMls. ──────────────

/** A fake broker MLS client recording ensureDirectGroup calls. */
function fakeBrokerMls(result, calls = {}) {
  return {
    async ensureDirectGroup(peerDid) {
      calls.ensureDirectGroup = { peerDid };
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

test('broker-native: calls mls.ensureDirectGroup + recordGroup, NEVER getOrchestrator', async () => {
  const brokerCalls = {};
  let recordArgs;
  const out = await ensureConversation({
    ...BASE,
    // Broker-native: the signing key is null by design (broker injects auth).
    signingKey: null,
    mls: fakeBrokerMls(
      { idp_group_id: 'idp-broker-1', local_group_id: 'BROKERGID', existing: false },
      brokerCalls,
    ),
    ctx: { useBrokerMls: true },
    deps: {
      resolveActiveGroupForOperator: async () => null,
      // The GUARD: getOrchestrator must NEVER be reached on the broker path.
      getOrchestrator: async () => assert.fail('getOrchestrator must not be called for a broker agent'),
      recordGroup: async (a) => {
        recordArgs = a;
      },
    },
  });

  assert.deepEqual(out, {
    idpGroupId: 'idp-broker-1',
    groupIdB64: 'BROKERGID',
    operatorDid: BASE.operatorDid,
  });
  // The broker direct-chat setup was driven once, with the operator did.
  assert.deepEqual(brokerCalls.ensureDirectGroup, { peerDid: BASE.operatorDid });
  // The mapping was persisted the same way the node path does (operator-scoped).
  assert.equal(recordArgs.idpGroupId, 'idp-broker-1');
  assert.equal(recordArgs.groupIdB64, 'BROKERGID');
  assert.equal(recordArgs.operatorDid, BASE.operatorDid);
  assert.deepEqual(recordArgs.deviceIds, [], 'broker owns device membership → node records no device ids');
});

test('broker-native: reuse path still honored (existing group, no broker call)', async () => {
  const existing = { idpGroupId: 'g-existing', groupIdB64: 'gid', operatorDid: BASE.operatorDid };
  const brokerCalls = {};
  const out = await ensureConversation({
    ...BASE,
    signingKey: null,
    mls: fakeBrokerMls({}, brokerCalls),
    ctx: { useBrokerMls: true },
    deps: {
      resolveActiveGroupForOperator: async () => existing,
      getOrchestrator: async () => assert.fail('should not orchestrate'),
      recordGroup: async () => assert.fail('should not record on reuse'),
    },
  });
  assert.deepEqual(out, existing);
  assert.deepEqual(brokerCalls, {}, 'reuse short-circuits before the broker call');
});

test('broker-native: throws when the broker returns no group ids', async () => {
  await assert.rejects(
    () =>
      ensureConversation({
        ...BASE,
        signingKey: null,
        mls: fakeBrokerMls({ /* no ids */ }),
        ctx: { useBrokerMls: true },
        deps: {
          resolveActiveGroupForOperator: async () => null,
          getOrchestrator: async () => assert.fail('must not orchestrate'),
          recordGroup: async () => assert.fail('must not record without ids'),
        },
      }),
    /no group ids/,
  );
});

test('broker-native: throws when mls lacks ensureDirectGroup (misconfigured client)', async () => {
  await assert.rejects(
    () =>
      ensureConversation({
        ...BASE,
        signingKey: null,
        mls: {}, // not a broker client
        ctx: { useBrokerMls: true },
        deps: {
          resolveActiveGroupForOperator: async () => null,
          getOrchestrator: async () => assert.fail('must not orchestrate'),
          recordGroup: async () => assert.fail('must not record'),
        },
      }),
    /requires an MlsBrokerClient/,
  );
});
