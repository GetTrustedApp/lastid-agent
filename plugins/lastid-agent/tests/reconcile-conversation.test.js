/**
 * reconcileConversationDevices (lib/reconcile-conversation.js) — now a thin
 * wrapper over the shared wasm `MlsOrchestrator.reconcileMemberDevices`.
 * Locks:
 *   - no-op when there's no conversation (creating one is ensureConversation's
 *     job),
 *   - delegate to the orchestrator with the resolved idp group id,
 *   - surface a coarse `changed` flag in the backward-compatible return shape,
 *   - require an operatorDid.
 *
 * Phase C2: the per-device plan/add/evict bookkeeping moved into the wasm core
 * (lastid_mls_core::reconcile::reconcile_group_device_membership_once). The
 * detailed planner/leaf/evict tests are now Rust unit tests; this file only
 * locks the JS glue.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reconcileConversationDevices } from '../lib/reconcile-conversation.js';

const BASE = {
  scope: 'main',
  agentDid: 'did:lastid:agent:zAgent',
  operatorDid: 'did:lastid:zOperator',
  idpUrl: 'https://idp.test',
  vcCompact: 'vc',
  signingKey: {},
};

function fakeOrchestrator(result, calls = {}) {
  return {
    async startDirectChat() {
      throw new Error('startDirectChat should not be called here');
    },
    async reconcileMemberDevices(groupId) {
      calls.reconcileMemberDevices = { groupId };
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

const GROUP = { idpGroupId: 'idp-1', groupIdB64: 'gid', operatorDid: BASE.operatorDid };

test('no-ops when there is no conversation yet', async () => {
  const calls = {};
  const out = await reconcileConversationDevices({
    ...BASE,
    deps: {
      resolveActiveGroupForOperator: async () => null,
      getOrchestrator: async () => fakeOrchestrator({ changed: false }, calls),
    },
  });
  assert.deepEqual(out, { added: 0, reason: 'no-group' });
  assert.deepEqual(calls, {}); // never bothered to construct the orchestrator
});

test('delegates to the orchestrator with the resolved IdP group id', async () => {
  const calls = {};
  const out = await reconcileConversationDevices({
    ...BASE,
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      getOrchestrator: async () => fakeOrchestrator({ changed: true }, calls),
    },
  });
  assert.deepEqual(calls.reconcileMemberDevices, { groupId: 'idp-1' });
  // Membership changed → backward-compat `added` reads non-zero.
  assert.equal(out.added, 1);
  assert.equal(out.changed, true);
});

test('surfaces a no-change pass cleanly', async () => {
  const calls = {};
  const out = await reconcileConversationDevices({
    ...BASE,
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      getOrchestrator: async () => fakeOrchestrator({ changed: false }, calls),
    },
  });
  assert.equal(out.added, 0);
  assert.equal(out.changed, false);
  assert.deepEqual(calls.reconcileMemberDevices, { groupId: 'idp-1' });
});

test('requires an operatorDid', async () => {
  await assert.rejects(
    () => reconcileConversationDevices({ ...BASE, operatorDid: '', deps: {} }),
    /operatorDid required/,
  );
});

test('bubbles orchestrator errors', async () => {
  await assert.rejects(
    () =>
      reconcileConversationDevices({
        ...BASE,
        deps: {
          resolveActiveGroupForOperator: async () => GROUP,
          getOrchestrator: async () => fakeOrchestrator(new Error('idp 503')),
        },
      }),
    /idp 503/,
  );
});
