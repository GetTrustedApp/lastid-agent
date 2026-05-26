/**
 * reconcileConversationDevices (lib/reconcile-conversation.js) — the agent's
 * device-consistency add path. Locks: only reconciles an existing group;
 * runs the (injected) shared planner; adds the new devices' key packages in
 * one batch + delivers + records; no-ops cleanly; tolerates a missing ledger;
 * and guards against provisioning lag.
 *
 * The planner is injected (the real one runs the shared Rust via wasm — out of
 * scope for a unit test); everything external is a stub.
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

function fakeMls(trace) {
  return {
    addMembers(groupId, kps) {
      trace.push(`addMembers:${groupId}:${kps.join('+')}`);
      return { commit_b64: 'COMMIT', welcome_b64: 'WELCOME', new_epoch: 2 };
    },
    async persist() {
      trace.push('persist');
    },
  };
}

const GROUP = { idpGroupId: 'idp-1', groupIdB64: 'gid', operatorDid: BASE.operatorDid };

test('no-ops when there is no conversation yet', async () => {
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls([]),
    deps: { resolveActiveGroupForOperator: async () => null },
  });
  assert.deepEqual(out, { added: 0, reason: 'no-group' });
});

test('adds a newly-appeared operator device using the shared plan', async () => {
  const trace = [];
  const calls = {};
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({
        keyPackages: [
          { keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' },
          { keyPackageB64: 'KP-B', ref: 'r2', deviceId: 'devB' }, // the new one
        ],
        remainingCount: 0,
      }),
      getGroupDeviceIds: async () => ['devA'],
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: (input) => {
        calls.planInput = input;
        return { backfill_device_ids: null, evict_device_ids: [], add_device_ids: ['devB'], action: 'AddMissingDevices' };
      },
      addGroupMember: async (a) => {
        calls.add = a;
      },
      recordGroup: async (a) => {
        calls.record = a;
      },
    },
  });

  assert.deepEqual(out, { added: 1, addedDeviceIds: ['devB'], evictPending: 0 });
  // Planner saw live (both) + ledger active (devA only).
  assert.deepEqual(calls.planInput.liveDeviceIds, ['devA', 'devB']);
  assert.deepEqual(calls.planInput.activeInGroup, ['devA']);
  // Only devB's key package was batch-added, in one commit.
  assert.deepEqual(trace, ['addMembers:gid:KP-B', 'persist']);
  // Welcome delivered to the operator; record now covers both devices.
  assert.equal(calls.add.mlsWelcomeB64, 'WELCOME');
  assert.deepEqual(calls.record.deviceIds, ['devA', 'devB']);
});

test('no-ops when the plan finds nothing to add', async () => {
  const trace = [];
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA'],
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: () => ({ backfill_device_ids: null, evict_device_ids: [], add_device_ids: [], action: 'NoOp' }),
    },
  });
  assert.deepEqual(out, { added: 0, evictPending: 0 });
  assert.deepEqual(trace, []); // no MLS change
});

test('falls back to the local record when the ledger fetch fails', async () => {
  const trace = [];
  const calls = {};
  await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }, { keyPackageB64: 'KP-B', ref: 'r2', deviceId: 'devB' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA'],
      fetchGroupMemberDevices: async () => {
        throw new Error('403 forbidden');
      },
      computeMemberReconcilePlan: (input) => {
        calls.planInput = input;
        return { backfill_device_ids: null, evict_device_ids: [], add_device_ids: ['devB'], action: 'AddMissingDevices' };
      },
      addGroupMember: async () => {},
      recordGroup: async () => {},
    },
  });
  // active falls back to the recorded set.
  assert.deepEqual(calls.planInput.activeInGroup, ['devA']);
  assert.deepEqual(trace, ['addMembers:gid:KP-B', 'persist']);
});

test('guards against provisioning lag (plan wants a device with no key package)', async () => {
  const trace = [];
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA'],
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      // Plan names devZ, but no key package was fetched for it.
      computeMemberReconcilePlan: () => ({ backfill_device_ids: null, evict_device_ids: [], add_device_ids: ['devZ'], action: 'AddMissingDevices' }),
    },
  });
  assert.deepEqual(out, { added: 0, reason: 'no-keypackages-for-missing' });
  assert.deepEqual(trace, []); // nothing applied
});
