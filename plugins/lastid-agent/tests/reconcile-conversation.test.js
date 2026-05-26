/**
 * reconcileConversationDevices (lib/reconcile-conversation.js) — the agent's
 * device-consistency reconcile. Locks: only reconciles an existing group;
 * runs the (injected) shared planner; ADDS the missing devices in one batch +
 * submits to member-devices/reconcile + records device→leaf; EVICTS stale
 * devices by their recorded leaf via member-devices/evict; no-ops cleanly;
 * tolerates a missing ledger; guards provisioning lag.
 *
 * The planner is injected (the real one runs the shared Rust via wasm);
 * everything external is a stub.
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
      // Assign leaves 1..n to the added kps, in order.
      return {
        commit_b64: 'ADDC',
        welcome_b64: 'ADDW',
        new_epoch: 3,
        assigned_leaf_indices: kps.map((_, i) => i + 1),
      };
    },
    removeMember(groupId, leaf) {
      trace.push(`removeMember:${groupId}:${leaf}`);
      return { commit_b64: `RMC-${leaf}`, new_epoch: 4 };
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

test('adds new devices (batch), submits to reconcile, records device→leaf', async () => {
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
          { keyPackageB64: 'KP-B', ref: 'r2', deviceId: 'devB' }, // new
        ],
        remainingCount: 0,
      }),
      getGroupDeviceIds: async () => ['devA'],
      getGroupDeviceLeaves: async () => ({ devA: 0 }),
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: () => ({ add_device_ids: ['devB'], evict_device_ids: [] }),
      reconcileMemberDevicesAdd: async (a) => {
        calls.add = a;
      },
      recordGroup: async (a) => {
        calls.record = a;
      },
    },
  });

  assert.deepEqual(out, { added: 1, evicted: 0, addedDeviceIds: ['devB'], evictedDeviceIds: [] });
  assert.deepEqual(trace, ['addMembers:gid:KP-B', 'persist']);
  // Submitted to the device ledger with the new device + expected epoch (new-1).
  assert.equal(calls.add.targetDeviceIds[0], 'devB');
  assert.equal(calls.add.expectedEpoch, 2);
  // Recorded the new device + its assigned leaf (1, from assigned_leaf_indices).
  assert.deepEqual(calls.record.deviceIds, ['devA', 'devB']);
  assert.equal(calls.record.deviceLeaves.devB, 1);
});

test('evicts a stale device by its recorded leaf via member-devices/evict', async () => {
  const trace = [];
  const calls = {};
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({
        keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }],
        remainingCount: 0,
      }),
      getGroupDeviceIds: async () => ['devA', 'devB'],
      // devB sat at leaf 2; it's no longer live → evict it.
      getGroupDeviceLeaves: async () => ({ devA: 0, devB: 2 }),
      fetchGroupMemberDevices: async () => ({
        known: true,
        activeDeviceIds: ['devA', 'devB'],
        pendingDeviceIds: [],
      }),
      computeMemberReconcilePlan: () => ({ add_device_ids: [], evict_device_ids: ['devB'] }),
      evictMemberDevices: async (a) => {
        calls.evict = a;
      },
      recordGroup: async (a) => {
        calls.record = a;
      },
    },
  });

  assert.deepEqual(out, { added: 0, evicted: 1, addedDeviceIds: [], evictedDeviceIds: ['devB'] });
  // Removed leaf 2 (devB's), then submitted the remove-commit to evict.
  assert.deepEqual(trace, ['removeMember:gid:2', 'persist']);
  assert.deepEqual(calls.evict.targetDeviceIds, ['devB']);
  assert.equal(calls.evict.mlsCommitB64, 'RMC-2');
  assert.equal(calls.evict.expectedEpoch, 3);
  // Record drops the evicted device + its leaf.
  assert.deepEqual(calls.record.deviceIds, ['devA']);
  assert.equal(calls.record.deviceLeaves.devB, undefined);
});

test('skips evicting a stale device with no recorded leaf (best-effort)', async () => {
  const trace = [];
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA', 'devZ'],
      getGroupDeviceLeaves: async () => ({ devA: 0 }), // no leaf for devZ
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA', 'devZ'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: () => ({ add_device_ids: [], evict_device_ids: ['devZ'] }),
      evictMemberDevices: async () => assert.fail('should not evict without a known leaf'),
    },
  });
  assert.deepEqual(out, { added: 0, evicted: 0 });
  assert.deepEqual(trace, []);
});

test('no-ops when the plan finds nothing to add or evict', async () => {
  const trace = [];
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA'],
      getGroupDeviceLeaves: async () => ({ devA: 0 }),
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: () => ({ add_device_ids: [], evict_device_ids: [] }),
    },
  });
  assert.deepEqual(out, { added: 0, evicted: 0 });
  assert.deepEqual(trace, []);
});

test('guards provisioning lag — plan wants a device with no key package', async () => {
  const trace = [];
  const out = await reconcileConversationDevices({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => GROUP,
      fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 }),
      getGroupDeviceIds: async () => ['devA'],
      getGroupDeviceLeaves: async () => ({ devA: 0 }),
      fetchGroupMemberDevices: async () => ({ known: true, activeDeviceIds: ['devA'], pendingDeviceIds: [] }),
      computeMemberReconcilePlan: () => ({ add_device_ids: ['devZ'], evict_device_ids: [] }),
    },
  });
  assert.deepEqual(out, { added: 0, evicted: 0 });
  assert.deepEqual(trace, []) // never added
})
