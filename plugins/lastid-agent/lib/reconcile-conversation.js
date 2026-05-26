/**
 * Device-consistency reconcile for the agent's conversation with its operator:
 * when the operator adds a NEW device, add it to the group so it can read the
 * agent's messages. Runs in the listener (single MLS-state writer).
 *
 * The DECISION is the shared Rust planner (lastid-mls-membership, via
 * `computeMemberReconcilePlan` in the wasm) — the SAME logic native runs, so
 * browser, agent, and native agree. This module only does the I/O + the
 * openmls batch add:
 *
 *   1. Fetch the operator's live devices (one key package per device).
 *   2. Fetch the IdP ledger's in-group device set (authoritative; falls back
 *      to our local record if unavailable).
 *   3. computeMemberReconcilePlan(...) → add_device_ids (the new devices).
 *   4. addMembers(their key packages) → one commit + one welcome → deliver,
 *      then record the expanded device set.
 *
 * Add-only: eviction of retired devices needs leaf-index bookkeeping (a
 * follow-up); `plan.evict_device_ids` is surfaced in the result but not acted
 * on here. Everything external is injected via `deps` for unit tests.
 */

import {
  resolveActiveGroupForOperator,
  recordGroup,
  getGroupDeviceIds,
  getGroupDeviceLeaves,
} from './agent-groups.js';
import {
  fetchPeerKeyPackages,
  fetchGroupMemberDevices,
  reconcileMemberDevicesAdd,
  evictMemberDevices,
} from './mls-groups-api.js';
import { computeMemberReconcilePlan } from './mls-client.js';

const DEFAULT_DEPS = {
  resolveActiveGroupForOperator,
  recordGroup,
  getGroupDeviceIds,
  getGroupDeviceLeaves,
  fetchPeerKeyPackages,
  fetchGroupMemberDevices,
  reconcileMemberDevicesAdd,
  evictMemberDevices,
  computeMemberReconcilePlan,
};

/**
 * @returns {Promise<{ added: number, addedDeviceIds?: string[], evictPending?: number, reason?: string }>}
 */
export async function reconcileConversationDevices({
  scope,
  mls,
  agentDid,
  operatorDid,
  idpUrl,
  vcCompact,
  signingKey,
  log,
  deps,
}) {
  const d = { ...DEFAULT_DEPS, ...(deps ?? {}) };
  const logLine = log ?? (() => {});
  if (!operatorDid) throw new Error('reconcileConversationDevices: operatorDid required');

  // Reconcile only an EXISTING conversation. Creating one is ensureConversation's job.
  const group = await d.resolveActiveGroupForOperator({ scope, operatorDid });
  if (!group) return { added: 0, reason: 'no-group' };

  // 1. The operator's current live devices, each with a claimable key package.
  const { keyPackages } = await d.fetchPeerKeyPackages({
    idpUrl,
    targetDid: operatorDid,
    perDevice: true,
    agentDid,
    vcCompact,
    signingKey,
  });
  const liveDeviceIds = keyPackages.map((kp) => kp.deviceId).filter(Boolean);

  // 2. The ledger's in-group device set (authoritative). Best-effort — fall
  //    back to our local record if the agent can't read it.
  const recorded = await d.getGroupDeviceIds({ scope, idpGroupId: group.idpGroupId });
  let activeInGroup = recorded;
  let pendingInGroup = [];
  try {
    const res = await d.fetchGroupMemberDevices({
      idpUrl,
      groupId: group.idpGroupId,
      memberDid: operatorDid,
      agentDid,
      vcCompact,
      signingKey,
    });
    if (res.known) {
      activeInGroup = res.activeDeviceIds;
      pendingInGroup = res.pendingDeviceIds;
    }
  } catch (e) {
    logLine(`[lastid-agent] reconcile: member-devices fetch failed (using local record): ${e?.message ?? e}`);
  }

  // 3. SHARED decision: what's missing (and, for later, what's stale).
  const plan = d.computeMemberReconcilePlan({
    inventoryLeafCount: recorded.length,
    inventoryDeviceIds: recorded,
    activeInGroup,
    pendingInGroup,
    liveDeviceIds,
  });

  const addDeviceIds = Array.isArray(plan.add_device_ids) ? plan.add_device_ids : [];
  const evictDeviceIds = Array.isArray(plan.evict_device_ids) ? plan.evict_device_ids : [];

  // The device → leaf-index map (captured at add time) — needed to evict a
  // specific device.
  const deviceLeaves = await d.getGroupDeviceLeaves({ scope, idpGroupId: group.idpGroupId });
  let nextRecorded = recorded.slice();
  let added = 0;
  let evicted = 0;
  const evictedDeviceIds = [];

  // 4a. ADD the missing devices in ONE commit, then submit to the device
  //     ledger (member-devices/reconcile) so the IdP's active set advances.
  if (addDeviceIds.length > 0) {
    // Keep plan order so assigned_leaf_indices aligns to addDeviceIds.
    const orderedKps = addDeviceIds
      .map((did) => keyPackages.find((kp) => kp.deviceId === did))
      .filter(Boolean);
    if (orderedKps.length !== addDeviceIds.length) {
      // Plan wants devices we don't hold key packages for — provisioning lag.
      logLine('[lastid-agent] reconcile: missing key packages for some new devices — skipping add');
    } else {
      const result = mls.addMembers(group.groupIdB64, orderedKps.map((kp) => kp.keyPackageB64));
      await mls.persist();
      await d.reconcileMemberDevicesAdd({
        idpUrl,
        groupId: group.idpGroupId,
        memberDid: operatorDid,
        targetDeviceIds: addDeviceIds,
        mlsCommitB64: result.commit_b64,
        mlsWelcomeB64: result.welcome_b64,
        expectedEpoch: Math.max(0, (result.new_epoch ?? 1) - 1),
        agentDid,
        vcCompact,
        signingKey,
      });
      // Record device_id → leaf_index (aligned to addDeviceIds order).
      const leaves = Array.isArray(result.assigned_leaf_indices) ? result.assigned_leaf_indices : [];
      addDeviceIds.forEach((did, i) => {
        if (typeof leaves[i] === 'number') deviceLeaves[did] = leaves[i];
      });
      nextRecorded = Array.from(new Set([...nextRecorded, ...addDeviceIds]));
      added = addDeviceIds.length;
    }
  }

  // 4b. EVICT stale devices — look up each leaf, remove it, submit the
  //     remove-commit to member-devices/evict. One commit per device (rare).
  for (const did of evictDeviceIds) {
    const leaf = deviceLeaves[did];
    if (typeof leaf !== 'number') {
      logLine(`[lastid-agent] reconcile: no leaf for stale device ${did} — skipping evict`);
      continue;
    }
    try {
      const commit = mls.removeMember(group.groupIdB64, leaf);
      await mls.persist();
      await d.evictMemberDevices({
        idpUrl,
        groupId: group.idpGroupId,
        memberDid: operatorDid,
        targetDeviceIds: [did],
        mlsCommitB64: commit.commit_b64,
        expectedEpoch: Math.max(0, (commit.new_epoch ?? 1) - 1),
        agentDid,
        vcCompact,
        signingKey,
      });
      delete deviceLeaves[did];
      nextRecorded = nextRecorded.filter((d2) => d2 !== did);
      evictedDeviceIds.push(did);
      evicted += 1;
    } catch (e) {
      logLine(`[lastid-agent] reconcile: evict ${did} failed: ${e?.message ?? e}`);
    }
  }

  if (added === 0 && evicted === 0) {
    return { added: 0, evicted: 0 };
  }

  await d.recordGroup({
    scope,
    idpGroupId: group.idpGroupId,
    groupIdB64: group.groupIdB64,
    operatorDid,
    deviceIds: nextRecorded,
    deviceLeaves,
  });
  logLine(`[lastid-agent] reconcile: +${added} device(s), -${evicted} device(s)`);
  return { added, evicted, addedDeviceIds: addDeviceIds, evictedDeviceIds };
}
