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

import { resolveActiveGroupForOperator, recordGroup, getGroupDeviceIds } from './agent-groups.js';
import { fetchPeerKeyPackages, fetchGroupMemberDevices, addGroupMember } from './mls-groups-api.js';
import { computeMemberReconcilePlan } from './mls-client.js';

const DEFAULT_DEPS = {
  resolveActiveGroupForOperator,
  recordGroup,
  getGroupDeviceIds,
  fetchPeerKeyPackages,
  fetchGroupMemberDevices,
  addGroupMember,
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

  if (!Array.isArray(plan.add_device_ids) || plan.add_device_ids.length === 0) {
    return { added: 0, evictPending: plan.evict_device_ids?.length ?? 0 };
  }

  // 4. Add the new devices in one commit (we already hold their key packages).
  const addSet = new Set(plan.add_device_ids);
  const addKps = keyPackages.filter((kp) => addSet.has(kp.deviceId)).map((kp) => kp.keyPackageB64);
  if (addKps.length === 0) {
    // Plan wants devices we don't have key packages for — provisioning lag.
    return { added: 0, reason: 'no-keypackages-for-missing' };
  }

  const result = mls.addMembers(group.groupIdB64, addKps);
  await mls.persist();
  await d.addGroupMember({
    idpUrl,
    groupId: group.idpGroupId,
    inviteeDid: operatorDid,
    mlsWelcomeB64: result.welcome_b64,
    mlsCommitB64: result.commit_b64,
    agentDid,
    vcCompact,
    signingKey,
  });

  const nextRecorded = Array.from(new Set([...recorded, ...plan.add_device_ids]));
  await d.recordGroup({
    scope,
    idpGroupId: group.idpGroupId,
    groupIdB64: group.groupIdB64,
    operatorDid,
    deviceIds: nextRecorded,
  });

  logLine(
    `[lastid-agent] reconcile: added ${plan.add_device_ids.length} new operator device(s) to the conversation`,
  );
  return {
    added: plan.add_device_ids.length,
    addedDeviceIds: plan.add_device_ids,
    evictPending: plan.evict_device_ids?.length ?? 0,
  };
}
