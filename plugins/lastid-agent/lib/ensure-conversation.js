/**
 * Establish an MLS conversation with the operator when none exists yet —
 * the agent-initiated self-heal. Runs ONLY in the listener (the single
 * MLS-state writer), invoked from the outbox drain when a queued reply
 * has no group to ride.
 *
 * Flow (mirror of the operator-side lastid.co AgentChatDock.createAndRegisterGroup,
 * inverted — the agent is the creator, the operator the invitee):
 *
 *   1. Already have a group with this operator? Use it. (A welcome that
 *      landed earlier recorded one — never create a second.)
 *   2. Fetch the operator's published KeyPackage(s).
 *   3. createGroup → exportGroupInfo → POST /v1/groups (register).
 *   4. addMember(operator device) → deliver the welcome via
 *      POST /v1/groups/:id/members; the IdP fans it to the operator's
 *      devices and they join.
 *   5. recordGroup so the send path (and future sends) resolve it.
 *
 * Phase 3 invites the operator's PRIMARY device (first KeyPackage). Full
 * multi-device + ongoing device-consistency reconciliation is phase 4 —
 * the loop seam is marked below.
 *
 * Everything external is injected via `deps` so this is unit-testable
 * without the network or the wasm client.
 */

import { randomBytes } from 'node:crypto';
import { resolveActiveGroupForOperator, recordGroup } from './agent-groups.js';
import { fetchPeerKeyPackages, createGroupOnIdp, addGroupMember } from './mls-groups-api.js';

/** A fresh, caller-reserved group id: 16 random bytes, base64. */
export function randomGroupIdB64() {
  return randomBytes(16).toString('base64');
}

const DEFAULT_DEPS = {
  resolveActiveGroupForOperator,
  recordGroup,
  fetchPeerKeyPackages,
  createGroupOnIdp,
  addGroupMember,
  randomGroupIdB64,
};

/**
 * @param {object} a
 * @param {string} a.scope
 * @param {import('./mls-client.js').MlsClient} a.mls  Live listener-owned client.
 * @param {string} a.agentDid
 * @param {string} a.operatorDid    - the agent's parent human (its only peer).
 * @param {string} a.idpUrl
 * @param {string} a.vcCompact      - agent VC SD-JWT (bearer).
 * @param {import('node:crypto').KeyObject} a.signingKey - agent Ed25519 (DPoP).
 * @param {(line: string) => void} [a.log]
 * @param {Partial<typeof DEFAULT_DEPS>} [a.deps]  - injected for tests.
 * @returns {Promise<{ idpGroupId: string, groupIdB64: string, operatorDid: string }>}
 */
export async function ensureConversation({
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
  if (!operatorDid) throw new Error('ensureConversation: operatorDid required');

  // 1. Never fork — reuse an existing group with this operator.
  const existing = await d.resolveActiveGroupForOperator({ scope, operatorDid });
  if (existing) return existing;

  // 2. The operator must have a KeyPackage on file to be invited.
  const { keyPackages } = await d.fetchPeerKeyPackages({
    idpUrl,
    targetDid: operatorDid,
    agentDid,
    vcCompact,
    signingKey,
  });
  if (keyPackages.length === 0) {
    throw new Error(
      `operator ${operatorDid} has no MLS key packages published — can't establish a conversation yet`,
    );
  }

  // 3. Author + register the group.
  const groupIdB64 = d.randomGroupIdB64();
  mls.createGroup(groupIdB64);
  await mls.persist();
  const mlsGroupInitB64 = mls.exportGroupInfo(groupIdB64);
  const created = await d.createGroupOnIdp({
    idpUrl,
    name: 'Direct chat',
    mlsGroupInitB64,
    groupType: 'direct',
    agentDid,
    vcCompact,
    signingKey,
  });
  if (!created || typeof created.id !== 'string') {
    throw new Error('createGroupOnIdp returned no group id');
  }

  // 4. Invite EVERY operator device — one KeyPackage per device (the IdP
  //    deduped/sorted them via per_device=true). Each addMember advances
  //    the epoch and emits a commit + a welcome: the welcome goes to that
  //    device, and the IdP fans the commit out to members already added.
  //    Add them one at a time so a mid-loop failure leaves a smaller-but-
  //    consistent group (the message still rides it) rather than nothing.
  for (const kp of keyPackages) {
    const add = mls.addMember(groupIdB64, kp.keyPackageB64);
    await mls.persist();
    await d.addGroupMember({
      idpUrl,
      groupId: created.id,
      inviteeDid: operatorDid,
      mlsWelcomeB64: add.welcome_b64,
      mlsCommitB64: add.commit_b64,
      agentDid,
      vcCompact,
      signingKey,
    });
  }

  // 5. Record so this + future sends resolve the group — including which
  //    operator devices we invited, the baseline device-consistency reconcile
  //    diffs against.
  const invitedDeviceIds = keyPackages.map((kp) => kp.deviceId).filter(Boolean)
  await d.recordGroup({ scope, idpGroupId: created.id, groupIdB64, operatorDid, deviceIds: invitedDeviceIds });
  logLine(
    `[lastid-agent] established a conversation with the operator → group ${created.id} ` +
      `(invited ${keyPackages.length} device${keyPackages.length === 1 ? '' : 's'})`,
  );
  return { idpGroupId: created.id, groupIdB64, operatorDid };
}
