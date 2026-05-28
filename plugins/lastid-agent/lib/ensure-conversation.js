/**
 * Establish an MLS conversation with the operator when none exists yet —
 * the agent-initiated self-heal. Runs ONLY in the listener (the single
 * MLS-state writer), invoked from the outbox drain when a queued reply
 * has no group to ride.
 *
 * Phase C2: this module is now a thin wrapper around the shared wasm
 * `MlsOrchestrator` (lib/mls-orchestrator.js). The hand-rolled per-device
 * "addMember per fetched key package" loop was a JS copy of the Rust
 * `commit_ops::create_and_register_direct_group_shell` +
 * `add_first_member_to_direct_group` flow — the same code lastid.co +
 * native now run via the orchestrator. We delegate to keep them bit-
 * identical across platforms (multi-device parity).
 *
 * The orchestrator handles steps 2-4 of the original flow (fetch KPs,
 * createGroup → register, addMember per device → deliver welcome).
 * Step 1 ("never fork") and step 5 (record the mapping so future sends
 * resolve the group) stay here — they touch the agent's local groups
 * map, which the wasm doesn't (and shouldn't) know about.
 *
 * Public signature is unchanged: callers (agent-send.js) don't move.
 */

import { resolveActiveGroupForOperator, recordGroup } from './agent-groups.js';
import { getOrchestrator } from './mls-orchestrator.js';

const DEFAULT_DEPS = {
  resolveActiveGroupForOperator,
  recordGroup,
  getOrchestrator,
};

/**
 * @param {object} a
 * @param {string} a.scope
 * @param {import('./mls-client.js').MlsClient} [a.mls]  Live listener-owned client (unused post-C2; kept for backward-compat with callers).
 * @param {string} a.agentDid
 * @param {string} a.operatorDid    - the agent's parent human (its only peer).
 * @param {string} a.idpUrl
 * @param {string} a.vcCompact      - agent VC SD-JWT (bearer).
 * @param {import('node:crypto').KeyObject} a.signingKey - agent Ed25519 (DPoP).
 * @param {(line: string) => void} [a.log]
 * @param {object} [a.ctx]          - listener context for orchestrator caching;
 *                                    when omitted we synthesize a local one (so
 *                                    callers that haven't been migrated still work).
 * @param {Partial<typeof DEFAULT_DEPS>} [a.deps]
 * @returns {Promise<{ idpGroupId: string, groupIdB64: string, operatorDid: string }>}
 */
export async function ensureConversation({
  scope,
  mls: _mls,
  agentDid,
  operatorDid,
  idpUrl,
  vcCompact,
  signingKey,
  log,
  ctx,
  deps,
}) {
  const d = { ...DEFAULT_DEPS, ...(deps ?? {}) };
  const logLine = log ?? (() => {});
  if (!operatorDid) throw new Error('ensureConversation: operatorDid required');

  // 1. Never fork — reuse an existing group with this operator. The
  //    orchestrator has its own "do we already have a session for this
  //    peer?" check, but it answers from openmls state; the agent also
  //    tracks the IdP group UUID ↔ openmls id mapping in groups.json,
  //    which is what the send path resolves against. Honor that mapping
  //    first so a known-good conversation is never silently re-created.
  const existing = await d.resolveActiveGroupForOperator({ scope, operatorDid });
  if (existing) return existing;

  // 2. Delegate to the shared wasm orchestrator. It runs:
  //      lastid_mls_core::commit_ops::create_and_register_direct_group_shell
  //      lastid_mls_core::commit_ops::add_first_member_to_direct_group
  //    via the callback bundles we wired up in mls-orchestrator.js (which
  //    route back through fetchPeerKeyPackages / createGroupOnIdp /
  //    addGroupMember — the SAME IdP calls the old hand-rolled loop made).
  const orchestratorCtx = ctx ?? {
    scope,
    agentDid,
    operatorDid,
    idpUrl,
    vcCompact,
    signingKey,
    log,
  };
  const orchestrator = await d.getOrchestrator(orchestratorCtx);
  const result = await orchestrator.startDirectChat(operatorDid);

  // The orchestrator's JS-facing return shape (see lastid_mls_wasm.d.ts):
  //   { idp_group_id, local_group_id, member_count, epoch, peer_device_ids }
  const idpGroupId = result?.idp_group_id;
  const groupIdB64 = result?.local_group_id;
  const peerDeviceIds = Array.isArray(result?.peer_device_ids) ? result.peer_device_ids : [];
  if (!idpGroupId || !groupIdB64) {
    throw new Error('ensureConversation: orchestrator returned no group ids');
  }

  // 3. Persist the IdP UUID ↔ openmls id mapping. This is what the send
  //    path resolves against (resolveActiveGroupForOperator → groups.json).
  //    The orchestrator doesn't write here — that file is a plugin
  //    concern, not a wasm one. deviceLeaves stays empty: the orchestrator
  //    bookkeeps the device → leaf map internally, and the local map was
  //    only used by the old JS-side evict path that the orchestrator now
  //    owns end-to-end.
  await d.recordGroup({
    scope,
    idpGroupId,
    groupIdB64,
    operatorDid,
    deviceIds: peerDeviceIds,
    deviceLeaves: {},
  });
  logLine(
    `[lastid-agent] established a conversation with the operator → group ${idpGroupId} ` +
      `(${peerDeviceIds.length} device${peerDeviceIds.length === 1 ? '' : 's'})`,
  );
  return { idpGroupId, groupIdB64, operatorDid };
}
