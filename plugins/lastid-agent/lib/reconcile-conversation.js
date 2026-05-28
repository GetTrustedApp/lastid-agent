/**
 * Device-consistency reconcile for the agent's conversation with its operator:
 * when the operator adds a NEW device, add it to the group so it can read the
 * agent's messages. Runs in the listener (single MLS-state writer).
 *
 * Phase C2: this module is now a thin wrapper around the shared wasm
 * `MlsOrchestrator` (lib/mls-orchestrator.js). The old JS-side flow — fetch
 * key packages, diff against the IdP ledger, call the shared
 * computeMemberReconcilePlan, then `addMembers` / `removeMember` + submit —
 * was a faithful port of the Rust `reconcile_group_device_membership_once`
 * core fn. We delegate to keep them bit-identical across platforms (browser,
 * agent, native) and so the add-and-evict bookkeeping (leaf indices, plan
 * ordering, retry policy) lives in ONE place.
 *
 * The orchestrator runs `reconcileMemberDevices(group_id)` for ALL members of
 * the group (not just the operator) — that's the core fn's contract. For a
 * direct chat that's two members (the agent + the operator); the agent's own
 * leaf is a no-op (one device).
 */

import { resolveActiveGroupForOperator } from './agent-groups.js';
import { getOrchestrator } from './mls-orchestrator.js';

const DEFAULT_DEPS = {
  resolveActiveGroupForOperator,
  getOrchestrator,
};

/**
 * @returns {Promise<{ added: number, evicted?: number, reason?: string, changed?: boolean }>}
 */
export async function reconcileConversationDevices({
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
  if (!operatorDid) throw new Error('reconcileConversationDevices: operatorDid required');

  // Reconcile only an EXISTING conversation. Creating one is ensureConversation's job.
  const group = await d.resolveActiveGroupForOperator({ scope, operatorDid });
  if (!group) return { added: 0, reason: 'no-group' };

  // Delegate to the wasm orchestrator. It runs:
  //   lastid_mls_core::reconcile::reconcile_group_device_membership_once
  // for the whole group, which iterates every member (the agent + the
  // operator), runs the shared planner per member, and applies the
  // add/evict via the callback bundles → addGroupMember /
  // reconcileMemberDevicesAdd / evictMemberDevices (same IdP routes the
  // old JS path used).
  //
  // The orchestrator's return shape (see lastid_mls_wasm.d.ts):
  //   { changed: bool }
  // — coarser than the old { added, evicted, addedDeviceIds, … } since
  // the bookkeeping moved Rust-side. We surface what we have; the
  // listener's log is what observability actually keys on.
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
  const result = await orchestrator.reconcileMemberDevices(group.idpGroupId);
  const changed = result?.changed === true;
  if (changed) {
    logLine(`[lastid-agent] reconcile: group ${group.idpGroupId} membership changed`);
  }
  // Backward-compatible return shape: existing call sites + tests read
  // `.added` and `.reason`. The orchestrator doesn't split add vs evict
  // counts to JS yet, so we surface a coarse `changed` boolean and a
  // best-effort `added: changed ? 1 : 0` so non-zero still reads as work.
  return { added: changed ? 1 : 0, evicted: 0, changed };
}
