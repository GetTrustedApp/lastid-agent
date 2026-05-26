/**
 * Agent-side IdP group REST — the mirror of the operator-side calls in
 * lastid.co/src/lib/mls-network.ts. Lets the agent fetch a peer's
 * KeyPackage, register a group it just created, and add members
 * (delivering the welcome). Used by the conversation self-heal: when the
 * agent has no group with its operator, it creates one and invites the
 * operator's devices instead of erroring.
 *
 * Auth mirrors agent-state-sync / mls-publish: the agent VC SD-JWT as a
 * `Bearer` token + a fresh `DPoP` proof per request (htu = origin+path,
 * no query string). `fetchImpl` is injectable so tests don't hit the net.
 */

import { mintDpopJwt } from './dpop.js';

/**
 * One authenticated IdP call. Returns parsed JSON ({} on empty body).
 * Throws on non-2xx with the response text. `body` undefined → no body
 * (GET); otherwise JSON-encoded with a content-type header.
 *
 * @param {object} a
 * @param {string} a.idpUrl
 * @param {'GET'|'POST'|'PUT'|'DELETE'} a.method
 * @param {string} a.path                 - leading-slash path, e.g. /v1/groups
 * @param {unknown} [a.body]
 * @param {string} a.agentDid
 * @param {string} a.vcCompact            - agent VC SD-JWT (bearer)
 * @param {import('node:crypto').KeyObject} a.signingKey - agent Ed25519 (DPoP)
 * @param {typeof fetch} [a.fetchImpl]
 */
export async function authedIdpFetch({
  idpUrl,
  method,
  path,
  body,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl = fetch,
}) {
  const trimmed = String(idpUrl ?? '').replace(/\/$/, '');
  if (!trimmed) throw new Error('authedIdpFetch: idpUrl required');
  const url = `${trimmed}${path}`;
  // DPoP htu is origin+path with NO query string (RFC 9449; matches the
  // agent-state-sync precedent which signs `base` but fetches `?since=…`).
  const htu = url.split('?')[0];
  const headers = {
    Authorization: `Bearer ${vcCompact}`,
    DPoP: mintDpopJwt({ agentDid, httpMethod: method, httpUri: htu, signingKey }),
    accept: 'application/json',
  };
  const init = { method, headers };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetchImpl(url, init);
  if (!res.ok) {
    const text = typeof res.text === 'function' ? await res.text().catch(() => '') : '';
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${text}`);
  }
  if (typeof res.json === 'function') {
    return await res.json().catch(() => ({}));
  }
  return {};
}

/**
 * GET /v1/mls/keypackages/:did — claim the peer's published KeyPackage(s).
 * `perDevice` (default true) asks the IdP for ONE KeyPackage per device,
 * deduped + sorted server-side — so inviting all of the operator's devices
 * is a single fetch + an addMember per returned package. The IdP atomically
 * CONSUMES what it returns. Mirror of the IdP bot's `fetchKeyPackagesAsBot`.
 *
 * @returns {Promise<{ keyPackages: Array<{ keyPackageB64: string, ref: string, deviceId: string|null }>, remainingCount: number }>}
 */
export async function fetchPeerKeyPackages({
  idpUrl,
  targetDid,
  perDevice = true,
  count,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!targetDid) throw new Error('fetchPeerKeyPackages: targetDid required');
  const query = [];
  if (perDevice) query.push('per_device=true');
  if (count !== undefined) query.push(`count=${count}`);
  const qs = query.length > 0 ? `?${query.join('&')}` : '';
  const body = await authedIdpFetch({
    idpUrl,
    method: 'GET',
    path: `/v1/mls/keypackages/${encodeURIComponent(targetDid)}${qs}`,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
  const list = Array.isArray(body?.key_packages) ? body.key_packages : [];
  const keyPackages = list
    .map((k) => ({
      keyPackageB64: k?.key_package ?? null,
      ref: k?.ref ?? null,
      deviceId: k?.device_id ?? null,
    }))
    .filter((k) => k.keyPackageB64 && k.ref);
  return {
    keyPackages,
    remainingCount: typeof body?.remaining_count === 'number' ? body.remaining_count : 0,
  };
}

/**
 * GET /v1/groups/:id/member-devices/:did — the IdP ledger's view of which of
 * a member's devices are active in the group (and which are pending eviction).
 * Non-consuming (unlike a key-package fetch). Used by device-consistency
 * reconcile to diff against the member's live devices. Mirrors native
 * `fetch_group_member_device_resolution`.
 *
 * @returns {Promise<{ known: boolean, activeDeviceIds: string[], pendingDeviceIds: string[] }>}
 */
export async function fetchGroupMemberDevices({
  idpUrl,
  groupId,
  memberDid,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!groupId) throw new Error('fetchGroupMemberDevices: groupId required');
  if (!memberDid) throw new Error('fetchGroupMemberDevices: memberDid required');
  const body = await authedIdpFetch({
    idpUrl,
    method: 'GET',
    path: `/v1/groups/${encodeURIComponent(groupId)}/member-devices/${encodeURIComponent(memberDid)}`,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
  return {
    known: body?.known === true,
    activeDeviceIds: Array.isArray(body?.active_device_ids) ? body.active_device_ids : [],
    pendingDeviceIds: Array.isArray(body?.pending_eviction_device_ids)
      ? body.pending_eviction_device_ids
      : [],
  };
}

/**
 * POST /v1/groups — register a freshly-created group. `mlsGroupInitB64`
 * is the base64 TLS GroupInfo from `MlsClient.exportGroupInfo`; the IdP
 * hashes it to derive the canonical mls_group_id. Members are NOT added
 * here — that's `addGroupMember`. Returns the IdP group descriptor; `id`
 * is the UUID later member/commit/message frames key on.
 *
 * @returns {Promise<{ id: string, mls_group_id?: string, name?: string }>}
 */
export async function createGroupOnIdp({
  idpUrl,
  name,
  mlsGroupInitB64,
  groupType = 'direct',
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!mlsGroupInitB64) throw new Error('createGroupOnIdp: mlsGroupInitB64 required');
  const body = { name: name ?? 'Direct chat', mls_group_init: mlsGroupInitB64 };
  if (groupType) body.group_type = groupType;
  return authedIdpFetch({
    idpUrl,
    method: 'POST',
    path: '/v1/groups',
    body,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
}

/**
 * POST /v1/groups/:id/members — add a peer. The IdP fans the welcome out
 * to the invitee's WS subscribers as `group_chat.welcome` and broadcasts
 * the commit to existing members as `group_chat.commit`. For the agent →
 * own-operator case the IdP carves out the human-invite auth requirement
 * (the agent's parent_human_did matches the group root).
 */
export async function addGroupMember({
  idpUrl,
  groupId,
  inviteeDid,
  mlsWelcomeB64,
  mlsCommitB64,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!groupId) throw new Error('addGroupMember: groupId required');
  if (!inviteeDid) throw new Error('addGroupMember: inviteeDid required');
  if (!mlsWelcomeB64) throw new Error('addGroupMember: mlsWelcomeB64 required');
  const body = { invitee_did: inviteeDid, mls_welcome: mlsWelcomeB64 };
  if (mlsCommitB64) body.mls_commit = mlsCommitB64;
  return authedIdpFetch({
    idpUrl,
    method: 'POST',
    path: `/v1/groups/${encodeURIComponent(groupId)}/members`,
    body,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
}

/**
 * POST /v1/groups/:id/member-devices/reconcile — the device-consistency ADD:
 * submit the commit + welcome that added `targetDeviceIds` to `memberDid`, so
 * the IdP advances the group AND updates its per-device ledger (active set).
 * `expectedEpoch` is the epoch BEFORE the commit (new_epoch - 1). Mirrors
 * native `submit_member_device_reconcile_to_idp`.
 */
export async function reconcileMemberDevicesAdd({
  idpUrl,
  groupId,
  memberDid,
  targetDeviceIds,
  mlsCommitB64,
  mlsWelcomeB64,
  expectedEpoch,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!groupId) throw new Error('reconcileMemberDevicesAdd: groupId required');
  return authedIdpFetch({
    idpUrl,
    method: 'POST',
    path: `/v1/groups/${encodeURIComponent(groupId)}/member-devices/reconcile`,
    body: {
      member_did: memberDid,
      target_device_ids: targetDeviceIds,
      mls_commit: mlsCommitB64,
      mls_welcome: mlsWelcomeB64,
      expected_epoch: expectedEpoch,
    },
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
}

/**
 * POST /v1/groups/:id/member-devices/evict — the device-consistency REMOVE:
 * submit the remove-commit that evicted `targetDeviceIds` from `memberDid`.
 * Pure remove (no welcome). `expectedEpoch` is the epoch before the commit.
 * Mirrors native `submit_member_device_evict_to_idp`.
 */
export async function evictMemberDevices({
  idpUrl,
  groupId,
  memberDid,
  targetDeviceIds,
  mlsCommitB64,
  expectedEpoch,
  reason = 'device_no_longer_active',
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!groupId) throw new Error('evictMemberDevices: groupId required');
  return authedIdpFetch({
    idpUrl,
    method: 'POST',
    path: `/v1/groups/${encodeURIComponent(groupId)}/member-devices/evict`,
    body: {
      member_did: memberDid,
      target_device_ids: targetDeviceIds,
      mls_commit: mlsCommitB64,
      expected_epoch: expectedEpoch,
      reason,
    },
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
}
