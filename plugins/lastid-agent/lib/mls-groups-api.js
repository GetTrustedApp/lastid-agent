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
import { brokerIdpFetch, brokerAvailable } from './broker-ipc.js';
import { brokerIdpEnabled } from './broker-supervisor.js';
import { getActiveScope } from './active-scope.js';

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
 * @param {string} [a.scope]              - broker routing target (default: ambient)
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
  scope,
  // Injectable so the dispatch is unit-testable without a real broker.
  _brokerIdpFetch = brokerIdpFetch,
  _brokerAvailable = brokerAvailable,
  _brokerEnabled = brokerIdpEnabled,
}) {
  // FORK1 (broker-credential-custody Phase 2): when broker routing is enabled
  // AND a broker is actually up for this scope, the SIGNED BROKER makes the call
  // — it holds the slot seed + mints the canonical DPoP resource-token, so node
  // derives no key and mints no DPoP here. No-flag-day: LASTID_BROKER_IDP is off
  // by default, and even when on we fall back to the legacy node path below
  // whenever no broker is running (brokerAvailable=false).
  const routeScope = scope ?? getActiveScope();
  if (_brokerEnabled() && (await _brokerAvailable(routeScope))) {
    return _brokerIdpFetch({ method, path, body, scope: routeScope });
  }

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
 * Self-revoke one of the agent's OWN devices by device_id
 * (DELETE /v1/identity/devices/:device_identity — subject-scoped to the
 * authenticated agent). Used by the reissue flow to retire the agent's OLD
 * `ad-`/`md-` device before the new identity takes over: the IdP evicts that
 * device's leaf from every group AND purges its KeyPackages, so no peer can
 * re-add the dead device via a stale KP (NoMatchingKeyPackage on the welcome).
 *
 * Pass the OLD identity's credentials (the device belongs to the old DID).
 *
 * @param {object} a
 * @param {string} a.idpUrl
 * @param {string} a.deviceId   - the device to revoke (`ad-`/`md-`)
 * @param {string} a.agentDid   - the OLD agent DID (subject of the old VC)
 * @param {string} a.vcCompact  - the OLD agent VC SD-JWT (bearer)
 * @param {import('node:crypto').KeyObject} a.signingKey - the OLD signing key (DPoP)
 * @param {typeof fetch} [a.fetchImpl]
 */
export async function revokeAgentDevice({
  idpUrl,
  deviceId,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl = fetch,
}) {
  if (!deviceId) throw new Error('revokeAgentDevice: deviceId required');
  return authedIdpFetch({
    idpUrl,
    method: 'DELETE',
    path: `/v1/identity/devices/${encodeURIComponent(deviceId)}`,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
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
 * GET /v1/trust/:did/devices — resolve a principal's active device(s) through
 * the IdP's durable resolver (`handleGetPeerDevices` →
 * `resolveDurableActiveDeviceIdsForDid` → `deriveAgentDeviceIds`). This is the
 * SAME source the reconcile endpoint gates target devices on
 * (group-device-membership-service.ts: eligibleDeviceIds =
 * resolveDurableActiveDeviceIdsForDid(memberDid)), so anything resolved here
 * agrees byte-for-byte with what the IdP will accept — ONE resolution source,
 * no desync. `did` may be the agent's OWN did (self-read, authorized because a
 * principal may enumerate its own devices) or a PEER's (the operator's), which
 * is authorized via the owned-agent ownership carve-out on the route. The
 * endpoint reports `active` per device (no `status` string) and never returns a
 * revoked device as active; `device_identity` mirrors `device_id` (the trust
 * endpoint carries no separate identity field).
 *
 * @returns {Promise<Array<{ device_id: string, device_identity: string, last_seen: string|null, active: boolean }>>}
 */
export async function fetchActiveDevicesForDid({
  idpUrl,
  did,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!did) throw new Error('fetchActiveDevicesForDid: did required');
  if (!agentDid) throw new Error('fetchActiveDevicesForDid: agentDid required');
  const body = await authedIdpFetch({
    idpUrl,
    method: 'GET',
    path: `/v1/trust/${encodeURIComponent(did)}/devices`,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
  const list = Array.isArray(body?.devices) ? body.devices : [];
  return list
    .map((d) => {
      const deviceId = typeof d?.device_id === 'string' ? d.device_id : '';
      return {
        device_id: deviceId,
        device_identity: deviceId,
        last_seen: typeof d?.last_seen === 'string' ? d.last_seen : null,
        // Endpoint marks each returned device active; treat a missing flag as
        // active, only an explicit false excludes (it never returns revoked).
        active: d?.active !== false,
      };
    })
    .filter((d) => d.device_id.length > 0);
}

/**
 * The agent's OWN active device(s) — the self-read specialization of
 * `fetchActiveDevicesForDid` (did === agentDid). Kept as a named helper because
 * the reconcile orchestrator's `own_devices` path resolves through it; the
 * agent owns exactly one device whose id IS its identity. Replaces the old V1
 * `/v1/identity/devices` master_fingerprint path (which 400s for agents).
 *
 * @returns {Promise<Array<{ device_id: string, device_identity: string, last_seen: string|null, active: boolean }>>}
 */
export async function listOwnDevices({
  idpUrl,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!agentDid) throw new Error('listOwnDevices: agentDid required');
  return fetchActiveDevicesForDid({
    idpUrl,
    did: agentDid,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
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
 * @returns {Promise<{ id: string, mls_group_id?: string, name?: string, existing?: boolean }>}
 */
export async function createGroupOnIdp({
  idpUrl,
  name,
  mlsGroupInitB64,
  groupType = 'direct',
  peerDid,
  forceNew,
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl,
}) {
  if (!mlsGroupInitB64) throw new Error('createGroupOnIdp: mlsGroupInitB64 required');
  const body = { name: name ?? 'Direct chat', mls_group_init: mlsGroupInitB64 };
  if (groupType) body.group_type = groupType;
  // Direct get-or-create: send the peer so the IdP keys ONE canonical group per
  // {creator, peer} identity pair (the server-side convergence anchor). The
  // response carries `existing:true` when the IdP returned an already-claimed
  // group for the pair instead of creating a new one.
  if (peerDid) body.peer_did = peerDid;
  // Rotation self-heal: skip reuse + repoint the pair claim to a fresh group.
  if (forceNew) body.force_new = true;
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
  welcomeSelf,
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
  // Single-commit "everyone at start": also welcome the inviter's own devices.
  if (welcomeSelf) body.welcome_self = true;
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
