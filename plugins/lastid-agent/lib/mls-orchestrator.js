/**
 * Bridge from the agent listener's JS surface to the shared wasm
 * `MlsOrchestrator` (vendored at vendor/lastid-mls-wasm/). The orchestrator
 * is the SAME Rust core that lastid.co + native run, so direct-chat creation
 * and device-consistency reconcile decisions are bit-identical across
 * platforms (multi-device parity, phase C2).
 *
 * What this module does:
 *   - Build the three JS callback bundles the wasm constructor wants:
 *     directory (read peer/own device + key package state from the IdP),
 *     transport (write group + member-device commits to the IdP), host
 *     (bearer credential + setup/reconcile events + retry scheduler).
 *   - Cache one orchestrator per listener lifecycle on the cli context —
 *     constructing it instantiates the wasm orchestrator (IDB-backed in
 *     the browser; in node it just rehydrates against the agent's
 *     existing MLS state), which is expensive and not idempotent.
 *
 * Callback contract:
 *   The wasm calls every method with a SINGLE JSON-string arg (or null)
 *   and expects either a JSON string (single arg returned) or a void
 *   Promise. Errors bubble as Promise rejection (the Rust side translates
 *   them into `GetTrustedError::MLSError`).
 *
 * We don't touch the wasm artifacts — they're built + copied by
 * lastid-sdk/scripts/build-and-copy-agent-wasm.sh and just need to be
 * imported via createRequire (same pattern as lib/mls-client.js).
 *
 * Public surface (consumed by ensure-conversation.js and
 * reconcile-conversation.js):
 *   - `getOrchestrator(ctx)`: returns the cached orchestrator, building
 *     it on first call. `ctx` is the listener's cli-side context object;
 *     we attach `ctx.__mlsOrchestrator` once.
 *   - `buildCallbackBundles({ ... })`: pure helper that produces the
 *     `{ directory, transport, host }` triple — exported for tests.
 *   - `disposeOrchestrator(ctx)`: free the wasm handle on shutdown.
 */

import { createRequire } from 'node:module';
import {
  fetchPeerKeyPackages,
  fetchGroupMemberDevices,
  createGroupOnIdp,
  addGroupMember,
  reconcileMemberDevicesAdd,
  evictMemberDevices,
  listOwnDevices,
  fetchActiveDevicesForDid,
} from './mls-groups-api.js';
import { diskKvCallbacks } from './mls-state-store.js';
import { deriveAgentDeviceId } from './agent-provisioning.js';

const localRequire = createRequire(import.meta.url);
const wasm = localRequire('../vendor/lastid-mls-wasm/lastid_mls_wasm.js');

/** Parse a JSON-string callback arg, tolerating null/undefined as `{}`. */
function parseArg(json) {
  if (json == null) return {};
  if (typeof json !== 'string') return json;
  try {
    return JSON.parse(json);
  } catch {
    return {};
  }
}

/** Stringify a callback return, tolerating undefined as `null`. */
function stringifyReturn(value) {
  if (value === undefined) return JSON.stringify(null);
  return JSON.stringify(value);
}

/**
 * Build the three JS callback bundles wired into the wasm orchestrator.
 *
 * `ctx` must carry: scope, agentDid, operatorDid, idpUrl, vcCompact,
 * signingKey, log (optional). All IdP calls reuse the agent's existing
 * `mls-groups-api.js` helpers, so authn (DPoP + Bearer) stays in one place.
 *
 * `deps` lets tests stub the IdP/transport methods without monkey-patching.
 */
export function buildCallbackBundles({ ctx, deps = {} }) {
  const log = ctx.log ?? (() => {});
  const auth = () => ({
    idpUrl: ctx.idpUrl,
    agentDid: ctx.agentDid,
    vcCompact: ctx.vcCompact,
    signingKey: ctx.signingKey,
  });

  const directoryDeps = {
    fetchPeerKeyPackages: deps.fetchPeerKeyPackages ?? fetchPeerKeyPackages,
    listOwnDevices: deps.listOwnDevices ?? listOwnDevices,
    fetchActiveDevicesForDid: deps.fetchActiveDevicesForDid ?? fetchActiveDevicesForDid,
    fetchGroupMemberDevices: deps.fetchGroupMemberDevices ?? fetchGroupMemberDevices,
  };
  const transportDeps = {
    createGroupOnIdp: deps.createGroupOnIdp ?? createGroupOnIdp,
    addGroupMember: deps.addGroupMember ?? addGroupMember,
    reconcileMemberDevicesAdd: deps.reconcileMemberDevicesAdd ?? reconcileMemberDevicesAdd,
    evictMemberDevices: deps.evictMemberDevices ?? evictMemberDevices,
  };

  // ─── DirectoryCallbacks ────────────────────────────────────────────────
  // Peer/own device + key-package lookups. All read-only against the IdP.
  const directory = {
    async peer_active_device_ids(argJson) {
      const { peer_did } = parseArg(argJson);
      // A peer device is a valid reconcile target only if it is BOTH addable
      // (has a published key package) AND eligible per the IdP's authoritative
      // active set — GET /v1/trust/:did/devices, the SAME resolver
      // (resolveDurableActiveDeviceIdsForDid) the reconcile endpoint gates on
      // (group-device-membership-service.ts: eligibleDeviceIds). The IdP can
      // still serve a stale key package for a revoked/rotated device; without
      // this intersection that device is sent as a reconcile target and the IdP
      // rejects the WHOLE batch DEVICE_NOT_ELIGIBLE, blocking the operator's
      // live devices from converging. Intersecting is subtractive only — it
      // never surfaces a device the key-package path didn't already.
      const { keyPackages } = await directoryDeps.fetchPeerKeyPackages({
        ...auth(),
        targetDid: peer_did,
        perDevice: true,
      });
      const kpIds = keyPackages.map((kp) => kp.deviceId).filter(Boolean);
      const activeList = await directoryDeps.fetchActiveDevicesForDid({
        ...auth(),
        did: peer_did,
      });
      const activeSet = new Set(
        activeList.filter((d) => d.active).map((d) => d.device_id),
      );
      const ids = kpIds.filter((id) => activeSet.has(id));
      return stringifyReturn(ids);
    },

    async own_devices(_argJson) {
      // Resolve the agent's REAL device list through the SAME durable resolver
      // every peer uses (GET /v1/trust/:agentDid/devices, a self-read) so the
      // orchestrator reconciles with the exact device_ids others resolve for
      // this agent — no drift between what the agent sees of itself and what
      // the operator's phone/desktop see of it. (Replaces the old
      // /v1/identity/devices V1 path, which 400s for agents.) Passes
      // `device_identity` through because lastid-mls-core/reconcile.rs:98
      // filters live devices by that field.
      const list = await directoryDeps.listOwnDevices(auth());
      const records = list
        .filter((d) => d.active)
        .map((d) => ({
          device_id: d.device_id,
          device_identity: d.device_identity,
          device_name: null,
          device_type: 'agent',
          capabilities: [],
          status: 'active',
          created_at: d.last_seen ?? new Date().toISOString(),
          last_seen: d.last_seen ?? null,
          // An agent runtime owns exactly ONE device and it IS this running
          // device. Flag it current so the single-commit own-device add never
          // tries to re-add the agent's own leaf (DuplicateSignatureKey) — an
          // agent has no sibling devices to fold in. Also completes the core
          // DeviceInfo shape (device_type/status/capabilities/created_at/
          // is_current_device are required for Vec<DeviceInfo> deserialize).
          is_current_device: true,
          did: ctx.agentDid,
        }));
      return stringifyReturn(records);
    },

    async peer_device_records(argJson) {
      const { peer_did } = parseArg(argJson);
      const { keyPackages } = await directoryDeps.fetchPeerKeyPackages({
        ...auth(),
        targetDid: peer_did,
        perDevice: true,
      });
      const records = keyPackages
        .filter((kp) => kp.deviceId)
        .map((kp) => ({ device_id: kp.deviceId, did: peer_did }));
      return stringifyReturn(records);
    },

    async fetch_peer_key_packages(argJson) {
      const { peer_did, device_ids } = parseArg(argJson);
      const { keyPackages } = await directoryDeps.fetchPeerKeyPackages({
        ...auth(),
        targetDid: peer_did,
        perDevice: true,
      });
      const want = new Set(Array.isArray(device_ids) ? device_ids : []);
      const out = keyPackages
        .filter((kp) => kp.deviceId && (want.size === 0 || want.has(kp.deviceId)))
        .map((kp) => ({ device_id: kp.deviceId, key_package: kp.keyPackageB64 }));
      return stringifyReturn(out);
    },

    async fetch_own_key_packages(argJson) {
      // Claim one KP per OTHER own device so reconcile can add them as MLS
      // members. The IdP's per-device claim (single-use) lives on
      // /v1/mls/keypackages/:did?per_device=true with `:did` set to OUR did.
      // If the agent only runs a single device this returns 0 entries (the
      // orchestrator's own-member backfill path no-ops on []), so no
      // regression for the common case; if the agent ever scales to N
      // devices this is the path that lets them all join.
      const { device_ids } = parseArg(argJson);
      const want = new Set(Array.isArray(device_ids) ? device_ids : []);
      const { keyPackages } = await directoryDeps.fetchPeerKeyPackages({
        ...auth(),
        targetDid: ctx.agentDid,
        perDevice: true,
      });
      const out = keyPackages
        .filter((kp) => kp.deviceId && (want.size === 0 || want.has(kp.deviceId)))
        .map((kp) => ({ device_id: kp.deviceId, key_package: kp.keyPackageB64 }));
      return stringifyReturn(out);
    },

    async fetch_peer_key_packages_per_device(argJson) {
      const { peer_did } = parseArg(argJson);
      const { keyPackages } = await directoryDeps.fetchPeerKeyPackages({
        ...auth(),
        targetDid: peer_did,
        perDevice: true,
      });
      const out = keyPackages
        .filter((kp) => kp.deviceId)
        .map((kp) => ({ device_id: kp.deviceId, key_package: kp.keyPackageB64 }));
      return stringifyReturn(out);
    },
  };

  // ─── TransportCallbacks ────────────────────────────────────────────────
  // Writes to the IdP — group registration + per-device member ops. All
  // return void to the wasm (the orchestrator only needs success/failure).
  const transport = {
    async register_direct_group(argJson) {
      const { peer_did, mls_group_init_b64, force_new } = parseArg(argJson);
      const created = await transportDeps.createGroupOnIdp({
        ...auth(),
        name: 'Direct chat',
        mlsGroupInitB64: mls_group_init_b64,
        groupType: 'direct',
        // Pass the peer so the IdP get-or-creates ONE canonical group per pair.
        peerDid: peer_did,
        // Rotation self-heal forwards force_new so the IdP repoints the pair.
        forceNew: force_new === true,
      });
      if (!created || typeof created.id !== 'string') {
        throw new Error('register_direct_group: IdP returned no group id');
      }
      // `existing:true` ⇒ the IdP returned the canonical group already claimed
      // by this pair; the wasm orchestrator adopts it instead of adding the peer.
      const existing = created.existing === true;
      log(
        `[lastid-agent] orchestrator: ${existing ? 'reused canonical' : 'registered'} direct group ${created.id} with peer ${peer_did}`,
      );
      return stringifyReturn({ idp_group_id: created.id, existing });
    },

    async submit_member_add(argJson) {
      const { group_id, member_did, commit } = parseArg(argJson);
      // commit is the wasm PreparedAddCommit (lastid-mls-core dto): its blobs
      // serialize as mls_commit / mls_welcome. Read THOSE — the old
      // commit_b64/welcome_b64 names never existed on the wire, so they
      // resolved to null and the IdP rejected the add. (Console reads the same.)
      const mlsWelcomeB64 = commit?.mls_welcome ?? null;
      const mlsCommitB64 = commit?.mls_commit ?? null;
      await transportDeps.addGroupMember({
        ...auth(),
        groupId: group_id,
        inviteeDid: member_did,
        mlsWelcomeB64,
        mlsCommitB64,
        // Single-commit "everyone at start": the core sets welcome_self when it
        // folded the inviter's own sibling devices into this commit, so the IdP
        // also welcomes the inviter's own DID.
        welcomeSelf: commit?.welcome_self === true,
      });
    },

    async submit_member_device_reconcile(argJson) {
      const { group_id, member_did, target_device_ids, commit } = parseArg(argJson);
      const mlsCommitB64 = commit?.mls_commit ?? null;
      const mlsWelcomeB64 = commit?.mls_welcome ?? null;
      const newEpoch = commit?.new_epoch ?? 0;
      await transportDeps.reconcileMemberDevicesAdd({
        ...auth(),
        groupId: group_id,
        memberDid: member_did,
        targetDeviceIds: target_device_ids ?? [],
        mlsCommitB64,
        mlsWelcomeB64,
        expectedEpoch: Math.max(0, Number(newEpoch) - 1),
      });
    },

    async submit_member_device_evict(argJson) {
      const { group_id, member_did, target_device_ids, commit, reason } = parseArg(argJson);
      const mlsCommitB64 = commit?.mls_commit ?? null;
      const newEpoch = commit?.new_epoch ?? 0;
      await transportDeps.evictMemberDevices({
        ...auth(),
        groupId: group_id,
        memberDid: member_did,
        targetDeviceIds: target_device_ids ?? [],
        mlsCommitB64,
        expectedEpoch: Math.max(0, Number(newEpoch) - 1),
        reason: reason ?? 'device_no_longer_active',
      });
    },

    async fetch_member_device_resolution(argJson) {
      const { group_id, member_did } = parseArg(argJson);
      const res = await directoryDeps.fetchGroupMemberDevices({
        ...auth(),
        groupId: group_id,
        memberDid: member_did,
      });
      return stringifyReturn({
        known: res.known === true,
        active_device_ids: res.activeDeviceIds ?? [],
        pending_eviction_device_ids: res.pendingDeviceIds ?? [],
      });
    },

    async is_group_valid(_argJson) {
      // No agent-side endpoint for this today; assume valid. The
      // orchestrator only uses it to gate its rotation classifier — a
      // pessimistic `false` would force pointless rotations.
      return stringifyReturn({ valid: true });
    },
  };

  // ─── HostCallbacks ─────────────────────────────────────────────────────
  // Out-of-band concerns: how to get a Bearer for IdP calls (we already
  // close over the agent's VC), where to emit setup/reconcile events
  // (listener logging for now — surfaced to the operator separately),
  // and the retry scheduler (best-effort log; the listener's own 5-min
  // timer drives the next attempt).
  const host = {
    async bearer_credential(_argJson) {
      return ctx.vcCompact ?? '';
    },

    async emit_setup_event(argJson) {
      const evt = parseArg(argJson);
      log(`[lastid-agent] orchestrator setup: ${JSON.stringify(evt)}`);
    },

    async emit_reconcile_event(argJson) {
      const evt = parseArg(argJson);
      log(`[lastid-agent] orchestrator reconcile: ${JSON.stringify(evt)}`);
    },

    async schedule_reconcile_retry(argJson) {
      const { group_id, reason } = parseArg(argJson);
      log(`[lastid-agent] orchestrator: deferred reconcile retry for ${group_id} (${reason})`);
    },

    async can_defer_reconcile_error(argJson) {
      const { error_message } = parseArg(argJson);
      // A transient network/IdP blip is deferrable; a logic error is not.
      const msg = String(error_message ?? '');
      const transient = /timeout|ECONN|ENETUNREACH|HTTP 5\d\d|fetch failed/i.test(msg);
      return stringifyReturn({ can_defer: transient });
    },
  };

  return { directory, transport, host };
}

/**
 * Construct (or return the cached) wasm orchestrator for this listener.
 * `ctx` is the listener's mutable bag — same one cli.js passes around —
 * carrying scope/agentDid/operatorDid/idpUrl/vcCompact/signingKey/log.
 *
 * Caching key: the `ctx.__mlsOrchestrator` slot. A single listener has
 * one orchestrator for its lifetime; we never construct a second one.
 */
export async function getOrchestrator(ctx, { deps = {}, wasmImpl = wasm } = {}) {
  if (!ctx) throw new Error('getOrchestrator: ctx required');
  if (!ctx.agentDid) throw new Error('getOrchestrator: ctx.agentDid required');
  // operatorDid is NOT required to build the handle — the orchestrator is
  // constructed with (agentDid, agentDid, …) and operatorDid is only the PEER
  // the ensure/reconcile flows pass as a method arg. The listener builds the
  // handle at startup (the dispatcher needs it to process inbound welcomes)
  // before any peer interaction, so requiring operatorDid here would block the
  // single-instance wiring for no reason.

  if (ctx.__mlsOrchestrator) return ctx.__mlsOrchestrator;

  // Coalesce concurrent callers onto the SAME construction promise so we
  // never instantiate the wasm orchestrator twice (the wasm side owns
  // openmls state that would otherwise fork).
  if (ctx.__mlsOrchestratorPending) return ctx.__mlsOrchestratorPending;

  const { directory, transport, host } = buildCallbackBundles({ ctx, deps });

  // B1 convergence: build the orchestrator over the SAME disk-backed RawKv the
  // MlsClient (dispatcher inbound + agent-send outbound + keypackage publish)
  // opens — `createMlsOrchestratorWithCallbacks` with `diskKvCallbacks` against
  // the agent's sealed mls-state.b64. The OLD path used `createMlsOrchestrator`,
  // the IndexedDB factory, which has NO real backend in Node — so the
  // orchestrator's startDirectChat/reconcile ran on a separate, non-durable
  // openmls state that the send/dispatch path never saw. That instance split is
  // the multi-device welcome bug (mem_01KSNXSY4TY7DK7EJTREPNY5RH): a group the
  // orchestrator created was invisible to the sender, and a welcome the sender
  // joined was invisible to reconcile. ONE instance fixes it.
  //
  // slotSeed is REQUIRED for the disk backend (it derives the at-rest wrap
  // key). The deps.makeKvCallbacks seam lets tests inject an in-memory backend.
  const factory =
    typeof wasmImpl?.createMlsOrchestratorWithCallbacks === 'function'
      ? wasmImpl.createMlsOrchestratorWithCallbacks.bind(wasmImpl)
      : null;
  if (!factory) {
    throw new Error(
      'mls-orchestrator: wasm createMlsOrchestratorWithCallbacks not available',
    );
  }
  const makeKvCallbacks = deps.makeKvCallbacks ?? diskKvCallbacks;
  if (!deps.makeKvCallbacks) {
    // The disk backend needs the 32-byte slot seed; a test injecting its own
    // backend via deps.makeKvCallbacks is exempt.
    if (!(ctx.slotSeed instanceof Uint8Array) || ctx.slotSeed.length !== 32) {
      throw new Error('getOrchestrator: ctx.slotSeed (32-byte Uint8Array) required for the disk backend');
    }
  }
  const kvCallbacks = makeKvCallbacks({
    slotSeed: ctx.slotSeed,
    scope: ctx.scope,
    log: ctx.log,
  });

  // This agent's stable device_id, stamped into every MLS credential the
  // orchestrator's openmls instance builds (own leaf + KeyPackages) so peers —
  // including a member welcomed into a group it didn't build — can map our
  // leaf→device. Only derivable with the real slot seed; a test backend
  // (deps.makeKvCallbacks, no seed) leaves it undefined → bare-DID credential.
  const deviceId =
    ctx.slotSeed instanceof Uint8Array && ctx.slotSeed.length === 32
      ? deriveAgentDeviceId(Buffer.from(ctx.slotSeed))
      : undefined;

  ctx.__mlsOrchestratorPending = (async () => {
    const orch = await factory(
      ctx.agentDid,
      ctx.agentDid,
      directory,
      transport,
      host,
      kvCallbacks,
      deviceId,
    );
    ctx.__mlsOrchestrator = orch;
    return orch;
  })();
  try {
    return await ctx.__mlsOrchestratorPending;
  } finally {
    // Whether it resolved or rejected, clear the pending slot — the
    // cached `ctx.__mlsOrchestrator` (if set) is what subsequent callers
    // want; a rejection means we'll retry from scratch next call.
    ctx.__mlsOrchestratorPending = null;
  }
}

/** Free the cached wasm handle (call on listener shutdown). Idempotent. */
export function disposeOrchestrator(ctx) {
  if (!ctx || !ctx.__mlsOrchestrator) return;
  try {
    ctx.__mlsOrchestrator.free();
  } catch {
    /* already freed */
  }
  ctx.__mlsOrchestrator = null;
}
