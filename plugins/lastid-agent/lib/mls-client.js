/**
 * MLS client wrapper around `lastid-mls-wasm::PersistentBotMlsClient`.
 *
 * Bindings are vendored (CJS, `--target nodejs`) at
 * `vendor/lastid-mls-wasm/`. Build + copy via
 * `lastid-sdk/scripts/build-and-copy-mls-wasm.sh`.
 *
 * BACKED BY a real openmls StorageProvider (lastid-mls-storage's
 * KvBackedStorageProvider, parameterized over a JS-callback-based RawKv).
 * NOT MemoryStorage + dump/restore: that path silently lost KeyPackage
 * bundle private parts and processWelcome would fail with NoMatchingKeyPackage
 * on multi-device delivery — the wasm port mistake that matched the native
 * SDK's storage-provider behaviour finally fixes here. The on-disk format
 * stays compatible (existing mls-state.b64 files load as-is).
 *
 * Persistence: the wasm-side method auto-flushes after every state-mutating
 * op. The flush callback this file supplies seals + writes the base64 blob
 * to `~/.lastid-agent/<scope>/mls-state.b64`, AES-256-GCM sealed by the
 * agent's slot_seed-derived key so a host-disk leak ≠ MLS state leak.
 * `persist()` is now a no-op kept for source compatibility.
 *
 * State recovery semantics. If the persisted file is missing or
 * unparseable we start fresh (no prior MLS state). The agent's stable
 * Ed25519 keypair is unchanged across this fallback — it lives in the
 * OS keychain alongside the VC — so peers that have the agent's
 * KeyPackage continue to encrypt to the same identity. They just need
 * to re-add the agent to any group it was previously a member of,
 * because MLS group state is per-client (not derivable from the keypair).
 */
import { createRequire } from 'node:module';
import { diskKvCallbacks } from './mls-state-store.js';
import { resolveAgentDeviceId } from './agent-provisioning.js';

const localRequire = createRequire(import.meta.url);
const wasm = localRequire('../vendor/lastid-mls-wasm/lastid_mls_wasm.js');

// One-time wasm-side init: pipes Rust panics to console so an MLS
// codec failure shows up with a stack trace instead of a generic
// `RuntimeError: unreachable`.
try {
  wasm.init();
} catch {
  // `init` is idempotent in practice; a second call from a re-imported
  // module instance is fine.
}

// Seal/load/flush + scope-path logic now lives in mls-state-store.js so the
// orchestrator opens the SAME sealed file as this client (B1 convergence).

/**
 * High-level MLS client. One instance per agent runtime; outlives
 * individual WS connects. Use:
 *
 *   const mls = await MlsClient.open({ agentDid, slotSeed, scope });
 *   const kpB64 = await mls.generateKeyPackage();
 *
 * Every state-mutating method is async + auto-persists before its
 * Promise resolves. `persist()` is a no-op kept for source compat.
 */
export class MlsClient {
  /** @type {import('../vendor/lastid-mls-wasm/lastid_mls_wasm.js').PersistentBotMlsClient} */
  #handle;
  #agentDid;
  // This client's resolved MLS device_id (`md-…` machine-bound, or the legacy
  // `ad-…`). The SINGLE source the KeyPackage publish reads (mls-publish uses
  // `mls.deviceId`), so the credential the handle stamps and the device_id the
  // KP is stored under can never disagree (the multi-device two-sources class).
  #deviceId;
  // True when this client OWNS the wasm handle (it opened it via `open`) and
  // may free it. False for `fromOrchestrator` wrappers, which borrow the
  // shared orchestrator handle the listener frees exactly once on shutdown.
  #ownsHandle;

  constructor({ handle, agentDid, deviceId = null, ownsHandle = true }) {
    this.#handle = handle;
    this.#agentDid = agentDid;
    this.#deviceId = deviceId ?? null;
    this.#ownsHandle = ownsHandle;
  }

  /**
   * Open the agent's MLS client. The wasm-side state is loaded from disk
   * (sealed mls-state.b64) via the loadBlob callback; subsequent writes
   * are flushed back via flushBlob after every state-mutating op. If the
   * file is missing or unparseable we start fresh.
   */
  static async open({ agentDid, slotSeed, wrapKey, scope, deviceId: persistedDeviceId }) {
    const resolvedScope = scope ?? 'main';
    // Stamp this agent's device_id into every credential this client builds so
    // peers can map our leaf→device (matches the orchestrator handle + the
    // device_id the IdP key-package store is keyed by). `resolveAgentDeviceId`
    // returns the value PINNED at provisioning (`md-…` for a machine-bound
    // agent) or the legacy `ad-…` derivation when none was persisted — the
    // no-flag-day seam, byte-identical to today for existing agents.
    //
    // MLS-custody: a broker-native agent passes `wrapKey` (no raw seed); it is
    // always machine-bound, so its device_id is the pinned `md-…` — no seed
    // needed to resolve it. Legacy agents pass `slotSeed` and derive as before.
    const deviceId =
      slotSeed instanceof Uint8Array && slotSeed.length === 32
        ? resolveAgentDeviceId({
            persistedDeviceId,
            slotSeed: Buffer.from(slotSeed),
            agentDid,
          })
        : (persistedDeviceId ?? undefined);
    const handle = await wasm.createPersistentBotClientWithCallbacks(
      agentDid,
      diskKvCallbacks({ slotSeed, wrapKey, scope: resolvedScope }),
      deviceId,
    );
    return new MlsClient({ handle, agentDid, deviceId: deviceId ?? null });
  }

  /**
   * Wrap an already-constructed shared MLS handle (the wasm `MlsOrchestrator`
   * from lib/mls-orchestrator.js) in the MlsClient method surface, so the
   * dispatcher + send path drive the SAME openmls instance the orchestrator's
   * ensure/reconcile flows use — B1 convergence: ONE instance per listener,
   * not a separate per-consumer client.
   *
   * The orchestrator handle returns the SAME JSON-string shapes
   * PersistentBotMlsClient does for every method this class wraps
   * (processWelcome/processInbound/createGroup/addMember(s)/encrypt/…), so the
   * wrapping is transparent. groupEpoch is async on the orchestrator — handled
   * by the async groupEpoch above.
   *
   * No slotSeed/scope: durability is owned by the orchestrator's own
   * disk-backed RawKv (it was built with the same diskKvCallbacks), so this
   * wrapper never opens a file of its own.
   */
  static fromOrchestrator(handle, agentDid, deviceId = null) {
    if (!handle) throw new Error('MlsClient.fromOrchestrator: handle required');
    if (!agentDid) throw new Error('MlsClient.fromOrchestrator: agentDid required');
    // `deviceId` is the SAME value the orchestrator handle was built with (the
    // listener resolves it once and threads it here) so KeyPackage publish via
    // this wrapper reports the device_id the shared handle's credentials carry.
    return new MlsClient({ handle, agentDid, deviceId, ownsHandle: false });
  }

  get agentDid() {
    return this.#agentDid;
  }

  /**
   * This client's resolved MLS device_id — the single source the KeyPackage
   * publish path reads so the KP's `device_id` matches the credential the
   * handle stamps. Null only for a test/bare-DID handle built without a seed.
   */
  get deviceId() {
    return this.#deviceId;
  }

  /**
   * Generate a fresh MLS KeyPackage. The bundle's private parts are written
   * into the storage provider AND flushed to disk before this Promise
   * resolves — the published public KeyPackage is usable across restarts.
   */
  async generateKeyPackage() {
    return await this.#handle.generateKeyPackage();
  }

  /**
   * Accept an MLS Welcome that adds this agent to a group. Returns
   * the parsed JoinedGroupInfo { group_id_b64, member_count, epoch }.
   */
  async processWelcome(welcomeB64, idpGroupId) {
    // Pass the IdP group UUID so the wasm seeds the idp→openmls id mapping at
    // join time (the welcome alone only carries the openmls id). Without it a
    // later reconcileMemberDevices(idpUuid) can't resolve the group and crashes
    // base64-decoding the UUID — leaving the operator's other devices unadded.
    return JSON.parse(await this.#handle.processWelcome(welcomeB64, idpGroupId ?? null));
  }

  /**
   * Seed the IdP-UUID → openmls-id mapping for a group joined in a PRIOR
   * session, so reconcile/group_handle can resolve it by IdP UUID instead of
   * crashing base64-decoding the UUID. Backfill for groups joined before
   * processWelcome started seeding it inline. Idempotent; no-op if the handle
   * doesn't expose it (older vendored wasm) so a stale artifact degrades
   * gracefully rather than throwing at startup.
   */
  async bindGroupIdMapping(idpGroupId, openmlsB64) {
    if (typeof this.#handle.bindGroupIdMapping !== 'function') return;
    await this.#handle.bindGroupIdMapping(idpGroupId, openmlsB64);
  }

  /**
   * Author a fresh MLS group with this agent as sole creator. Pass a
   * caller-reserved `group_id_b64`. Returns parsed JoinedGroupInfo.
   */
  async createGroup(groupIdB64) {
    return JSON.parse(await this.#handle.createGroup(groupIdB64));
  }

  /**
   * Export the group's GroupInfo as base64 TLS — the `mls_group_init`
   * POST /v1/groups requires (the IdP hashes it into the canonical
   * mls_group_id). Read-only on group state, but async because the wasm
   * surface is async.
   */
  async exportGroupInfo(groupIdB64) {
    return await this.#handle.exportGroupInfo(groupIdB64);
  }

  /**
   * Add a peer (base64-TLS KeyPackage) to a group this agent owns.
   * Returns parsed { commit_b64, welcome_b64, new_epoch }.
   */
  async addMember(groupIdB64, keyPackageB64) {
    return JSON.parse(await this.#handle.addMember(groupIdB64, keyPackageB64));
  }

  /**
   * Add several peers in ONE commit. `keyPackagesB64` is an array of base64
   * KeyPackages. Returns parsed { commit_b64, welcome_b64, new_epoch }.
   */
  async addMembers(groupIdB64, keyPackagesB64) {
    return JSON.parse(
      await this.#handle.addMembers(groupIdB64, JSON.stringify(keyPackagesB64)),
    );
  }

  /**
   * Remove a member by its MLS leaf index. Returns parsed { commit_b64,
   * new_epoch }.
   */
  async removeMember(groupIdB64, leafIndex) {
    return JSON.parse(await this.#handle.removeMember(groupIdB64, leafIndex));
  }

  /**
   * Process an inbound message — application, commit, or proposal.
   * Returns the parsed `InboundResult` JSON.
   */
  async processInbound(messageB64) {
    return JSON.parse(await this.#handle.processInbound(messageB64));
  }

  /**
   * Encrypt a payload for the named group. Returns the base64-
   * encoded MLS wire payload the caller POSTs as a
   * `group_chat.message` event.
   */
  async encryptApplicationMessage(groupIdB64, plaintextB64) {
    return await this.#handle.encryptApplicationMessage(groupIdB64, plaintextB64);
  }

  /**
   * Current MLS epoch for a group. ASYNC: the standalone
   * PersistentBotMlsClient returns a sync BigInt, but the shared orchestrator
   * handle (B1 convergence — see fromOrchestrator) returns a Promise (its
   * groupEpoch is op-lock-serialized). `await` works for both — awaiting a
   * BigInt just yields it — so this one signature covers both backends.
   */
  async groupEpoch(groupIdB64) {
    return await this.#handle.groupEpoch(groupIdB64);
  }

  /**
   * Wipe local MlsGroup state for a dissolved group. Idempotent.
   */
  async forgetGroup(groupIdB64) {
    await this.#handle.forgetGroup(groupIdB64);
  }

  /**
   * Issue a commit covering every pending proposal openmls has
   * queued locally for this group.
   */
  async commitPendingProposals(groupIdB64) {
    return JSON.parse(await this.#handle.commitPendingProposals(groupIdB64));
  }

  /**
   * Discard any locally-prepared-but-not-yet-published commit.
   */
  async rollbackPendingCommit(groupIdB64) {
    await this.#handle.rollbackPendingCommit(groupIdB64);
  }

  /**
   * No-op — kept for source compatibility with the old BotMlsClient path.
   * The wasm-side method now auto-flushes via the flushBlob callback after
   * every state-mutating op; callers don't need to persist explicitly.
   */
  async persist() {
    /* state is already durable when the awaited mutating method resolved */
  }

  /**
   * Free the underlying wasm handle. Call when shutting down.
   *
   * NOTE: when this client was built via `fromOrchestrator`, the handle is the
   * SHARED orchestrator — freeing it here would pull it out from under the
   * ensure/reconcile paths. The listener frees the orchestrator once via
   * disposeOrchestrator(ctx) on shutdown, so a fromOrchestrator-wrapped client
   * should NOT also free it. Tracked by `#ownsHandle`.
   */
  free() {
    if (!this.#ownsHandle) return;
    try {
      this.#handle.free();
    } catch {
      // Already freed.
    }
  }
}

/**
 * Device-consistency reconcile decision for one group member — runs the
 * SHARED Rust planner (lastid-mls-membership) via wasm, so the agent decides
 * exactly what native does. Input: { inventoryLeafCount, inventoryDeviceIds,
 * activeInGroup, pendingInGroup, liveDeviceIds }. Returns
 * { backfill_device_ids, evict_device_ids, add_device_ids, action }.
 * No state, no I/O — the caller fetches the inputs and applies the result.
 */
export function computeMemberReconcilePlan(input) {
  const payload = JSON.stringify({
    inventory_leaf_count: input.inventoryLeafCount ?? 0,
    inventory_device_ids: input.inventoryDeviceIds ?? [],
    active_in_group: input.activeInGroup ?? [],
    pending_in_group: input.pendingInGroup ?? [],
    live_device_ids: input.liveDeviceIds ?? [],
  });
  return JSON.parse(wasm.computeMemberReconcilePlan(payload));
}
