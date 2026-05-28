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
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  hkdfSync,
} from 'node:crypto';

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

const STATE_FILE_NAME = 'mls-state.b64';
const STATE_NONCE_LEN = 12;
const HKDF_SALT = Buffer.from('lastid/agent/mls-state/v1');

/**
 * Path the plugin saves MLS state to, keyed by `scope` (matches the
 * `--scope` flag from cli.js — defaults to `main`).
 */
function stateFilePath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', STATE_FILE_NAME);
}

/**
 * Derive the AES-256-GCM at-rest key from the agent's slot_seed.
 * The slot_seed is the 32-byte BIP85-derived secret the wallet
 * sealed at provision time; the plugin already holds it in the
 * keychain (alongside the VC) and treats it as "if you have this
 * you ARE the agent." Using it as the wrap-key for MLS state is
 * the cheapest correct posture — host-disk leak ≠ MLS state leak,
 * but a slot_seed leak already loses you the agent.
 */
function deriveWrapKey(slotSeed) {
  if (!(slotSeed instanceof Uint8Array) || slotSeed.length !== 32) {
    throw new Error('mls-client: slotSeed must be a 32-byte Uint8Array');
  }
  return Buffer.from(
    hkdfSync('sha256', slotSeed, HKDF_SALT, Buffer.from('aes-256-gcm wrap'), 32),
  );
}

function sealStateBlob(slotSeed, stateB64) {
  const key = deriveWrapKey(slotSeed);
  const nonce = randomBytes(STATE_NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const plaintext = Buffer.from(stateB64, 'utf-8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Wire shape: 1-byte version || 12 nonce || 16 tag || ciphertext
  return Buffer.concat([Buffer.from([1]), nonce, tag, ct]).toString('base64');
}

function openStateBlob(slotSeed, blobB64) {
  const blob = Buffer.from(blobB64, 'base64');
  if (blob.length < 1 + STATE_NONCE_LEN + 16 || blob[0] !== 1) {
    throw new Error('mls-client: state blob has unexpected version/length');
  }
  const nonce = blob.subarray(1, 1 + STATE_NONCE_LEN);
  const tag = blob.subarray(1 + STATE_NONCE_LEN, 1 + STATE_NONCE_LEN + 16);
  const ct = blob.subarray(1 + STATE_NONCE_LEN + 16);
  const key = deriveWrapKey(slotSeed);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf-8');
}

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
  #slotSeed;
  #scope;

  constructor({ handle, agentDid, slotSeed, scope }) {
    this.#handle = handle;
    this.#agentDid = agentDid;
    this.#slotSeed = slotSeed;
    this.#scope = scope ?? 'main';
  }

  /**
   * Open the agent's MLS client. The wasm-side state is loaded from disk
   * (sealed mls-state.b64) via the loadBlob callback; subsequent writes
   * are flushed back via flushBlob after every state-mutating op. If the
   * file is missing or unparseable we start fresh.
   */
  static async open({ agentDid, slotSeed, scope }) {
    const resolvedScope = scope ?? 'main';
    const path = stateFilePath(resolvedScope);
    const loadBlob = async () => {
      try {
        const blob = await readFile(path, 'utf-8');
        return openStateBlob(slotSeed, blob.trim());
      } catch (err) {
        if (err.code === 'ENOENT') return null;
        process.stderr.write(
          `[lastid-agent] mls: failed to load prior state (${err.message}); starting fresh\n`,
        );
        return null;
      }
    };
    const flushBlob = async (stateB64) => {
      const sealed = sealStateBlob(slotSeed, stateB64);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, sealed, 'utf-8');
    };
    const handle = await wasm.createPersistentBotClientWithCallbacks(agentDid, {
      loadBlob,
      flushBlob,
    });
    return new MlsClient({ handle, agentDid, slotSeed, scope: resolvedScope });
  }

  get agentDid() {
    return this.#agentDid;
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
  async processWelcome(welcomeB64) {
    return JSON.parse(await this.#handle.processWelcome(welcomeB64));
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

  /** Current MLS epoch for a group (as BigInt). Read-only; sync. */
  groupEpoch(groupIdB64) {
    return this.#handle.groupEpoch(groupIdB64);
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

  /** Free the underlying wasm handle. Call when shutting down. */
  free() {
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
