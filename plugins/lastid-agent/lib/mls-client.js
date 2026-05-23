/**
 * MLS client wrapper around `lastid-mls-wasm::BotMlsClient`.
 *
 * Bindings are vendored (CJS, `--target nodejs`) at
 * `vendor/lastid-mls-wasm/`. Build + copy via
 * `lastid-sdk/scripts/build-and-copy-mls-wasm.sh`.
 *
 * Wraps the raw wasm surface with:
 *   - Lifecycle: instantiate fresh or from persisted state.
 *   - Persistence: serialize to a base64 state blob the plugin saves
 *     under `~/.lastid-agent/<scope>/mls-state.b64`. Sealed by the
 *     agent's slot_seed-derived AES key so a host-disk leak doesn't
 *     expose group epochs / committer state.
 *   - Inbound dispatch: parse the JSON `InboundResult` enum into a
 *     discriminated union JS consumers can switch on.
 *
 * State recovery semantics. If the persisted file is missing or
 * unparseable we fall back to `createBotClient` (fresh state). The
 * agent's stable Ed25519 keypair is unchanged across this fallback
 * — it lives in the OS keychain alongside the VC — so peers that
 * have the agent's KeyPackage continue to encrypt to the same
 * identity. They just need to re-add the agent to any group it
 * was previously a member of, because MLS group state is per-
 * client (not derivable from the keypair).
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
 *   const kpB64 = mls.generateKeyPackage();
 *   await mls.persist(); // after every state-mutating op
 */
export class MlsClient {
  /** @type {import('../vendor/lastid-mls-wasm/lastid_mls_wasm.js').BotMlsClient} */
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
   * Open the agent's MLS client. Restores from disk when possible,
   * otherwise creates fresh.
   */
  static async open({ agentDid, slotSeed, scope }) {
    let handle;
    try {
      const blob = await readFile(stateFilePath(scope ?? 'main'), 'utf-8');
      const stateB64 = openStateBlob(slotSeed, blob.trim());
      handle = wasm.BotMlsClient.restoreBotClient(agentDid, stateB64);
    } catch (err) {
      // ENOENT or unparseable — start fresh. NOT an error; just means
      // either first run or the file is from a different agent and
      // can't be decrypted.
      if (err.code !== 'ENOENT') {
        process.stderr.write(
          `[lastid-agent] mls: failed to restore prior state (${err.message}); starting fresh\n`,
        );
      }
      handle = wasm.BotMlsClient.createBotClient(agentDid);
    }
    return new MlsClient({ handle, agentDid, slotSeed, scope });
  }

  get agentDid() {
    return this.#agentDid;
  }

  /**
   * Generate a fresh MLS KeyPackage. Caller is responsible for:
   *   1. POSTing to `/v1/mls/keypackages` so peers can fetch it.
   *   2. Calling `persist()` immediately — the underlying wasm
   *      generates a private credential the dump captures. Skipping
   *      persist means the generated KeyPackage is unusable on the
   *      next restart.
   */
  generateKeyPackage() {
    return this.#handle.generateKeyPackage();
  }

  /**
   * Accept an MLS Welcome that adds this agent to a group. Returns
   * the parsed JoinedGroupInfo { group_id_b64, member_count, epoch }.
   */
  processWelcome(welcomeB64) {
    return JSON.parse(this.#handle.processWelcome(welcomeB64));
  }

  /**
   * Process an inbound message — application, commit, or proposal.
   * Returns the parsed `InboundResult` JSON. Application messages
   * include `application_b64` (the encrypted plaintext, base64);
   * commits / proposals are merged into local group state and the
   * result carries a `kind` tag callers can switch on.
   */
  processInbound(messageB64) {
    return JSON.parse(this.#handle.processInbound(messageB64));
  }

  /**
   * Encrypt a payload for the named group. Returns the base64-
   * encoded MLS wire payload the caller POSTs as a
   * `group_chat.message` event.
   */
  encryptApplicationMessage(groupIdB64, plaintextB64) {
    return this.#handle.encryptApplicationMessage(groupIdB64, plaintextB64);
  }

  /** Current MLS epoch for a group (as BigInt). */
  groupEpoch(groupIdB64) {
    return this.#handle.groupEpoch(groupIdB64);
  }

  /**
   * Serialize + seal current state to disk. Call after every
   * mutating op (generateKeyPackage / processWelcome /
   * processInbound that landed a commit). Cheap (~few ms on small
   * groups).
   */
  async persist() {
    const stateB64 = this.#handle.dumpState();
    const sealed = sealStateBlob(this.#slotSeed, stateB64);
    const path = stateFilePath(this.#scope);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, sealed, 'utf-8');
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
