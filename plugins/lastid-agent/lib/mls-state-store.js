/**
 * Shared on-disk MLS state backend for the Node agent.
 *
 * This is the ONE durable backend every MLS consumer in the listener shares:
 * the inbound dispatcher, the outbound send path, keypackage publish, and the
 * orchestrator's ensure/reconcile flows ALL open their wasm handle against the
 * same sealed file via `diskKvCallbacks`. That's the whole point of B1
 * convergence — a single openmls instance, so a group one path creates is
 * visible to every other path (the bug behind multi-device welcome failure:
 * mem_01KSNXSY4TY7DK7EJTREPNY5RH).
 *
 * The wasm side keeps a real per-key RawKv cache (callback_kv.rs) and calls
 * `flushBlob` after every state-mutating op with the FULL serialized cache.
 * We seal that blob AES-256-GCM with a slot_seed-derived key and write it
 * atomically to `~/.lastid-agent/<scope>/mls-state.b64`. `loadBlob` reverses
 * it once at open. On-disk format is byte-compatible with what
 * `BotMlsClient::dump_state` produced, so existing state files migrate as-is.
 *
 * (Extracted verbatim from mls-client.js so MlsClient AND the orchestrator
 * share one seal/scope discipline instead of each hand-rolling it.)
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';
import { Buffer } from 'node:buffer';

const STATE_FILE_NAME = 'mls-state.b64';
const STATE_NONCE_LEN = 12;
const HKDF_SALT = Buffer.from('lastid/agent/mls-state/v1');

/**
 * Path the plugin saves MLS state to, keyed by `scope` (matches the
 * `--scope` flag from cli.js — defaults to `main`).
 */
export function stateFilePath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', STATE_FILE_NAME);
}

/**
 * Derive the AES-256-GCM at-rest key from the agent's slot_seed.
 * The slot_seed is the 32-byte BIP85-derived secret the wallet sealed at
 * provision time; the plugin already holds it in the keychain (alongside the
 * VC) and treats it as "if you have this you ARE the agent." Using it as the
 * wrap-key for MLS state is the cheapest correct posture — host-disk leak ≠
 * MLS state leak, but a slot_seed leak already loses you the agent.
 */
export function deriveWrapKey(slotSeed) {
  if (!(slotSeed instanceof Uint8Array) || slotSeed.length !== 32) {
    throw new Error('mls-state-store: slotSeed must be a 32-byte Uint8Array');
  }
  return Buffer.from(
    hkdfSync('sha256', slotSeed, HKDF_SALT, Buffer.from('aes-256-gcm wrap'), 32),
  );
}

/** Validate a 32-byte AES key (the broker-derived wrap key or deriveWrapKey). */
function requireWrapKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('mls-state-store: wrap key must be a 32-byte buffer');
  }
  return key;
}

/**
 * Seal with a PRE-DERIVED 32-byte wrap key. MLS-custody: a broker-native agent
 * gets this key from the broker (brokerDeriveMlsStateKey) — byte-identical to
 * deriveWrapKey — so it never holds the raw seed. Same wire shape either way.
 */
export function sealStateBlobWithKey(key, stateB64) {
  requireWrapKey(key);
  const nonce = randomBytes(STATE_NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const plaintext = Buffer.from(stateB64, 'utf-8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Wire shape: 1-byte version || 12 nonce || 16 tag || ciphertext
  return Buffer.concat([Buffer.from([1]), nonce, tag, ct]).toString('base64');
}

export function sealStateBlob(slotSeed, stateB64) {
  return sealStateBlobWithKey(deriveWrapKey(slotSeed), stateB64);
}

/** Open with a PRE-DERIVED 32-byte wrap key (MLS-custody; see sealStateBlobWithKey). */
export function openStateBlobWithKey(key, blobB64) {
  requireWrapKey(key);
  const blob = Buffer.from(blobB64, 'base64');
  if (blob.length < 1 + STATE_NONCE_LEN + 16 || blob[0] !== 1) {
    throw new Error('mls-state-store: state blob has unexpected version/length');
  }
  const nonce = blob.subarray(1, 1 + STATE_NONCE_LEN);
  const tag = blob.subarray(1 + STATE_NONCE_LEN, 1 + STATE_NONCE_LEN + 16);
  const ct = blob.subarray(1 + STATE_NONCE_LEN + 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf-8');
}

export function openStateBlob(slotSeed, blobB64) {
  return openStateBlobWithKey(deriveWrapKey(slotSeed), blobB64);
}

/**
 * Build the `{ loadBlob, flushBlob }` callback bundle the wasm
 * `createPersistentBotClientWithCallbacks` / `createMlsOrchestratorWithCallbacks`
 * constructors take. Both consumers pass the SAME bundle (same slotSeed +
 * scope) so they open the SAME sealed file → the SAME openmls state.
 *
 * - `loadBlob()` — invoked once at open. Returns the unsealed base64 of the
 *   prior state, or null for a fresh client (missing file). An unparseable
 *   file logs + starts fresh (the agent's Ed25519 identity is unchanged, so
 *   peers re-add it to groups; MLS group state is per-client, not derivable
 *   from the keypair).
 * - `flushBlob(b64)` — invoked after every state-mutating op. Seals + writes
 *   atomically (tmp + rename) so a crash mid-write never truncates the live
 *   file. Awaited by the wasm so the JS Promise only resolves once durable.
 *
 * Supply EITHER `slotSeed` (legacy: derives the wrap key in node) OR `wrapKey`
 * (MLS-custody: the broker-derived 32-byte key, so node never holds the raw
 * seed). They produce the identical wire key, so a file sealed under one opens
 * under the other.
 *
 * @param {{ slotSeed?: Uint8Array, wrapKey?: Uint8Array, scope?: string, log?: (line:string)=>void }} a
 * @returns {{ loadBlob: () => Promise<string|null>, flushBlob: (b64:string) => Promise<void> }}
 */
export function diskKvCallbacks({ slotSeed, wrapKey, scope, log }) {
  // Resolve the 32-byte wrap key from whichever source was given. wrapKey wins
  // (broker-native); else derive from the raw seed (legacy).
  const key = wrapKey != null ? requireWrapKey(wrapKey) : deriveWrapKey(slotSeed);
  const resolvedScope = scope ?? 'main';
  const path = stateFilePath(resolvedScope);
  const warn =
    log ?? ((line) => process.stderr.write(`${line}\n`));

  const loadBlob = async () => {
    try {
      const blob = await readFile(path, 'utf-8');
      return openStateBlobWithKey(key, blob.trim());
    } catch (err) {
      if (err && err.code === 'ENOENT') return null;
      warn(
        `[lastid-agent] mls: failed to load prior state (${err?.message ?? err}); starting fresh`,
      );
      return null;
    }
  };

  const flushBlob = async (stateB64) => {
    const sealed = sealStateBlobWithKey(key, stateB64);
    await mkdir(dirname(path), { recursive: true });
    // Atomic write: tmp + rename so a crash mid-write can't truncate the
    // live sealed state and brick the agent's MLS identity.
    const tmp = `${path}.tmp-${process.pid}`;
    await writeFile(tmp, sealed, 'utf-8');
    const { rename } = await import('node:fs/promises');
    await rename(tmp, path);
  };

  return { loadBlob, flushBlob };
}
