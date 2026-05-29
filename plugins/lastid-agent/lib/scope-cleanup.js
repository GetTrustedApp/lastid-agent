/**
 * Scope cleanup — wipe ALL state for a sub-agent's local scope when its
 * VC has been revoked at the IdP and the listener has confirmed it via
 * a `Credential has been revoked` response on the WS upgrade.
 *
 * THE PROBLEM this exists to solve (verified 2026-05-29): when an
 * operator edits a sub-agent's capabilities, the IdP revokes the OLD VC
 * and issues a NEW one at a fresh DID. The new identity gets persisted
 * to a NEW scope dir; the OLD scope's listener kept running with the
 * dead VC and reconnected to /v1/ws every ~10s for 14+ HOURS (attempt
 * #871 observed live), spamming the prod IdP logs with
 * `"Credential has been revoked"` warnings and hammering an endpoint
 * that would NEVER let it in again. There is no recovery path — a
 * revoked VC cannot be un-revoked; the listener has no business
 * existing once that's true.
 *
 * The cleanup wipes both halves of a scope's identity:
 *   - `~/.lastid-agent/<scope>/` — the listener's data dir (mls state,
 *     audit chain, cached vault shares, listener.log, operator-state,
 *     cli-bindings, etc.)
 *   - macOS Keychain entries — slot_seed, VC, slot_index, agent_did,
 *     idp_url, project_root_seed (via the existing `deleteAgentVc(scope)`
 *     in lib/keychain.js)
 *
 * NOT TOUCHED:
 *   - The parent's own scope dir (the caller wouldn't be revoking
 *     itself in normal operation; if it ever DOES self-revoke we don't
 *     want a sibling listener on the same machine to lose data).
 *   - Sub-agent class-slug-keyed entries in keychain
 *     (`SERVICE_SUB_SLOT_SEED:<classSlug>`, `SERVICE_SUB_VC:<classSlug>`)
 *     — those are the PARENT's record of what it provisioned; the parent
 *     wipes them on its own revoke-handling path.
 *
 * Safety: the dir wipe and keychain wipe are LOG-AND-CONTINUE — if one
 * fails the other still runs, so a stuck file lock or a missing
 * keychain entry doesn't leave us in a half-cleaned state. The function
 * returns a structured summary so callers can decide whether to exit
 * with success or non-zero.
 */

import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { deleteAgentVc } from './keychain.js';

/**
 * Resolve the scope's data dir. Pure helper — exposed so tests can pin
 * the resolution without monkey-patching homedir().
 */
export function scopeDataDir(scope, homedirFn = homedir) {
  if (typeof scope !== 'string' || scope.trim().length === 0) {
    throw new Error('scopeDataDir: scope must be a non-empty string');
  }
  return join(homedirFn(), '.lastid-agent', scope.trim());
}

/**
 * Wipe a scope. Returns a summary; never throws on filesystem or
 * keychain errors (logged + reported via the summary).
 *
 * @param {string} scope
 * @param {{
 *   rmDir?: (path: string) => Promise<void>,
 *   deleteVc?: (scope: string) => Promise<void>,
 *   logger?: (line: string) => void,
 *   homedirFn?: () => string,
 * }} [deps]
 * @returns {Promise<{
 *   scope: string,
 *   dataDirRemoved: boolean,
 *   dataDirError: string | null,
 *   keychainCleared: boolean,
 *   keychainError: string | null,
 * }>}
 */
export async function cleanupRevokedScope(scope, deps = {}) {
  const rmDir = deps.rmDir ?? ((p) => rm(p, { recursive: true, force: true }));
  const deleteVc = deps.deleteVc ?? deleteAgentVc;
  const logger = deps.logger ?? ((line) => process.stderr.write(line));
  const homedirFn = deps.homedirFn ?? homedir;

  const dir = scopeDataDir(scope, homedirFn);
  let dataDirRemoved = false;
  let dataDirError = null;
  try {
    await rmDir(dir);
    dataDirRemoved = true;
    logger(`[lastid-agent] scope-cleanup: removed data dir ${dir}\n`);
  } catch (err) {
    dataDirError = err instanceof Error ? err.message : String(err);
    logger(`[lastid-agent] scope-cleanup: data dir wipe failed: ${dataDirError}\n`);
  }

  let keychainCleared = false;
  let keychainError = null;
  try {
    await deleteVc(scope);
    keychainCleared = true;
    logger(`[lastid-agent] scope-cleanup: keychain entries deleted for scope=${scope}\n`);
  } catch (err) {
    keychainError = err instanceof Error ? err.message : String(err);
    logger(`[lastid-agent] scope-cleanup: keychain delete failed: ${keychainError}\n`);
  }

  return { scope, dataDirRemoved, dataDirError, keychainCleared, keychainError };
}
