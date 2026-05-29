/**
 * Agent-side group map — the IdP group UUID ↔ openmls group_id_b64
 * link, plus the operator (peer) DID, persisted so the outbound send
 * path can resolve "reply to IdP group X" → "encrypt for openmls
 * group Y".
 *
 * Why this exists: inbound `group_chat.*` events key by the IdP's
 * group UUID (`payload.group_id`), but the MLS client encrypts /
 * decrypts by the openmls-internal `group_id_b64`. The link is only
 * observable at join time — `processWelcome` returns the openmls id
 * while the welcome event carries the IdP UUID. We capture it there
 * and persist it so a later send (possibly after a restart) can
 * resolve the pair without re-deriving it.
 *
 * Storage: `~/.lastid-agent/<scope>/groups.json`, a single JSON
 * object keyed by IdP group UUID:
 *
 *   {
 *     "<idp_group_uuid>": {
 *       "group_id_b64": "<openmls id>",
 *       "operator_did": "did:lastid:z…",
 *       "updated_at": "<ISO-8601>"
 *     }
 *   }
 *
 * Single-writer posture: the listener daemon is the only process
 * that records (it owns the MLS state + the WS). The MCP tool only
 * reads (to validate a group_id before enqueuing a send) — never
 * writes. Reads tolerate a missing / malformed file as "no groups
 * yet".
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

function groupsPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'groups.json');
}

async function readAll(scope) {
  try {
    const raw = await readFile(groupsPath(scope), 'utf-8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    // ENOENT or malformed — treat as empty.
    return {};
  }
}

/**
 * Record (or refresh) the mapping for an IdP group. Called by the
 * dispatcher at welcome time (full mapping) and on inbound messages
 * (refreshes operator_did / updated_at). `groupIdB64` may be null on
 * a message-only refresh where we don't re-derive the openmls id —
 * an existing group_id_b64 is preserved in that case.
 */
export async function recordGroup({ scope, idpGroupId, groupIdB64, operatorDid, deviceIds, deviceLeaves }) {
  if (!idpGroupId) return;
  const all = await readAll(scope);
  const prior = all[idpGroupId] ?? {};
  all[idpGroupId] = {
    group_id_b64: groupIdB64 ?? prior.group_id_b64 ?? null,
    operator_did: operatorDid ?? prior.operator_did ?? null,
    // Operator device ids the agent has added to this group — the local
    // inventory device-consistency reconcile diffs against. Preserved across
    // a message-only refresh (deviceIds omitted).
    device_ids: Array.isArray(deviceIds) ? deviceIds : (prior.device_ids ?? []),
    // device_id → MLS leaf index, captured at add time (from the wasm's
    // assigned_leaf_indices). Needed to evict a specific device — the DID
    // credential is ambiguous across a member's leaves. Merged with prior.
    device_leaves:
      deviceLeaves && typeof deviceLeaves === 'object'
        ? { ...(prior.device_leaves ?? {}), ...deviceLeaves }
        : (prior.device_leaves ?? {}),
    updated_at: new Date().toISOString(),
  };
  const path = groupsPath(scope);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(all, null, 2)}\n`, 'utf-8');
}

/**
 * One-time startup repair of the persisted group map.
 *
 * Two problems this heals, both from before processWelcome seeded the
 * idp→openmls mapping inline:
 *
 *  1. CORRUPT records — `group_id_b64` holds a base64-encoded UUID (36 raw
 *     bytes with hyphens) instead of the 32-byte openmls id. These can never
 *     load (openmls base64-decode hits the UUID's hyphen → InvalidByte(8,45))
 *     and there's no way to recover the real openmls id, so we DROP them. The
 *     next send/welcome re-establishes a fresh group cleanly.
 *  2. VALID-but-unmapped records — a real 32-byte openmls id that was never
 *     pushed into the wasm client's idp→openmls map (the agent only ever
 *     recorded it to groups.json). On a fresh process the map is empty, so
 *     `group_handle(idpUuid)` would mis-treat the UUID as the openmls id and
 *     crash. We re-seed the mapping via `mls.bindGroupIdMapping` so reconcile
 *     resolves the group.
 *
 * `mls.bindGroupIdMapping` is the MlsClient wrapper over the orchestrator
 * handle's bindGroupIdMapping (writes the same key group_handle reads, through
 * the listener's one shared backend). Best-effort + idempotent: a per-record
 * failure is logged and skipped, never aborts startup.
 *
 * @returns {Promise<{ seeded: number, dropped: number, scanned: number }>}
 */
export async function repairGroupIdMappings({ scope, mls, log }) {
  const logLine = log ?? (() => {});
  const all = await readAll(scope);
  const entries = Object.entries(all);
  let seeded = 0;
  let dropped = 0;
  let mutated = false;

  for (const [idpGroupId, v] of entries) {
    const b64 = v?.group_id_b64;
    if (!b64) continue;

    // A real openmls id decodes to exactly 32 bytes. A base64'd UUID decodes
    // to 36 bytes (and the bytes are ASCII hyphens/hex). Anything not 32 bytes
    // is corrupt and unrecoverable → drop it.
    let byteLen = -1;
    try {
      byteLen = Buffer.from(b64, 'base64').length;
    } catch {
      byteLen = -1;
    }
    if (byteLen !== 32) {
      delete all[idpGroupId];
      mutated = true;
      dropped += 1;
      logLine(
        `[lastid-agent] groups repair: dropped corrupt record ${idpGroupId} ` +
          `(group_id_b64 decoded to ${byteLen} bytes, not a 32-byte openmls id)`,
      );
      continue;
    }

    // Valid openmls id — re-seed the idp→openmls mapping into the live MLS
    // client so reconcile can resolve this group by its IdP UUID this session.
    if (mls && typeof mls.bindGroupIdMapping === 'function') {
      try {
        await mls.bindGroupIdMapping(idpGroupId, b64);
        seeded += 1;
      } catch (err) {
        logLine(
          `[lastid-agent] groups repair: bindGroupIdMapping ${idpGroupId} failed: ${err?.message ?? err}`,
        );
      }
    }
  }

  if (mutated) {
    const path = groupsPath(scope);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(all, null, 2)}\n`, 'utf-8');
  }
  if (seeded || dropped) {
    logLine(
      `[lastid-agent] groups repair: scanned ${entries.length}, seeded ${seeded} mapping(s), dropped ${dropped} corrupt`,
    );
  }
  return { seeded, dropped, scanned: entries.length };
}

/** Operator device ids the agent has recorded as added to a group ([] if none/unknown). */
export async function getGroupDeviceIds({ scope, idpGroupId }) {
  const all = await readAll(scope);
  const entry = all[idpGroupId];
  return Array.isArray(entry?.device_ids) ? entry.device_ids : [];
}

/** device_id → leaf-index map the agent recorded for a group ({} if none). */
export async function getGroupDeviceLeaves({ scope, idpGroupId }) {
  const all = await readAll(scope);
  const entry = all[idpGroupId];
  return entry?.device_leaves && typeof entry.device_leaves === 'object' ? entry.device_leaves : {};
}

/**
 * Resolve a single IdP group UUID → { group_id_b64, operator_did }.
 * Returns null when unknown (no welcome recorded it, or groups.json
 * was lost).
 */
export async function resolveGroup({ scope, idpGroupId }) {
  const all = await readAll(scope);
  const entry = all[idpGroupId];
  if (!entry || !entry.group_id_b64) return null;
  return {
    idpGroupId,
    groupIdB64: entry.group_id_b64,
    operatorDid: entry.operator_did ?? null,
  };
}

/** Every known group, for the MCP tool to surface "who can I reply to". */
export async function listGroups({ scope }) {
  const all = await readAll(scope);
  return Object.entries(all).map(([idpGroupId, v]) => ({
    idpGroupId,
    groupIdB64: v.group_id_b64 ?? null,
    operatorDid: v.operator_did ?? null,
    updatedAt: v.updated_at ?? null,
  }));
}

/**
 * Find the active group with a given operator. An agent has one
 * operator (its parent human), so in the normal case there's exactly
 * one direct group with them. If somehow more than one exists (e.g. a
 * group was recreated), return the most-recently-updated — that's the
 * live conversation. Returns null when there's no group with that
 * operator yet. Lets the send tool stay "just send text" — the LLM
 * never handles a group id.
 */
export async function resolveActiveGroupForOperator({ scope, operatorDid }) {
  // SECURITY: an agent must NEVER message anyone but its operator.
  // We only ever return a group whose recorded operator_did is an
  // EXACT match for the caller-supplied operatorDid (the agent's
  // parent_human_did from its VC). No "single group" / "most recent
  // group" fallback — those could resolve to a group whose other
  // member isn't the operator, and the agent would leak a message to
  // a stranger. No operatorDid ⇒ no group, full stop.
  if (!operatorDid) return null;
  const all = await readAll(scope);
  let best = null;
  for (const [idpGroupId, v] of Object.entries(all)) {
    if (!v.group_id_b64) continue;
    if (v.operator_did !== operatorDid) continue;
    const ts = Date.parse(v.updated_at ?? '') || 0;
    if (!best || ts > best.ts) {
      best = { ts, idpGroupId, groupIdB64: v.group_id_b64 };
    }
  }
  if (!best) return null;
  return {
    idpGroupId: best.idpGroupId,
    groupIdB64: best.groupIdB64,
    operatorDid,
  };
}
