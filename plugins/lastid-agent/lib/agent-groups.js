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
export async function recordGroup({ scope, idpGroupId, groupIdB64, operatorDid }) {
  if (!idpGroupId) return;
  const all = await readAll(scope);
  const prior = all[idpGroupId] ?? {};
  all[idpGroupId] = {
    group_id_b64: groupIdB64 ?? prior.group_id_b64 ?? null,
    operator_did: operatorDid ?? prior.operator_did ?? null,
    updated_at: new Date().toISOString(),
  };
  const path = groupsPath(scope);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(all, null, 2)}\n`, 'utf-8');
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
