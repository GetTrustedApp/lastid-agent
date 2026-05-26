/**
 * Agent-state sync client.
 *
 * saas-migration.md §2.3/§6: the agent pulls its slot_seed-encrypted
 * rules + memories from the IdP agent-state store, VERIFIES the operator's
 * delegation_authority signature, decrypts locally, and applies them to
 * the OperatorStore. The same incremental `?since=<cursor>` GET serves
 * both real-time (WS doorbell) and bootstrap/catch-up.
 *
 * Auth mirrors ws-client.js: agent VC SD-JWT as a `Bearer` token + a
 * fresh `DPoP` proof per request (htu = origin+path).
 *
 * The IdP embeds the operator's delegation_authority public key
 * (`operator_delegation_jwk`) in the response so the agent can verify
 * each record's signature without a separate fetch (same precedent as
 * approval rows). RULES are fail-closed — an unverified rule is dropped.
 */
import { mintDpopJwt } from './dpop.js';
import { decryptContent } from './agent-content-crypto.js';
import { applyVaultRecords } from './vault-cache.js';
import {
  decryptProjectContent,
  deriveProjectRoutingId,
  GLOBAL_SHARED_PROJECT_KEY,
} from './project-crypto.js';
import { verifyRecordSignature } from './agent-sig-verify.js';

export const RULES_PATH = '/v1/agent-state/rules';
export const MEMORIES_PATH = '/v1/agent-state/memories';
export const VAULT_PATH = '/v1/agent-state/vault';
export const AUDIT_POLICY_PATH = '/v1/agent-state/audit-policy';

/**
 * Decode one wire record into the OperatorStore shape. Revoked /
 * forgotten records carry no ciphertext — they pass through so the store
 * removes them. Active records decrypt their JSON content. Returns the
 * store record plus the raw decrypted bytes (for signature/hash checks).
 */
export function decodeRecord(record, slotSeed, projectRootSeed = null) {
  // A shared record (wire target 'project') whose routing_id matches the
  // operator's GLOBAL routing is a global memory OR rule riding the project
  // Option-B rails — retarget it to 'global' so it injects/enforces ALWAYS
  // (operator-store global tier), not repo-gated like a real project record.
  // Kind-agnostic: a global rule and a global memory share this routing and are
  // told apart by `record.kind` downstream. The routing is derived from the
  // project_root_seed already sealed to this agent, so no new key + no
  // re-provision. DECRYPTION still keys off the WIRE target below (the record is
  // sealed under the project content key either way), and signature
  // verification runs on the wire record (target 'project') upstream — so this
  // only changes where the decoded record lands locally.
  let target = record.target ?? null;
  if (record.target === 'project' && Buffer.isBuffer(projectRootSeed) && typeof record.routing_id === 'string') {
    try {
      if (record.routing_id === deriveProjectRoutingId(projectRootSeed, GLOBAL_SHARED_PROJECT_KEY)) {
        target = 'global';
      }
    } catch {
      /* derivation failed — leave as project */
    }
  }
  const base = {
    id: record.id,
    kind: record.kind,
    target,
    version: Number(record.version) || 0,
    updated_at: record.updated_at ?? null,
  };
  if (record.status && record.status !== 'active') {
    return { storeRecord: { ...base, status: record.status }, contentBytes: null };
  }
  // Project-tier records are encrypted under the project content key (derived
  // from the record's plaintext routing_id + the operator's project_root_seed),
  // NOT the agent's slot_seed. Without the project seed (older agent) we can't
  // read them — surface as undecryptable so the caller skips, not crashes.
  let contentBytes;
  if (record.target === 'project') {
    if (!Buffer.isBuffer(projectRootSeed) || typeof record.routing_id !== 'string') {
      throw new Error('project record but no project_root_seed/routing_id');
    }
    contentBytes = decryptProjectContent(projectRootSeed, record.routing_id, record.enc_b64);
  } else {
    contentBytes = decryptContent(slotSeed, record.enc_b64);
  }
  const content = JSON.parse(contentBytes.toString('utf8'));
  return { storeRecord: { ...base, status: 'active', content }, contentBytes };
}

async function fetchKind({ idpUrl, path, since, agentDid, vcCompact, signingKey, fetchImpl }) {
  const base = `${idpUrl}${path}`;
  const url = `${base}?since=${encodeURIComponent(since)}`;
  const headers = {
    Authorization: `Bearer ${vcCompact}`,
    DPoP: mintDpopJwt({ agentDid, httpMethod: 'GET', httpUri: base, signingKey }),
    accept: 'application/json',
  };
  const res = await fetchImpl(url, { method: 'GET', headers });
  if (!res.ok) {
    const text = typeof res.text === 'function' ? await res.text() : '';
    throw new Error(`agent-state ${path} fetch failed: ${res.status} ${text}`);
  }
  const body = await res.json();
  return {
    records: Array.isArray(body?.records) ? body.records : [],
    cursor: typeof body?.cursor === 'number' ? body.cursor : since,
    operatorJwk: body?.operator_delegation_jwk ?? null,
  };
}

/**
 * Pull incremental agent-state, verify provenance, and apply it locally.
 *
 * @param {Object} deps
 * @param {string} deps.idpUrl
 * @param {string} deps.agentDid
 * @param {string} deps.vcCompact          - agent VC SD-JWT (bearer)
 * @param {import('node:crypto').KeyObject} deps.signingKey - agent Ed25519 (DPoP)
 * @param {Buffer} deps.slotSeed           - 32-byte content-decryption seed
 * @param {import('./operator-store.js').OperatorStore} deps.store
 * @param {Function} [deps.fetchImpl]      - injectable fetch (default global)
 * @param {{x_b64u,y_b64u}} [deps.operatorJwk] - override operator key (tests)
 * @param {Function} [deps.verifyRecord]   - override the provenance check (tests);
 *        (record, contentBytes) => true | { ok, reason }. Defaults to the built-in
 *        delegation_authority verification.
 * @param {(record, reason) => void} [deps.onReject] - observability hook.
 * @returns {Promise<{applied:number, cursor:number, fetched:number, rejected:number}>}
 */
export async function syncAgentState({
  idpUrl,
  agentDid,
  vcCompact,
  signingKey,
  slotSeed,
  projectRootSeed = null,
  store,
  memoryStore = null,
  scope = 'main',
  fetchImpl = globalThis.fetch,
  operatorJwk = null,
  verifyRecord = null,
  onReject = null,
}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('syncAgentState: no fetch implementation available');
  }
  const since = store.cursor;
  const [rules, memories, vault, auditPolicy] = await Promise.all([
    fetchKind({ idpUrl, path: RULES_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }),
    fetchKind({ idpUrl, path: MEMORIES_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }),
    // Vault shares ride the same per-operator cursor. We store them SEALED
    // (no decrypt here) — the listener verifies + unfurls only at inject time.
    // A failed vault fetch must not break rules/memories, so fail soft to empty.
    fetchKind({ idpUrl, path: VAULT_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: since, operatorJwk: null }),
    ),
    // Audit policy (kind 'audit_policy') — the operator's signed control over
    // which classes the agent audits. Sealed per-agent + ES256-signed like a
    // global rule; decoded + verified (fail-closed) + applied below, then
    // honored at the source by audit-policy.js. Fail soft to empty.
    fetchKind({ idpUrl, path: AUDIT_POLICY_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: since, operatorJwk: null }),
    ),
  ]);

  // Vault: persist the sealed blobs to the local vault cache (never decrypted
  // at rest). vault_list decodes on demand + strips the secret; the inject path
  // (listener) verifies the operator signature before use. Best-effort.
  try {
    applyVaultRecords(scope, vault.records);
  } catch (err) {
    safely(onReject, { id: 'vault-cache', kind: 'vault' }, `vault cache: ${err?.message ?? err}`);
  }

  // Operator delegation key for signature verification. TRUST-ON-FIRST-USE: the
  // IdP supplies it embedded in the sync response, but we PIN it on the first
  // sync and verify against the pinned key thereafter — a later response that
  // hands over a DIFFERENT key (a compromised/forged IdP) is ignored, so it
  // can't swap the verification key and forge operator rules/memories. (A test
  // override via operatorJwk wins, for determinism.)
  const supplied = operatorJwk ?? rules.operatorJwk ?? memories.operatorJwk ?? auditPolicy.operatorJwk ?? null;
  const pinned = store.pinnedDelegationJwk;
  let opJwk = pinned;
  if (!pinned && supplied) {
    store.pinDelegationJwk(supplied);
    opJwk = supplied;
  } else if (pinned && supplied && (supplied.x_b64u !== pinned.x_b64u || supplied.y_b64u !== pinned.y_b64u)) {
    // Key-swap attempt — verify against the PINNED key, not the swapped one.
    safely(onReject, { id: 'delegation-key', kind: 'rule' },
      'operator delegation key changed since first sync — ignoring sync-supplied key, using the pinned one');
  }
  const verify =
    verifyRecord ??
    ((rec, contentBytes) => verifyRecordSignature(rec, contentBytes, opJwk, { agentDid }));

  const all = [...rules.records, ...memories.records, ...auditPolicy.records];
  let maxCursor = Math.max(since, rules.cursor, memories.cursor, vault.cursor ?? since, auditPolicy.cursor ?? since);
  const decoded = [];
  let reconciled = 0;
  for (const rec of all) {
    if (typeof rec.cursor === 'number' && rec.cursor > maxCursor) maxCursor = rec.cursor;

    let storeRecord;
    let contentBytes = null;
    try {
      const d = decodeRecord(rec, slotSeed, projectRootSeed);
      storeRecord = d.storeRecord;
      contentBytes = d.contentBytes;
    } catch (err) {
      // Undecryptable (wrong key / corrupt) — skip, don't fail the batch.
      safely(onReject, rec, `decrypt: ${err?.message ?? err}`);
      continue;
    }

    // Provenance gate (rules fail-closed; memories verify-if-signed).
    let v;
    try {
      v = verify(rec, contentBytes);
    } catch (err) {
      v = { ok: false, reason: `verify: ${err?.message ?? err}` };
    }
    const ok = v === true || (v && v.ok === true);
    if (!ok) {
      safely(onReject, rec, (v && v.reason) || 'rejected');
      continue;
    }

    // Reconcile agent-authored memories (+ any memory revoke) into the local
    // memory store — the cross-session/host path. The memory store decides
    // (version-guarded; ignores operator-authored actives).
    if (memoryStore && rec.kind === 'memory') {
      try {
        if (memoryStore.applySync(storeRecord, rec.author)) reconciled += 1;
      } catch (err) {
        safely(onReject, rec, `reconcile: ${err?.message ?? err}`);
      }
    }

    // The agent's OWN authored memory ACTIVES live in the memory store, not the
    // operator-store — skip them here to avoid double-injection. Revokes still
    // flow to the operator-store (it removes the id if it holds it; harmless
    // no-op otherwise). Operator-authored + promoted records apply normally.
    if (rec.kind === 'memory' && rec.author === 'agent' && storeRecord.status !== 'revoked') {
      continue;
    }

    decoded.push(storeRecord);
  }
  const applied = store.applyRecords(decoded, maxCursor);
  return {
    applied,
    reconciled,
    cursor: store.cursor,
    fetched: all.length,
    rejected: all.length - decoded.length,
  };
}

function safely(fn, ...args) {
  if (typeof fn !== 'function') return;
  try {
    fn(...args);
  } catch {
    // observability hook must never break sync
  }
}

/**
 * Build a WS event handler that turns agent-state change "doorbell"
 * events into a (debounced) sync pull. The doorbell carries only a
 * cursor — no content — so all it does is trigger the same incremental
 * GET used for catch-up. Returns true if it handled the event.
 */
export function makeDoorbellHandler(triggerSync, { debounceMs = 250 } = {}) {
  const CHANGED = new Set(['rules.changed', 'memory.changed', 'vault.changed', 'agent_state.changed']);
  let timer = null;
  return function onEvent(event) {
    const type = typeof event === 'string' ? event : event?.type ?? '';
    if (!CHANGED.has(type)) return false;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      Promise.resolve(triggerSync(event)).catch(() => {});
    }, debounceMs);
    if (typeof timer.unref === 'function') timer.unref();
    return true;
  };
}
