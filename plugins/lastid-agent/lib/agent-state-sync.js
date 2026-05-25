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
import { verifyRecordSignature } from './agent-sig-verify.js';

export const RULES_PATH = '/v1/agent-state/rules';
export const MEMORIES_PATH = '/v1/agent-state/memories';

/**
 * Decode one wire record into the OperatorStore shape. Revoked /
 * forgotten records carry no ciphertext — they pass through so the store
 * removes them. Active records decrypt their JSON content. Returns the
 * store record plus the raw decrypted bytes (for signature/hash checks).
 */
export function decodeRecord(record, slotSeed) {
  const base = {
    id: record.id,
    kind: record.kind,
    target: record.target ?? null,
    version: Number(record.version) || 0,
    updated_at: record.updated_at ?? null,
  };
  if (record.status && record.status !== 'active') {
    return { storeRecord: { ...base, status: record.status }, contentBytes: null };
  }
  const contentBytes = decryptContent(slotSeed, record.enc_b64);
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
  store,
  memoryStore = null,
  fetchImpl = globalThis.fetch,
  operatorJwk = null,
  verifyRecord = null,
  onReject = null,
}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('syncAgentState: no fetch implementation available');
  }
  const since = store.cursor;
  const [rules, memories] = await Promise.all([
    fetchKind({ idpUrl, path: RULES_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }),
    fetchKind({ idpUrl, path: MEMORIES_PATH, since, agentDid, vcCompact, signingKey, fetchImpl }),
  ]);

  // Operator delegation key for signature verification (IdP-embedded).
  const opJwk = operatorJwk ?? rules.operatorJwk ?? memories.operatorJwk ?? null;
  const verify =
    verifyRecord ?? ((rec, contentBytes) => verifyRecordSignature(rec, contentBytes, opJwk));

  const all = [...rules.records, ...memories.records];
  let maxCursor = Math.max(since, rules.cursor, memories.cursor);
  const decoded = [];
  let reconciled = 0;
  for (const rec of all) {
    if (typeof rec.cursor === 'number' && rec.cursor > maxCursor) maxCursor = rec.cursor;

    let storeRecord;
    let contentBytes = null;
    try {
      const d = decodeRecord(rec, slotSeed);
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
  const CHANGED = new Set(['rules.changed', 'memory.changed', 'agent_state.changed']);
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
