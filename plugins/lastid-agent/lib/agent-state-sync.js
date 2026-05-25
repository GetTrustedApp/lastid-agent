/**
 * Agent-state sync client.
 *
 * saas-migration.md §2.3/§6: the agent pulls its slot_seed-encrypted
 * rules + memories from the IdP agent-state store, decrypts them
 * locally, and applies them to the OperatorStore. The same incremental
 * `?since=<cursor>` GET serves both real-time (triggered by the WS
 * doorbell) and bootstrap/catch-up (a fresh or long-offline agent pulls
 * from cursor 0). One code path; no separate "apply live message" logic.
 *
 * Auth mirrors ws-client.js: the agent VC SD-JWT as a `Bearer` token
 * plus a fresh `DPoP` proof per request (htu = origin+path, RFC-9449
 * style, query excluded — the IdP verifier compares the same).
 *
 * The server returns only records this agent is scoped for (its own
 * per-agent records + the global-tier copies that were encrypted to
 * THIS agent's slot_seed), so every `enc_b64` is decryptable here.
 */
import { mintDpopJwt } from './dpop.js';
import { decryptJson } from './agent-content-crypto.js';

export const RULES_PATH = '/v1/agent-state/rules';
export const MEMORIES_PATH = '/v1/agent-state/memories';

/**
 * Decode one wire record into the OperatorStore shape. Revoked /
 * forgotten records carry no ciphertext — they pass through so the
 * store removes them. Active records decrypt their JSON content.
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
    return { ...base, status: record.status };
  }
  return { ...base, status: 'active', content: decryptJson(slotSeed, record.enc_b64) };
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
  };
}

/**
 * Pull incremental agent-state and apply it to the local store.
 *
 * @param {Object} deps
 * @param {string} deps.idpUrl
 * @param {string} deps.agentDid
 * @param {string} deps.vcCompact          - agent VC SD-JWT (bearer)
 * @param {import('node:crypto').KeyObject} deps.signingKey - agent Ed25519 (DPoP)
 * @param {Buffer} deps.slotSeed           - 32-byte content-decryption seed
 * @param {import('./operator-store.js').OperatorStore} deps.store
 * @param {Function} [deps.fetchImpl]      - injectable fetch (default global)
 * @param {(record) => boolean} [deps.verifyRecord] - provenance gate; return
 *        true to accept. Should return true for kinds it does not gate
 *        (e.g. unsigned memories). A throw or falsy result rejects the record.
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
  fetchImpl = globalThis.fetch,
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

  const all = [...rules.records, ...memories.records];
  let maxCursor = Math.max(since, rules.cursor, memories.cursor);
  const decoded = [];
  for (const rec of all) {
    if (typeof rec.cursor === 'number' && rec.cursor > maxCursor) maxCursor = rec.cursor;
    if (verifyRecord) {
      let ok = false;
      try {
        ok = verifyRecord(rec) === true;
      } catch {
        ok = false;
      }
      if (!ok) {
        safely(onReject, rec, 'signature');
        continue;
      }
    }
    try {
      decoded.push(decodeRecord(rec, slotSeed));
    } catch (err) {
      // A record we can't decrypt (wrong key / corrupt) is skipped, not
      // fatal — the rest of the batch still applies and the cursor still
      // advances past it (it won't be re-fetched). Surfaced via onReject.
      safely(onReject, rec, `decrypt: ${err?.message ?? err}`);
    }
  }
  const applied = store.applyRecords(decoded, maxCursor);
  return {
    applied,
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
 *
 * Debounced so a burst of changes collapses into a single pull; the
 * timer is unref'd so it never keeps the process alive on its own.
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
