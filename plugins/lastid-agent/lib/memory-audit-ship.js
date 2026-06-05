/**
 * Ship the agent's local memory audit chain to the IdP so the operator can
 * view it from the browser / desktop / mobile. Same auth as agent-state sync:
 * the agent VC as a Bearer token + a fresh DPoP proof. Offline-safe — the
 * ship cursor (memory-audit.js) only advances on a 2xx, so a down IdP just
 * means we retry on the next connect/drain.
 *
 * The records carry NON-sensitive metadata only (no memory claim), so the
 * server stores an audit trail of WHAT happened without seeing content.
 */
import { authedIdpFetch } from './mls-groups-api.js';
import { shipUnshipped } from './memory-audit.js';

export const AUDIT_PATH = '/v1/agent-state/audit';

export async function shipMemoryAudit({
  idpUrl,
  scope = 'main',
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof fetchImpl !== 'function') return 0;
  // Ship THIS agent's chain (the file is keyed by the listener's agentDid — the
  // same key that signs the records and the same VC that authenticates here).
  // Route through the shared, broker-aware authedIdpFetch (FORK1); keep the
  // offline-safe BOOLEAN contract (true on 2xx, false on any error → cursor
  // stays, retry next drain). authedIdpFetch throws on non-2xx, so try/catch.
  return shipUnshipped(scope, agentDid, async (records) => {
    try {
      await authedIdpFetch({
        idpUrl,
        method: 'POST',
        path: AUDIT_PATH,
        body: { records },
        agentDid,
        vcCompact,
        signingKey,
        fetchImpl,
        scope,
      });
      return true;
    } catch {
      return false; // network error / non-2xx → cursor stays, retry later
    }
  });
}
