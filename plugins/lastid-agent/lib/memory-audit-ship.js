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
import { mintDpopJwt } from './dpop.js';
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
  const base = `${idpUrl}${AUDIT_PATH}`;
  // Ship THIS agent's chain (the file is keyed by the listener's agentDid — the
  // same key that signs the records and the same VC that authenticates here).
  return shipUnshipped(scope, agentDid, async (records) => {
    let res;
    try {
      res = await fetchImpl(base, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${vcCompact}`,
          DPoP: mintDpopJwt({ agentDid, httpMethod: 'POST', httpUri: base, signingKey }),
        },
        body: JSON.stringify({ records }),
      });
    } catch {
      return false; // network error → cursor stays, retry later
    }
    return res?.ok === true || (typeof res?.status === 'number' && res.status >= 200 && res.status < 300);
  });
}
