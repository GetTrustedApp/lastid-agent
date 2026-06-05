/**
 * Ship locally-recorded rule-hit metrics to the IdP. Best-effort, like the
 * memory-audit shipper: the ship cursor (rule-metrics.js) only advances on a
 * 2xx, so a down IdP just leaves the queue for next time. Runs in the listener
 * (off the tool-call latency path). Carries only rule id / severity / tool
 * category / curated provenance — never command or pattern text.
 */
import { authedIdpFetch } from './mls-groups-api.js';
import { shipRuleHits } from './rule-metrics.js';

export const RULE_HITS_PATH = '/v1/agent-state/rule-hits';

export async function shipRuleMetrics({
  idpUrl,
  scope = 'main',
  agentDid,
  vcCompact,
  signingKey,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof fetchImpl !== 'function' || !idpUrl || !vcCompact || !signingKey) return 0;
  // Route through the shared, broker-aware authedIdpFetch (FORK1); preserve the
  // offline-safe BOOLEAN contract + the 5s timeout (passed as `signal`, which
  // authedIdpFetch forwards to the legacy fetch; the broker path has its own
  // IPC timeout). authedIdpFetch throws on non-2xx, so try/catch → false.
  return shipRuleHits(scope, async (records) => {
    try {
      await authedIdpFetch({
        idpUrl,
        method: 'POST',
        path: RULE_HITS_PATH,
        body: { hits: records },
        agentDid,
        vcCompact,
        signingKey,
        fetchImpl,
        scope,
        ...(typeof AbortSignal?.timeout === 'function' ? { signal: AbortSignal.timeout(5000) } : {}),
      });
      return true;
    } catch {
      return false; // offline/timeout/non-2xx → cursor stays, retry next tick
    }
  });
}
