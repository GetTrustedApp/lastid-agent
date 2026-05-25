/**
 * Ship locally-recorded rule-hit metrics to the IdP. Best-effort, like the
 * memory-audit shipper: the ship cursor (rule-metrics.js) only advances on a
 * 2xx, so a down IdP just leaves the queue for next time. Runs in the listener
 * (off the tool-call latency path). Carries only rule id / severity / tool
 * category / curated provenance — never command or pattern text.
 */
import { mintDpopJwt } from './dpop.js';
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
  return shipRuleHits(scope, async (records) => {
    try {
      const res = await fetchImpl(`${idpUrl}${RULE_HITS_PATH}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${vcCompact}`,
          DPoP: mintDpopJwt({ agentDid, httpMethod: 'POST', httpUri: `${idpUrl}${RULE_HITS_PATH}`, signingKey }),
        },
        body: JSON.stringify({ hits: records }),
        ...(typeof AbortSignal?.timeout === 'function' ? { signal: AbortSignal.timeout(5000) } : {}),
      });
      return res?.ok === true || (typeof res?.status === 'number' && res.status >= 200 && res.status < 300);
    } catch {
      return false; // offline/timeout → cursor stays, retry next tick
    }
  });
}
