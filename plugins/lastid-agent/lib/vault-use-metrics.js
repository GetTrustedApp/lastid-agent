/**
 * Ship the agent's vault-use timings to the IdP so the operator's guardrail
 * metrics reflect the REAL permissioned/credentialed window — the sell of the
 * JIT model ("the credential was decrypted for ~1s, vs a standing key for 30
 * days"). Posts one row to POST /v2/agents/:agent_did/credentialed-use (agent
 * VC + DPoP — the route accepts the agent's own VC), mirroring the desktop's
 * CredentialedUsePublisher: a 'minted' row at handle mint, a 'consumed' row at
 * http_fetch with credentialed_secs.
 *
 * Best-effort: a metrics failure must NEVER disrupt the vault flow, so callers
 * fire-and-forget and this never throws.
 */
import { authedIdpFetch } from './mls-groups-api.js';

/** Build the credentialed-use body for one handle event. Pure + exported so the
 *  field mapping (handle → wire row) is unit-tested. `kind` is 'mint'|'consume'. */
export function credentialedUseBody(kind, handle, metrics) {
  const ttlSecs = Math.max(1, Math.round((handle.ttlMs ?? 0) / 1000));
  const body = {
    item_id: handle.itemId,
    decision_kind: handle.wasApproved ? 'approval' : 'auto_allow',
    minted_at: new Date(handle.mintedAtMs ?? Date.now()).toISOString(),
    ttl_secs: ttlSecs,
    ...(handle.shareId ? { share_id: handle.shareId } : {}),
    ...(handle.approvalId ? { approval_id: handle.approvalId } : {}),
  };
  if (kind === 'mint') {
    body.status = 'minted';
  } else {
    body.status = 'consumed';
    body.consumed_at = new Date().toISOString();
    // credentialed_secs = the actual UNENCRYPTED window (decrypt→zeroize), as
    // FRACTIONAL seconds at ms precision. Do NOT floor to a whole second — a
    // 0.3s window must read as 0.3s, not "1s" (that inflated the number and
    // buried the whole point: the credential was exposed for a fraction of a
    // second, vs a standing key for weeks).
    if (metrics && typeof metrics.credentialed_ms === 'number') {
      body.credentialed_secs = Math.round(metrics.credentialed_ms) / 1000;
    }
  }
  return body;
}

export async function publishCredentialedUse({
  idpUrl,
  agentDid,
  vcCompact,
  signingKey,
  kind,
  handle,
  metrics,
  fetchImpl = globalThis.fetch,
  _authedIdpFetch = authedIdpFetch,
}) {
  try {
    // Broker-native agents have a null signingKey; auth is covered by the broker via authedIdpFetch.
    if (!vcCompact || !handle?.itemId) return;
    const body = credentialedUseBody(kind, handle, metrics);
    // Route through the shared, broker-aware authedIdpFetch (FORK1). Fire-and-
    // forget: the outer try/catch swallows everything (a metrics failure must
    // NEVER disrupt the vault flow), and scope is ambient (getActiveScope).
    await _authedIdpFetch({
      idpUrl,
      method: 'POST',
      path: `/v2/agents/${encodeURIComponent(agentDid)}/credentialed-use`,
      body,
      agentDid,
      vcCompact,
      signingKey,
      fetchImpl,
    });
  } catch {
    /* best-effort: metrics must never disrupt the vault flow */
  }
}
