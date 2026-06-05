/**
 * Just-in-time fetch of a vault share's SECRET from the IdP, WRAPPED TO THE
 * HANDLE. The agent caches only the secret-free metadata. At http_fetch time
 * the listener POSTs its ephemeral handle PUBLIC key + handle_id; the IdP wraps
 * the stored (opaque, slot-sealed) secret to that key and returns it. The agent
 * opens it with the handle private key, then unseals with its slot key.
 *
 * Agent-authenticated (VC bearer + per-request DPoP), like the use-approval loop.
 * The IdP returns ciphertext only — it never sees plaintext and the wrap binds
 * the delivery to this one handle (single-use, replay-proof).
 */
import { authedIdpFetch } from './mls-groups-api.js';

/**
 * @returns {Promise<string|null>} the base64 `wrapped_secret_b64`, or null when
 *   the IdP has nothing to release (404 — revoked, never shared, or wrong agent).
 */
export async function fetchWrappedVaultSecret({
  idpUrl,
  agentDid,
  vcCompact,
  signingKey,
  id,
  handlePubB64,
  handleId,
  fetchImpl = globalThis.fetch,
}) {
  if (!vcCompact) throw new Error('no agent VC — cannot fetch vault secret');
  if (!signingKey) throw new Error('no signingKey — cannot mint DPoP for vault secret');
  if (!handlePubB64 || !handleId) throw new Error('handle pubkey + id required to wrap the secret');
  // Route through the shared, broker-aware authedIdpFetch (FORK1). Preserve the
  // 404 → null contract (revoked / never shared / wrong agent): authedIdpFetch
  // throws on non-2xx and tags the error with `.status`, so a 404 maps to null
  // and any other non-2xx re-throws. Scope is ambient (getActiveScope).
  let json;
  try {
    json = await authedIdpFetch({
      idpUrl,
      method: 'POST',
      path: `/v1/agent-state/vault/${encodeURIComponent(id)}/secret`,
      body: { handle_pubkey_b64: handlePubB64, handle_id: handleId },
      agentDid,
      vcCompact,
      signingKey,
      fetchImpl,
    });
  } catch (e) {
    if (e?.status === 404) return null;
    throw e;
  }
  return typeof json?.wrapped_secret_b64 === 'string' ? json.wrapped_secret_b64 : null;
}
