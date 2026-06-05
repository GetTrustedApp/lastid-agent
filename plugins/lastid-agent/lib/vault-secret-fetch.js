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
import { mintDpopJwt } from './dpop.js';

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
  const url = `${idpUrl}/v1/agent-state/vault/${encodeURIComponent(id)}/secret`;
  // mintDpopJwt feature-detects the alg from the KeyObject (Ed25519→EdDSA,
  // P-256→ES256) so an Ed25519 agent doesn't 401 on `agent_pop: header.alg
  // must be 'EdDSA' for a Ed25519 cnf.jwk, got 'ES256'`.
  const popJwt = mintDpopJwt({
    agentDid,
    httpMethod: 'POST',
    httpUri: url,
    signingKey,
  });
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${vcCompact}`, DPoP: popJwt, 'Content-Type': 'application/json' },
    body: JSON.stringify({ handle_pubkey_b64: handlePubB64, handle_id: handleId }),
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`vault secret fetch: HTTP ${res.status} ${(await res.text?.().catch(() => '')) ?? ''}`);
  }
  const json = await res.json();
  return typeof json?.wrapped_secret_b64 === 'string' ? json.wrapped_secret_b64 : null;
}
