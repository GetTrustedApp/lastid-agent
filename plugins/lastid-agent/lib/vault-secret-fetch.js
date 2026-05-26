/**
 * Just-in-time fetch of a vault share's SECRET ciphertext from the IdP.
 *
 * The agent caches only the secret-free metadata (vault-cache.js). The credential
 * itself is released on demand: at http_fetch time the listener calls this to GET
 * the sealed `enc_secret_b64` from the IdP, then decrypts it with its slot_seed,
 * injects, and zeroizes. Agent-authenticated (VC bearer + per-request DPoP),
 * exactly like the use-approval loop. The IdP returns ciphertext only.
 */
import { mintAgentPopJwt } from './sdk-bindings.js';

/**
 * @returns {Promise<string|null>} the base64 `enc_secret_b64`, or null when the
 *   IdP has nothing to release (404 — revoked, never shared, or wrong agent).
 */
export async function fetchVaultSecretEnc({
  idpUrl,
  agentDid,
  vcCompact,
  signingSeed,
  id,
  fetchImpl = globalThis.fetch,
}) {
  if (!vcCompact) throw new Error('no agent VC — cannot fetch vault secret');
  if (!signingSeed) throw new Error('no signingSeed — cannot mint DPoP for vault secret');
  const url = `${idpUrl}/v1/agent-state/vault/${encodeURIComponent(id)}/secret`;
  const popJwt = await mintAgentPopJwt(
    { signingKeyBytes: new Uint8Array(signingSeed) },
    { agentDid, method: 'GET', uri: url },
  );
  const res = await fetchImpl(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${vcCompact}`, DPoP: popJwt },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`vault secret fetch: HTTP ${res.status} ${await res.text?.().catch(() => '') ?? ''}`);
  }
  const json = await res.json();
  return typeof json?.enc_secret_b64 === 'string' ? json.enc_secret_b64 : null;
}
