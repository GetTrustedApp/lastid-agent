/**
 * OAuth2 client_credentials token exchange — run BY THE LISTENER at use-time.
 *
 * We deliberately do NOT store a minted access token in the vault: it would be
 * stale by next week. The vault seals the durable CLIENT SECRET (+ the injection
 * carries client_id / token_endpoint / scope); at each vault_use the listener
 * mints a fresh access token here and injects THAT, then zeroizes both. The
 * exchange goes out from the agent's own machine, so IP-allowlisted OAuth apps
 * see the right source IP (an IdP broker would mint from the wrong one).
 *
 * Pure of vault internals: takes the resolved client_secret + the injectable
 * fetch, returns the access token string, throws loud on any failure (so a
 * broken exchange surfaces as an error, never a silently un-credentialed call).
 */

/**
 * @param {object} a
 * @param {string} a.tokenEndpoint  OAuth2 token endpoint URL
 * @param {string} a.clientId       OAuth client id (public)
 * @param {string} a.clientSecret   OAuth client secret (the sealed vault secret)
 * @param {string} [a.scope]        optional space-delimited scope
 * @param {(url:string, opts:object)=>Promise<{status?:number, json?:()=>Promise<any>}>} fetchImpl
 * @returns {Promise<string>} the minted access_token
 */
export async function exchangeClientCredentials(
  { tokenEndpoint, clientId, clientSecret, scope } = {},
  fetchImpl,
) {
  if (!tokenEndpoint || !clientId || !clientSecret) {
    throw new Error('client_credentials exchange needs token_endpoint, client_id, and client_secret');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('client_credentials exchange needs a fetch implementation');
  }
  // RFC 6749 §4.4: POST application/x-www-form-urlencoded, credentials in the
  // body (client_secret_post). We use body creds (not Basic) so the same path
  // works for the providers that only accept one or the other in practice.
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
  });
  if (scope && scope.trim()) form.set('scope', scope.trim());

  let res;
  try {
    res = await fetchImpl(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: form.toString(),
    });
  } catch (e) {
    throw new Error(`token endpoint unreachable: ${e?.message ?? e}`);
  }

  const status = typeof res?.status === 'number' ? res.status : 0;
  let json = null;
  try {
    json = typeof res?.json === 'function' ? await res.json() : null;
  } catch {
    json = null;
  }

  // RFC 6749 §5.1: a success response is JSON carrying access_token.
  if (status < 200 || status >= 300 || !json || typeof json.access_token !== 'string' || json.access_token.length === 0) {
    const detail = json?.error_description || json?.error || `HTTP ${status || 'no response'}`;
    throw new Error(`token exchange failed: ${detail}`);
  }
  return json.access_token;
}
