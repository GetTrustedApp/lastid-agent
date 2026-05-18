/**
 * DPoP-shaped Proof-of-Possession JWT (RFC 9449 flavor).
 *
 * The desktop MCP transport requires a fresh DPoP per call:
 *
 *   header  = { typ: 'dpop+jwt', alg: 'EdDSA', kid: '<agent did>' }
 *   payload = { jti, htm: 'POST', htu: '<this URL>', iat: <unix-sec> }
 *
 * Signed by the agent's Ed25519 slot key (the one whose public half
 * encodes into the DID's multibase suffix). The desktop verifier
 * reconstructs the pubkey from the kid directly — no JWK lookup —
 * so we don't ship a `jwk` header for these.
 *
 * Match the wire format produced by `lastid-vc::pop::create_pop_jwt`
 * exactly, including the EdDSA signature being raw 64 bytes
 * (Node's `crypto.sign(null, …, ed25519Key)` already returns this).
 */
import { randomUUID, sign as cryptoSign } from 'node:crypto';

function b64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj), 'utf-8'));
}

/**
 * Mint a fresh DPoP JWT.
 *
 * @param {Object} params
 * @param {string} params.agentDid - Agent's `did:lastid:agent:z…` (becomes `kid`).
 * @param {string} params.httpMethod - Uppercase, e.g. `'POST'`.
 * @param {string} params.httpUri - Exact URL the agent is calling.
 * @param {import('node:crypto').KeyObject} params.signingKey - Ed25519 KeyObject.
 * @returns {string} compact JWS
 */
export function mintDpopJwt({ agentDid, httpMethod, httpUri, signingKey }) {
  const header = {
    typ: 'dpop+jwt',
    alg: 'EdDSA',
    kid: agentDid,
  };
  const payload = {
    jti: randomUUID(),
    htm: httpMethod,
    htu: httpUri,
    iat: Math.floor(Date.now() / 1000),
  };
  const headerB64 = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, 'utf-8'), signingKey);
  return `${signingInput}.${b64url(sig)}`;
}
