/**
 * DPoP-shaped Proof-of-Possession JWT (RFC 9449 flavor).
 *
 * The desktop MCP transport (and the IdP resource paths) require a fresh
 * DPoP per call:
 *
 *   header  = { typ: 'dpop+jwt', alg: 'EdDSA'|'ES256', kid: '<agent did>' }
 *   payload = { jti, htm: 'POST', htu: '<this URL>', iat: <unix-sec> }
 *
 * Dual-algo / feature-detected from the agent's slot key (the one whose
 * public half encodes into the DID's multibase suffix). The verifier
 * reconstructs the pubkey from the kid directly — no JWK lookup — so we
 * don't ship a `jwk` header for these.
 *
 *   - Ed25519 (existing agents): `alg:'EdDSA'`, signature is raw 64 bytes
 *     (Node's `crypto.sign(null, …, ed25519Key)` returns this directly).
 *   - P-256 (new agents): `alg:'ES256'`, signature is raw 64-byte r||s
 *     (Node's `crypto.sign('sha256', …, { dsaEncoding: 'ieee-p1363' })`
 *     produces exactly that encoding — what the WASM `mintPopJwt` emits and
 *     the IdP verifies).
 *
 * Either way the wire format is byte-identical to
 * `lastid-vc::pop::create_pop_jwt` for the matching algorithm — no JS-side
 * crypto reimplementation, just the standard signing primitive over the
 * SDK-derived key.
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
 * @param {import('node:crypto').KeyObject} params.signingKey - Ed25519 or P-256 KeyObject.
 * @returns {string} compact JWS
 */
export function mintDpopJwt({ agentDid, httpMethod, httpUri, signingKey }) {
  // Feature-detect the algorithm from the key itself — existing agents have
  // an Ed25519 slot key (EdDSA), new agents a P-256 one (ES256).
  const isEd25519 = signingKey?.asymmetricKeyType === 'ed25519';
  const header = {
    typ: 'dpop+jwt',
    alg: isEd25519 ? 'EdDSA' : 'ES256',
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
  const sig = isEd25519
    ? // EdDSA: Node returns the raw 64-byte Ed25519 signature directly.
      cryptoSign(null, Buffer.from(signingInput, 'utf-8'), signingKey)
    : // ES256: SHA-256 + ECDSA over P-256, raw r||s (ieee-p1363) — NOT DER.
      cryptoSign('sha256', Buffer.from(signingInput, 'utf-8'), {
        key: signingKey,
        dsaEncoding: 'ieee-p1363',
      });
  return `${signingInput}.${b64url(sig)}`;
}
