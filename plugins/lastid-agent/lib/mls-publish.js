/**
 * Plugin-side MLS KeyPackage publish.
 *
 * Fires automatically right after provisioning persists the agent
 * VC so the agent is reachable by the operator's chat dock the
 * moment provision returns. Authenticates with the agent's freshly-
 * issued LastID.Agent.Base VC + a DPoP-bound proof signed by the
 * agent's Ed25519 signing key.
 *
 * IdP route + schema:
 *   POST /v1/mls/keypackages
 *   body: { key_package: base64, device_id: string }
 *   strict — additional keys are rejected.
 *
 * device_id for an agent runtime is the agent DID itself. One
 * agent runtime = one device-level identity.
 */
import { MlsClient } from './mls-client.js';
import { mintDpopJwt } from './dpop.js';
import { deriveAgentEd25519Keypair } from './agent-provisioning.js';
import { agentDeviceIdFromEd25519Jwk } from './agent-device-id.js';
import { createPublicKey } from 'node:crypto';

/**
 * Publish a fresh KeyPackage for this agent. Idempotent at the
 * caller level — the IdP de-dupes by content hash, but we still
 * generate a fresh KP each call so the wasm's per-KP private
 * credential lands in the persisted state file.
 *
 * @param {object} args
 * @param {string} args.idpUrl
 * @param {string} args.agentDid
 * @param {string} args.vcCompact   — compact SD-JWT for the LastID.Agent.Base
 * @param {Buffer} args.slotSeed    — 32 bytes; MLS state seed AND Ed25519
 *                                   keypair source. The signing key is
 *                                   derived internally so the caller
 *                                   doesn't need to plumb it through.
 * @param {string} [args.scope]
 *
 * @returns {Promise<{ ok: true, ref?: string }>}
 *   On the IdP success path the body includes a `ref` field; we
 *   pass it through verbatim. Errors throw — the caller decides
 *   whether to surface them (we log + continue from cmdProvision).
 */
export async function publishAgentKeyPackage({
  idpUrl,
  agentDid,
  vcCompact,
  slotSeed,
  scope,
}) {
  const trimmed = String(idpUrl ?? '').replace(/\/$/, '');
  if (!trimmed) throw new Error('publishAgentKeyPackage: idpUrl required');
  if (!agentDid) throw new Error('publishAgentKeyPackage: agentDid required');
  if (!vcCompact) throw new Error('publishAgentKeyPackage: vcCompact required');
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('publishAgentKeyPackage: slotSeed must be 32 bytes');
  }

  const { signingKey } = deriveAgentEd25519Keypair(slotSeed);

  // device_id for the IdP's key-package store. The IdP keys set
  // entries as `${deviceId}:${ref}` and splits on `:` to parse them
  // back — passing the agent DID directly breaks that parsing
  // because DIDs contain colons. Derive a stable colon-free
  // identifier from the agent's Ed25519 public key, matching the
  // bot pattern in lastid-idp/packages/credential-service/src/mls/
  // bot-device-id.ts.
  const publicJwk = createPublicKey(signingKey).export({ format: 'jwk' });
  const deviceId = agentDeviceIdFromEd25519Jwk({
    kty: 'OKP',
    crv: 'Ed25519',
    x: publicJwk.x,
  });

  const mls = await MlsClient.open({
    agentDid,
    slotSeed,
    scope: scope ?? 'main',
  });
  const keyPackageB64 = mls.generateKeyPackage();
  // Persist immediately — the freshly-generated KP carries a
  // private credential in the wasm state. Skipping persist would
  // make the KP unusable on the next restart even if the IdP has
  // already accepted it.
  await mls.persist();

  const url = `${trimmed}/v1/mls/keypackages`;
  const dpopProof = mintDpopJwt({
    agentDid,
    httpMethod: 'POST',
    httpUri: url,
    signingKey,
  });

  // Auth pattern: Bearer SD-JWT VC compact + DPoP proof in a
  // separate header. The IdP's vc-auth middleware sends Bearer-VC
  // requests through `verifySDJWTVC` → recognises LastID.Agent.Base
  // → validates the DPoP proof against the credential's `cnf.jwk`.
  // The `DPoP <token>` scheme is for IdP-issued OAuth resource
  // access tokens; sending a raw VC compact under that scheme makes
  // the middleware try `verifyResourceAccessToken` which fails with
  // an "ML-DSA signature verification failed" error.
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${vcCompact}`,
      DPoP: dpopProof,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      key_package: keyPackageB64,
      device_id: deviceId,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '<no body>');
    throw new Error(
      `POST /v1/mls/keypackages failed: HTTP ${res.status} ${text}`,
    );
  }

  const body = await res.json().catch(() => ({}));
  return { ok: true, ref: typeof body?.ref === 'string' ? body.ref : undefined };
}
