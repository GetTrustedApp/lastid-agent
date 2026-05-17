/**
 * Agent-side provisioning client.
 *
 * Drives the wallet-mediated agent provisioning loop end-to-end:
 *
 *   1. Generate an Ed25519 keypair locally (Node's `crypto`).
 *   2. POST `/v1/oid4vci/agent-provision/initiate` with the agent's
 *      OKP/Ed25519 JWK; receive a `user_code`, `device_code`, and
 *      `verification_uri` to surface to the operator.
 *   3. Poll `/v1/oid4vci/agent-provision/poll` until the operator
 *      approves in their LastID wallet — the IdP returns the
 *      `credential_offer_uri` once human_authorization has been
 *      verified.
 *   4. Parse the offer, exchange the pre-authorized code at
 *      `/v1/oid4vci/token`, then claim the SD-JWT VC at
 *      `/v1/oid4vci/credential` with an EdDSA proof JWT.
 *
 * The agent's seed (Ed25519 private key, 32 bytes) and the issued
 * SD-JWT VC are persisted to the host keychain by the caller.
 */

import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

// Default to dev while LastID.Agent.Base issuance is pre-production.
// Flip to `https://human.lastid.co` once the agent flow ships to prod.
// Override per-host with `--idp <url>` or `LASTID_IDP_URL`.
const DEFAULT_IDP = 'https://human.dev.lastid.co';

function b64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function b64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj), 'utf-8'));
}

/**
 * Generate an Ed25519 keypair. Returns { privateKey (KeyObject), publicJwk, seed (32 bytes raw priv key) }.
 */
export function generateAgentKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubJwk = publicKey.export({ format: 'jwk' });
  // Extract the 32-byte raw private seed via the PKCS8 DER export. Node
  // doesn't give us the raw scalar directly, but the PKCS8 ASN.1 for
  // Ed25519 has the seed as the last 32 bytes of the DER buffer.
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  return {
    privateKey,
    publicJwk: {
      kty: pubJwk.kty,
      crv: pubJwk.crv,
      x: pubJwk.x,
    },
    seed,
  };
}

/**
 * Step 1: tell the IdP we want a credential, surface verification URL
 * + device_code to the operator.
 */
export async function initiateProvisioning(opts) {
  const idp = opts.idpUrl ?? DEFAULT_IDP;
  const body = {
    agent_pubkey_jwk: opts.agentPubkeyJwk,
    parent_human_did: opts.parentHumanDid,
    runtime_name: opts.runtimeName ?? 'lastid-agent-plugin',
    project_hint: opts.projectHint ?? null,
  };
  const response = await fetch(`${idp}/v1/oid4vci/agent-provision/initiate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(
      `initiate failed: ${response.status} ${await response.text()}`,
    );
  }
  return response.json();
}

/**
 * Step 2: poll until the wallet approves and an offer URI is minted.
 * Returns the offer URI; the caller drives the OID4VCI claim flow.
 */
export async function pollUntilApproved(opts) {
  const idp = opts.idpUrl ?? DEFAULT_IDP;
  const intervalMs = (opts.intervalSeconds ?? 5) * 1000;
  const deadlineMs = Date.now() + (opts.timeoutSeconds ?? 600) * 1000;
  while (Date.now() < deadlineMs) {
    const response = await fetch(`${idp}/v1/oid4vci/agent-provision/poll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ device_code: opts.deviceCode }),
    });
    if (response.status === 410) {
      throw new Error(
        `provisioning rejected: ${response.status} ${await response.text()}`,
      );
    }
    if (response.ok) {
      const body = await response.json();
      if (body.status === 'approved' && body.credential_offer_uri) {
        return body.credential_offer_uri;
      }
    }
    await delay(intervalMs);
  }
  throw new Error('provisioning timed out before wallet approval');
}

/**
 * Parse an `openid-credential-offer://` URI. Returns
 * `{ credentialIssuer, credentialConfigurationIds, preAuthorizedCode }`.
 */
export function parseCredentialOffer(uri) {
  const url = new URL(uri);
  const inline = url.searchParams.get('credential_offer');
  let offer;
  if (inline) {
    offer = JSON.parse(inline);
  } else {
    throw new Error(
      'by-reference credential_offer_uri not supported yet (no credential_offer query param)',
    );
  }
  const grantKey = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const preAuth = offer.grants?.[grantKey]?.['pre-authorized_code'];
  if (!preAuth) {
    throw new Error('credential offer missing pre-authorized_code grant');
  }
  return {
    credentialIssuer: offer.credential_issuer,
    credentialConfigurationIds: offer.credential_configuration_ids,
    preAuthorizedCode: preAuth,
  };
}

/**
 * Step 3a: exchange the pre-authorized code at /v1/oid4vci/token.
 * Returns `{ accessToken, cNonce }`.
 */
export async function exchangeToken(offer) {
  const tokenUrl = `${offer.credentialIssuer}/v1/oid4vci/token`;
  const form = new URLSearchParams();
  form.set('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
  form.set('pre-authorized_code', offer.preAuthorizedCode);
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  if (!response.ok) {
    throw new Error(
      `token exchange failed: ${response.status} ${await response.text()}`,
    );
  }
  const body = await response.json();
  return { accessToken: body.access_token, cNonce: body.c_nonce };
}

/**
 * Build a JWT proof of possession over (audience=credential_issuer,
 * nonce=cNonce, iss=agent_did), signed by the agent's Ed25519 private
 * key. Header carries `jwk` so the IdP's holder-binding verifier finds
 * the public key without a lookup.
 */
export function mintProofJwt({ credentialIssuer, cNonce, agentDid, agentPubkeyJwk, privateKey }) {
  const header = {
    typ: 'openid4vci-proof+jwt',
    alg: 'EdDSA',
    jwk: agentPubkeyJwk,
  };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: agentDid,
    aud: credentialIssuer,
    iat: now,
    nonce: cNonce,
  };
  const headerB64 = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sigBytes = cryptoSign(null, Buffer.from(signingInput, 'utf-8'), privateKey);
  return `${signingInput}.${b64url(sigBytes)}`;
}

/**
 * Step 3b: redeem the access token + proof JWT for the SD-JWT VC.
 */
export async function claimCredential({
  credentialIssuer,
  accessToken,
  proofJwt,
}) {
  const credentialUrl = `${credentialIssuer}/v1/oid4vci/credential`;
  const body = {
    format: 'vc+sd-jwt',
    vct: 'LastID.Agent.Base',
    proof: {
      proof_type: 'jwt',
      jwt: proofJwt,
    },
  };
  const response = await fetch(credentialUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(
      `credential issuance failed: ${response.status} ${await response.text()}`,
    );
  }
  return response.json();
}

/**
 * Top-level orchestrator: keypair → initiate → wait for operator →
 * poll → claim.
 * `onUserCode` is invoked synchronously with `{ userCode, verificationUri }`
 * so the caller can print/QR/render however it wants.
 */
export async function provisionAgent({
  idpUrl,
  parentHumanDid,
  runtimeName,
  projectHint,
  onUserCode,
  intervalSeconds = 5,
  timeoutSeconds = 600,
}) {
  const keypair = generateAgentKeypair();
  const initiate = await initiateProvisioning({
    idpUrl,
    parentHumanDid,
    runtimeName,
    projectHint,
    agentPubkeyJwk: keypair.publicJwk,
  });
  if (typeof onUserCode === 'function') {
    onUserCode({
      userCode: initiate.user_code,
      verificationUri: initiate.verification_uri,
      agentDid: initiate.agent_did,
      expiresIn: initiate.expires_in,
    });
  }
  const offerUri = await pollUntilApproved({
    idpUrl,
    deviceCode: initiate.device_code,
    intervalSeconds,
    timeoutSeconds,
  });
  const offer = parseCredentialOffer(offerUri);
  const { accessToken, cNonce } = await exchangeToken(offer);
  const proofJwt = mintProofJwt({
    credentialIssuer: offer.credentialIssuer,
    cNonce,
    agentDid: initiate.agent_did,
    agentPubkeyJwk: keypair.publicJwk,
    privateKey: keypair.privateKey,
  });
  const issued = await claimCredential({
    credentialIssuer: offer.credentialIssuer,
    accessToken,
    proofJwt,
  });
  return {
    agentDid: initiate.agent_did,
    seed: keypair.seed,
    publicJwk: keypair.publicJwk,
    vcCompact: issued.credential,
    cNonce: issued.c_nonce ?? null,
    cNonceExpiresIn: issued.c_nonce_expires_in ?? null,
  };
}

// Internal re-exports for tests.
export const _internal = { b64url, b64urlJson };
