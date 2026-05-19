/**
 * OAuth + OID4VCI client.
 *
 * Drives the agent's provisioning + claim flows against the LastID
 * IdP. Stages:
 *
 *   1. `runProvisioningFlow` (first-time)
 *      a. Generate a fresh Ed25519 keypair locally via the SDK.
 *      b. Render a verification URL the operator opens in their
 *         browser. That URL surfaces a user_code which the operator
 *         types into their LastID wallet (or scans). The wallet
 *         POSTs to the IdP, signing a human_authorization JWS with
 *         the human's delegation_authority key.
 *      c. The IdP returns a credential offer URI to the wallet; the
 *         wallet hands it to this plugin (via deep-link callback to
 *         a localhost port the plugin spun up, or by polling).
 *      d. Plugin parses the offer, exchanges the pre-auth code for
 *         an access token, requests the credential.
 *      e. Returns { seed, vcCompact, agentDid, capabilities, mayDelegate }.
 *
 *   2. `requestSubAgentOffer` (sub-agent spawn)
 *      Parent agent POSTs to `/v1/oid4vci/agent-offer/sub` with its
 *      DPoP-PoP JWT + presented parent VC. Receives an offer URI for
 *      the sub-agent.
 *
 *   3. `claimVcFromOffer` (used by both top-level and sub-agent)
 *      Pure OID4VCI claim flow: parse offer → token exchange → request
 *      credential.
 *
 * All HTTP calls go to `https://human.dev.lastid.co` by default (the
 * pre-prod IdP); override via `LASTID_IDP_URL` for prod
 * (`https://human.lastid.co`).
 */

import { createHash } from 'node:crypto';

const IDP_BASE_URL = process.env.LASTID_IDP_URL ?? 'https://human.dev.lastid.co';

export async function runProvisioningFlow({ sdk, projectPath }) {
  // Step 1: derive a fresh agent slot. The SDK picks the next free
  // index from the human's `ai_agent_seed` tree by inspecting which
  // VCs are already registered with the IdP for this human DID.
  const { seed, keypair } = await sdk.deriveFreshAgentKeypair();

  // Step 2: open the verification URL with the operator. The URL
  // encodes the agent's pubkey + a callback hint for the wallet.
  const verification = await initiateProvisioning({
    agentPubkeyJwk: keypair.jwk,
    projectHint: projectPath ? hashProjectPath(projectPath) : undefined,
  });

  process.stdout.write(
    `\n[lastid-agent] Approve this agent in your LastID wallet:\n` +
      `    ${verification.verificationUri}\n` +
      `    user_code: ${verification.userCode}\n\n` +
      `Waiting for approval...\n`
  );

  // Step 3: poll the IdP for the offer URI. The wallet POSTs the
  // signed human_authorization to the IdP, which mints a pre-auth code
  // and stages the offer; we pick it up on the next poll.
  const offerUri = await pollForOffer(verification.deviceCode, verification.interval);

  // Step 4: claim the VC.
  const claim = await claimVcFromOffer({ offerUri, agentKeypair: keypair });

  return {
    seed,
    keypair,
    vcCompact: claim.vcCompact,
    agentDid: claim.claims.sub,
    capabilities: claim.claims.capabilities,
    mayDelegate: claim.claims.may_delegate,
    claims: claim.claims,
  };
}

export async function requestSubAgentOffer({
  parentVcCompact,
  parentKeypair,
  subAgentClass,
  subAgentPubkeyJwk,
  capabilitiesSubset,
  exp,
}) {
  const popJwt = await mintPopJwt(parentKeypair, {
    method: 'POST',
    uri: `${IDP_BASE_URL}/v1/oid4vci/agent-offer/sub`,
  });
  const res = await fetch(`${IDP_BASE_URL}/v1/oid4vci/agent-offer/sub`, {
    method: 'POST',
    headers: {
      Authorization: `DPoP ${popJwt}`,
      'X-LastID-Agent-VC': parentVcCompact,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      sub_agent_class: subAgentClass,
      sub_agent_pubkey_jwk: subAgentPubkeyJwk,
      capabilities_subset: capabilitiesSubset,
      exp,
    }),
  });
  if (!res.ok) {
    throw new Error(`sub-agent offer request failed: ${res.status} ${await res.text()}`);
  }
  const { credential_offer_uri: offerUri } = await res.json();
  return offerUri;
}

export async function claimVcFromOffer({ offerUri, agentKeypair }) {
  // Parse the offer URI: openid-credential-offer://?credential_offer={...}
  const offer = parseOffer(offerUri);
  const preAuthCode =
    offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'];
  if (!preAuthCode) {
    throw new Error('credential offer is missing the pre-authorized code grant');
  }

  // Exchange pre-auth code for access token + c_nonce.
  const tokenRes = await fetch(`${offer.credential_issuer}/v1/oid4vci/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthCode,
    }),
  });
  if (!tokenRes.ok) {
    throw new Error(`token exchange failed: ${tokenRes.status} ${await tokenRes.text()}`);
  }
  const token = await tokenRes.json();

  // Mint EdDSA proof JWT covering c_nonce + issuer audience.
  const proofJwt = await mintEdDsaProofJwt(agentKeypair, {
    audience: offer.credential_issuer,
    nonce: token.c_nonce,
  });

  // Request the credential.
  const credRes = await fetch(`${offer.credential_issuer}/v1/oid4vci/credential`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      format: 'vc+sd-jwt',
      proof: { proof_type: 'jwt', jwt: proofJwt },
    }),
  });
  if (!credRes.ok) {
    throw new Error(`credential request failed: ${credRes.status} ${await credRes.text()}`);
  }
  const credResult = await credRes.json();
  const vcCompact = credResult.credential;
  // Decode (but don't verify; SessionStart calls sdk.verifyAgentVc).
  const claims = decodeJwtPayload(vcCompact);
  return {
    vcCompact,
    claims,
    thumbprint: claims.cnf?.jwk
      ? await jwkThumbprint(claims.cnf.jwk)
      : undefined,
  };
}

// ---------------------------------------------------------------------
// Helpers — these intentionally don't do crypto; they shell to the SDK.
// The actual signing functions are imported from sdk-bindings.js.
// ---------------------------------------------------------------------

async function initiateProvisioning({ agentPubkeyJwk, projectHint }) {
  const res = await fetch(`${IDP_BASE_URL}/v1/oid4vci/agent-provision/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_pubkey_jwk: agentPubkeyJwk,
      project_hint: projectHint,
    }),
  });
  if (!res.ok) {
    throw new Error(`provisioning initiate failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

async function pollForOffer(deviceCode, intervalSeconds) {
  const pollUrl = `${IDP_BASE_URL}/v1/oid4vci/agent-provision/poll`;
  while (true) {
    await sleep((intervalSeconds ?? 5) * 1000);
    const res = await fetch(pollUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_code: deviceCode }),
    });
    if (res.status === 202) continue;
    if (!res.ok) throw new Error(`poll failed: ${res.status} ${await res.text()}`);
    const { credential_offer_uri: offerUri } = await res.json();
    return offerUri;
  }
}

function parseOffer(uri) {
  const url = new URL(uri);
  const offer = url.searchParams.get('credential_offer');
  if (!offer) {
    throw new Error('credential_offer parameter missing from offer URI');
  }
  return JSON.parse(offer);
}

function decodeJwtPayload(jws) {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('malformed JWS');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
}

async function mintPopJwt(keypair, { method, uri }) {
  // Delegates to the SDK; thin shim here so the file remains readable.
  const { mintAgentPopJwt } = await import('./sdk-bindings.js');
  return mintAgentPopJwt(keypair, { method, uri });
}

async function mintEdDsaProofJwt(keypair, { audience, nonce }) {
  const { mintOid4vciProofJwt } = await import('./sdk-bindings.js');
  return mintOid4vciProofJwt(keypair, { audience, nonce });
}

async function jwkThumbprint(jwk) {
  const { computeEd25519JwkThumbprint } = await import('./sdk-bindings.js');
  return computeEd25519JwkThumbprint(jwk);
}

function hashProjectPath(p) {
  // 16-char hex prefix of SHA-256 — short, stable, non-reversible.
  return createHash('sha256').update(p).digest('hex').slice(0, 16);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
