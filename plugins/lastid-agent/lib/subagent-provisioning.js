/**
 * Sub-agent provisioning orchestrator (parent acts as issuer).
 *
 * When the agent-state sync picks up an `active` subagent record from
 * the operator's console publish, this module:
 *
 *   1. Re-derives the sub-agent's seed deterministically from the
 *      parent's slot_seed via HKDF (`deriveSubAgentSeed`) — recoverable
 *      from the operator's mnemonic without IdP storage.
 *   2. Derives the sub-agent's Ed25519 keypair + DID from that seed.
 *   3. Builds a `parent_authorization` JWS over the sub-agent's pubkey
 *      thumbprint + capabilities, signed with the parent's existing
 *      agent signing key (the one in its VC's `cnf.jwk`).
 *   4. POSTs `/v1/oid4vci/agent-provision/sub` authenticated as the
 *      parent (Bearer VC + DPoP).
 *   5. Completes the OID4VCI exchange (token + proof JWT + credential)
 *      with the sub-agent's keypair as holder.
 *   6. Persists the sub-agent's VC + seed under
 *      `lastid.co/agent-vc:<parent-scope>-<slug>` so the existing
 *      `loadAgentVc('<parent-scope>-<slug>')` path finds it
 *      transparently when the spawned plugin instance boots.
 *
 * Idempotent: if a VC already exists in keychain for the sub-agent's
 * scope, the orchestrator short-circuits and returns
 * `{ alreadyProvisioned: true, ... }`. Safe to call on every doorbell
 * pickup.
 *
 * No /poll round-trip: the sub-agent runs as a child process on the
 * same host as the parent listener, so the seed never leaves this
 * machine. The IdP's `sealed_slot_seed` field is sent as an empty
 * string (placeholder); the seed is persisted to keychain locally.
 */

import { randomUUID } from 'node:crypto';

import { initializeSdkBindings } from './sdk-bindings.js';
import {
  deriveAgentEd25519Keypair,
  parseCredentialOffer,
  exchangeToken,
  mintProofJwt,
  claimCredential,
} from './agent-provisioning.js';
import { mintDpopJwt } from './dpop.js';
import { loadAgentVc, persistAgentVc } from './keychain.js';

// Sub-agent VC validity ceiling. The IdP clamps to ≤ parent.exp too;
// this is the listener-side ceiling that goes into the parent_auth JWS.
const SUBAGENT_EXP_WINDOW_SECONDS = 30 * 24 * 60 * 60; // 30 days

/**
 * Provision a sub-agent VC. Returns the sub-agent's scope + DID. Safe
 * to call repeatedly — short-circuits if already provisioned.
 *
 * @param {Object} deps
 * @param {string} deps.idpUrl                    - IdP base URL
 * @param {Buffer} deps.parentSlotSeed            - parent's 32-byte slot seed
 * @param {import('node:crypto').KeyObject} deps.parentSigningKey - parent's Ed25519 KeyObject (DPoP)
 * @param {string} deps.parentDid                 - parent agent DID
 * @param {string} deps.parentVcCompact           - parent VC (Bearer)
 * @param {string} deps.parentScope               - parent's LASTID_AGENT_SCOPE (e.g. 'main')
 * @param {Object} deps.subagent                  - decoded subagent record content
 * @param {string} deps.subagent.slug             - sub-agent slug (a.k.a class)
 * @param {Array}  [deps.subagent.capabilities]   - capability subset to grant
 * @param {boolean}[deps.subagent.may_delegate]   - whether the sub-agent can delegate further
 * @param {typeof globalThis.fetch} [deps.fetchImpl]
 */
export async function provisionSubagent({
  idpUrl,
  parentSlotSeed,
  parentSigningKey,
  parentDid,
  parentVcCompact,
  parentScope,
  subagent,
  fetchImpl = globalThis.fetch,
}) {
  if (!Buffer.isBuffer(parentSlotSeed) || parentSlotSeed.length !== 32) {
    throw new Error('provisionSubagent: parentSlotSeed must be a 32-byte Buffer');
  }
  if (!subagent || typeof subagent.slug !== 'string' || !subagent.slug) {
    throw new Error('provisionSubagent: subagent.slug required');
  }

  const subScope = `${parentScope}-${subagent.slug}`;

  // Idempotency: if the keychain already has a VC under this sub-scope,
  // assume a prior sync already provisioned it. The seed is deterministic
  // so a re-derive would produce the same identity anyway.
  const existing = await loadAgentVc(subScope).catch(() => null);
  if (existing && existing.vcCompact) {
    process.stderr.write(
      `[lastid-agent] subagent already provisioned: scope=${subScope}\n`,
    );
    return {
      ok: true,
      alreadyProvisioned: true,
      scope: subScope,
      agentDid: existing.agentDid,
    };
  }
  process.stderr.write(
    `[lastid-agent] subagent provisioning: scope=${subScope}\n`,
  );

  const sdk = await initializeSdkBindings();

  // 1) Derive sub-agent seed deterministically from the parent's slot_seed.
  //    `index = 0` for first instance of this slug; the SDK supports
  //    multiple indices per slug, but the v1 console flow only allocates
  //    one — slug is unique within the parent.
  const subSeedBytes = sdk.deriveSubAgentSeed(
    parentSlotSeed,
    subagent.slug,
    0,
  );
  const subagentSeed = Buffer.from(subSeedBytes);

  // 2) Sub-agent keypair from seed (same HKDF path as top-level agents).
  const {
    signingKey: subSigningKey,
    publicJwk: subPublicJwk,
  } = deriveAgentEd25519Keypair(subagentSeed);
  const subPubkeyBytes = Buffer.from(subPublicJwk.x, 'base64url');
  const subAgentDid = sdk.agentDidFromPubkey(subPubkeyBytes);
  const subPubkeyJwkThumb = sdk.ed25519JwkThumbprint(subPubkeyBytes);

  // 3) Build parent_authorization claims + sign with parent's key.
  //    The parent's signing seed comes from re-deriving the keypair from
  //    its slot_seed; we already have parentSigningKey (KeyObject) for
  //    DPoP, but the WASM signer wants raw bytes — so call the derivation
  //    again for the seed-bytes path. Cheap; runs once per provision.
  const { signingSeed: parentSigningSeed } = deriveAgentEd25519Keypair(
    parentSlotSeed,
  );

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: parentDid,
    sub: subAgentDid,
    agent_pubkey_jwk_thumb: subPubkeyJwkThumb,
    capabilities: Array.isArray(subagent.capabilities)
      ? subagent.capabilities
      : [],
    may_delegate: subagent.may_delegate === true,
    iat: now,
    exp: now + SUBAGENT_EXP_WINDOW_SECONDS,
    jti: `urn:uuid:${randomUUID()}`,
  };
  // claims_json is the EXACT byte sequence the JWS will encode in its
  // payload. Stringify once; the WASM signer treats the input as the
  // serialized claims value verbatim.
  const claimsJson = JSON.stringify(claims);
  const parentAuthorization = sdk.signParentAuthorization(
    parentSigningSeed,
    null,
    claimsJson,
  );

  // 4) POST /sub authenticated as parent.
  const subUrl = `${idpUrl}/v1/oid4vci/agent-provision/sub`;
  const dpop = mintDpopJwt({
    agentDid: parentDid,
    httpMethod: 'POST',
    httpUri: subUrl,
    signingKey: parentSigningKey,
  });
  const provisionRes = await fetchImpl(subUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${parentVcCompact}`,
      DPoP: dpop,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sub_agent_class: subagent.slug,
      sub_agent_pubkey_jwk: subPublicJwk,
      capabilities_subset: claims.capabilities,
      may_delegate: claims.may_delegate,
      exp: claims.exp,
      parent_authorization: parentAuthorization,
      // Same-host: no relay needed. Placeholder satisfies the route's
      // body-shape check; the seed is persisted to keychain locally.
      sealed_slot_seed: '',
    }),
  });
  if (!provisionRes.ok) {
    const text =
      typeof provisionRes.text === 'function' ? await provisionRes.text() : '';
    throw new Error(
      `subagent /sub failed: ${provisionRes.status} ${text}`,
    );
  }
  const provisioned = await provisionRes.json();
  if (
    !provisioned ||
    provisioned.ok !== true ||
    typeof provisioned.credential_offer_uri !== 'string' ||
    provisioned.sub_agent_did !== subAgentDid
  ) {
    throw new Error(
      `subagent /sub returned unexpected shape: ${JSON.stringify(provisioned)}`,
    );
  }

  // 5) OID4VCI exchange (token → proof JWT → credential) using the
  //    sub-agent's own keypair as holder.
  const offer = parseCredentialOffer(provisioned.credential_offer_uri);
  const { accessToken, cNonce } = await exchangeToken(offer);
  const proofJwt = mintProofJwt({
    credentialIssuer: offer.credentialIssuer,
    cNonce,
    agentDid: subAgentDid,
    agentPubkeyJwk: subPublicJwk,
    signingKey: subSigningKey,
  });
  const issued = await claimCredential({
    credentialIssuer: offer.credentialIssuer,
    accessToken,
    proofJwt,
  });
  if (!issued || typeof issued.credential !== 'string') {
    throw new Error(
      `subagent credential claim returned no credential: ${JSON.stringify(issued)}`,
    );
  }

  // 6) Persist under the sub-scope so the existing `loadAgentVc(scope)`
  //    path finds the sub-agent's identity when the spawned plugin
  //    instance boots with LASTID_AGENT_SCOPE=<parent>-<slug>. No new
  //    code path needed downstream.
  await persistAgentVc(
    {
      slotSeed: subagentSeed,
      // Sub-agents have no BIP85 slot in the human's tree; 0 is a
      // sentinel meaning "no slot allocated", matching what the IdP
      // writes into the VC metadata.
      slotIndex: 0,
      agentDid: subAgentDid,
      vcCompact: issued.credential,
      idpUrl,
    },
    subScope,
  );

  process.stderr.write(
    `[lastid-agent] subagent provisioned OK: scope=${subScope} did=${subAgentDid}\n`,
  );
  return {
    ok: true,
    alreadyProvisioned: false,
    scope: subScope,
    agentDid: subAgentDid,
  };
}

/**
 * On listener startup (and any time after the initial sync), walk the
 * installed subagents index and run `provisionSubagent` for any entry
 * whose sub-scope is missing a VC in keychain. This handles the case
 * where the doorbell-driven apply wrote the scope dir + index entry but
 * the OID4VCI provisioning round-trip failed (network blip, IdP error,
 * etc.) — the on-disk artifact is there but the VC isn't.
 *
 * Idempotent: provisionSubagent itself short-circuits when a VC already
 * exists, so this is safe to call whenever (startup, reconnect, etc.).
 *
 * Returns counts so the caller can log: { attempted, ok, failed, alreadyOk }.
 */
export async function selfHealSubagents({
  idpUrl,
  parentSlotSeed,
  parentSigningKey,
  parentDid,
  parentVcCompact,
  parentScope,
  fetchImpl = globalThis.fetch,
}) {
  const { listSubagents } = await import('./subagents.js');
  const installed = await listSubagents(parentScope).catch(() => []);
  let attempted = 0;
  let ok = 0;
  let failed = 0;
  let alreadyOk = 0;
  for (const entry of installed) {
    if (!entry || !entry.slug) continue;
    attempted += 1;
    try {
      const result = await provisionSubagent({
        idpUrl,
        parentSlotSeed,
        parentSigningKey,
        parentDid,
        parentVcCompact,
        parentScope,
        subagent: {
          slug: entry.slug,
          // The applied record's content isn't re-decrypted here — only
          // the slug + capabilities are needed to rebuild the parent_auth
          // claims. capabilities were captured on the on-disk index by
          // installStubSub (via the published content). If the index lacks
          // them, provisionSubagent treats it as an empty set and the IdP
          // enforces subset rules.
          name: entry.name,
          capabilities: [],
          may_delegate: false,
        },
        fetchImpl,
      });
      if (result.alreadyProvisioned) {
        alreadyOk += 1;
      } else {
        ok += 1;
      }
    } catch (err) {
      failed += 1;
      process.stderr.write(
        `[lastid-agent] subagent self-heal failed: scope=${parentScope}-${entry.slug} err=${err?.message ?? err}\n`,
      );
    }
  }
  return { attempted, ok, failed, alreadyOk };
}
