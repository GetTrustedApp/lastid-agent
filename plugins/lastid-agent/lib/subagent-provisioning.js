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
  // Operator's project_root_seed — shared across ALL the operator's agents
  // (parent + every sub) so they can all decrypt the same global-shared
  // rules + memories. Sub-agents don't have their own; they reuse the
  // operator's, passed in by the parent listener.
  parentProjectRootSeed = null,
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

  // The OPERATOR-PICKED capabilities are the contract — log them at
  // provision time so a wrong-caps issue is observable in the log instead
  // of only showing up later in the issued VC.
  const desiredCaps = Array.isArray(subagent.capabilities) ? subagent.capabilities : [];
  process.stderr.write(
    `[lastid-agent] subagent provisioning: scope=${subScope} caps=${JSON.stringify(desiredCaps)}\n`,
  );

  // Idempotency: if the keychain already has a VC under this sub-scope,
  // check whether the VC's capabilities match what the operator currently
  // picked. If they match — short-circuit (deterministic seed = same DID;
  // the VC is still valid). If they DON'T match — the VC was minted with a
  // stale cap set (e.g. an old self-heal that lacked the picked caps);
  // re-mint by deleting the keychain entry first so the OID4VCI flow runs
  // again with the correct caps. The operator's pick is the source of
  // truth, period.
  const existing = await loadAgentVc(subScope).catch(() => null);
  if (existing && existing.vcCompact) {
    const existingCaps = readCapabilitiesFromVc(existing.vcCompact);
    if (capabilitiesEqual(existingCaps, desiredCaps)) {
      process.stderr.write(
        `[lastid-agent] subagent already provisioned: scope=${subScope} (caps match)\n`,
      );
      // Backfill: ensure the operator's project_root_seed is in the
      // sub-scope's keychain. Sub-agents provisioned BEFORE this fix
      // landed never got the seed → their listener can't decrypt
      // global-shared rules + memories. Writing it idempotently here
      // closes that gap WITHOUT forcing a VC re-mint.
      //
      // Critical: a running sub-listener daemon LOADED its credentials
      // at startup. Writing to keychain doesn't refresh the daemon's
      // in-memory state. So when we add a missing seed, also REAP the
      // running daemon so its parent-watchdog respawn picks up the
      // fresh credential bundle on its next startup. Detect "missing
      // before" by reading the sub-scope's current loaded bundle once.
      let seedWasMissing = false;
      if (parentProjectRootSeed && Buffer.isBuffer(parentProjectRootSeed)) {
        try {
          const existingSubLoaded = await loadAgentVc(subScope).catch(() => null);
          seedWasMissing = !existingSubLoaded?.projectRootSeed;
          if (seedWasMissing) {
            const { persistProjectRootSeed } = await import('./keychain.js');
            await persistProjectRootSeed(
              subScope,
              Buffer.from(parentProjectRootSeed).toString('base64url'),
            );
            process.stderr.write(
              `[lastid-agent] subagent project_root_seed backfilled: scope=${subScope} — respawning listener so it picks up new creds\n`,
            );
            // Reap the running daemon. spawnSubagentListener below will
            // respawn it on the same scope with a fresh credential load.
            await stopSubagentListener(subScope);
          }
        } catch (err) {
          process.stderr.write(
            `[lastid-agent] subagent project_root_seed backfill failed (non-fatal): scope=${subScope} err=${err?.message ?? err}\n`,
          );
        }
      }
      // Even on the already-provisioned path, make sure the listener
      // daemon is alive. A previous successful provision spawned it, but
      // a host reboot / SIGKILL / stale-version cleanup could have left
      // the sub-scope without a running listener — ensureListenerRunning
      // is idempotent and will respawn only when needed. If we just
      // reaped above because of a seed backfill, this respawns it now.
      await spawnSubagentListener(subScope);
      return {
        ok: true,
        alreadyProvisioned: true,
        scope: subScope,
        agentDid: existing.agentDid,
      };
    }
    process.stderr.write(
      `[lastid-agent] subagent caps drift: scope=${subScope} existing=${JSON.stringify(existingCaps)} desired=${JSON.stringify(desiredCaps)} — re-minting VC\n`,
    );
    const { deleteAgentVc } = await import('./keychain.js');
    await deleteAgentVc(subScope).catch(() => null);
  }

  const sdk = await initializeSdkBindings();

  // 1) Ask the IdP for the next monotonic HKDF index for this
  //    (parent_agent_did, sub_agent_class) pair. Revoke + re-create
  //    advances the IdP-side counter so the new sub-agent gets a fresh
  //    DID rather than reusing the revoked one. The /sub endpoint
  //    transactionally validates the claimed index, so a stale value
  //    here returns 409 sub_agent_index_stale (we then refetch + retry).
  const subAgentIndex = await fetchNextSubagentIndex({
    idpUrl,
    parentDid,
    parentSigningKey,
    parentVcCompact,
    subAgentClass: subagent.slug,
    fetchImpl,
  });

  // 2) Derive sub-agent seed deterministically from the parent's slot_seed
  //    + (slug, index). The index participates in the HKDF info so a fresh
  //    index yields a fresh seed → fresh DID.
  const subSeedBytes = sdk.deriveSubAgentSeed(
    parentSlotSeed,
    subagent.slug,
    subAgentIndex,
  );
  const subagentSeed = Buffer.from(subSeedBytes);

  // 3) Sub-agent keypair from seed (same HKDF path as top-level agents).
  const {
    signingKey: subSigningKey,
    publicJwk: subPublicJwk,
  } = deriveAgentEd25519Keypair(subagentSeed);
  const subPubkeyBytes = Buffer.from(subPublicJwk.x, 'base64url');
  const subAgentDid = sdk.agentDidFromPubkey(subPubkeyBytes);
  const subPubkeyJwkThumb = sdk.ed25519JwkThumbprint(subPubkeyBytes);

  // 4) Build parent_authorization claims + sign with parent's key.
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
    sub_agent_class: subagent.slug,
    sub_agent_index: subAgentIndex,
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
      sub_agent_index: subAgentIndex,
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
      // Forward the operator's project_root_seed — shared across all
      // the operator's agents. Without this the sub-agent's listener
      // can decrypt per-agent records (under its own slot_seed) but
      // NOT global-shared records (rules + memories the operator
      // published with target='global'), so the sub-agent runs
      // ungoverned. persistAgentVc no-ops when this is null/missing.
      ...(parentProjectRootSeed ? { projectRootSeed: parentProjectRootSeed } : {}),
    },
    subScope,
  );

  process.stderr.write(
    `[lastid-agent] subagent provisioned OK: scope=${subScope} did=${subAgentDid}\n`,
  );

  // 7) Spawn the sub-agent's OWN listener daemon. A sub-agent is just an
  //    agent — it gets its own running plugin: its own WS to the IdP, its
  //    own agent-state sync (globals + project memories + records targeted
  //    at its DID land in its scope's operator-store), its own audit
  //    chain shipper, its own per-turn memory injection. Without this the
  //    sub-agent has identity but no brain: no rules synced, no global
  //    bedrocks, no operator-side updates flow to it.
  await spawnSubagentListener(subScope);

  return {
    ok: true,
    alreadyProvisioned: false,
    scope: subScope,
    agentDid: subAgentDid,
  };
}

/**
 * Read the IdP's authoritative next HKDF index for this
 * (parent_agent_did, sub_agent_class) pair. Authenticated as the parent
 * agent — same DPoP + VC the /sub call uses. Returns the integer index
 * the caller MUST bind into both the parent_authorization JWS claims and
 * the /sub request body. /sub re-checks transactionally; a stale value
 * here returns sub_agent_index_stale (409) and the caller should refetch.
 */
async function fetchNextSubagentIndex({
  idpUrl,
  parentDid,
  parentSigningKey,
  parentVcCompact,
  subAgentClass,
  fetchImpl,
}) {
  const url = `${idpUrl}/v1/oid4vci/agent-provision/sub/next-index?sub_agent_class=${encodeURIComponent(subAgentClass)}`;
  const dpop = mintDpopJwt({
    agentDid: parentDid,
    httpMethod: 'GET',
    httpUri: url,
    signingKey: parentSigningKey,
  });
  const res = await fetchImpl(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${parentVcCompact}`,
      DPoP: dpop,
      accept: 'application/json',
    },
  });
  if (!res.ok) {
    const text = typeof res.text === 'function' ? await res.text() : '';
    throw new Error(`/sub/next-index failed: ${res.status} ${text}`);
  }
  const body = await res.json();
  if (!body || !Number.isInteger(body.next_index) || body.next_index < 0) {
    throw new Error(`/sub/next-index returned unexpected shape: ${JSON.stringify(body)}`);
  }
  return body.next_index;
}

/**
 * Spawn (or confirm) the sub-agent's own listener daemon. Idempotent —
 * `ensureListenerRunning` no-ops when a current-version listener is
 * already alive for this scope. Fail-soft: a spawn failure logs but
 * never undoes provisioning or breaks the caller.
 */
async function spawnSubagentListener(subScope) {
  try {
    const { ensureListenerRunning } = await import('./listener-daemon.js');
    const { fileURLToPath } = await import('node:url');
    const cliPath = fileURLToPath(new URL('../bin/lastid-agent.js', import.meta.url));
    const result = await ensureListenerRunning({ scope: subScope, cliPath });
    process.stderr.write(
      `[lastid-agent] subagent listener: scope=${subScope} status=${result?.status ?? '?'}${
        result?.pid ? ` pid=${result.pid}` : ''
      }\n`,
    );
    return result;
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] subagent listener spawn failed (non-fatal): scope=${subScope} err=${err?.message ?? err}\n`,
    );
    return null;
  }
}

/**
 * Stop (reap) the sub-agent's listener daemon. Called from the
 * revoke path so a revoked sub-agent doesn't keep a stray daemon
 * holding an open WS + draining audits. Best-effort.
 */
export async function stopSubagentListener(subScope) {
  try {
    const { reapScopeListeners } = await import('./listener-daemon.js');
    await reapScopeListeners({ scope: subScope, keep: null });
    process.stderr.write(
      `[lastid-agent] subagent listener stopped: scope=${subScope}\n`,
    );
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] subagent listener stop failed (non-fatal): scope=${subScope} err=${err?.message ?? err}\n`,
    );
  }
}

/**
 * Decode an SD-JWT VC's payload to extract the credentialSubject's
 * capability list. Returns [] if the VC is unparseable or has no caps.
 * Used by provisionSubagent's drift-detection to compare what the
 * existing keychain VC actually grants vs. what the operator currently
 * has picked. Not a security check (the VC's signature is validated by
 * the IdP at issuance) — just a content read.
 */
function readCapabilitiesFromVc(vcCompact) {
  try {
    // SD-JWT format: JWS~disclosure~disclosure~... — we only need the JWS
    // payload (segment 1 of the JWS).
    const jwsPart = String(vcCompact).split('~')[0] ?? '';
    const segs = jwsPart.split('.');
    if (segs.length !== 3) return [];
    const payload = JSON.parse(Buffer.from(segs[1], 'base64url').toString('utf-8'));
    // SD-JWT credentialSubject claims may be top-level on the payload or
    // nested under `credentialSubject` depending on issuer convention.
    // Check both.
    const caps =
      payload?.capabilities ??
      payload?.credentialSubject?.capabilities ??
      [];
    return Array.isArray(caps) ? caps : [];
  } catch {
    return [];
  }
}

/**
 * Byte-compare two capability lists (deep equality). Capabilities are
 * small JSON arrays of {resource, actions[], constraints?[]} — a
 * canonical-JSON comparison is sufficient and avoids the order-sensitivity
 * of deep-equal libraries.
 */
function capabilitiesEqual(a, b) {
  const A = Array.isArray(a) ? a : [];
  const B = Array.isArray(b) ? b : [];
  return JSON.stringify(A) === JSON.stringify(B);
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
  parentProjectRootSeed = null,
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
        parentProjectRootSeed,
        subagent: {
          slug: entry.slug,
          name: entry.name,
          // Read capabilities + may_delegate VERBATIM from the index
          // entry — those were persisted at apply time from the original
          // operator-published content. The picker's selection IS the
          // contract; never default to empty here.
          capabilities: Array.isArray(entry.capabilities) ? entry.capabilities : [],
          may_delegate: entry.may_delegate === true,
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
