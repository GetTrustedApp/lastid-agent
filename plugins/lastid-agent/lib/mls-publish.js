/**
 * Plugin-side MLS KeyPackage publish.
 *
 * Each KeyPackage is consumed (atomically claimed) by the IdP the
 * first time a peer fetches it. To keep the operator's dock able to
 * reach the agent across multiple sessions, we publish a small batch
 * of regulars + one last-resort:
 *
 *   - REGULAR_COUNT regulars: consumed one-per-add-to-group. The
 *     IdP enforces TTL + per-device caps.
 *   - 1 last-resort: never consumed, ensures the dock can always
 *     create a fresh group even after regulars are exhausted.
 *
 * Maintenance posture: on every cmdListen startup we top up to
 * REGULAR_COUNT if the inventory dropped below TOPUP_THRESHOLD,
 * keeping the operator-side dock reliable.
 *
 * IdP routes:
 *   POST /v1/mls/keypackages/batch
 *   body: { key_packages: [{ key_package, device_id, is_last_resort? }] }
 *   GET  /v1/mls/keypackages/me?device_id=<id>
 *
 * device_id is derived from the agent's P-256 public key via
 * `agentDeviceIdFromP256Jwk`. Stable across reinstalls,
 * deterministic, colon-free.
 */
import { MlsClient } from './mls-client.js';
import { mintDpopJwt } from './dpop.js';
import { deriveAgentKeypair, resolveAgentDeviceId } from './agent-provisioning.js';

/** How many regular (consumable) KeyPackages to keep on file. */
const REGULAR_COUNT = 5;
/** Inventory floor — below this, top up back to REGULAR_COUNT. */
const TOPUP_THRESHOLD = 2;

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
 * @param {import('./mls-client.js').MlsClient} [args.mls]  — the listener's
 *   SHARED MLS handle. **MUST** be passed when a listener is running: the
 *   KeyPackage's private credential is minted into THIS handle's openmls
 *   state, and only this handle (which also processes inbound welcomes) can
 *   later match it. If publish opens its OWN client while the listener's
 *   orchestrator is live, the two instances over the same sealed file clobber
 *   each other's flush and the private parts vanish → `NoMatchingKeyPackage`
 *   on the operator's welcome — the multi-device delivery bug
 *   (mem_01KSNXSY4TY7DK7EJTREPNY5RH). Omit ONLY at provision time, before any
 *   listener exists (no concurrent instance, so a throwaway client is safe).
 *
 * @returns {Promise<{ ok: true, refs: string[], count: number }>}
 *   On the IdP success path the body includes a `refs` array (one per
 *   published KeyPackage); we pass it through verbatim (or `[]` if the
 *   IdP omits it). `count` is how many KeyPackages this call published.
 *   Errors throw — the caller decides whether to surface them (we log +
 *   continue from cmdProvision).
 */
export async function publishAgentKeyPackage({
  idpUrl,
  agentDid,
  vcCompact,
  slotSeed,
  scope,
  // The device_id PINNED at provisioning (`md-…`), from the keychain install
  // record. Threaded into the throwaway-client (provision-time) path; the
  // listener passes `mls` and the device_id rides on that shared handle.
  deviceId: persistedDeviceId,
  mls: sharedMls,
}) {
  const trimmed = String(idpUrl ?? '').replace(/\/$/, '');
  if (!trimmed) throw new Error('publishAgentKeyPackage: idpUrl required');
  if (!agentDid) throw new Error('publishAgentKeyPackage: agentDid required');
  if (!vcCompact) throw new Error('publishAgentKeyPackage: vcCompact required');
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('publishAgentKeyPackage: slotSeed must be 32 bytes');
  }

  const { signingKey } = deriveAgentKeypair(slotSeed, agentDid);

  // Reuse the listener's shared handle when given (B1 convergence — see the
  // `mls` param doc). Only fall back to a throwaway client at provision time,
  // when no listener (and so no competing instance) exists. The throwaway
  // client resolves its device_id from the persisted (`md-…`) value when one
  // was pinned at provisioning, else the legacy `ad-…` derivation.
  const mls =
    sharedMls ??
    (await MlsClient.open({
      agentDid,
      slotSeed,
      scope: scope ?? 'main',
      deviceId: persistedDeviceId,
    }));

  // device_id for the IdP's key-package store — READ FROM THE HANDLE, so the
  // KP is stored under exactly the device_id the handle's credentials carry.
  // No independent derivation here = the KP and the credential cannot disagree
  // (the multi-device two-sources class). The IdP keys set entries as
  // `${deviceId}:${ref}` and splits on `:`, so a colon-free `ad-`/`md-` id is
  // required (DIDs contain colons). Fall back to the resolved derivation only
  // for a handle built without a device_id (test / bare-DID).
  const deviceId =
    mls.deviceId ??
    (Buffer.isBuffer(slotSeed) && slotSeed.length === 32
      ? resolveAgentDeviceId({ persistedDeviceId, slotSeed, agentDid })
      : undefined);

  // Mint REGULAR_COUNT consumable KPs + 1 last-resort. Each
  // generateKeyPackage call mints a fresh KP with its own private
  // credential held in the wasm state; persist once at the end so
  // every credential ends up in the sealed state file (skipping
  // persist would invalidate all of them on the next restart).
  // cred_version: 2 — the agent's MLS handle is built with its device_id, so
  // every credential it mints is the structured (v2) form. Declaring it lets
  // the IdP one-time-purge this device's legacy v1 (bare-DID) packages on the
  // first v2 publish (self-limiting server-side).
  const items = [];
  for (let i = 0; i < REGULAR_COUNT; i++) {
    items.push({
      key_package: await mls.generateKeyPackage(),
      device_id: deviceId,
      cred_version: 2,
    });
  }
  items.push({
    key_package: await mls.generateKeyPackage(),
    device_id: deviceId,
    is_last_resort: true,
    cred_version: 2,
  });
  // generateKeyPackage already auto-flushes via the storage-provider's
  // flushBlob callback; persist() is a kept-for-compat no-op.
  await mls.persist();

  const url = `${trimmed}/v1/mls/keypackages/batch`;
  const dpopProof = mintDpopJwt({
    agentDid,
    httpMethod: 'POST',
    httpUri: url,
    signingKey,
  });

  // Auth pattern: Bearer SD-JWT VC compact + DPoP proof in a
  // separate header. See note in single-publish flow — `DPoP <token>`
  // scheme is for IdP-issued OAuth access tokens, not raw VCs.
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${vcCompact}`,
      DPoP: dpopProof,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ key_packages: items }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '<no body>');
    throw new Error(
      `POST /v1/mls/keypackages/batch failed: HTTP ${res.status} ${text}`,
    );
  }

  const body = await res.json().catch(() => ({}));
  const refs = Array.isArray(body?.refs) ? body.refs : [];
  return { ok: true, refs, count: items.length };
}

/**
 * Inventory + maintenance pass. Pulls the agent's current KP count
 * from GET /me, and re-publishes a fresh batch if it dropped below
 * TOPUP_THRESHOLD. Idempotent — re-running mid-pool is cheap and
 * the IdP de-dupes by content hash so duplicate posts don't pile up.
 *
 * Returns `{ available, replenished, refs? }`.
 */
export async function maintainAgentKeyPackages({
  idpUrl,
  agentDid,
  vcCompact,
  slotSeed,
  scope,
  deviceId: persistedDeviceId,
  mls: sharedMls,
}) {
  const trimmed = String(idpUrl ?? '').replace(/\/$/, '');
  if (!trimmed) throw new Error('maintainAgentKeyPackages: idpUrl required');
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('maintainAgentKeyPackages: slotSeed must be 32 bytes');
  }
  const { signingKey } = deriveAgentKeypair(slotSeed, agentDid);

  const htu = `${trimmed}/v1/mls/keypackages/me`;
  const dpop = mintDpopJwt({
    agentDid,
    httpMethod: 'GET',
    httpUri: htu,
    signingKey,
  });
  let available = 0;
  try {
    const res = await fetch(htu, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${vcCompact}`,
        DPoP: dpop,
      },
    });
    if (res.ok) {
      const body = await res.json().catch(() => ({}));
      // Count non-last-resort packages — last-resorts don't get
      // consumed so they're not what determines "do we need more?".
      const all = Array.isArray(body?.key_packages) ? body.key_packages : [];
      available = all.filter((p) => !p.is_last_resort).length;
    }
  } catch {
    // Network hiccup → fall through and publish (safer to over-publish).
  }

  if (available >= TOPUP_THRESHOLD) {
    return { available, replenished: false };
  }
  // Thread the shared handle through so the replenish mints into the
  // listener's ONE instance, not a competing one (B1 convergence).
  const result = await publishAgentKeyPackage({
    idpUrl,
    agentDid,
    vcCompact,
    slotSeed,
    scope,
    deviceId: persistedDeviceId,
    mls: sharedMls,
  });
  return { available, replenished: true, refs: result.refs };
}
