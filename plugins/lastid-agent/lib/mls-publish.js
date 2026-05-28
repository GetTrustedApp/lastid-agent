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
 * device_id is derived from the agent's Ed25519 public key via
 * `agentDeviceIdFromEd25519Jwk`. Stable across reinstalls,
 * deterministic, colon-free.
 */
import { MlsClient } from './mls-client.js';
import { mintDpopJwt } from './dpop.js';
import { deriveAgentEd25519Keypair } from './agent-provisioning.js';
import { agentDeviceIdFromEd25519Jwk } from './agent-device-id.js';
import { createPublicKey } from 'node:crypto';

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

  // Mint REGULAR_COUNT consumable KPs + 1 last-resort. Each
  // generateKeyPackage call mints a fresh KP with its own private
  // credential held in the wasm state; persist once at the end so
  // every credential ends up in the sealed state file (skipping
  // persist would invalidate all of them on the next restart).
  const items = [];
  for (let i = 0; i < REGULAR_COUNT; i++) {
    items.push({
      key_package: await mls.generateKeyPackage(),
      device_id: deviceId,
    });
  }
  items.push({
    key_package: await mls.generateKeyPackage(),
    device_id: deviceId,
    is_last_resort: true,
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
}) {
  const trimmed = String(idpUrl ?? '').replace(/\/$/, '');
  if (!trimmed) throw new Error('maintainAgentKeyPackages: idpUrl required');
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('maintainAgentKeyPackages: slotSeed must be 32 bytes');
  }
  const { signingKey } = deriveAgentEd25519Keypair(slotSeed);

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
  const result = await publishAgentKeyPackage({
    idpUrl,
    agentDid,
    vcCompact,
    slotSeed,
    scope,
  });
  return { available, replenished: true, refs: result.refs };
}
