/**
 * Stable per-agent-runtime device_id.
 *
 * Mirrors the bot pattern at
 * `lastid-idp/packages/credential-service/src/mls/bot-device-id.ts`:
 * one agent runtime owns one device_id across mls_key_packages,
 * device_prekeys, and any future per-device row. Without this the
 * key-package store mis-keys colon-containing identifiers (the agent
 * DID contains `:` so the set entry `${deviceId}:${ref}` splits
 * wrong and gets pruned on every read).
 *
 * Contract:
 *   `ad-<sha256(canonical-jwk(agent_ed25519_pubkey))[:32]>`
 *
 * - Stable across plugin reinstalls — derives from the public Ed25519
 *   key material only.
 * - Deterministic — same agent_pubkey on same OR different machines
 *   produces the same id (per-slot identity is wallet-derived from
 *   BIP85, so re-provisioning the same slot reuses the same id).
 * - 35 chars total — well under Firestore / Redis key-segment limits.
 * - `ad-` prefix keeps it visually distinct from `device-<uuid>`
 *   (human) and `bd-…` (bot) ids in logs without colliding.
 * - Contains no `:` so the IdP key-package service's
 *   `loadStoredPackages` set-entry split parses it correctly.
 */
import { createHash } from 'node:crypto';

/**
 * @param {{ kty: 'OKP'; crv: 'Ed25519'; x: string }} jwk
 * @returns {string}
 */
export function agentDeviceIdFromEd25519Jwk(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error(
      'agentDeviceIdFromEd25519Jwk: expected an Ed25519 OKP JWK with string `x`',
    );
  }
  // RFC 7638-style canonical JSON (lexicographically sorted required
  // members, no whitespace). For Ed25519 OKP the required members are
  // crv, kty, x. Bot helper uses the same shape minus the curve point
  // (EC has x + y instead of just x).
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `ad-${hash.slice(0, 32)}`;
}
