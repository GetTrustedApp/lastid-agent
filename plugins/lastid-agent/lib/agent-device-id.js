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
 *   `ad-<sha256(canonical-jwk(agent_p256_pubkey))[:32]>`
 *
 * The agent identity is now NIST P-256 (ES256), matching the SDK/WASM
 * and the IdP. The canonical JWK is the RFC 7638 member ordering for an
 * EC key: `{"crv":"P-256","kty":"EC","x":"<b64url32>","y":"<b64url32>"}`
 * (lexicographically sorted required members, no whitespace), SHA-256,
 * then `ad-` + the first 32 hex chars. This is byte-identical to the
 * IdP's agent device-id derivation — if they diverge, agent↔operator
 * MLS membership silently breaks. The KAT for seed `[42;32]` is pinned
 * in `tests/agent-device-id.test.js`.
 *
 * - Stable across plugin reinstalls — derives from the public P-256
 *   key material only.
 * - Deterministic — same agent_pubkey on same OR different machines
 *   produces the same id (per-slot identity is wallet-derived from
 *   BIP85, so re-provisioning the same slot reuses the same id).
 * - 35 chars total — well under Firestore / Redis key-segment limits.
 * - `ad-` prefix keeps it visually distinct from `device-<uuid>`
 *   (human) and `bd-…` (bot) ids in logs without colliding.
 * - Contains no `:` so the IdP key-package service's
 *   `loadStoredPackages` set-entry split parses it correctly.
 *
 * Note: the same canonical bytes back the WASM `p256JwkThumbprint`
 * (RFC 7638) — the device-id is the first 32 HEX chars of that SHA-256
 * while the thumbprint is the full base64url. Single canonical form,
 * one source of truth.
 */
import { createHash } from 'node:crypto';

/**
 * The 32-hex-char body shared by ALL P-256 device-id prefixes (`ad-` the
 * agent's own device, `md-` the machine it runs on, `bd-` bots). Only the
 * prefix differs — the hash is the SAME canonical RFC 7638 EC JWK
 * (`{"crv","kty","x","y"}`, sorted, no whitespace) → SHA-256 → first 32 hex.
 * Extracting it here makes `ad-`/`md-` structurally incapable of diverging,
 * mirroring the Rust `p256_device_id_hex` shared by the same prefixes. MUST
 * stay byte-identical to the WASM `p256_jwk_thumbprint` canonical form and
 * the IdP's device-id derivation.
 * @param {{ kty: 'EC'; crv: 'P-256'; x: string; y: string }} jwk
 * @returns {string} 32 lowercase hex chars
 */
function p256DeviceIdHex(jwk) {
  if (
    !jwk ||
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string'
  ) {
    throw new Error(
      'p256DeviceIdHex: expected an EC P-256 JWK with string `x` and `y`',
    );
  }
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 32);
}

/**
 * The agent's OWN device id (`ad-`), derived from its operational P-256 key.
 * @param {{ kty: 'EC'; crv: 'P-256'; x: string; y: string }} jwk
 * @returns {string}
 */
export function agentDeviceIdFromP256Jwk(jwk) {
  return `ad-${p256DeviceIdHex(jwk)}`;
}

/**
 * The MACHINE device id (`md-`), derived from the machine's Secure-Enclave
 * P-256 public key (supplied by the signed broker). This is the parent-owned
 * device the agent's operational key attaches onto at enrollment and the
 * sticky-revoke boundary; it is the agent's MLS device_id once the agent has
 * been (re)issued machine-bound. Same hash body as `ad-` — only the prefix
 * differs — so it is byte-identical to the Rust
 * `machine_device_id_from_p256_coords` and the IdP's `machineDeviceIdFromJwk`.
 * If they diverge, the agent's key-package store key and the IdP's machine
 * device row silently disagree.
 * @param {{ kty: 'EC'; crv: 'P-256'; x: string; y: string }} jwk
 * @returns {string}
 */
export function machineDeviceIdFromP256Jwk(jwk) {
  return `md-${p256DeviceIdHex(jwk)}`;
}

/**
 * Ed25519 backward-compat path. Existing agents have an Ed25519 identity
 * (`did:lastid:agent:z6Mk…`); their device_id derives from the OKP JWK,
 * not the EC one. Contract:
 *   `ad-<sha256(canonical-jwk(agent_ed25519_pubkey))[:32]>`
 * where the canonical JWK is the RFC 7638 member ordering for an OKP key:
 * `{"crv":"Ed25519","kty":"OKP","x":"<b64url32>"}`. Byte-identical to the
 * IdP's Ed25519 agent device-id derivation — if they diverge, agent↔operator
 * MLS membership silently breaks for the existing Ed25519 fleet.
 *
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
