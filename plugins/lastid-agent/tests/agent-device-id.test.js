/**
 * Device-id derivation contract (`ad-` agent device, `md-` machine device).
 *
 * The `md-` machine device-id is the agent's MLS device_id once it has been
 * (re)issued machine-bound (L5). It MUST be byte-identical to the Rust
 * `machine_device_id_from_p256_coords` and the IdP's `machineDeviceIdFromJwk`,
 * and it MUST share its 32-hex body with `ad-` (only the prefix differs) — if
 * either diverges, the agent's key-package store key and the IdP's machine
 * device row silently disagree (the multi-device two-sources class).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  agentDeviceIdFromP256Jwk,
  machineDeviceIdFromP256Jwk,
} from '../lib/agent-device-id.js';

// Pinned vector — the P-256 public key derived from slot seed [42;32]
// (see agent-provisioning.test.js KAT). The same canonical RFC 7638 EC JWK
// backs both prefixes and the WASM `p256_jwk_thumbprint`.
const KAT_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '7QzUQKKfT8idSUWe6yEMhAhyCylEwH4BI1AUWsn4TAk',
  y: 'CFK9En0kVMCifo6MSOiM7TKaVuLj62Kiyh7j_fHKvdU',
};
const KAT_HEX = '1ef73378e49013f06656bc0a223f46ad';

test('KAT: md- machine device-id is byte-identical to the Rust/IdP derivation', () => {
  assert.equal(machineDeviceIdFromP256Jwk(KAT_JWK), `md-${KAT_HEX}`);
});

test('ad- and md- share the same 32-hex body — only the prefix differs', () => {
  const ad = agentDeviceIdFromP256Jwk(KAT_JWK);
  const md = machineDeviceIdFromP256Jwk(KAT_JWK);
  assert.equal(ad, `ad-${KAT_HEX}`);
  assert.equal(md, `md-${KAT_HEX}`);
  // The shared-body extraction (p256DeviceIdHex) makes divergence structurally
  // impossible; this locks it so a future refactor can't reintroduce it.
  assert.equal(ad.slice(3), md.slice(3));
  assert.notEqual(ad, md);
});

test('machineDeviceIdFromP256Jwk rejects non-EC / malformed JWKs', () => {
  assert.throws(() => machineDeviceIdFromP256Jwk(null), /EC P-256 JWK/);
  assert.throws(
    () => machineDeviceIdFromP256Jwk({ kty: 'OKP', crv: 'Ed25519', x: 'z' }),
    /EC P-256 JWK/,
  );
  assert.throws(
    () => machineDeviceIdFromP256Jwk({ kty: 'EC', crv: 'P-256', x: 'AAAA' }),
    /EC P-256 JWK/,
  );
});
