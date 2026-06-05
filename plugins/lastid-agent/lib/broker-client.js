/**
 * Plugin → signed-broker bridge.
 *
 * Everything that needs the machine's Secure-Enclave keys goes through the
 * code-signed Rust broker (it is the SOLE reader of the SE / keychain;
 * unsigned node can't touch the Secure Enclave — that's the broker's whole
 * reason for existing). This module is the seed of that bridge; today it
 * carries one call — the per-machine SE pubkey for agent provisioning — and
 * FORK1's full IdP-call routing grows here later.
 *
 * The broker binary ships INSIDE the plugin (the `native/` dir) and is
 * resolved relative to the plugin, so an install carries its own broker.
 * `LASTID_AGENT_BROKER_BIN` overrides the path for dev (e.g. pointing at a
 * freshly signed build under lastid-sdk).
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the signed broker binary shipped in the plugin's `native/` dir.
 *
 * The broker is a code-signed macOS `.app` bundle (it MUST run inside a bundle
 * so macOS resolves its CFBundleIdentifier + provisioning-profile entitlement,
 * which authorizes Secure-Enclave keychain access — a bare Mach-O can't). We
 * exec the inner Mach-O directly; macOS still recognizes the enclosing bundle.
 * `LASTID_AGENT_BROKER_BIN` overrides for dev (point at a freshly signed build).
 */
export function resolveBrokerPath() {
  if (process.env.LASTID_AGENT_BROKER_BIN) {
    return process.env.LASTID_AGENT_BROKER_BIN;
  }
  return fileURLToPath(
    new URL(
      '../native/lastid-agent-broker.app/Contents/MacOS/lastid-agent-broker',
      import.meta.url,
    ),
  );
}

/**
 * Parse the `machine-pubkey` subcommand's stdout into a validated P-256 JWK,
 * or `null` if it isn't a well-formed `{ machine_se_pubkey_jwk: {EC P-256} }`.
 * Pure — unit-tested independently of the spawn.
 */
export function parseMachinePubkeyOutput(stdout) {
  if (typeof stdout !== 'string' || stdout.trim().length === 0) return null;
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  const jwk = parsed?.machine_se_pubkey_jwk;
  if (
    jwk &&
    jwk.kty === 'EC' &&
    jwk.crv === 'P-256' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string'
  ) {
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }
  return null;
}

/**
 * Ask the signed broker for the per-machine Secure-Enclave public key (as a
 * P-256 JWK) so `/agent-provision/initiate` can present `machine_se_pubkey_jwk`
 * and the wallet can sign a `device_authorization` over the machine `md-`.
 *
 * Returns `null` — and provisioning proceeds WITHOUT a machine device
 * (no-flag-day legacy flow) — whenever the broker is absent, not on macOS, not
 * yet signed (SE keygen fails), times out, or prints anything unexpected. The
 * machine SE key is never reached by the plugin directly; only the broker.
 *
 * `spawnImpl` / `brokerPath` are injectable for tests.
 */
export function getMachineSePubkeyJwk({
  spawnImpl = spawnSync,
  brokerPath,
  platform = process.platform,
} = {}) {
  // The signed broker is macOS-only (it owns the macOS Secure Enclave). On any
  // other platform there is no machine SE key → no machine device; provisioning
  // falls through to the legacy no-machine-device flow (no-flag-day), exactly
  // as when the broker is absent. `platform` is injectable for tests.
  if (platform !== 'darwin') return null;
  let bin;
  try {
    bin = brokerPath ?? resolveBrokerPath();
  } catch {
    return null;
  }
  let result;
  try {
    result = spawnImpl(bin, ['machine-pubkey'], {
      encoding: 'utf8',
      timeout: 10_000,
    });
  } catch {
    // ENOENT (no broker shipped), EACCES, etc. — degrade to legacy.
    return null;
  }
  if (!result || result.status !== 0) return null;
  return parseMachinePubkeyOutput(result.stdout);
}
