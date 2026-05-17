/**
 * Node FFI shim around the LastID SDK C ABI (cdylib emitted by the
 * `lastid-agent-ffi` Rust crate). The native lib lives in
 * `native/<platform>-<arch>/liblastid_agent_ffi.{dylib,so,dll}`.
 *
 * This module exposes a small async API the plugin uses:
 *
 *   initializeSdkBindings()          → SdkHandle
 *   deriveFreshAgentKeypair()        → { seed, keypair }
 *   deriveSubAgentKeypair({…})       → { seed, keypair, jwk }
 *   verifyAgentVc(jws, opts)         → { ok, claims?, error? }
 *   mintAgentPopJwt(keypair, opts)   → compact JWT string
 *   mintOid4vciProofJwt(keypair, …)  → compact JWT string
 *   computeEd25519JwkThumbprint(jwk) → base64url SHA-256 thumbprint
 *
 * The FFI surface mirrors the Rust public API:
 *   - lastid-identity::AgentKeypair::from_seed
 *   - lastid-vc::agent_vc::verify_outer / verify_with_human_authorization
 *   - lastid-vc::pop::create_pop_jwt
 *   - lastid-vc::human_authorization::ed25519_jwk_thumbprint
 *
 * Until the FFI crate ships, this file provides a JS-only stub that
 * speaks the same shape. The plugin will fail loudly when called
 * without native bindings; tests can swap in the stub via a flag.
 */

let cached;

export async function initializeSdkBindings() {
  if (cached) return cached;
  if (process.env.LASTID_AGENT_USE_STUB === '1') {
    cached = makeStub();
    return cached;
  }
  // TODO: load native library via dlopen / node:ffi-napi. Tracked
  // alongside the lastid-agent-ffi crate scaffold in lastid-sdk.
  throw new Error(
    'lastid-agent native bindings not built yet; set LASTID_AGENT_USE_STUB=1 to use the JS stub during development.'
  );
}

export async function deriveFreshAgentKeypair() {
  const sdk = await initializeSdkBindings();
  return sdk.deriveFreshAgentKeypair();
}

export async function deriveSubAgentKeypair(opts) {
  const sdk = await initializeSdkBindings();
  return sdk.deriveSubAgentKeypair(opts);
}

export async function verifyAgentVc(jws, opts) {
  const sdk = await initializeSdkBindings();
  return sdk.verifyAgentVc(jws, opts);
}

export async function mintAgentPopJwt(keypair, opts) {
  const sdk = await initializeSdkBindings();
  return sdk.mintAgentPopJwt(keypair, opts);
}

export async function mintOid4vciProofJwt(keypair, opts) {
  const sdk = await initializeSdkBindings();
  return sdk.mintOid4vciProofJwt(keypair, opts);
}

export async function computeEd25519JwkThumbprint(jwk) {
  const sdk = await initializeSdkBindings();
  return sdk.computeEd25519JwkThumbprint(jwk);
}

// ---------------------------------------------------------------------
// Development stub
// ---------------------------------------------------------------------

function makeStub() {
  return {
    deriveFreshAgentKeypair: async () => {
      throw new Error('SDK stub: deriveFreshAgentKeypair not implemented; build the native FFI crate.');
    },
    deriveSubAgentKeypair: async () => {
      throw new Error('SDK stub: deriveSubAgentKeypair not implemented.');
    },
    verifyAgentVc: async () => ({ ok: false, error: 'stub: no verification' }),
    mintAgentPopJwt: async () => 'stub.pop.jwt',
    mintOid4vciProofJwt: async () => 'stub.proof.jwt',
    computeEd25519JwkThumbprint: async () => 'stub-thumbprint',
  };
}
