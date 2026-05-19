/**
 * Real Rust crypto via `lastid-agent-wasm`. The .wasm + JS bindings live
 * in `../vendor/lastid-agent-wasm/`, copied in from the SDK by
 * `lastid-sdk/scripts/build-and-copy-agent-wasm.sh`. When we move to a
 * private npm registry the import will switch to `@lastid/agent-wasm`
 * with zero call-site churn.
 *
 * Exposed shape (loosely matches the previous FFI stub so existing
 * call-sites in tools/ keep working):
 *
 *   initializeSdkBindings()                 → SdkHandle
 *   deriveFreshAgentKeypair()               → not implemented (use
 *                                              agent-provisioning.js)
 *   verifyAgentVc(jws, opts)                → { ok, claims?, error? }
 *   mintAgentPopJwt(keypair, opts)          → compact JWT string
 *   mintOid4vciProofJwt(keypair, opts)      → compact JWT string
 *   computeEd25519JwkThumbprint(jwk)        → base64url SHA-256 thumbprint
 *
 * Anything that hasn't been ported off the stub will throw a clear
 * message pointing at the lib that owns the real path (e.g. fresh
 * keypair generation is owned by `agent-provisioning.js`, not this
 * shim — agent identity is derived by the wallet, not the plugin).
 */

import { createRequire } from 'node:module';

// Bindings are CJS (wasm-pack `--target nodejs`); load via createRequire
// so ESM call-sites get them without ESM↔CJS interop pain.
const localRequire = createRequire(import.meta.url);
const wasm = localRequire('../vendor/lastid-agent-wasm/lastid_agent_wasm.js');

let cached;

export async function initializeSdkBindings() {
  if (cached) return cached;
  cached = {
    // ── Identity ────────────────────────────────────────────────────
    agentKeypairFromSeed(seed) {
      return wasm.agentKeypairFromSeed(seed);
    },
    agentDidFromPubkey(pubkeyBytes) {
      return wasm.agentDidFromPubkey(pubkeyBytes);
    },
    parseAgentDid(did) {
      return wasm.parseAgentDid(did);
    },
    ed25519JwkThumbprint(pubkeyBytes) {
      return wasm.ed25519JwkThumbprint(pubkeyBytes);
    },
    deriveAgentSlotSeed(aiAgentSeed, slotIndex) {
      return wasm.deriveAgentSlotSeed(aiAgentSeed, slotIndex);
    },
    deriveSubAgentSeed(parentSlotSeed, classSlug, index) {
      return wasm.deriveSubAgentSeed(parentSlotSeed, classSlug, index);
    },

    // ── Signing ────────────────────────────────────────────────────
    signEd25519(signingKeyBytes, payload) {
      return wasm.signEd25519(signingKeyBytes, payload);
    },
    verifyEd25519(pubkeyBytes, payload, signature) {
      return wasm.verifyEd25519(pubkeyBytes, payload, signature);
    },

    // ── OID4VCI proof JWT (EdDSA, agent-side) ──────────────────────
    async mintOid4vciProofJwt(keypair, opts) {
      const signingKey = keypair.signingKeyBytes ?? keypair.signing_key_bytes;
      if (!signingKey) {
        throw new Error('mintOid4vciProofJwt: keypair must include signingKeyBytes');
      }
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      return wasm.mintOid4vciProofJwtEdDsa(
        signingKey,
        opts.holderDid,
        opts.audience,
        opts.cNonce,
        now,
      );
    },

    // ── DPoP / PoP JWT (agent steady-state auth) ───────────────────
    async mintAgentPopJwt(keypair, opts) {
      const signingKey = keypair.signingKeyBytes ?? keypair.signing_key_bytes;
      if (!signingKey) {
        throw new Error('mintAgentPopJwt: keypair must include signingKeyBytes');
      }
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      return wasm.mintPopJwt(
        signingKey,
        opts.agentDid,
        opts.httpMethod ?? opts.method,
        opts.httpUri ?? opts.uri,
        opts.accessToken ?? null,
        now,
      );
    },

    async verifyPopJwt(jwt, opts) {
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      try {
        const v = wasm.verifyPopJwt(
          jwt,
          opts.expectedMethod ?? opts.method,
          opts.expectedUri ?? opts.uri,
          opts.expectedAccessToken ?? null,
          now,
          opts.maxAgeSeconds ?? 60,
        );
        return { ok: true, agentDid: v.agentDid, jti: v.jti, htm: v.htm, htu: v.htu, iat: v.iat };
      } catch (err) {
        return { ok: false, error: String(err?.message ?? err) };
      }
    },

    // ── Agent VC verification ──────────────────────────────────────
    async verifyAgentVc(jws, opts) {
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      try {
        const verified = opts.humanDelegationPubkeyJwk
          ? wasm.verifyAgentVcWithHumanAuthorization(
              jws,
              opts.idpPubkeyJwk,
              opts.humanDelegationPubkeyJwk,
              now,
            )
          : wasm.verifyAgentVcOuter(jws, opts.idpPubkeyJwk, now);
        return {
          ok: true,
          claims: verified.claims,
          humanAuthorizationVerified: verified.humanAuthorizationVerified,
        };
      } catch (err) {
        return { ok: false, error: String(err?.message ?? err) };
      }
    },

    async verifyHumanAuthorization(jws, opts) {
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      try {
        const v = wasm.verifyHumanAuthorization(jws, opts.humanPubkeyJwk, now);
        return { ok: true, claims: v.claims };
      } catch (err) {
        return { ok: false, error: String(err?.message ?? err) };
      }
    },

    // ── Capability checks ──────────────────────────────────────────
    capabilityPermits(capability, resource, action) {
      return wasm.capabilityPermits(capability, resource, action);
    },
    capabilitiesPermits(capabilities, resource, action) {
      return wasm.capabilitiesPermits(capabilities, resource, action);
    },
    capabilityIsSubsetOf(child, parent) {
      return wasm.capabilityIsSubsetOf(child, parent);
    },
    capabilitiesIsSubsetOf(child, parent) {
      return wasm.capabilitiesIsSubsetOf(child, parent);
    },

    // ── Convenience wrappers matching the previous stub shape ──────
    async computeEd25519JwkThumbprint(jwk) {
      if (typeof jwk === 'object' && jwk?.x) {
        // OKP JWK → decode x → call the raw helper.
        const xBytes = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        return wasm.ed25519JwkThumbprint(new Uint8Array(xBytes));
      }
      throw new Error('computeEd25519JwkThumbprint: expected an OKP/Ed25519 JWK');
    },

    // Identity-derivation does not happen in this shim. The wallet
    // derives the agent's stable keypair (BIP85-rooted, slot-allocated
    // by the IdP) and seals the slot seed to a one-shot ECDH-P256
    // envelope key supplied by agent-provisioning.js. Anything that
    // calls `deriveFreshAgentKeypair` is on the old design and needs
    // to be migrated to the provisioning loop.
    async deriveFreshAgentKeypair() {
      throw new Error(
        'deriveFreshAgentKeypair is deprecated; use agent-provisioning.js — the wallet derives the agent keypair from the BIP85 tree.',
      );
    },
    async deriveSubAgentKeypair() {
      throw new Error(
        'deriveSubAgentKeypair is deprecated; sub-agents are enrolled via the parent agent calling /v1/oid4vci/agent-offer/sub.',
      );
    },
  };
  return cached;
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
