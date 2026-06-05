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
 *   mintOid4vciProofJwt(keypair, opts)      → compact JWT string
 *
 *   (mintAgentPopJwt was a P-256/ES256-only PoP minter — REMOVED. Use
 *   `mintDpopJwt` from `./dpop.js` instead: a KeyObject-driven dual-algo
 *   helper that picks EdDSA for Ed25519 agents and ES256 for P-256 ones.
 *   The old single-alg path was a regression for Ed25519 agents — the IdP
 *   rejected the ES256 proof with "header.alg must be 'EdDSA'…".)
 *   computeP256JwkThumbprint(jwk)           → base64url SHA-256 thumbprint
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
    p256JwkThumbprint(pubkeyBytes) {
      return wasm.p256JwkThumbprint(pubkeyBytes);
    },
    deriveAgentSlotSeed(aiAgentSeed, slotIndex) {
      return wasm.deriveAgentSlotSeed(aiAgentSeed, slotIndex);
    },
    deriveSubAgentSeed(parentSlotSeed, classSlug, index) {
      return wasm.deriveSubAgentSeed(parentSlotSeed, classSlug, index);
    },

    // ── Signing (P-256 / ES256) ────────────────────────────────────
    signP256(signingKeyBytes, payload) {
      return wasm.signP256(signingKeyBytes, payload);
    },
    verifyP256(pubkeyBytes, payload, signature) {
      return wasm.verifyP256(pubkeyBytes, payload, signature);
    },

    // ── Parent-authorization JWS (parent agent → sub-agent issuance) ──
    // Compact JWS signed with the parent's existing P-256 (ES256) agent
    // signing key. Used by the listener when it acts as issuer for an
    // operator-published sub-agent. Mirrors sign_human_authorization,
    // verified by the IdP against the parent's VC cnf.jwk.
    signParentAuthorization(signingKeyBytes, kid, claimsJson) {
      return wasm.signParentAuthorization(signingKeyBytes, kid ?? undefined, claimsJson);
    },

    // ── SessionFingerprint (agent-signed env claim) ────────────────
    // The wasm side canonicalizes via serde_json_canonicalizer (single
    // source of canonical bytes — no JS reimplementation, no drift).
    signSessionFingerprint(signingKeyBytes, fingerprint) {
      return wasm.signSessionFingerprint(signingKeyBytes, fingerprint);
    },
    verifySessionFingerprint(fingerprint) {
      return wasm.verifySessionFingerprint(fingerprint);
    },

    // ── Approval-decision JWS (operator-signed soft-deny outcome) ──
    // Single source of truth lives in lastid-vc/src/decision_jws.rs.
    // The plugin verifies before forwarding to the desktop as a
    // defense-in-depth check (desktop re-verifies authoritatively).
    verifyDecisionJws({
      jwsCompact,
      operatorJwkXB64u,
      operatorJwkYB64u,
      nowEpochSec,
      expectedApprovalId = null,
      expectedParentHumanDid = null,
      expectedAgentDid = null,
      expectedShareId = null,
    }) {
      return wasm.verifyDecisionJws(
        jwsCompact,
        operatorJwkXB64u,
        operatorJwkYB64u,
        BigInt(nowEpochSec),
        expectedApprovalId,
        expectedParentHumanDid,
        expectedAgentDid,
        expectedShareId,
      );
    },
    // Canonical (agent_did, item_id) → share_id mapping for the
    // policy-plane approval flow. The IdP, plugin, and desktop all
    // call into this so the bind check on retry never spuriously fails.
    computeShareId({ agentDid, itemId }) {
      return wasm.computeShareId(agentDid, itemId);
    },

    // ── OID4VCI proof JWT (ES256 / P-256, agent-side) ──────────────
    async mintOid4vciProofJwt(keypair, opts) {
      const signingKey = keypair.signingKeyBytes ?? keypair.signing_key_bytes;
      if (!signingKey) {
        throw new Error('mintOid4vciProofJwt: keypair must include signingKeyBytes');
      }
      const now = typeof opts.now === 'bigint' ? opts.now : BigInt(opts.now ?? Math.floor(Date.now() / 1000));
      return wasm.mintOid4vciProofJwtEs256(
        signingKey,
        opts.holderDid,
        opts.audience,
        opts.cNonce,
        now,
      );
    },

    // ── DPoP / PoP JWT (agent steady-state auth) ───────────────────
    // Minter intentionally removed — use `mintDpopJwt` from `./dpop.js`
    // (KeyObject-driven, dual-algo). Verification stays here because it
    // reconstructs the pubkey from the `kid` (the agent DID) and the WASM
    // verifier already handles both Ed25519 and P-256 paths.

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

    // ── Vault handle envelope (JIT credential delivery, agent side) ──
    // Mint an ephemeral handle keypair per vault-use; the public key goes to
    // the holder (IdP) to wrap the released credential to, the private key
    // stays in the listener's memory and opens the wrapped blob exactly once.
    genVaultHandleKeypair() {
      return JSON.parse(wasm.sdkGenVaultHandleKeypair());
    },
    // Open a handle-wrapped blob → the inner (still slot-sealed) bytes
    // (Uint8Array). Verifies handle_id; throws on a wrong key/id or tamper.
    openWithHandle(handleSecretSec1B64, handleId, sealedB64) {
      return wasm.sdkOpenWithHandle(handleSecretSec1B64, handleId, sealedB64);
    },

    // ── Convenience wrappers matching the previous stub shape ──────
    async computeP256JwkThumbprint(jwk) {
      const obj = jwk instanceof Map ? Object.fromEntries(jwk) : jwk;
      if (obj && typeof obj === 'object' && obj.x && obj.y) {
        // EC P-256 JWK → SEC1 uncompressed point (0x04 || X || Y) → raw helper.
        const x = Buffer.from(obj.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const y = Buffer.from(obj.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const sec1 = Buffer.concat([Buffer.from([0x04]), x, y]);
        return wasm.p256JwkThumbprint(new Uint8Array(sec1));
      }
      throw new Error('computeP256JwkThumbprint: expected an EC/P-256 JWK with x and y');
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

export async function mintOid4vciProofJwt(keypair, opts) {
  const sdk = await initializeSdkBindings();
  return sdk.mintOid4vciProofJwt(keypair, opts);
}

export async function computeP256JwkThumbprint(jwk) {
  const sdk = await initializeSdkBindings();
  return sdk.computeP256JwkThumbprint(jwk);
}

export async function genVaultHandleKeypair() {
  const sdk = await initializeSdkBindings();
  return sdk.genVaultHandleKeypair();
}

export async function openWithHandle(handleSecretSec1B64, handleId, sealedB64) {
  const sdk = await initializeSdkBindings();
  return sdk.openWithHandle(handleSecretSec1B64, handleId, sealedB64);
}
