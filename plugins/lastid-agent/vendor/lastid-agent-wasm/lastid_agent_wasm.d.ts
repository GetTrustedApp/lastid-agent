/* tslint:disable */
/* eslint-disable */

/**
 * JS-shaped result of `agentKeypairFromSeed`.
 */
export class AgentKeypairJs {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly agentDid: string;
    readonly jwkThumbprint: string;
    readonly publicJwk: any;
    readonly signingKeyBytes: Uint8Array;
}

/**
 * JS-shaped result of agent-VC verification. The full claim
 * structure is returned as a JSON value for convenience; consumers
 * can pick what they need.
 */
export class VerifiedAgentVcJs {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Full `AgentVcClaims` payload as a plain JS object.
     */
    readonly claims: any;
    /**
     * True iff `verifyAgentVcWithHumanAuthorization` was called and
     * the embedded JWS verified against the human delegation key.
     */
    readonly humanAuthorizationVerified: boolean;
}

/**
 * JS-shaped result of `verifyHumanAuthorization`.
 */
export class VerifiedHumanAuthorizationJs {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly claims: any;
}

/**
 * JS-shaped result of [`js_verify_pop_jwt`].
 */
export class VerifiedPopJs {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly agentDid: string;
    readonly htm: string;
    readonly htu: string;
    readonly iat: bigint;
    readonly jti: string;
}

/**
 * Encode a raw Ed25519 public key (32 bytes) as a
 * `did:lastid:agent:` DID.
 */
export function agentDidFromPubkey(pubkey_bytes: Uint8Array): string;

/**
 * Derive an agent's stable Ed25519 keypair from a 32-byte seed.
 */
export function agentKeypairFromSeed(seed: Uint8Array): AgentKeypairJs;

/**
 * Is every `Capability` in `child` bounded by some `Capability` in
 * `parent`?
 */
export function capabilitiesIsSubsetOf(child_json: any, parent_json: any): boolean;

/**
 * Does any `Capability` in the given `Capabilities` bundle permit
 * `(resource, action)`?
 */
export function capabilitiesPermits(capabilities_json: any, resource: string, action: string): boolean;

/**
 * Is `child` a subset of `parent`? Used by sub-agent issuance to
 * validate the proposed sub-VC's capabilities never exceed parent's.
 */
export function capabilityIsSubsetOf(child_json: any, parent_json: any): boolean;

/**
 * Does the given `Capability` JSON permit `(resource, action)`?
 * `action` is the snake-case form: `read`, `write`, `list`, etc.
 * Constraint enforcement is the caller's job with full context.
 */
export function capabilityPermits(capability_json: any, resource: string, action: string): boolean;

/**
 * Compute the synthetic share_id the desktop uses for an
 * (agent_did, item_id) pair. Plugin uses this when POSTing
 * /v1/agent-use-approvals so the IdP row's share_id matches what
 * the desktop will check on retry — no JS-side string-template
 * drift between the two sides. Single source: `lastid_vc::decision_jws::compute_share_id`.
 */
export function computeShareId(agent_did: string, item_id: string): string;

/**
 * Derive a 32-byte slot seed from a 32-byte `ai_agent_seed`.
 */
export function deriveAgentSlotSeed(ai_agent_seed: Uint8Array, slot_index: number): Uint8Array;

/**
 * Derive a 32-byte sub-agent seed.
 */
export function deriveSubAgentSeed(parent_slot_seed: Uint8Array, class_slug: string, index: number): Uint8Array;

/**
 * Compute the RFC 7638 JWK thumbprint of a raw Ed25519 pubkey.
 */
export function ed25519JwkThumbprint(pubkey_bytes: Uint8Array): string;

/**
 * Initialize panic hook for readable error messages in Node /
 * browser consoles. Idempotent.
 */
export function init(): void;

/**
 * Mint an Ed25519 OID4VCI proof JWT. Called by the agent runtime
 * after the IdP returns a `c_nonce` from `POST /oauth/token`. The
 * signing key is the agent's stable identity key (derived via
 * `agentKeypairFromSeed`).
 *
 * Header: `{ "alg": "EdDSA", "typ": "openid4vci-proof+jwt",
 *            "jwk": { "kty":"OKP","crv":"Ed25519","x":"..." } }`
 * Payload: `{ "iss": holder_did, "aud": audience,
 *             "iat": now, "nonce": c_nonce }`
 */
export function mintOid4vciProofJwtEdDsa(signing_key_bytes: Uint8Array, holder_did: string, audience: string, c_nonce: string, now: bigint): string;

/**
 * Build a DPoP-shaped PoP JWT signed by the agent's Ed25519 key.
 * `access_token` is optional: pass `None` to skip the `ath` claim,
 * pass `Some(token)` to bind this PoP to a specific token.
 */
export function mintPopJwt(signing_key_bytes: Uint8Array, agent_did: string, http_method: string, http_uri: string, access_token: string | null | undefined, now: bigint): string;

/**
 * Parse a `did:lastid:agent:` DID and return the encoded
 * Ed25519 public key as 32 bytes.
 */
export function parseAgentDid(did: string): Uint8Array;

/**
 * Sign an arbitrary payload with an Ed25519 signing key. Returns the
 * raw 64-byte signature. The keypair this wraps is the agent's
 * stable identity keypair, derived earlier via
 * `agentKeypairFromSeed`. Use for the agent-side audit log signing
 * and any custom challenge protocols.
 */
export function signEd25519(signing_key_bytes: Uint8Array, payload: Uint8Array): Uint8Array;

/**
 * Sign a SessionFingerprint with the agent's Ed25519 signing key.
 * Plugin path: SessionStart hook builds the unsigned fingerprint
 * (session_id, agent_did, project, timestamps, optional
 * parent_session_id), passes it here, gets back the same object
 * with `signature` filled. The plugin then ships the signed
 * object in the body of `POST /session` on the desktop MCP
 * server.
 *
 * Input JS object shape (snake_case fields, matching the Rust
 * struct):
 *
 * ```ignore
 * {
 *   session_id: "uuid",
 *   agent_did: "did:lastid:agent:z...",
 *   project: {
 *     cwd_hash: "...",
 *     host_machine_id: "...",
 *     git_remote: "..." | null,
 *     head_commit_sha: "..." | null,
 *     package_root_hash: "..." | null,
 *   },
 *   started_at_ms: 1700000000000,
 *   signed_at_ms: 1700000000500,
 *   parent_session_id: null,
 *   signature: ""
 * }
 * ```
 */
export function signSessionFingerprint(signing_key_bytes: Uint8Array, fingerprint: any): any;

/**
 * Verify the outer SD-JWT VC signature only against the IdP's
 * P-256 verifying key. JWK shape: `{ kty:"EC", crv:"P-256",
 * x:"<b64url>", y:"<b64url>" }`.
 */
export function verifyAgentVcOuter(jws_compact: string, idp_pubkey_jwk: any, now: bigint): VerifiedAgentVcJs;

/**
 * Verify the outer agent VC AND the embedded `human_authorization`
 * JWS against the human's delegation P-256 pubkey. Checks all
 * binding fields (sub, parent_human_did, capabilities, may_delegate,
 * exp, agent_pubkey_jwk_thumb).
 */
export function verifyAgentVcWithHumanAuthorization(jws_compact: string, idp_pubkey_jwk: any, human_delegation_pubkey_jwk: any, now: bigint): VerifiedAgentVcJs;

/**
 * Verify an operator-signed decision JWS against the operator's
 * `delegation_authority` P-256 pubkey, then check the claims bind
 * to the expected (approval_id, parent_human_did, agent_did,
 * share_id) tuple. Returns the parsed claims on success; throws
 * with a precise reason on any failure (bad sig, wrong typ,
 * expired, future, bind mismatch).
 *
 * This is the plugin-side defense-in-depth check: even though the
 * desktop will re-verify the JWS authoritatively, having the
 * plugin verify before forwarding catches a poisoned IdP response
 * at the earliest possible point.
 *
 * `expected_parent_human_did` and `expected_agent_did` are
 * recommended to be passed as Option in JS as either a string or
 * `null` / undefined to skip that bind check; same for share_id.
 */
export function verifyDecisionJws(jws_compact: string, operator_jwk_x_b64u: string, operator_jwk_y_b64u: string, now_epoch_sec: bigint, expected_approval_id?: string | null, expected_parent_human_did?: string | null, expected_agent_did?: string | null, expected_share_id?: string | null): any;

/**
 * Verify a raw Ed25519 signature. Returns true on valid, false on
 * invalid (never throws for a structurally-correct but
 * cryptographically-wrong signature).
 */
export function verifyEd25519(pubkey_bytes: Uint8Array, payload: Uint8Array, signature_bytes: Uint8Array): boolean;

/**
 * Verify a standalone human-authorization JWS against the human's
 * delegation P-256 pubkey. Useful for consumers that have a
 * human_authorization string outside the context of an outer VC.
 */
export function verifyHumanAuthorization(jws_compact: string, human_pubkey_jwk: any, now: bigint): VerifiedHumanAuthorizationJs;

/**
 * Verify a DPoP-shaped PoP JWT. Pubkey is extracted from the `kid`
 * claim (which IS the agent's DID — no network resolution).
 */
export function verifyPopJwt(jwt: string, expected_method: string, expected_uri: string, expected_access_token: string | null | undefined, now: bigint, max_age_seconds: number): VerifiedPopJs;

/**
 * Verify a SessionFingerprint by reconstructing the Ed25519
 * verifying key from its `agent_did` field. Returns `true` on
 * valid; throws (a `JsError` with a precise reason) on any
 * failure. Useful on the desktop side and for integration tests
 * inside the plugin.
 */
export function verifySessionFingerprint(fingerprint: any): boolean;
