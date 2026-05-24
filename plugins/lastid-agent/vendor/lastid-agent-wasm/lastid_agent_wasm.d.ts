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
 * Derive a LastID v2 identity profile from a mnemonic + master
 * password. Returns the public profile fields the UI needs —
 * `canonical_did`, `identity_id`, `base_id`, the root public keys
 * (P-256 + ML-DSA-65 hex-encoded). Secret seeds stay in the
 * returned struct's other fields and the caller can fish them out
 * of `__inner_seeds_DO_NOT_LOG` if they need to mint device keys
 * or sign; the JS layer should normally just keep the public
 * profile and let further crypto happen inside WASM.
 *
 * The master password is the same input mobile / desktop ask
 * for at signup — it salts the BIP39 → BIP85 root expansion via
 * the standard BIP39 passphrase mechanism (`bip39::Mnemonic::to_seed`),
 * so the same `(mnemonic, password)` pair produces the same
 * identity on every surface.
 */
export function deriveIdentityFromMnemonic(mnemonic_words: any, master_password: string): any;

/**
 * Derive a 32-byte sub-agent seed.
 */
export function deriveSubAgentSeed(parent_slot_seed: Uint8Array, class_slug: string, index: number): Uint8Array;

/**
 * Compute the RFC 7638 JWK thumbprint of a raw Ed25519 pubkey.
 */
export function ed25519JwkThumbprint(pubkey_bytes: Uint8Array): string;

/**
 * Generate a fresh 24-word BIP39 mnemonic using the browser's
 * `crypto.getRandomValues` (via `getrandom`'s `js` feature). Returns
 * the word list as a JS array of strings — display once with the
 * "save this, we cannot recover it" treatment. The entropy never
 * leaves the browser tab.
 *
 * Always 24 words (256 bits of entropy) — matches what
 * `lastid_core::crypto::operations::CryptoOperations::generate_mnemonic`
 * produces on native, so a phrase generated here can be re-typed
 * into the iOS / macOS / Android restore screen and recover the
 * same identity.
 */
export function generateMnemonic(): any;

/**
 * Encrypt a mnemonic + render an iOS / macOS / Android-scannable
 * recovery QR. Output struct fields:
 *
 *   `qr_image_b64` — SVG QR code, base64 of UTF-8 SVG bytes. Drop
 *                    into `<img src="data:image/svg+xml;base64,…">`.
 *   `qr_data_b64`  — base64-encoded bincode of `QRRecoveryData`
 *                    (the actual scanned payload). The QR image
 *                    above encodes exactly this string.
 *   `instructions` — human-facing "save this in a password manager
 *                    or print it" string.
 *
 * The `master_password` argument is required — it's the same
 * passphrase the operator will type into the iOS LastID app when
 * restoring (PBKDF2-HMAC-SHA256 → AES-256-GCM key derivation,
 * 100k iterations). Without it, the QR cannot be decrypted on any
 * surface, including this one.
 */
export function generateRecoveryQr(mnemonic_words: any, master_password: string): any;

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
 * Approve an agent provisioning request — full slot-aware flow.
 *
 * **NOT YET IMPLEMENTED.** Implementing this requires unsealing
 * the operator's `SeedBundle` from IndexedDB to recover
 * `ai_agent_seed` + `delegation_authority_seed`. The seal is
 * ECDH-P256-bound to the WebAuthn device key, and the native
 * `PlatformKeyResolver` uses `tokio::task::block_in_place` to
 * bridge sync `KeyResolver::ecdh` into async
 * `platform_security.perform_raw_ecdh` — that doesn't exist on
 * wasm32 (single-threaded, no multi-thread tokio runtime).
 *
 * Next-turn work is to add an async unseal path in
 * `lastid-envelope` (`open_seed_bundle_async`) that pre-computes
 * the ECDH shared secrets via the async platform call BEFORE
 * invoking the sync envelope decryptor with a precomputed
 * resolver. Once that lands, the body of this function:
 *   1. Loads sealed SeedBundle from IndexedDB
 *   2. Async-unseals via webcrypto-backed resolver
 *   3. Reads `ai_agent_seed` + `delegation_authority_seed`
 *   4. GETs `/next-slot`
 *   5. Derives slot keypair via `derive_agent_slot_seed`
 *   6. Seals slot_seed to the ephemeral recipient via
 *      `lastid_envelope::envelope_encrypt`
 *   7. Builds + signs the `human_authorization` JWS via
 *      `sign_human_authorization`
 *   8. POSTs `/complete` with the envelope-and-JWS bundle
 *   9. Returns `{ agent_did, slot_index, offer_id }` to JS
 *
 * Surfaces a structured error JS can route on.
 */
export function sdkApproveAgentProvisioning(user_code: string, idp_url: string, capabilities_json: any, may_delegate: boolean, exp_secs: bigint): Promise<any>;

export function sdkAuditEmit(input: any): Promise<any>;

export function sdkAuditList(limit?: number | null): Promise<any>;

export function sdkAuditVerifyChain(): Promise<any>;

/**
 * Generic authenticated REST call to the IdP.
 *
 * Mirrors the per-endpoint helpers (`sdkFetchAgentProvisioningPending`,
 * `sdkDenyAgentProvisioning`, etc.) but takes the method + path
 * + body from JS so the browser-side MLS dock can hit any
 * `/v1/*` route without us shipping a new wasm export per
 * endpoint. Auth posture is identical: at-rest unlock → Base
 * credential → ApiClient with WebCrypto platform_security →
 * `Authorization: DPoP <token>` + `DPoP: <proof>` headers via
 * `send_v2_request`.
 *
 * `path` is a /v1/-prefixed string ("/v1/mls/keypackages/..."),
 * resolved against `idp_url`. `method` is upper-case GET / POST
 * / PUT / DELETE / PATCH. `body_json` is the request body shape
 * JS wants serialized as JSON; pass `JsValue::NULL` for GET /
 * DELETE with no body.
 *
 * Returns the parsed JSON response body (or `{}` for empty 2xx
 * responses). Non-2xx responses throw an Error whose message
 * includes the status code + raw body, so JS can branch on the
 * IdP's structured error envelope.
 */
export function sdkAuthedFetch(method: string, path: string, body_json: any, idp_url: string): Promise<any>;

/**
 * Build the URL + subprotocol list the browser needs to open an
 * authenticated WebSocket to `<idp_url>/v1/ws`.
 *
 * The browser `WebSocket` API does not let JS set `Authorization`
 * or `DPoP` headers on the upgrade — see
 * `lastid-idp/src/api/websocket/handlers/subprotocol-auth.ts` for
 * the full rationale. Native clients (tungstenite) attach those
 * headers directly. For the browser console we smuggle them in
 * `Sec-WebSocket-Protocol`:
 *
 *   new WebSocket(wsUrl, subprotocols);
 *
 * `subprotocols` is the array this function returns:
 *
 *   [
 *     "lastid.v1",                          // contractual real protocol — echoed back by server
 *     "lastid.bearer.<DPoP-bound access_token>",
 *     "lastid.dpop.<single-use DPoP proof JWT>",
 *   ]
 *
 * This function reuses the same `ApiClient::build_v2_rest_headers`
 * path the native SDK uses for every authenticated REST call,
 * so the bearer + DPoP proof shape is byte-identical to what
 * tungstenite would have produced — no parallel auth code path.
 *
 * The returned bundle must be used immediately. The DPoP proof
 * is single-use (the server tracks `jti` against replay) and
 * the access_token, while longer-lived (5min cache), should be
 * re-minted on each `connect` so reconnection picks up a fresh
 * nonce. JS should call this from inside the connect step, not
 * cache the returned object across reconnects.
 *
 * Pops a WebAuthn assertion only if the session cache is empty
 * (cold start) — within a session the wrap-key cache makes this
 * silent.
 */
export function sdkBuildWebSocketAuth(idp_url: string): Promise<any>;

/**
 * Browser-side wrapper for the canonical V2 OID4VCI credential
 * claim. Calls `lastid_identity::v2_claim::do_claim_credential_v2_in`
 * — same Rust path the native FRB wallets reach. Reads the
 * already-minted V2 identity profile from IndexedDB, signs the
 * device-auth + proof JWTs with the hardware-backed device key,
 * completes the full OID4VCI dance with the IdP (offer, token,
 * credential request, SD-JWT verification), and persists the
 * issued credential via the WebAuthn-PRF-keyed
 * IndexedDbCredentialStorage.
 *
 * `credential_type_str` is the VC type ("Base" / "Persona" /
 * "VerifiedEmail" etc) — the wasm-bindgen layer matches it to
 * the `CredentialType` enum. `params_json` is an optional JSON
 * object the IdP forwards into the credential-request payload
 * (persona_id for Persona claims, peer_did for trust-level
 * claims, etc).
 */
export function sdkClaimCredential(credential_type_str: string, params_json: any): Promise<any>;

/**
 * Browser-side wrapper around `lastid_identity::v2_signup::do_create_identity_v2_in`.
 *
 * Constructs the browser's three trait-object dependencies —
 * `IndexedDbStorage` (KeyValueStorage), `WebCryptoPlatformSecurity`
 * (PlatformSecurity), and an in-memory `AuditSystem` — then calls
 * the canonical Rust orchestrator FRB+native already share. Same
 * 14-step v2 create flow (mnemonic + BIP85 tree + device key +
 * attestation challenge + 5 subsystem seeds + sealed SeedBundle
 * + audit emission); same `CreateIdentityResult` JSON shape; same
 * IndexedDB-persisted state that subsequent sign-ins read back.
 *
 * Returns a `JsValue` carrying the serialized `CreateIdentityResult`
 * (matches the FRB-exposed shape from the native wallets). On
 * errors returns a `JsError` whose message starts with the
 * `IdentityError` variant so the console can surface specific
 * failure modes ("attestation missing", "identity already exists",
 * etc.) to the operator.
 *
 * Note: the device-key generation path is gated behind the
 * `WebCryptoPlatformSecurity` impl, which today returns
 * `OperationNotSupported` until the WebAuthn impl lands in
 * sub-commit F. End-to-end `js_sdk_create_identity` will not
 * produce a working identity until F lands; this export wires the
 * orchestrator + storage + audit so F is a one-file change.
 */
export function sdkCreateIdentity(password: string, use_biometrics: boolean): Promise<any>;

/**
 * POST `/v1/oid4vci/agent-provision/deny` with a reason. Used by
 * the approve page's Deny button. Caller must already have
 * fetched `/pending` (which attached the row to their DID) — the
 * IdP enforces the same DID match here.
 */
export function sdkDenyAgentProvisioning(user_code: string, reason: string, idp_url: string): Promise<any>;

/**
 * GET `/v1/oid4vci/agent-provision/pending/:user_code` with the
 * operator's authenticated session.
 *
 * First authenticated read also triggers the IdP's atomic
 * `attachParentHumanDid` step (see
 * `lastid-idp/src/services/agent/agent-provisioning-store.ts`).
 * The IdP binds the operator's canonical DID to the pending row
 * at this point — OAuth device-code semantics where the user_code
 * is the unforgeable secret and possession + authenticated session
 * is the binding act.
 *
 * Returns the pending row's serialized JSON shape:
 *
 *   {
 *     user_code,
 *     ephemeral_pubkey_jwk,     // recipient for the sealed slot seed
 *     runtime_name,
 *     project_hint,             // may be null
 *     parent_human_did,         // post-attach this is the caller's DID
 *   }
 *
 * Surfaces clean errors on the two failure cases the browser
 * approve page renders distinctly:
 *   - 412 `delegation_authority_not_registered` — caller hasn't
 *     registered their delegation_authority pubkey yet
 *   - 403 — pending row already attached to a different operator
 */
export function sdkFetchAgentProvisioningPending(user_code: string, idp_url: string): Promise<any>;

/**
 * Settings → "Recovery QR" view. Reads the persisted
 * `QRRecoveryData` blob the signup orchestrator stored under
 * `qr_recovery_data_<master_id>`, regenerates the SVG-encoded
 * QR image, and returns it alongside the base64 payload
 * (suitable for "copy to clipboard" + "download .png") and
 * the customer-friendly backup instructions.
 *
 * No WebAuthn prompt — the QR is stored as a canonical
 * recovery artifact, not behind operator presence (the
 * payload is encrypted with the operator's master password
 * already, so unwrapping the IndexedDB envelope adds nothing).
 *
 * Returns `{ qr_recovery_image, qr_recovery_data, qr_backup_instructions }`.
 * Returns `null` if no QR has been minted yet (signup didn't
 * complete or this is a fresh browser without a v2 identity).
 */
export function sdkGetRecoveryQr(master_id: string): Promise<any>;

/**
 * Read the persisted V2 identity profile from IndexedDB and
 * return it as a plain JS object. No WebAuthn prompt — the
 * profile is the public identity descriptor (canonical_did,
 * identity_id, base_id, root public keys), not secret
 * material, so unwrapping it doesn't need operator presence.
 * Mobile / desktop wallets call the equivalent foundation
 * method `get_v2_identity_profile_json` for the same purpose.
 *
 * Returns `null` if no profile exists yet (fresh browser, no
 * signup completed). Callers should treat `null` as "no
 * identity in this origin" and route to signup, the same way
 * `sdkHasV2DeviceKey` is treated.
 *
 * Used by:
 *   - MLS prekey persistence: the dock needs the operator's
 *     `canonical_did` to scope IDB mls_kv rows per-human so
 *     two different operators in the same browser don't
 *     collide on KeyPackage privates / group state. Without
 *     this the dock falls back to a placeholder DID; reads
 *     written under the placeholder are stranded if the real
 *     DID later becomes available.
 *   - Audit chain authoring: the chain's `master_identity_id`
 *     field is the identity_id from this profile.
 *   - Settings page: surfaces the canonical_did for the
 *     operator-visible identity card.
 */
export function sdkGetV2IdentityProfile(): Promise<any>;

/**
 * True iff a V2 device key with WebAuthn-backed PQ operational
 * signing has been provisioned in this origin's IndexedDB.
 * Drives the login-vs-signup decision in the browser console.
 */
export function sdkHasV2DeviceKey(key_id: string): Promise<boolean>;

/**
 * Return-visit login: WebAuthn assertion against the existing
 * V2 device-key credential → recovers the PRF output →
 * at-rest wrap key is cached on a fresh
 * `WebCryptoPlatformSecurity` session. Returns the persisted
 * V2 identity info + list of credentials the operator holds.
 *
 * One biometric prompt: the WebAuthn assertion that unlocks
 * the session. After this resolves the operator is logged in;
 * `sdkClaimCredential` for a refresh works without an
 * additional prompt (the cached wrap key flows through).
 *
 * Errors:
 *   - `no v2 device key for id …` — caller should route to
 *     signup instead of login.
 *   - WebAuthn assertion cancelled / declined by operator —
 *     returned with the underlying authenticator error.
 */
export function sdkLogin(): Promise<any>;

/**
 * Return the persisted ML-DSA-65 public key for `key_id` (1952
 * bytes). Operator-side audit chain consumers + verifiers fetch
 * this to validate signatures produced by `sdkSignWithPqDeviceKey`.
 */
export function sdkMldsaPublicKey(key_id: string): Promise<Uint8Array>;

/**
 * Register the operator's `delegation_authority` public key with
 * the IdP. Must be called once after signup before any agent can
 * be provisioned — the IdP's `/v1/oid4vci/agent-provision/pending`
 * attach step refuses to bind a row to a human DID unless that
 * DID has a registered DA pubkey, because the `human_authorization`
 * JWS that authorizes the agent VC has nothing to verify against
 * otherwise.
 *
 * Endpoint is upsert-safe — calling it twice with the same JWK
 * is idempotent, and re-registering with a different JWK rotates
 * the trust anchor for subsequent provisions.
 */
export function sdkRegisterDelegationAuthority(idp_url: string): Promise<any>;

/**
 * Sign `data` with the ML-DSA-65 operational key bound to
 * `key_id`. Pops one WebAuthn assertion (operator presence) to
 * recover the PRF output, unwraps the at-rest-encrypted secret,
 * and signs in-WASM. Returns a 3293-byte ML-DSA-65 signature.
 *
 * This is the PQ-default sign path matching the native V2 wallets'
 * ML-DSA-65 default. Verifiers consume the signature alongside
 * the ML-DSA public key returned by `sdkMldsaPublicKey`.
 */
export function sdkSignWithPqDeviceKey(key_id: string, data: Uint8Array): Promise<Uint8Array>;

/**
 * Browser-side wrapper for the full v2 signup flow — composes
 * `do_create_identity_v2_in` + `do_create_persona_v2_in` in one
 * wasm call. Browser console invokes once on operator click and
 * gets back both the freshly-minted identity (with 24-word
 * mnemonic) and the persona record bound to it. Same canonical
 * orchestrators the native FRB wallets reach.
 *
 * `persona_json` is a JSON-serialized `lastid_core::types::Persona`
 * object. The browser console builds the minimal subset
 * (persona_type + persona_name + optional contact fields) and
 * the orchestrator stamps in the id + identity binding +
 * timestamps.
 */
export function sdkSignup(password: string, use_biometrics: boolean, persona_json: any, idp_url: string): Promise<any>;

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
