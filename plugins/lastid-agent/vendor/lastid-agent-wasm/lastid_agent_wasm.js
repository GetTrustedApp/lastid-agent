/* @ts-self-types="./lastid_agent_wasm.d.ts" */

/**
 * JS-shaped result of `agentKeypairFromSeed`.
 */
class AgentKeypairJs {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(AgentKeypairJs.prototype);
        obj.__wbg_ptr = ptr;
        AgentKeypairJsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AgentKeypairJsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_agentkeypairjs_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get agentDid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.agentkeypairjs_agentDid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get jwkThumbprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.agentkeypairjs_jwkThumbprint(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {any}
     */
    get publicJwk() {
        const ret = wasm.agentkeypairjs_publicJwk(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    get signingKeyBytes() {
        const ret = wasm.agentkeypairjs_signingKeyBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) AgentKeypairJs.prototype[Symbol.dispose] = AgentKeypairJs.prototype.free;
exports.AgentKeypairJs = AgentKeypairJs;

/**
 * JS-shaped result of agent-VC verification. The full claim
 * structure is returned as a JSON value for convenience; consumers
 * can pick what they need.
 */
class VerifiedAgentVcJs {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(VerifiedAgentVcJs.prototype);
        obj.__wbg_ptr = ptr;
        VerifiedAgentVcJsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifiedAgentVcJsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifiedagentvcjs_free(ptr, 0);
    }
    /**
     * Full `AgentVcClaims` payload as a plain JS object.
     * @returns {any}
     */
    get claims() {
        const ret = wasm.verifiedagentvcjs_claims(this.__wbg_ptr);
        return ret;
    }
    /**
     * True iff `verifyAgentVcWithHumanAuthorization` was called and
     * the embedded JWS verified against the human delegation key.
     * @returns {boolean}
     */
    get humanAuthorizationVerified() {
        const ret = wasm.verifiedagentvcjs_humanAuthorizationVerified(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) VerifiedAgentVcJs.prototype[Symbol.dispose] = VerifiedAgentVcJs.prototype.free;
exports.VerifiedAgentVcJs = VerifiedAgentVcJs;

/**
 * JS-shaped result of `verifyHumanAuthorization`.
 */
class VerifiedHumanAuthorizationJs {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(VerifiedHumanAuthorizationJs.prototype);
        obj.__wbg_ptr = ptr;
        VerifiedHumanAuthorizationJsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifiedHumanAuthorizationJsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifiedhumanauthorizationjs_free(ptr, 0);
    }
    /**
     * @returns {any}
     */
    get claims() {
        const ret = wasm.verifiedhumanauthorizationjs_claims(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) VerifiedHumanAuthorizationJs.prototype[Symbol.dispose] = VerifiedHumanAuthorizationJs.prototype.free;
exports.VerifiedHumanAuthorizationJs = VerifiedHumanAuthorizationJs;

/**
 * JS-shaped result of [`js_verify_pop_jwt`].
 */
class VerifiedPopJs {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(VerifiedPopJs.prototype);
        obj.__wbg_ptr = ptr;
        VerifiedPopJsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifiedPopJsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifiedpopjs_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get agentDid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedpopjs_agentDid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get htm() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedpopjs_htm(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get htu() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedpopjs_htu(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {bigint}
     */
    get iat() {
        const ret = wasm.verifiedpopjs_iat(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string}
     */
    get jti() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedpopjs_jti(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) VerifiedPopJs.prototype[Symbol.dispose] = VerifiedPopJs.prototype.free;
exports.VerifiedPopJs = VerifiedPopJs;

/**
 * Encode a raw Ed25519 public key (32 bytes) as a
 * `did:lastid:agent:` DID.
 * @param {Uint8Array} pubkey_bytes
 * @returns {string}
 */
function agentDidFromPubkey(pubkey_bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(pubkey_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.agentDidFromPubkey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.agentDidFromPubkey = agentDidFromPubkey;

/**
 * Derive an agent's stable Ed25519 keypair from a 32-byte seed.
 * @param {Uint8Array} seed
 * @returns {AgentKeypairJs}
 */
function agentKeypairFromSeed(seed) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.agentKeypairFromSeed(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AgentKeypairJs.__wrap(ret[0]);
}
exports.agentKeypairFromSeed = agentKeypairFromSeed;

/**
 * Is every `Capability` in `child` bounded by some `Capability` in
 * `parent`?
 * @param {any} child_json
 * @param {any} parent_json
 * @returns {boolean}
 */
function capabilitiesIsSubsetOf(child_json, parent_json) {
    const ret = wasm.capabilitiesIsSubsetOf(child_json, parent_json);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.capabilitiesIsSubsetOf = capabilitiesIsSubsetOf;

/**
 * Does any `Capability` in the given `Capabilities` bundle permit
 * `(resource, action)`?
 * @param {any} capabilities_json
 * @param {string} resource
 * @param {string} action
 * @returns {boolean}
 */
function capabilitiesPermits(capabilities_json, resource, action) {
    const ptr0 = passStringToWasm0(resource, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(action, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.capabilitiesPermits(capabilities_json, ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.capabilitiesPermits = capabilitiesPermits;

/**
 * Is `child` a subset of `parent`? Used by sub-agent issuance to
 * validate the proposed sub-VC's capabilities never exceed parent's.
 * @param {any} child_json
 * @param {any} parent_json
 * @returns {boolean}
 */
function capabilityIsSubsetOf(child_json, parent_json) {
    const ret = wasm.capabilityIsSubsetOf(child_json, parent_json);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.capabilityIsSubsetOf = capabilityIsSubsetOf;

/**
 * Does the given `Capability` JSON permit `(resource, action)`?
 * `action` is the snake-case form: `read`, `write`, `list`, etc.
 * Constraint enforcement is the caller's job with full context.
 * @param {any} capability_json
 * @param {string} resource
 * @param {string} action
 * @returns {boolean}
 */
function capabilityPermits(capability_json, resource, action) {
    const ptr0 = passStringToWasm0(resource, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(action, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.capabilityPermits(capability_json, ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.capabilityPermits = capabilityPermits;

/**
 * Compute the synthetic share_id the desktop uses for an
 * (agent_did, item_id) pair. Plugin uses this when POSTing
 * /v1/agent-use-approvals so the IdP row's share_id matches what
 * the desktop will check on retry — no JS-side string-template
 * drift between the two sides. Single source: `lastid_vc::decision_jws::compute_share_id`.
 * @param {string} agent_did
 * @param {string} item_id
 * @returns {string}
 */
function computeShareId(agent_did, item_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(agent_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(item_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.computeShareId(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.computeShareId = computeShareId;

/**
 * Derive a 32-byte slot seed from a 32-byte `ai_agent_seed`.
 * @param {Uint8Array} ai_agent_seed
 * @param {number} slot_index
 * @returns {Uint8Array}
 */
function deriveAgentSlotSeed(ai_agent_seed, slot_index) {
    const ptr0 = passArray8ToWasm0(ai_agent_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deriveAgentSlotSeed(ptr0, len0, slot_index);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}
exports.deriveAgentSlotSeed = deriveAgentSlotSeed;

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
 * @param {any} mnemonic_words
 * @param {string} master_password
 * @returns {any}
 */
function deriveIdentityFromMnemonic(mnemonic_words, master_password) {
    const ptr0 = passStringToWasm0(master_password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deriveIdentityFromMnemonic(mnemonic_words, ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.deriveIdentityFromMnemonic = deriveIdentityFromMnemonic;

/**
 * Derive a 32-byte sub-agent seed.
 * @param {Uint8Array} parent_slot_seed
 * @param {string} class_slug
 * @param {number} index
 * @returns {Uint8Array}
 */
function deriveSubAgentSeed(parent_slot_seed, class_slug, index) {
    const ptr0 = passArray8ToWasm0(parent_slot_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(class_slug, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.deriveSubAgentSeed(ptr0, len0, ptr1, len1, index);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}
exports.deriveSubAgentSeed = deriveSubAgentSeed;

/**
 * Compute the RFC 7638 JWK thumbprint of a raw Ed25519 pubkey.
 * @param {Uint8Array} pubkey_bytes
 * @returns {string}
 */
function ed25519JwkThumbprint(pubkey_bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(pubkey_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.ed25519JwkThumbprint(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.ed25519JwkThumbprint = ed25519JwkThumbprint;

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
 * @returns {any}
 */
function generateMnemonic() {
    const ret = wasm.generateMnemonic();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.generateMnemonic = generateMnemonic;

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
 * @param {any} mnemonic_words
 * @param {string} master_password
 * @returns {any}
 */
function generateRecoveryQr(mnemonic_words, master_password) {
    const ptr0 = passStringToWasm0(master_password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generateRecoveryQr(mnemonic_words, ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.generateRecoveryQr = generateRecoveryQr;

/**
 * Initialize panic hook for readable error messages in Node /
 * browser consoles. Idempotent.
 */
function init() {
    wasm.init();
}
exports.init = init;

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
 * @param {Uint8Array} signing_key_bytes
 * @param {string} holder_did
 * @param {string} audience
 * @param {string} c_nonce
 * @param {bigint} now
 * @returns {string}
 */
function mintOid4vciProofJwtEdDsa(signing_key_bytes, holder_did, audience, c_nonce, now) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passArray8ToWasm0(signing_key_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(holder_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(audience, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(c_nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.mintOid4vciProofJwtEdDsa(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, now);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}
exports.mintOid4vciProofJwtEdDsa = mintOid4vciProofJwtEdDsa;

/**
 * Build a DPoP-shaped PoP JWT signed by the agent's Ed25519 key.
 * `access_token` is optional: pass `None` to skip the `ath` claim,
 * pass `Some(token)` to bind this PoP to a specific token.
 * @param {Uint8Array} signing_key_bytes
 * @param {string} agent_did
 * @param {string} http_method
 * @param {string} http_uri
 * @param {string | null | undefined} access_token
 * @param {bigint} now
 * @returns {string}
 */
function mintPopJwt(signing_key_bytes, agent_did, http_method, http_uri, access_token, now) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passArray8ToWasm0(signing_key_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(agent_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(http_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(http_uri, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(access_token) ? 0 : passStringToWasm0(access_token, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.mintPopJwt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, now);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}
exports.mintPopJwt = mintPopJwt;

/**
 * Parse a `did:lastid:agent:` DID and return the encoded
 * Ed25519 public key as 32 bytes.
 * @param {string} did
 * @returns {Uint8Array}
 */
function parseAgentDid(did) {
    const ptr0 = passStringToWasm0(did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parseAgentDid(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}
exports.parseAgentDid = parseAgentDid;

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
 * @param {string} user_code
 * @param {string} idp_url
 * @param {any} capabilities_json
 * @param {boolean} may_delegate
 * @param {bigint} exp_secs
 * @returns {Promise<any>}
 */
function sdkApproveAgentProvisioning(user_code, idp_url, capabilities_json, may_delegate, exp_secs) {
    const ptr0 = passStringToWasm0(user_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkApproveAgentProvisioning(ptr0, len0, ptr1, len1, capabilities_json, may_delegate, exp_secs);
    return ret;
}
exports.sdkApproveAgentProvisioning = sdkApproveAgentProvisioning;

/**
 * @param {any} input
 * @returns {Promise<any>}
 */
function sdkAuditEmit(input) {
    const ret = wasm.sdkAuditEmit(input);
    return ret;
}
exports.sdkAuditEmit = sdkAuditEmit;

/**
 * @param {number | null} [limit]
 * @returns {Promise<any>}
 */
function sdkAuditList(limit) {
    const ret = wasm.sdkAuditList(isLikeNone(limit) ? 0x100000001 : (limit) >>> 0);
    return ret;
}
exports.sdkAuditList = sdkAuditList;

/**
 * @returns {Promise<any>}
 */
function sdkAuditVerifyChain() {
    const ret = wasm.sdkAuditVerifyChain();
    return ret;
}
exports.sdkAuditVerifyChain = sdkAuditVerifyChain;

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
 * @param {string} method
 * @param {string} path
 * @param {any} body_json
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkAuthedFetch(method, path, body_json, idp_url) {
    const ptr0 = passStringToWasm0(method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sdkAuthedFetch(ptr0, len0, ptr1, len1, body_json, ptr2, len2);
    return ret;
}
exports.sdkAuthedFetch = sdkAuthedFetch;

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
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkBuildWebSocketAuth(idp_url) {
    const ptr0 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkBuildWebSocketAuth(ptr0, len0);
    return ret;
}
exports.sdkBuildWebSocketAuth = sdkBuildWebSocketAuth;

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
 * @param {string} credential_type_str
 * @param {any} params_json
 * @returns {Promise<any>}
 */
function sdkClaimCredential(credential_type_str, params_json) {
    const ptr0 = passStringToWasm0(credential_type_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkClaimCredential(ptr0, len0, params_json);
    return ret;
}
exports.sdkClaimCredential = sdkClaimCredential;

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
 * @param {string} password
 * @param {boolean} use_biometrics
 * @returns {Promise<any>}
 */
function sdkCreateIdentity(password, use_biometrics) {
    const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkCreateIdentity(ptr0, len0, use_biometrics);
    return ret;
}
exports.sdkCreateIdentity = sdkCreateIdentity;

/**
 * Decrypt an agent-state content envelope (base64 LIDE SymmetricOnly)
 * for the agent at `slot_index`, returning the plaintext content bytes.
 * Operator-side read-back: lets the console show + edit the rules it
 * authored (the operator can derive any of its agents' slot_seeds). The
 * slot_seed is derived in-WASM and never crosses into JS.
 * @param {number} slot_index
 * @param {string} enc_b64
 * @returns {Promise<Uint8Array>}
 */
function sdkDecryptAgentContentForSlot(slot_index, enc_b64) {
    const ptr0 = passStringToWasm0(enc_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkDecryptAgentContentForSlot(slot_index, ptr0, len0);
    return ret;
}
exports.sdkDecryptAgentContentForSlot = sdkDecryptAgentContentForSlot;

/**
 * POST `/v1/oid4vci/agent-provision/deny` with a reason. Used by
 * the approve page's Deny button. Caller must already have
 * fetched `/pending` (which attached the row to their DID) — the
 * IdP enforces the same DID match here.
 * @param {string} user_code
 * @param {string} reason
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkDenyAgentProvisioning(user_code, reason, idp_url) {
    const ptr0 = passStringToWasm0(user_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(reason, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sdkDenyAgentProvisioning(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}
exports.sdkDenyAgentProvisioning = sdkDenyAgentProvisioning;

/**
 * Encrypt a rule/memory record for the agent at `slot_index`. Returns a
 * base64 LIDE SymmetricOnly envelope the agent decrypts with its slot_seed.
 * @param {number} slot_index
 * @param {Uint8Array} content
 * @returns {Promise<string>}
 */
function sdkEncryptAgentContentForSlot(slot_index, content) {
    const ptr0 = passArray8ToWasm0(content, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkEncryptAgentContentForSlot(slot_index, ptr0, len0);
    return ret;
}
exports.sdkEncryptAgentContentForSlot = sdkEncryptAgentContentForSlot;

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
 * @param {string} user_code
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkFetchAgentProvisioningPending(user_code, idp_url) {
    const ptr0 = passStringToWasm0(user_code, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkFetchAgentProvisioningPending(ptr0, len0, ptr1, len1);
    return ret;
}
exports.sdkFetchAgentProvisioningPending = sdkFetchAgentProvisioningPending;

/**
 * Load the full message-array JSON for a conversation. Returns
 * `null` when nothing has been persisted yet.
 * @param {string} conversation_id
 * @returns {Promise<any>}
 */
function sdkGetChatThread(conversation_id) {
    const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkGetChatThread(ptr0, len0);
    return ret;
}
exports.sdkGetChatThread = sdkGetChatThread;

/**
 * Get a single conversation record by id. `null` when absent.
 * @param {string} conversation_id
 * @returns {Promise<any>}
 */
function sdkGetConversation(conversation_id) {
    const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkGetConversation(ptr0, len0);
    return ret;
}
exports.sdkGetConversation = sdkGetConversation;

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
 * @param {string} master_id
 * @returns {Promise<any>}
 */
function sdkGetRecoveryQr(master_id) {
    const ptr0 = passStringToWasm0(master_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkGetRecoveryQr(ptr0, len0);
    return ret;
}
exports.sdkGetRecoveryQr = sdkGetRecoveryQr;

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
 * @returns {Promise<any>}
 */
function sdkGetV2IdentityProfile() {
    const ret = wasm.sdkGetV2IdentityProfile();
    return ret;
}
exports.sdkGetV2IdentityProfile = sdkGetV2IdentityProfile;

/**
 * True iff a V2 device key with WebAuthn-backed PQ operational
 * signing has been provisioned in this origin's IndexedDB.
 * Drives the login-vs-signup decision in the browser console.
 * @param {string} key_id
 * @returns {Promise<boolean>}
 */
function sdkHasV2DeviceKey(key_id) {
    const ptr0 = passStringToWasm0(key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkHasV2DeviceKey(ptr0, len0);
    return ret;
}
exports.sdkHasV2DeviceKey = sdkHasV2DeviceKey;

/**
 * List every conversation record as a JSON array string. The
 * console renders this as the conversation list (parity with
 * the native `sdkGetGroupConversations`).
 * @returns {Promise<string>}
 */
function sdkListConversations() {
    const ret = wasm.sdkListConversations();
    return ret;
}
exports.sdkListConversations = sdkListConversations;

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
 * @returns {Promise<any>}
 */
function sdkLogin() {
    const ret = wasm.sdkLogin();
    return ret;
}
exports.sdkLogin = sdkLogin;

/**
 * Return the persisted ML-DSA-65 public key for `key_id` (1952
 * bytes). Operator-side audit chain consumers + verifiers fetch
 * this to validate signatures produced by `sdkSignWithPqDeviceKey`.
 * @param {string} key_id
 * @returns {Promise<Uint8Array>}
 */
function sdkMldsaPublicKey(key_id) {
    const ptr0 = passStringToWasm0(key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkMldsaPublicKey(ptr0, len0);
    return ret;
}
exports.sdkMldsaPublicKey = sdkMldsaPublicKey;

/**
 * Persist the full message-array JSON for a conversation
 * (sealed). The caller passes the complete array; this
 * overwrites the prior blob.
 * @param {string} conversation_id
 * @param {string} messages_json
 * @returns {Promise<void>}
 */
function sdkPutChatThread(conversation_id, messages_json) {
    const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(messages_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkPutChatThread(ptr0, len0, ptr1, len1);
    return ret;
}
exports.sdkPutChatThread = sdkPutChatThread;

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
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkRegisterDelegationAuthority(idp_url) {
    const ptr0 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkRegisterDelegationAuthority(ptr0, len0);
    return ret;
}
exports.sdkRegisterDelegationAuthority = sdkRegisterDelegationAuthority;

/**
 * Sign an agent-state record (rule/memory) with the operator's
 * delegation_authority. Returns a compact JWS the agent verifies before
 * applying. `record_json` is the canonical record object.
 * @param {any} record_json
 * @returns {Promise<string>}
 */
function sdkSignAgentStateRecord(record_json) {
    const ret = wasm.sdkSignAgentStateRecord(record_json);
    return ret;
}
exports.sdkSignAgentStateRecord = sdkSignAgentStateRecord;

/**
 * Sign `data` with the ML-DSA-65 operational key bound to
 * `key_id`. Pops one WebAuthn assertion (operator presence) to
 * recover the PRF output, unwraps the at-rest-encrypted secret,
 * and signs in-WASM. Returns a 3293-byte ML-DSA-65 signature.
 *
 * This is the PQ-default sign path matching the native V2 wallets'
 * ML-DSA-65 default. Verifiers consume the signature alongside
 * the ML-DSA public key returned by `sdkMldsaPublicKey`.
 * @param {string} key_id
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
function sdkSignWithPqDeviceKey(key_id, data) {
    const ptr0 = passStringToWasm0(key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkSignWithPqDeviceKey(ptr0, len0, ptr1, len1);
    return ret;
}
exports.sdkSignWithPqDeviceKey = sdkSignWithPqDeviceKey;

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
 * @param {string} password
 * @param {boolean} use_biometrics
 * @param {any} persona_json
 * @param {string} idp_url
 * @returns {Promise<any>}
 */
function sdkSignup(password, use_biometrics, persona_json, idp_url) {
    const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(idp_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkSignup(ptr0, len0, use_biometrics, persona_json, ptr1, len1);
    return ret;
}
exports.sdkSignup = sdkSignup;

/**
 * Upsert a conversation record (sealed). `record_json` is the
 * caller-defined ConversationRecord shape. Keyed by
 * `conversation_id` (the peer's DID for a 1:1) — this is the
 * dedup index.
 * @param {string} conversation_id
 * @param {string} record_json
 * @returns {Promise<void>}
 */
function sdkUpsertConversation(conversation_id, record_json) {
    const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(record_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkUpsertConversation(ptr0, len0, ptr1, len1);
    return ret;
}
exports.sdkUpsertConversation = sdkUpsertConversation;

/**
 * Sign an arbitrary payload with an Ed25519 signing key. Returns the
 * raw 64-byte signature. The keypair this wraps is the agent's
 * stable identity keypair, derived earlier via
 * `agentKeypairFromSeed`. Use for the agent-side audit log signing
 * and any custom challenge protocols.
 * @param {Uint8Array} signing_key_bytes
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 */
function signEd25519(signing_key_bytes, payload) {
    const ptr0 = passArray8ToWasm0(signing_key_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.signEd25519(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}
exports.signEd25519 = signEd25519;

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
 * @param {Uint8Array} signing_key_bytes
 * @param {any} fingerprint
 * @returns {any}
 */
function signSessionFingerprint(signing_key_bytes, fingerprint) {
    const ptr0 = passArray8ToWasm0(signing_key_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.signSessionFingerprint(ptr0, len0, fingerprint);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.signSessionFingerprint = signSessionFingerprint;

/**
 * Verify the outer SD-JWT VC signature only against the IdP's
 * P-256 verifying key. JWK shape: `{ kty:"EC", crv:"P-256",
 * x:"<b64url>", y:"<b64url>" }`.
 * @param {string} jws_compact
 * @param {any} idp_pubkey_jwk
 * @param {bigint} now
 * @returns {VerifiedAgentVcJs}
 */
function verifyAgentVcOuter(jws_compact, idp_pubkey_jwk, now) {
    const ptr0 = passStringToWasm0(jws_compact, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verifyAgentVcOuter(ptr0, len0, idp_pubkey_jwk, now);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return VerifiedAgentVcJs.__wrap(ret[0]);
}
exports.verifyAgentVcOuter = verifyAgentVcOuter;

/**
 * Verify the outer agent VC AND the embedded `human_authorization`
 * JWS against the human's delegation P-256 pubkey. Checks all
 * binding fields (sub, parent_human_did, capabilities, may_delegate,
 * exp, agent_pubkey_jwk_thumb).
 * @param {string} jws_compact
 * @param {any} idp_pubkey_jwk
 * @param {any} human_delegation_pubkey_jwk
 * @param {bigint} now
 * @returns {VerifiedAgentVcJs}
 */
function verifyAgentVcWithHumanAuthorization(jws_compact, idp_pubkey_jwk, human_delegation_pubkey_jwk, now) {
    const ptr0 = passStringToWasm0(jws_compact, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verifyAgentVcWithHumanAuthorization(ptr0, len0, idp_pubkey_jwk, human_delegation_pubkey_jwk, now);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return VerifiedAgentVcJs.__wrap(ret[0]);
}
exports.verifyAgentVcWithHumanAuthorization = verifyAgentVcWithHumanAuthorization;

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
 * @param {string} jws_compact
 * @param {string} operator_jwk_x_b64u
 * @param {string} operator_jwk_y_b64u
 * @param {bigint} now_epoch_sec
 * @param {string | null} [expected_approval_id]
 * @param {string | null} [expected_parent_human_did]
 * @param {string | null} [expected_agent_did]
 * @param {string | null} [expected_share_id]
 * @returns {any}
 */
function verifyDecisionJws(jws_compact, operator_jwk_x_b64u, operator_jwk_y_b64u, now_epoch_sec, expected_approval_id, expected_parent_human_did, expected_agent_did, expected_share_id) {
    const ptr0 = passStringToWasm0(jws_compact, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(operator_jwk_x_b64u, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(operator_jwk_y_b64u, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(expected_approval_id) ? 0 : passStringToWasm0(expected_approval_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(expected_parent_human_did) ? 0 : passStringToWasm0(expected_parent_human_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    var ptr5 = isLikeNone(expected_agent_did) ? 0 : passStringToWasm0(expected_agent_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len5 = WASM_VECTOR_LEN;
    var ptr6 = isLikeNone(expected_share_id) ? 0 : passStringToWasm0(expected_share_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len6 = WASM_VECTOR_LEN;
    const ret = wasm.verifyDecisionJws(ptr0, len0, ptr1, len1, ptr2, len2, now_epoch_sec, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.verifyDecisionJws = verifyDecisionJws;

/**
 * Verify a raw Ed25519 signature. Returns true on valid, false on
 * invalid (never throws for a structurally-correct but
 * cryptographically-wrong signature).
 * @param {Uint8Array} pubkey_bytes
 * @param {Uint8Array} payload
 * @param {Uint8Array} signature_bytes
 * @returns {boolean}
 */
function verifyEd25519(pubkey_bytes, payload, signature_bytes) {
    const ptr0 = passArray8ToWasm0(pubkey_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(signature_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyEd25519(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.verifyEd25519 = verifyEd25519;

/**
 * Verify a standalone human-authorization JWS against the human's
 * delegation P-256 pubkey. Useful for consumers that have a
 * human_authorization string outside the context of an outer VC.
 * @param {string} jws_compact
 * @param {any} human_pubkey_jwk
 * @param {bigint} now
 * @returns {VerifiedHumanAuthorizationJs}
 */
function verifyHumanAuthorization(jws_compact, human_pubkey_jwk, now) {
    const ptr0 = passStringToWasm0(jws_compact, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verifyHumanAuthorization(ptr0, len0, human_pubkey_jwk, now);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return VerifiedHumanAuthorizationJs.__wrap(ret[0]);
}
exports.verifyHumanAuthorization = verifyHumanAuthorization;

/**
 * Verify a DPoP-shaped PoP JWT. Pubkey is extracted from the `kid`
 * claim (which IS the agent's DID — no network resolution).
 * @param {string} jwt
 * @param {string} expected_method
 * @param {string} expected_uri
 * @param {string | null | undefined} expected_access_token
 * @param {bigint} now
 * @param {number} max_age_seconds
 * @returns {VerifiedPopJs}
 */
function verifyPopJwt(jwt, expected_method, expected_uri, expected_access_token, now, max_age_seconds) {
    const ptr0 = passStringToWasm0(jwt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(expected_uri, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(expected_access_token) ? 0 : passStringToWasm0(expected_access_token, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.verifyPopJwt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, now, max_age_seconds);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return VerifiedPopJs.__wrap(ret[0]);
}
exports.verifyPopJwt = verifyPopJwt;

/**
 * Verify a SessionFingerprint by reconstructing the Ed25519
 * verifying key from its `agent_did` field. Returns `true` on
 * valid; throws (a `JsError` with a precise reason) on any
 * failure. Useful on the desktop side and for integration tests
 * inside the plugin.
 * @param {any} fingerprint
 * @returns {boolean}
 */
function verifySessionFingerprint(fingerprint) {
    const ret = wasm.verifySessionFingerprint(fingerprint);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.verifySessionFingerprint = verifySessionFingerprint;

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_2e59b1b37a9a34c3: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_e6ffdb596c888833: function(arg0) {
            const ret = Number(arg0);
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_bigint_get_as_i64_2c5082002e4826e2: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_a86c216575a75c30: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_dd5d2d07ce9e6c57: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_4bd7a57e54337366: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_6c98f7e945dacdde: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_49868bde5eb1e745: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_344c8750a8525473: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_40c5a80572e8f9d3: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_b29b5c5a8065ba1a: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c0cca72b82b86f4d: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_7d430e744a913d26: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_3a72ae764d46d944: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_7579aab02a8a620c: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_914df97fcfa788f2: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_81fc77679af83bc6: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_3c3b4f651835fbcb: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_abort_5ee4083ce26e0b01: function(arg0) {
            arg0.abort();
        },
        __wbg_abort_7a67cb8f9383baa1: function(arg0, arg1) {
            arg0.abort(arg1);
        },
        __wbg_append_29fe4ab6f2c88ba2: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            arg0.append(getStringFromWasm0(arg1, arg2), arg3);
        }, arguments); },
        __wbg_append_4aa39f0c1ef8161e: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_append_59da1e75d76c3126: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            arg0.append(getStringFromWasm0(arg1, arg2), arg3, getStringFromWasm0(arg4, arg5));
        }, arguments); },
        __wbg_append_c015600138ae60bb: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_arrayBuffer_dae084a298aa5fe0: function() { return handleError(function (arg0) {
            const ret = arg0.arrayBuffer();
            return ret;
        }, arguments); },
        __wbg_call_7f2987183bb62793: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_d578befcc3145dee: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_clearTimeout_113b1cde814ec762: function(arg0) {
            const ret = clearTimeout(arg0);
            return ret;
        },
        __wbg_clearTimeout_6b8d9a38b9263d65: function(arg0) {
            const ret = clearTimeout(arg0);
            return ret;
        },
        __wbg_clear_973335ff78e5473c: function() { return handleError(function (arg0) {
            const ret = arg0.clear();
            return ret;
        }, arguments); },
        __wbg_commit_1a74f28f26c0cbd8: function() { return handleError(function (arg0) {
            arg0.commit();
        }, arguments); },
        __wbg_createObjectStore_6e567b25160be2fa: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.createObjectStore(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_create_f6a33f2bac447c7c: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.create(arg1);
            return ret;
        }, arguments); },
        __wbg_credentials_36333a7b3fe68bcb: function(arg0) {
            const ret = arg0.credentials;
            return ret;
        },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_delete_fc24bd7dfa57938e: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.delete(arg1);
            return ret;
        }, arguments); },
        __wbg_deriveBits_71a0d662d4bc391a: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.deriveBits(arg1, arg2, arg3 >>> 0);
            return ret;
        }, arguments); },
        __wbg_done_547d467e97529006: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_616b1a459b85be0b: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_error_58469b8474e13592: function() { return handleError(function (arg0) {
            const ret = arg0.error;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_error_c57846662bf0e748: function(arg0) {
            const ret = arg0.error;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_exportKey_99bb9b98984e3a4e: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.exportKey(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_fetch_1a731e18c5e21884: function(arg0, arg1) {
            const ret = arg0.fetch(arg1);
            return ret;
        },
        __wbg_fetch_9dad4fe911207b37: function(arg0) {
            const ret = fetch(arg0);
            return ret;
        },
        __wbg_generateKey_2d7e8fadfbbeb0c8: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.generateKey(arg1, arg2 !== 0, arg3);
            return ret;
        }, arguments); },
        __wbg_getAllKeys_122dfa5978e6ca9a: function() { return handleError(function (arg0) {
            const ret = arg0.getAllKeys();
            return ret;
        }, arguments); },
        __wbg_getAllKeys_ab049bbab10262c9: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.getAllKeys(arg1, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_getAllKeys_de3ce10f99737daa: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.getAllKeys(arg1);
            return ret;
        }, arguments); },
        __wbg_getAll_0d772ddb77a3abf6: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.getAll(arg1, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_getAll_19e833a015c08d39: function() { return handleError(function (arg0) {
            const ret = arg0.getAll();
            return ret;
        }, arguments); },
        __wbg_getAll_93336699ea033b51: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.getAll(arg1);
            return ret;
        }, arguments); },
        __wbg_getClientExtensionResults_ee0e5fdd5452c516: function(arg0) {
            const ret = arg0.getClientExtensionResults();
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getRandomValues_d49329ff89a07af1: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getTime_f6ac312467f7cf09: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_get_4848e350b40afc16: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_560cb483e5c0133e: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.get(arg1);
            return ret;
        }, arguments); },
        __wbg_get_84638f46881f3720: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.get(arg1);
            return ret;
        }, arguments); },
        __wbg_get_dba5fa38b6597b3f: function(arg0, arg1, arg2) {
            const ret = arg1[arg2 >>> 0];
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_get_ed0642c4b9d31ddf: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_f96702c6245e4ef9: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_unchecked_7d7babe32e9e6a54: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_has_3ec5c22db2e5237a: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.has(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_headers_e08dcb5aa09b9a63: function(arg0) {
            const ret = arg0.headers;
            return ret;
        },
        __wbg_host_142a4b1e170efc7f: function() { return handleError(function (arg0, arg1) {
            const ret = arg1.host;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_hostname_a42f31a9081ac639: function() { return handleError(function (arg0, arg1) {
            const ret = arg1.hostname;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_importKey_444a3b620c5933b8: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
            const ret = arg0.importKey(getStringFromWasm0(arg1, arg2), arg3, arg4, arg5 !== 0, arg6);
            return ret;
        }, arguments); },
        __wbg_instanceof_ArrayBuffer_ff7c1337a5e3b33a: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_CryptoKey_c7ae7491b5be7627: function(arg0) {
            let result;
            try {
                result = arg0 instanceof CryptoKey;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbDatabase_0af111edb4be95f4: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBDatabase;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbFactory_7c303c3d8528cef3: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBFactory;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbOpenDbRequest_92df356941adf31e: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBOpenDBRequest;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbRequest_fc5918c726448f04: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBRequest;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbTransaction_de69712ce07dde97: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBTransaction;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Map_a10a2795ef4bfe97: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Map;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Object_72ee0c53dd8f0726: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Object;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_PublicKeyCredential_57412b8dfa7394d4: function(arg0) {
            let result;
            try {
                result = arg0 instanceof PublicKeyCredential;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Response_06795eab66cc4036: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Response;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_SubtleCrypto_37de618f31835734: function(arg0) {
            let result;
            try {
                result = arg0 instanceof SubtleCrypto;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_4b8da683deb25d72: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_c0fee4c064502536: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_db61795ad004c139: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_ea83862ba994770c: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_de403ef31815a3e6: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_length_0c32cb8543c8e4c8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_3804262ff442a7a3: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_6e821edde497a532: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_location_91b3fdbca3c76d9e: function(arg0) {
            const ret = arg0.location;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_navigator_9b09ea705d03d227: function(arg0) {
            const ret = arg0.navigator;
            return ret;
        },
        __wbg_new_0_bfa2ef4bc447daa2: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_3a112826a89cb962: function() { return handleError(function () {
            const ret = new Headers();
            return ret;
        }, arguments); },
        __wbg_new_4f9fafbb3909af72: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_56a7f7f78a9437aa: function() { return handleError(function () {
            const ret = new FormData();
            return ret;
        }, arguments); },
        __wbg_new_99cabae501c0a8a0: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_9abbf7148481485e: function() { return handleError(function () {
            const ret = new AbortController();
            return ret;
        }, arguments); },
        __wbg_new_a560378ea1240b14: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_e3b04b4d53d1b593: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_f3c9df4f38f3f798: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_from_slice_2580ff33d0d10520: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_14d7cc391ce53d2c: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h0242163d3b2fc76a(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_length_9cedd08484b73942: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_new_with_str_and_init_f663b6d334baa878: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new Request(getStringFromWasm0(arg0, arg1), arg2);
            return ret;
        }, arguments); },
        __wbg_new_with_u8_array_sequence_and_options_0ea871c78d13a6d8: function() { return handleError(function (arg0, arg1) {
            const ret = new Blob(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_next_01132ed6134b8ef5: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_b3713ec761a9dbfd: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_88621c9c9a4f3ffc: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_objectStoreNames_990d8e55c661828b: function(arg0) {
            const ret = arg0.objectStoreNames;
            return ret;
        },
        __wbg_objectStore_3d4cade4416cd432: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.objectStore(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_open_254d9b392262d9ef: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.open(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_open_ac04ec9d75d0eeaf: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.open(getStringFromWasm0(arg1, arg2), arg3 >>> 0);
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_3e05eb9545565046: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_6bdbc990be5ac37b: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_put_015a7e88e46a2502: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.put(arg1);
            return ret;
        }, arguments); },
        __wbg_put_4485a4012273f7ef: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.put(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_queueMicrotask_abaf92f0bd4e80a4: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_df5a6dac26d818f3: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_0a79de24e9d2267b: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_result_452c1006fc727317: function() { return handleError(function (arg0) {
            const ret = arg0.result;
            return ret;
        }, arguments); },
        __wbg_setTimeout_ef24d2fc3ad97385: function() { return handleError(function (arg0, arg1) {
            const ret = setTimeout(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_setTimeout_f757f00851f76c42: function(arg0, arg1) {
            const ret = setTimeout(arg0, arg1);
            return ret;
        },
        __wbg_set_08463b1df38a7e29: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_16a9c1a07b3d38ec: function(arg0, arg1, arg2) {
            arg0.set(getArrayU8FromWasm0(arg1, arg2));
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_6c60b2e8ad0e9383: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_8ee2d34facb8466e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_body_a304d09cb50cefbe: function(arg0, arg1) {
            arg0.body = arg1;
        },
        __wbg_set_cache_cc687e2b96e9608c: function(arg0, arg1) {
            arg0.cache = __wbindgen_enum_RequestCache[arg1];
        },
        __wbg_set_credentials_7693e63055f5e838: function(arg0, arg1) {
            arg0.credentials = __wbindgen_enum_RequestCredentials[arg1];
        },
        __wbg_set_headers_6ab1105e542834e2: function(arg0, arg1) {
            arg0.headers = arg1;
        },
        __wbg_set_key_path_6edd6ee0e8d75af3: function(arg0, arg1) {
            arg0.keyPath = arg1;
        },
        __wbg_set_method_1971272fe557e972: function(arg0, arg1, arg2) {
            arg0.method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_mode_d1b643087602281a: function(arg0, arg1) {
            arg0.mode = __wbindgen_enum_RequestMode[arg1];
        },
        __wbg_set_onabort_6b6df7a41aa97c23: function(arg0, arg1) {
            arg0.onabort = arg1;
        },
        __wbg_set_oncomplete_20fb27150b4ee0d4: function(arg0, arg1) {
            arg0.oncomplete = arg1;
        },
        __wbg_set_onerror_2b7dfa4e6dea4159: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onerror_3c4b5087146b11b6: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onsuccess_f7e5b5cbed5008b1: function(arg0, arg1) {
            arg0.onsuccess = arg1;
        },
        __wbg_set_onupgradeneeded_d7e8e03a1999bf5d: function(arg0, arg1) {
            arg0.onupgradeneeded = arg1;
        },
        __wbg_set_signal_8564a226c5c6853c: function(arg0, arg1) {
            arg0.signal = arg1;
        },
        __wbg_set_type_ef754f25329c9096: function(arg0, arg1, arg2) {
            arg0.type = getStringFromWasm0(arg1, arg2);
        },
        __wbg_sign_681e47de9a9887e1: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.sign(arg1, arg2, arg3);
            return ret;
        }, arguments); },
        __wbg_signal_9172c3282bfba2f5: function(arg0) {
            const ret = arg0.signal;
            return ret;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_f2e0f995a21329ff: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_24f78b6d23f286ea: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_59fd959c540fe405: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_status_44ecb0ac1da253f4: function(arg0) {
            const ret = arg0.status;
            return ret;
        },
        __wbg_stringify_a2c39d991e1bf91d: function() { return handleError(function (arg0) {
            const ret = JSON.stringify(arg0);
            return ret;
        }, arguments); },
        __wbg_subarray_0f98d3fb634508ad: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_target_732d56b173b7e87c: function(arg0) {
            const ret = arg0.target;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_text_43bdfba45e602cf9: function() { return handleError(function (arg0) {
            const ret = arg0.text();
            return ret;
        }, arguments); },
        __wbg_then_00eed3ac0b8e82cb: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_a0c8db0381c8994c: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_transaction_904b9a3920efb0b5: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transaction(arg1, __wbindgen_enum_IdbTransactionMode[arg2]);
            return ret;
        }, arguments); },
        __wbg_url_95d8a83d33709572: function(arg0, arg1) {
            const ret = arg1.url;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_7f6052747ccf940f: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 1270, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h07eda6f9933457e4);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("Event")], shim_idx: 853, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h1725375cb213b3e4);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("IDBVersionChangeEvent")], shim_idx: 795, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hfba200ffcbc2c4fb);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 453, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h23499dd81690a033);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 940, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h3c6c61154a9359bf);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000008: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000009: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_000000000000000a: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_cast_000000000000000b: function(arg0, arg1) {
            var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 1, 1);
            // Cast intrinsic for `Vector(U8) -> Externref`.
            const ret = v0;
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./lastid_agent_wasm_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__h23499dd81690a033(arg0, arg1) {
    wasm.wasm_bindgen__convert__closures_____invoke__h23499dd81690a033(arg0, arg1);
}

function wasm_bindgen__convert__closures_____invoke__h3c6c61154a9359bf(arg0, arg1) {
    wasm.wasm_bindgen__convert__closures_____invoke__h3c6c61154a9359bf(arg0, arg1);
}

function wasm_bindgen__convert__closures_____invoke__h1725375cb213b3e4(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h1725375cb213b3e4(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__hfba200ffcbc2c4fb(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__hfba200ffcbc2c4fb(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h07eda6f9933457e4(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h07eda6f9933457e4(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h0242163d3b2fc76a(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h0242163d3b2fc76a(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_IdbTransactionMode = ["readonly", "readwrite", "versionchange", "readwriteflush", "cleanup"];


const __wbindgen_enum_RequestCache = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];


const __wbindgen_enum_RequestCredentials = ["omit", "same-origin", "include"];


const __wbindgen_enum_RequestMode = ["same-origin", "no-cors", "cors", "navigate"];
const AgentKeypairJsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_agentkeypairjs_free(ptr >>> 0, 1));
const VerifiedAgentVcJsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifiedagentvcjs_free(ptr >>> 0, 1));
const VerifiedHumanAuthorizationJsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifiedhumanauthorizationjs_free(ptr >>> 0, 1));
const VerifiedPopJsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifiedpopjs_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/lastid_agent_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasm = new WebAssembly.Instance(wasmModule, __wbg_get_imports()).exports;
wasm.__wbindgen_start();
