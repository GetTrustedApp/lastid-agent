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
        __wbg_call_7f2987183bb62793: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
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
        __wbg_getRandomValues_d49329ff89a07af1: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_4848e350b40afc16: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_ed0642c4b9d31ddf: function() { return handleError(function (arg0, arg1) {
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
        __wbg_length_6e821edde497a532: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_4f9fafbb3909af72: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_99cabae501c0a8a0: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_a560378ea1240b14: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_f3c9df4f38f3f798: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_next_01132ed6134b8ef5: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_b3713ec761a9dbfd: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_3e05eb9545565046: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_set_08463b1df38a7e29: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_6c60b2e8ad0e9383: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_7f6052747ccf940f: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
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
