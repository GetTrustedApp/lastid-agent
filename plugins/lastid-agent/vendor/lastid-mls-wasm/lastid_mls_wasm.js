/* @ts-self-types="./lastid_mls_wasm.d.ts" */

/**
 * JS-callable handle to a single bot's MLS state. The Node side
 * constructs one per request: either fresh (`createBotClient`) or
 * restored from a previously-dumped state blob
 * (`restoreBotClient`), then calls `generateKeyPackage()` /
 * `dumpState()` and discards. All persistence happens Node-side.
 */
class BotMlsClient {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BotMlsClient.prototype);
        obj.__wbg_ptr = ptr;
        BotMlsClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BotMlsClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_botmlsclient_free(ptr, 0);
    }
    /**
     * Add a peer to an existing group. Returns JSON
     * `AddMemberResult` with `commit_b64` (broadcast to existing
     * members), `welcome_b64` (deliver to the new member), and
     * `new_epoch`.
     * @param {string} group_id_b64
     * @param {string} key_package_b64
     * @returns {string}
     */
    addMember(group_id_b64, key_package_b64) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(key_package_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_addMember(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Bulk-load per-key MLS state entries from durable storage. JS
     * passes a JSON array of `[key_b64, value_b64]` tuples — one tuple
     * per row read from the v2 storage table.
     *
     * Does NOT touch the baseline. Callers MUST call `snapshotBaseline`
     * after this and before the first state-mutating op.
     * @param {string} entries_json
     */
    applyLoaded(entries_json) {
        const ptr0 = passStringToWasm0(entries_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_applyLoaded(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Bot DID this handle is bound to.
     * @returns {string}
     */
    get botDid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.botmlsclient_botDid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Issue a commit covering every pending proposal openmls has
     * queued for this group. Used when the IDP designates this
     * bot as the new committer via `group_chat.proposal_reassigned`.
     * @param {string} group_id_b64
     * @returns {string}
     */
    commitPendingProposals(group_id_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_commitPendingProposals(this.__wbg_ptr, ptr0, len0);
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
    /**
     * Create a fresh bot client with no prior state.
     * @param {string} bot_did
     * @returns {BotMlsClient}
     */
    static createBotClient(bot_did) {
        const ptr0 = passStringToWasm0(bot_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_createBotClient(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BotMlsClient.__wrap(ret[0]);
    }
    /**
     * Author a fresh MLS group with the bot as sole creator.
     * Returns JSON `JoinedGroupInfo` (group_id_b64, member_count=1,
     * epoch=0). Subsequent `addMember` calls populate the group.
     * @param {string} group_id_b64
     * @returns {string}
     */
    createGroup(group_id_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_createGroup(this.__wbg_ptr, ptr0, len0);
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
    /**
     * Destroy a group: encrypt a farewell, remove every other
     * member, merge + delete local state. Returns a
     * JSON-serialized `DestroyGroupResult` carrying the two
     * wire payloads the caller pushes to the IDP.
     * @param {string} group_id_b64
     * @param {string} farewell_plaintext_b64
     * @returns {string}
     */
    destroyGroup(group_id_b64, farewell_plaintext_b64) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(farewell_plaintext_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_destroyGroup(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Serialize the bot's MLS state to an opaque base64 blob suitable
     * for KMS-envelope encryption + DynamoDB storage.
     *
     * Retained for the v1 → v2 storage migration path. New code should
     * use `applyLoaded` (load entries from v2 table) + `takeDiff`
     * (extract per-op delta to persist) instead.
     * @returns {string}
     */
    dumpState() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.botmlsclient_dumpState(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Encrypt an application message in the given group. The
     * returned string is base64 of the TLS-serialized
     * MlsMessageOut wire payload.
     * @param {string} group_id_b64
     * @param {string} plaintext_b64
     * @returns {string}
     */
    encryptApplicationMessage(group_id_b64, plaintext_b64) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(plaintext_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_encryptApplicationMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Wipe local MlsGroup state for a dissolved group. Idempotent:
     * calling on an absent group is a no-op. Subsequent
     * `processInbound` for the same group_id surfaces
     * `GroupNotFound` (the subscriber drops it silently).
     * @param {string} group_id_b64
     */
    forgetGroup(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_forgetGroup(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Generate a fresh KeyPackage and return it as base64 of the TLS
     * serialization. Mutates internal state — caller MUST call
     * `dumpState()` and persist before discarding the handle, or the
     * generated KeyPackage will never be decryptable.
     * @returns {string}
     */
    generateKeyPackage() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.botmlsclient_generateKeyPackage(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Return the bot's current MLS epoch for the named group.
     * Used to populate `payload.epoch` on `group_chat.message`
     * events the bot sends back to the IDP.
     * @param {string} group_id_b64
     * @returns {bigint}
     */
    groupEpoch(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_groupEpoch(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * Process an inbound private/public message. Returns a
     * JSON-serialized `InboundResult` — see Rust-side docs for
     * the schema.
     * @param {string} message_b64
     * @returns {string}
     */
    processInbound(message_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(message_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_processInbound(this.__wbg_ptr, ptr0, len0);
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
    /**
     * Process an MLS Welcome and join the new group. Returns a
     * JSON-serialized `JoinedGroupInfo`. The new group state is
     * persisted into provider storage; caller MUST `dumpState`
     * + persist before discarding this handle.
     * @param {string} welcome_b64
     * @returns {string}
     */
    processWelcome(welcome_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(welcome_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_processWelcome(this.__wbg_ptr, ptr0, len0);
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
    /**
     * Remove a member by leaf index. Returns JSON `CommitResult`.
     * @param {string} group_id_b64
     * @param {number} member_leaf_index
     * @returns {string}
     */
    removeMember(group_id_b64, member_leaf_index) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_removeMember(this.__wbg_ptr, ptr0, len0, member_leaf_index);
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
    /**
     * Restore a bot client from a previously-dumped (base64) state blob.
     * @param {string} bot_did
     * @param {string} state_b64
     * @returns {BotMlsClient}
     */
    static restoreBotClient(bot_did, state_b64) {
        const ptr0 = passStringToWasm0(bot_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(state_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_restoreBotClient(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BotMlsClient.__wrap(ret[0]);
    }
    /**
     * Discard any locally-prepared-but-not-yet-published commit.
     * Used when committer authority is reassigned away from us.
     * @param {string} group_id_b64
     */
    rollbackPendingCommit(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.botmlsclient_rollbackPendingCommit(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Rotate the bot's own leaf without changing membership.
     * Returns JSON `CommitResult`. The caller broadcasts the
     * commit to advance other members' epochs.
     * @param {string} group_id_b64
     * @returns {string}
     */
    selfUpdate(group_id_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_selfUpdate(this.__wbg_ptr, ptr0, len0);
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
    /**
     * Snapshot the current storage map as the baseline for the next
     * `takeDiff`. Call this immediately before each state-mutating op
     * so the diff captures exactly that op's writes/deletes.
     */
    snapshotBaseline() {
        const ret = wasm.botmlsclient_snapshotBaseline(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Extract the writes + deletes since the last `snapshotBaseline`.
     * Returns a JSON object `{ writes: [[k_b64,v_b64], ...], deletes:
     * [k_b64, ...] }`. Resets the baseline to the current state.
     * @returns {string}
     */
    takeDiffJson() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.botmlsclient_takeDiffJson(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
}
if (Symbol.dispose) BotMlsClient.prototype[Symbol.dispose] = BotMlsClient.prototype.free;
exports.BotMlsClient = BotMlsClient;

/**
 * Returns a JSON-serialized [`CiphersuiteSupportReport`]. Useful as a smoke
 * test from the credential-service test harness.
 * @returns {string}
 */
function ciphersuiteSupportJson() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.ciphersuiteSupportJson();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}
exports.ciphersuiteSupportJson = ciphersuiteSupportJson;

/**
 * Install a panic hook that pipes Rust panics to the JS console. Call once.
 */
function init() {
    wasm.init();
}
exports.init = init;

/**
 * The target ciphersuite code point as a `u32` (JS-friendly).
 * @returns {number}
 */
function targetCiphersuiteCodePoint() {
    const ret = wasm.targetCiphersuiteCodePoint();
    return ret >>> 0;
}
exports.targetCiphersuiteCodePoint = targetCiphersuiteCodePoint;

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
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
        __wbg___wbindgen_throw_81fc77679af83bc6: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_d578befcc3145dee: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
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
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_76dfc69825c9c552: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_0c32cb8543c8e4c8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_with_length_9cedd08484b73942: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_88621c9c9a4f3ffc: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_3e05eb9545565046: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
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
        __wbg_subarray_0f98d3fb634508ad: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
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
        "./lastid_mls_wasm_bg.js": import0,
    };
}

const BotMlsClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_botmlsclient_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
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

const wasmPath = `${__dirname}/lastid_mls_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasm = new WebAssembly.Instance(wasmModule, __wbg_get_imports()).exports;
wasm.__wbindgen_start();
