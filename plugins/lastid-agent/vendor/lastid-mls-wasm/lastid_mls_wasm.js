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
     * Export the GroupInfo for a freshly-created group as
     * TLS-serialized base64 — the `mls_group_init` the IdP wants in
     * `POST /v1/groups`, which it hashes into the canonical
     * mls_group_id every peer agrees on. Call right after
     * `createGroup`, before `addMember`. Read-only.
     * @param {string} group_id_b64
     * @returns {string}
     */
    exportGroupInfo(group_id_b64) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.botmlsclient_exportGroupInfo(this.__wbg_ptr, ptr0, len0);
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
 * Durable MLS client. Constructed via the async
 * [`createPersistentBotClient`] free function below; this opaque
 * handle wraps the client + its backing `IndexedDbRawKv` so each
 * state-mutating method can await a flush before returning.
 */
class PersistentBotMlsClient {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(PersistentBotMlsClient.prototype);
        obj.__wbg_ptr = ptr;
        PersistentBotMlsClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PersistentBotMlsClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_persistentbotmlsclient_free(ptr, 0);
    }
    /**
     * Add a peer to an existing group. Returns JSON
     * `AddMemberResult`.
     * @param {string} group_id_b64
     * @param {string} key_package_b64
     * @returns {Promise<string>}
     */
    addMember(group_id_b64, key_package_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_package_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_addMember(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Bot DID this handle is bound to.
     * @returns {string}
     */
    get botDid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.persistentbotmlsclient_botDid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Commit every pending queued proposal.
     * @param {string} group_id_b64
     * @returns {Promise<string>}
     */
    commitPendingProposals(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_commitPendingProposals(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Author a fresh group with this client as sole creator.
     * Returns JSON `JoinedGroupInfo`.
     * @param {string} group_id_b64
     * @returns {Promise<string>}
     */
    createGroup(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_createGroup(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Destroy a group. Returns JSON `DestroyGroupResult`.
     * @param {string} group_id_b64
     * @param {string} farewell_plaintext_b64
     * @returns {Promise<string>}
     */
    destroyGroup(group_id_b64, farewell_plaintext_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(farewell_plaintext_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_destroyGroup(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Encrypt an application message in `group_id_b64`. Plaintext
     * is passed as base64. Returns base64 of the wire payload.
     * @param {string} group_id_b64
     * @param {string} plaintext_b64
     * @returns {Promise<string>}
     */
    encryptApplicationMessage(group_id_b64, plaintext_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(plaintext_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_encryptApplicationMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Export the GroupInfo for a freshly-created group as
     * TLS-serialized base64. This is what the IdP wants in its
     * `POST /v1/groups { mls_group_init: <this> }` body — it
     * hashes the bytes to derive the canonical mls_group_id
     * that every peer ends up agreeing on. Read-only; no
     * state mutation, no flush.
     * @param {string} group_id_b64
     * @returns {Promise<string>}
     */
    exportGroupInfo(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_exportGroupInfo(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Explicit flush — drain the pending queue without doing
     * any new MLS op first. Useful when JS wants to be defensive
     * (e.g. before a tab-close handler) or to drain any tail
     * queue from a prior method that bailed before its own
     * flush completed. Idempotent — no-op when queue is empty.
     * @returns {Promise<void>}
     */
    flushPending() {
        const ret = wasm.persistentbotmlsclient_flushPending(this.__wbg_ptr);
        return ret;
    }
    /**
     * Wipe local state for a dissolved group. Idempotent.
     * @param {string} group_id_b64
     * @returns {Promise<void>}
     */
    forgetGroup(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_forgetGroup(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Generate a fresh KeyPackage. Returns the base64-encoded
     * TLS-serialized KeyPackage. Awaits IDB flush before
     * resolving so the private credentials openmls just minted
     * are durable before JS sees the KeyPackage bytes (and
     * before the caller publishes them to the IdP).
     * @returns {Promise<string>}
     */
    generateKeyPackage() {
        const ret = wasm.persistentbotmlsclient_generateKeyPackage(this.__wbg_ptr);
        return ret;
    }
    /**
     * Current MLS epoch for the named group. Read-only — no
     * flush needed.
     * @param {string} group_id_b64
     * @returns {bigint}
     */
    groupEpoch(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_groupEpoch(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * Process an inbound MLS message. Returns JSON
     * `InboundResult` — see Rust-side docs for the schema.
     * @param {string} message_b64
     * @returns {Promise<string>}
     */
    processInbound(message_b64) {
        const ptr0 = passStringToWasm0(message_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_processInbound(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Process an MLS Welcome and join the new group.
     * @param {string} welcome_b64
     * @returns {Promise<string>}
     */
    processWelcome(welcome_b64) {
        const ptr0 = passStringToWasm0(welcome_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_processWelcome(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Remove a member by leaf index. Returns JSON `CommitResult`.
     * @param {string} group_id_b64
     * @param {number} member_leaf_index
     * @returns {Promise<string>}
     */
    removeMember(group_id_b64, member_leaf_index) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_removeMember(this.__wbg_ptr, ptr0, len0, member_leaf_index);
        return ret;
    }
    /**
     * Discard a locally-prepared-but-not-yet-published commit.
     * @param {string} group_id_b64
     * @returns {Promise<void>}
     */
    rollbackPendingCommit(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_rollbackPendingCommit(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Rotate this client's own leaf without changing membership.
     * @param {string} group_id_b64
     * @returns {Promise<string>}
     */
    selfUpdate(group_id_b64) {
        const ptr0 = passStringToWasm0(group_id_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.persistentbotmlsclient_selfUpdate(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) PersistentBotMlsClient.prototype[Symbol.dispose] = PersistentBotMlsClient.prototype.free;
exports.PersistentBotMlsClient = PersistentBotMlsClient;

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
 * Open or rehydrate a persistent MLS client for `bot_did`. If
 * IndexedDB has prior `mls_kv` rows for this scope they are
 * loaded into the in-mem cache; if not, the client starts
 * fresh. Either way, every subsequent op writes through to
 * IndexedDB inside an atomic flush before the Promise resolves.
 *
 * The same bot_did calling this twice returns two independent
 * handles sharing IDB state — useful for tests, an antipattern
 * in production (one client per bot_did per tab).
 * @param {string} bot_did
 * @returns {Promise<PersistentBotMlsClient>}
 */
function createPersistentBotClient(bot_did) {
    const ptr0 = passStringToWasm0(bot_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.createPersistentBotClient(ptr0, len0);
    return ret;
}
exports.createPersistentBotClient = createPersistentBotClient;

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
        __wbg___wbindgen_debug_string_dd5d2d07ce9e6c57: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
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
        __wbg___wbindgen_throw_81fc77679af83bc6: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_3c3b4f651835fbcb: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_call_d578befcc3145dee: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_commit_1a74f28f26c0cbd8: function() { return handleError(function (arg0) {
            arg0.commit();
        }, arguments); },
        __wbg_continue_33780bb54847c9c4: function() { return handleError(function (arg0, arg1) {
            arg0.continue(arg1);
        }, arguments); },
        __wbg_continue_5d0cea5632bb62b2: function() { return handleError(function (arg0) {
            arg0.continue();
        }, arguments); },
        __wbg_createObjectStore_6e567b25160be2fa: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.createObjectStore(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_delete_fc24bd7dfa57938e: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.delete(arg1);
            return ret;
        }, arguments); },
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
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_76dfc69825c9c552: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_dba5fa38b6597b3f: function(arg0, arg1, arg2) {
            const ret = arg1[arg2 >>> 0];
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_get_f96702c6245e4ef9: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
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
        __wbg_instanceof_IdbCursorWithValue_5ece76174155fcb4: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBCursorWithValue;
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
        __wbg_key_dca96029ad629531: function() { return handleError(function (arg0) {
            const ret = arg0.key;
            return ret;
        }, arguments); },
        __wbg_length_0c32cb8543c8e4c8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_3804262ff442a7a3: function(arg0) {
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
        __wbg_new_4f9fafbb3909af72: function() {
            const ret = new Object();
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
                        return wasm_bindgen__convert__closures_____invoke__h40481bbae026f68a(a, state0.b, arg0, arg1);
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
        __wbg_openCursor_406fce6f59842aa3: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.openCursor(arg1, __wbindgen_enum_IdbCursorDirection[arg2]);
            return ret;
        }, arguments); },
        __wbg_openCursor_57332d991702ab2d: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.openCursor(arg1);
            return ret;
        }, arguments); },
        __wbg_openCursor_cc809bbe55c6438a: function() { return handleError(function (arg0) {
            const ret = arg0.openCursor();
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
        __wbg_persistentbotmlsclient_new: function(arg0) {
            const ret = PersistentBotMlsClient.__wrap(arg0);
            return ret;
        },
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
        __wbg_request_e114ae47c8953a51: function(arg0) {
            const ret = arg0.request;
            return ret;
        },
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
        __wbg_set_key_path_6edd6ee0e8d75af3: function(arg0, arg1) {
            arg0.keyPath = arg1;
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
        __wbg_target_732d56b173b7e87c: function(arg0) {
            const ret = arg0.target;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_then_a0c8db0381c8994c: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_transaction_904b9a3920efb0b5: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transaction(arg1, __wbindgen_enum_IdbTransactionMode[arg2]);
            return ret;
        }, arguments); },
        __wbg_value_80885804084976f6: function() { return handleError(function (arg0) {
            const ret = arg0.value;
            return ret;
        }, arguments); },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 737, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h6bbf4240b2ac3152);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("Event")], shim_idx: 558, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hf8dc1552a3079bbe);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("IDBVersionChangeEvent")], shim_idx: 544, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h06cd8775ba25515b);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
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

function wasm_bindgen__convert__closures_____invoke__hf8dc1552a3079bbe(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__hf8dc1552a3079bbe(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h06cd8775ba25515b(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h06cd8775ba25515b(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h6bbf4240b2ac3152(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h6bbf4240b2ac3152(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h40481bbae026f68a(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h40481bbae026f68a(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_IdbCursorDirection = ["next", "nextunique", "prev", "prevunique"];


const __wbindgen_enum_IdbTransactionMode = ["readonly", "readwrite", "versionchange", "readwriteflush", "cleanup"];
const BotMlsClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_botmlsclient_free(ptr >>> 0, 1));
const PersistentBotMlsClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_persistentbotmlsclient_free(ptr >>> 0, 1));

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
