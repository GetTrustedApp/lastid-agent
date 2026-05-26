/* tslint:disable */
/* eslint-disable */

/**
 * JS-callable handle to a single bot's MLS state. The Node side
 * constructs one per request: either fresh (`createBotClient`) or
 * restored from a previously-dumped state blob
 * (`restoreBotClient`), then calls `generateKeyPackage()` /
 * `dumpState()` and discards. All persistence happens Node-side.
 */
export class BotMlsClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add a peer to an existing group. Returns JSON
     * `AddMemberResult` with `commit_b64` (broadcast to existing
     * members), `welcome_b64` (deliver to the new member), and
     * `new_epoch`.
     */
    addMember(group_id_b64: string, key_package_b64: string): string;
    /**
     * Add several peers in ONE commit. `key_packages_b64` is a JSON array
     * of base64 KeyPackages. Returns JSON `AddMemberResult` (one commit,
     * one welcome covering all). Used by device-consistency reconcile to
     * add every missing device of a member at once.
     */
    addMembers(group_id_b64: string, key_packages_b64_json: string): string;
    /**
     * Bulk-load per-key MLS state entries from durable storage. JS
     * passes a JSON array of `[key_b64, value_b64]` tuples — one tuple
     * per row read from the v2 storage table.
     *
     * Does NOT touch the baseline. Callers MUST call `snapshotBaseline`
     * after this and before the first state-mutating op.
     */
    applyLoaded(entries_json: string): void;
    /**
     * Issue a commit covering every pending proposal openmls has
     * queued for this group. Used when the IDP designates this
     * bot as the new committer via `group_chat.proposal_reassigned`.
     */
    commitPendingProposals(group_id_b64: string): string;
    /**
     * Create a fresh bot client with no prior state.
     */
    static createBotClient(bot_did: string): BotMlsClient;
    /**
     * Author a fresh MLS group with the bot as sole creator.
     * Returns JSON `JoinedGroupInfo` (group_id_b64, member_count=1,
     * epoch=0). Subsequent `addMember` calls populate the group.
     */
    createGroup(group_id_b64: string): string;
    /**
     * Destroy a group: encrypt a farewell, remove every other
     * member, merge + delete local state. Returns a
     * JSON-serialized `DestroyGroupResult` carrying the two
     * wire payloads the caller pushes to the IDP.
     */
    destroyGroup(group_id_b64: string, farewell_plaintext_b64: string): string;
    /**
     * Serialize the bot's MLS state to an opaque base64 blob suitable
     * for KMS-envelope encryption + DynamoDB storage.
     *
     * Retained for the v1 → v2 storage migration path. New code should
     * use `applyLoaded` (load entries from v2 table) + `takeDiff`
     * (extract per-op delta to persist) instead.
     */
    dumpState(): string;
    /**
     * Encrypt an application message in the given group. The
     * returned string is base64 of the TLS-serialized
     * MlsMessageOut wire payload.
     */
    encryptApplicationMessage(group_id_b64: string, plaintext_b64: string): string;
    /**
     * Export the GroupInfo for a freshly-created group as
     * TLS-serialized base64 — the `mls_group_init` the IdP wants in
     * `POST /v1/groups`, which it hashes into the canonical
     * mls_group_id every peer agrees on. Call right after
     * `createGroup`, before `addMember`. Read-only.
     */
    exportGroupInfo(group_id_b64: string): string;
    /**
     * Wipe local MlsGroup state for a dissolved group. Idempotent:
     * calling on an absent group is a no-op. Subsequent
     * `processInbound` for the same group_id surfaces
     * `GroupNotFound` (the subscriber drops it silently).
     */
    forgetGroup(group_id_b64: string): void;
    /**
     * Generate a fresh KeyPackage and return it as base64 of the TLS
     * serialization. Mutates internal state — caller MUST call
     * `dumpState()` and persist before discarding the handle, or the
     * generated KeyPackage will never be decryptable.
     */
    generateKeyPackage(): string;
    /**
     * Return the bot's current MLS epoch for the named group.
     * Used to populate `payload.epoch` on `group_chat.message`
     * events the bot sends back to the IDP.
     */
    groupEpoch(group_id_b64: string): bigint;
    /**
     * Process an inbound private/public message. Returns a
     * JSON-serialized `InboundResult` — see Rust-side docs for
     * the schema.
     */
    processInbound(message_b64: string): string;
    /**
     * Process an MLS Welcome and join the new group. Returns a
     * JSON-serialized `JoinedGroupInfo`. The new group state is
     * persisted into provider storage; caller MUST `dumpState`
     * + persist before discarding this handle.
     */
    processWelcome(welcome_b64: string): string;
    /**
     * Remove a member by leaf index. Returns JSON `CommitResult`.
     */
    removeMember(group_id_b64: string, member_leaf_index: number): string;
    /**
     * Restore a bot client from a previously-dumped (base64) state blob.
     */
    static restoreBotClient(bot_did: string, state_b64: string): BotMlsClient;
    /**
     * Discard any locally-prepared-but-not-yet-published commit.
     * Used when committer authority is reassigned away from us.
     */
    rollbackPendingCommit(group_id_b64: string): void;
    /**
     * Rotate the bot's own leaf without changing membership.
     * Returns JSON `CommitResult`. The caller broadcasts the
     * commit to advance other members' epochs.
     */
    selfUpdate(group_id_b64: string): string;
    /**
     * Snapshot the current storage map as the baseline for the next
     * `takeDiff`. Call this immediately before each state-mutating op
     * so the diff captures exactly that op's writes/deletes.
     */
    snapshotBaseline(): void;
    /**
     * Extract the writes + deletes since the last `snapshotBaseline`.
     * Returns a JSON object `{ writes: [[k_b64,v_b64], ...], deletes:
     * [k_b64, ...] }`. Resets the baseline to the current state.
     */
    takeDiffJson(): string;
    /**
     * Bot DID this handle is bound to.
     */
    readonly botDid: string;
}

/**
 * Durable MLS client. Constructed via the async
 * [`createPersistentBotClient`] free function below; this opaque
 * handle wraps the client + its backing `IndexedDbRawKv` so each
 * state-mutating method can await a flush before returning.
 */
export class PersistentBotMlsClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add a peer to an existing group. Returns JSON
     * `AddMemberResult`.
     */
    addMember(group_id_b64: string, key_package_b64: string): Promise<string>;
    /**
     * Commit every pending queued proposal.
     */
    commitPendingProposals(group_id_b64: string): Promise<string>;
    /**
     * Author a fresh group with this client as sole creator.
     * Returns JSON `JoinedGroupInfo`.
     */
    createGroup(group_id_b64: string): Promise<string>;
    /**
     * Destroy a group. Returns JSON `DestroyGroupResult`.
     */
    destroyGroup(group_id_b64: string, farewell_plaintext_b64: string): Promise<string>;
    /**
     * Encrypt an application message in `group_id_b64`. Plaintext
     * is passed as base64. Returns base64 of the wire payload.
     */
    encryptApplicationMessage(group_id_b64: string, plaintext_b64: string): Promise<string>;
    /**
     * Export the GroupInfo for a freshly-created group as
     * TLS-serialized base64. This is what the IdP wants in its
     * `POST /v1/groups { mls_group_init: <this> }` body — it
     * hashes the bytes to derive the canonical mls_group_id
     * that every peer ends up agreeing on. Read-only; no
     * state mutation, no flush.
     */
    exportGroupInfo(group_id_b64: string): Promise<string>;
    /**
     * Explicit flush — drain the pending queue without doing
     * any new MLS op first. Useful when JS wants to be defensive
     * (e.g. before a tab-close handler) or to drain any tail
     * queue from a prior method that bailed before its own
     * flush completed. Idempotent — no-op when queue is empty.
     */
    flushPending(): Promise<void>;
    /**
     * Wipe local state for a dissolved group. Idempotent.
     */
    forgetGroup(group_id_b64: string): Promise<void>;
    /**
     * Generate a fresh KeyPackage. Returns the base64-encoded
     * TLS-serialized KeyPackage. Awaits IDB flush before
     * resolving so the private credentials openmls just minted
     * are durable before JS sees the KeyPackage bytes (and
     * before the caller publishes them to the IdP).
     */
    generateKeyPackage(): Promise<string>;
    /**
     * Current MLS epoch for the named group. Read-only — no
     * flush needed.
     */
    groupEpoch(group_id_b64: string): bigint;
    /**
     * Process an inbound MLS message. Returns JSON
     * `InboundResult` — see Rust-side docs for the schema.
     */
    processInbound(message_b64: string): Promise<string>;
    /**
     * Process an MLS Welcome and join the new group.
     */
    processWelcome(welcome_b64: string): Promise<string>;
    /**
     * Remove a member by leaf index. Returns JSON `CommitResult`.
     */
    removeMember(group_id_b64: string, member_leaf_index: number): Promise<string>;
    /**
     * Discard a locally-prepared-but-not-yet-published commit.
     */
    rollbackPendingCommit(group_id_b64: string): Promise<void>;
    /**
     * Rotate this client's own leaf without changing membership.
     */
    selfUpdate(group_id_b64: string): Promise<string>;
    /**
     * Bot DID this handle is bound to.
     */
    readonly botDid: string;
}

/**
 * Returns a JSON-serialized [`CiphersuiteSupportReport`]. Useful as a smoke
 * test from the credential-service test harness.
 */
export function ciphersuiteSupportJson(): string;

/**
 * Device-consistency reconcile decision for ONE group member — the SAME
 * pure logic native runs (lastid-mls-membership). Input JSON:
 * `{ inventory_leaf_count, inventory_device_ids, active_in_group,
 * pending_in_group, live_device_ids }`. Output JSON:
 * `{ backfill_device_ids, evict_device_ids, add_device_ids, action }`.
 * The JS caller does the I/O (fetch device lists / key packages, submit)
 * and the openmls mechanics (`addMembers`); this just decides.
 */
export function computeMemberReconcilePlan(input_json: string): string;

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
 */
export function createPersistentBotClient(bot_did: string): Promise<PersistentBotMlsClient>;

/**
 * Install a panic hook that pipes Rust panics to the JS console. Call once.
 */
export function init(): void;

/**
 * The target ciphersuite code point as a `u32` (JS-friendly).
 */
export function targetCiphersuiteCodePoint(): number;
