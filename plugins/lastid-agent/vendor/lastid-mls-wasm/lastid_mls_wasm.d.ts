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
 * JS-side handle around the IndexedDB-backed wasm orchestrator. Cheap to
 * clone (each field is Arc-shared) — but `wasm-bindgen` exposes it as an
 * opaque handle; JS sees `MlsOrchestrator` and uses its methods.
 */
export class MlsOrchestrator {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add a peer to an existing group. Resolves to JSON `AddMemberResult`.
     */
    addMember(group_id_b64: string, key_package_b64: string): Promise<any>;
    /**
     * Add several peers in ONE commit. `key_packages_b64_json` is a JSON
     * array of base64 KeyPackages. Resolves to JSON `AddMemberResult`.
     */
    addMembers(group_id_b64: string, key_packages_b64_json: string): Promise<any>;
    /**
     * Commit every pending queued proposal. Resolves to JSON `CommitResult`.
     */
    commitPendingProposals(group_id_b64: string): Promise<any>;
    /**
     * Author a fresh group with this client as sole creator. Resolves to
     * JSON `JoinedGroupInfo`.
     */
    createGroup(group_id_b64: string): Promise<any>;
    /**
     * Destroy a group (self-remove + farewell). `farewell_plaintext_b64` is
     * base64. Resolves to JSON `DestroyGroupResult`.
     */
    destroyGroup(group_id_b64: string, farewell_plaintext_b64: string): Promise<any>;
    /**
     * Encrypt an application message in `group_id_b64`. `plaintext_b64` is
     * base64; resolves to base64 of the wire payload.
     */
    encryptApplicationMessage(group_id_b64: string, plaintext_b64: string): Promise<any>;
    /**
     * Export the GroupInfo for a freshly-created group (TLS-serialized
     * base64) for the IdP `POST /v1/groups` body. Read-only; no flush.
     */
    exportGroupInfo(group_id_b64: string): Promise<any>;
    /**
     * Explicit flush — drain the pending queue without a new MLS op.
     * Idempotent; no-op when the queue is empty.
     */
    flushPending(): Promise<any>;
    /**
     * Wipe local state for a dissolved group. Idempotent.
     */
    forgetGroup(group_id_b64: string): Promise<any>;
    /**
     * Generate a fresh KeyPackage (base64 TLS-serialized). Flushes before
     * resolving so the minted private credentials are durable.
     */
    generateKeyPackage(): Promise<any>;
    /**
     * Current MLS epoch for `group_id_b64`. Read-only — still serialized
     * under the op-lock so it never reads torn state mid-commit.
     */
    groupEpoch(group_id_b64: string): Promise<any>;
    /**
     * Decide whether a direct group's backing session should be reconciled
     * or rotated. Returns a Promise resolving to
     *   `{ outcome: "noop" | "archive_and_rotate" }`.
     *
     * B5 design: core returns the decision; the JS host performs the
     * archive + restart when `outcome === "archive_and_rotate"` (native
     * equivalent: `archive_direct_group_session` + `mls_start_direct_chat`).
     * Those steps touch native MLS LRU + the host's session/thread tables
     * that have no equivalent in this crate, so they stay caller-side.
     */
    maybeRotateDirectGroup(group_id: string, peer_did: string): Promise<any>;
    /**
     * Process an inbound MLS message. Resolves to JSON `InboundResult`.
     */
    processInbound(message_b64: string): Promise<any>;
    /**
     * Process an MLS Welcome and join the new group. Resolves to JSON
     * `JoinedGroupInfo`.
     */
    processWelcome(welcome_b64: string): Promise<any>;
    /**
     * Run one pass of
     * [`lastid_mls_core::reconcile::reconcile_group_device_membership_once`]
     * for `group_id`. Returns a Promise resolving to
     *   `{ changed: bool }`.
     *
     * Note: the core fn iterates ALL members of the group (not a single
     * member — that's the native + core contract); the per-member granularity
     * the planner operates on lives inside the loop, not in the entry
     * signature.
     */
    reconcileMemberDevices(group_id: string): Promise<any>;
    /**
     * Remove a member by leaf index. Resolves to JSON `CommitResult`.
     */
    removeMember(group_id_b64: string, member_leaf_index: number): Promise<any>;
    /**
     * Discard a locally-prepared-but-not-yet-published commit.
     */
    rollbackPendingCommit(group_id_b64: string): Promise<any>;
    /**
     * Rotate this client's own leaf without changing membership. Resolves
     * to JSON `CommitResult`.
     */
    selfUpdate(group_id_b64: string): Promise<any>;
    /**
     * Create + finalize a direct chat with `peer_did`. Runs:
     *   1. [`lastid_mls_core::commit_ops::create_and_register_direct_group_shell`]
     *      — mint local group + register with IdP via the transport port,
     *   2. [`lastid_mls_core::commit_ops::add_first_member_to_direct_group`]
     *      — fetch peer key packages, prepare add, submit, confirm + persist.
     *
     * Returns a Promise resolving to a plain JS object:
     *   `{ idp_group_id: string, local_group_id: string,
     *      member_count: number, epoch: number,
     *      peer_device_ids: string[] }`.
     *
     * On failure rejects with an Error carrying the
     * `GetTrustedError::MLSError` message string (so the rotation classifier
     * `is_direct_session_stale_error_message` matches across native + wasm).
     */
    startDirectChat(peer_did: string): Promise<any>;
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
     * Add several peers in ONE commit. `key_packages_b64_json` is a JSON
     * array of base64 KeyPackages. Returns JSON `AddMemberResult` (one
     * commit, one welcome). Matches the sync client's `addMembers` so
     * browser device-consistency reconcile uses the same primitive.
     */
    addMembers(group_id_b64: string, key_packages_b64_json: string): Promise<string>;
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
 * Seed the persisted IdP-UUID → openmls-group-id-b64 mapping that
 * `WasmMlsClient::group_handle(idp_uuid)` reads when the orchestrator's
 * reconcile / rotation paths look up a group by its IdP id.
 *
 * Background: `set_idp_group_id` writes this mapping when a group is
 * FRESHLY CREATED in the orchestrator path (during
 * `create_and_register_direct_group_shell`). For groups that existed
 * BEFORE that fix landed — or any group whose initial create happened
 * in a code revision that didn't write the mapping — there's no entry,
 * so `group_handle(uuid)` falls back to treating the UUID itself as
 * the openmls_b64 and `openmls_group_id()` panics on the UUID's first
 * hyphen at position 8 ("base64: InvalidByte(8, 45)") the moment the
 * caller tries to load the group.
 *
 * The console's `hydrateConversations` already knows both ids for
 * every persisted conversation record — call this once per record at
 * hydrate time to backfill the mapping idempotently. The cached
 * `IndexedDbRawKv` is shared with every other consumer of the same
 * bot_scope (see `IndexedDbRawKv::open`'s process cache), so this
 * write is immediately visible to the orchestrator's client.
 *
 * Pure RawKv I/O — touches no `PersistentBotMlsClient` handle, so it
 * can't collide with any in-flight handle method's wasm-bindgen borrow.
 * Awaits a flush so the write is durable in IDB before the Promise
 * resolves.
 */
export function bindMlsGroupIdMapping(bot_did: string, idp_group_id: string, openmls_b64: string): Promise<void>;

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

export function createMlsOrchestrator(bot_did: string, my_did: string, directory: any, transport: any, host: any): Promise<MlsOrchestrator>;

/**
 * Node-side orchestrator constructor: same shape as `createMlsOrchestrator`
 * but the RawKv backing is JS-callback-based instead of IndexedDB. The
 * callback bundle is the same `{ loadBlob, flushBlob }` shape
 * `createPersistentBotClientWithCallbacks` accepts — passing a separate
 * bundle (vs sharing the agent client's) is intentional: the agent's MLS
 * group state and the orchestrator's group-store keys both live in the same
 * `mls-state.b64`-style blob in the host's data dir, but the orchestrator's
 * reconcile/rotate paths are an independent process — they don't share an
 * in-memory cache with the agent's main client (yet). To start, give them
 * their own `loadBlob`/`flushBlob` pointing at distinct files. Future work
 * can unify the backend (mirroring how the browser's `IndexedDbRawKv::open`
 * is process-cached).
 */
export function createMlsOrchestratorWithCallbacks(bot_did: string, my_did: string, directory: any, transport: any, host: any, callbacks: any): Promise<MlsOrchestrator>;

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
 * Open or rehydrate a persistent MLS client for `bot_did` with host-
 * supplied storage callbacks. Designed for Node — the agent plugin runs
 * outside a browser so `IndexedDbRawKv` (web-sys-backed) isn't an option.
 *
 * `callbacks` is a plain JS object with two Function fields:
 *
 *   - `loadBlob(): Promise<string | null>` — invoked ONCE at open. Return
 *     the base64 of the previously-flushed state (or null / empty string
 *     for a fresh client). The format is the same length-prefixed binary
 *     `BotMlsClient::dump_state` produced, so EXISTING `mls-state.b64`
 *     files migrate just by being handed back as the load result.
 *
 *   - `flushBlob(b64: string): Promise<void>` — invoked after every
 *     state-mutating wasm method (the existing `flush(self)` async tail).
 *     Receives the FULL current KV cache as base64; the host writes it
 *     atomically (e.g. tmp + rename). Awaited so the JS Promise the
 *     wasm-bindgen method returns only resolves once the host has the
 *     blob durable.
 *
 * The returned handle is the SAME `PersistentBotMlsClient` JS class as
 * `createPersistentBotClient` returns — every method (generateKeyPackage,
 * processWelcome, encryptApplicationMessage, …) works identically. The
 * JS host doesn't see which backend it's on.
 */
export function createPersistentBotClientWithCallbacks(bot_did: string, callbacks: any): Promise<PersistentBotMlsClient>;

/**
 * Install a panic hook that pipes Rust panics to the JS console. Call once.
 */
export function init(): void;

/**
 * The target ciphersuite code point as a `u32` (JS-friendly).
 */
export function targetCiphersuiteCodePoint(): number;
