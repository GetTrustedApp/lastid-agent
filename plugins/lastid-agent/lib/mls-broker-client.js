/**
 * Broker-backed MLS client (MLS-into-broker, unit B3).
 *
 * A duck-typed stand-in for {@link import('./mls-client.js').MlsClient} whose
 * every method delegates to the signed broker over IPC, so a BROKER-NATIVE
 * (P-256 `zDn…`) agent's listener drives MLS through the broker — which now
 * SERVES the openmls primitives — instead of a node wasm openmls handle. The
 * result: operator↔agent chat with ZERO MLS key material in node.
 *
 * It is consumed UNCHANGED by lib/mls-dispatch.js, lib/mls-publish.js, and the
 * send path because it returns the EXACT shapes the wasm-backed MlsClient
 * returns. The wasm client JSON.parses some wasm method results into objects and
 * returns others as raw strings; the broker already replies with structured JSON
 * bodies, so this client reads the matching field/object off the body rather than
 * parsing a string:
 *
 *   wasm MlsClient                         | broker client (this file)
 *   ---------------------------------------|-----------------------------------------
 *   generateKeyPackage() → string          | body.key_package (string)
 *   processWelcome() → JoinedGroupInfo obj | body (JoinedGroupInfo object)
 *   createGroup() → JoinedGroupInfo obj     | body (JoinedGroupInfo object)
 *   exportGroupInfo() → string             | body.group_info (string)
 *   addMember()/addMembers() → AddMember   | body (AddMemberResult object)
 *   removeMember()/commitPending() → Commit| body (CommitResult object)
 *   processInbound() → InboundResult obj    | body (InboundResult object)
 *   encryptApplicationMessage() → string   | body.message (string)
 *   groupEpoch() → BigInt (sync wasm)       | Number(body.epoch) — see note below
 *   forgetGroup()/rollbackPending() → void  | undefined
 *   bindGroupIdMapping() → void             | undefined
 *
 * groupEpoch NOTE: the standalone wasm PersistentBotMlsClient returned a BigInt,
 * but the ONLY consumer of groupEpoch in this codebase (agent-send.js:315) wraps
 * the result in `Number(...)` already, and no caller does BigInt arithmetic on
 * it. So this client returns a plain Number — ergonomic, JSON-friendly, and
 * loss-free for any realistic epoch. (Callers `await` it; awaiting a Number just
 * yields it, exactly as awaiting the wasm BigInt did.)
 *
 * agentDid / deviceId are the values threaded in from the listener (deviceId is
 * the resolved keychain-pinned `md-…`). free()/persist() are no-ops: the broker
 * owns durability + the handle lifecycle, so there is nothing for node to flush
 * or release.
 */
import { brokerMlsCall } from './broker-ipc.js';

/**
 * @typedef {object} MlsBrokerClientOptions
 * @property {string} [scope]      Defaults to 'main'.
 * @property {string} agentDid     This agent's DID (for the `agentDid` getter).
 * @property {string|null} [deviceId] The resolved `md-…` device id (threaded from the listener).
 * @property {typeof brokerMlsCall} [call]  Injectable IPC seam for tests; defaults to brokerMlsCall.
 */

export class MlsBrokerClient {
  #scope;
  #agentDid;
  #deviceId;
  #call;

  /** @param {MlsBrokerClientOptions} opts */
  constructor({ scope = 'main', agentDid, deviceId = null, call = brokerMlsCall } = {}) {
    if (!agentDid) throw new Error('MlsBrokerClient: agentDid required');
    this.#scope = scope ?? 'main';
    this.#agentDid = agentDid;
    this.#deviceId = deviceId ?? null;
    this.#call = call;
  }

  /** This agent's DID — read by the dispatcher's self-echo / committer checks. */
  get agentDid() {
    return this.#agentDid;
  }

  /**
   * This agent's resolved MLS device_id (the keychain-pinned `md-…`). The single
   * source mls-publish.js reads to key the KeyPackage store — same contract as
   * the wasm client's `deviceId` getter.
   */
  get deviceId() {
    return this.#deviceId;
  }

  #mls(kind, fields) {
    return this.#call({ scope: this.#scope, kind, fields });
  }

  /** Generate a fresh MLS KeyPackage. Returns the base64 public KeyPackage string. */
  async generateKeyPackage() {
    const body = await this.#mls('mls_generate_key_package', {});
    return body.key_package;
  }

  /**
   * Accept an MLS Welcome that adds this agent to a group. Returns the
   * JoinedGroupInfo { group_id_b64, member_count, epoch }. The IdP group UUID is
   * passed only when provided (parity with the wasm client's `idpGroupId ?? null`
   * — but here we omit the field entirely when absent so the broker sees no key).
   */
  async processWelcome(welcomeB64, idpGroupId) {
    const fields = { welcome_b64: welcomeB64 };
    if (idpGroupId != null) fields.idp_group_id = idpGroupId;
    return this.#mls('mls_process_welcome', fields);
  }

  /**
   * Seed the IdP-UUID → openmls-id mapping for a group joined in a prior session.
   * Void in the wasm client; void here too.
   */
  async bindGroupIdMapping(idpGroupId, openmlsB64) {
    await this.#mls('mls_bind_group_id', { idp_group_id: idpGroupId, openmls_b64: openmlsB64 });
  }

  /** Author a fresh MLS group with this agent as sole creator. Returns JoinedGroupInfo. */
  async createGroup(groupIdB64) {
    return this.#mls('mls_create_group', { group_id_b64: groupIdB64 });
  }

  /** Export the group's GroupInfo as base64 TLS. Returns the string. */
  async exportGroupInfo(groupIdB64) {
    const body = await this.#mls('mls_export_group_info', { group_id_b64: groupIdB64 });
    return body.group_info;
  }

  /**
   * Add a peer (base64-TLS KeyPackage) to a group this agent owns. Returns the
   * AddMemberResult { commit_b64, welcome_b64, new_epoch, assigned_leaf_indices }.
   */
  async addMember(groupIdB64, keyPackageB64) {
    return this.#mls('mls_add_member', {
      group_id_b64: groupIdB64,
      key_package_b64: keyPackageB64,
    });
  }

  /** Add several peers in ONE commit. Returns the AddMemberResult. */
  async addMembers(groupIdB64, keyPackagesB64) {
    return this.#mls('mls_add_members', {
      group_id_b64: groupIdB64,
      key_packages_b64: keyPackagesB64,
    });
  }

  /** Remove a member by MLS leaf index. Returns the CommitResult { commit_b64, new_epoch }. */
  async removeMember(groupIdB64, leafIndex) {
    return this.#mls('mls_remove_member', { group_id_b64: groupIdB64, leaf_index: leafIndex });
  }

  /** Process an inbound message — application, commit, or proposal. Returns the InboundResult. */
  async processInbound(messageB64) {
    return this.#mls('mls_process_inbound', { message_b64: messageB64 });
  }

  /** Encrypt a payload for the named group. Returns the base64 MLS wire payload string. */
  async encryptApplicationMessage(groupIdB64, plaintextB64) {
    const body = await this.#mls('mls_encrypt_app_message', {
      group_id_b64: groupIdB64,
      plaintext_b64: plaintextB64,
    });
    return body.message;
  }

  /**
   * Current MLS epoch for a group. Returns a Number (see the file header's
   * groupEpoch NOTE — the lone consumer Number()-wraps it and none does BigInt
   * math, so a plain Number matches the wasm client's behaviour at every call
   * site without dragging BigInt through the IPC boundary).
   */
  async groupEpoch(groupIdB64) {
    const body = await this.#mls('mls_group_epoch', { group_id_b64: groupIdB64 });
    return Number(body.epoch);
  }

  /** Wipe local MlsGroup state for a dissolved group. Void. */
  async forgetGroup(groupIdB64) {
    await this.#mls('mls_forget_group', { group_id_b64: groupIdB64 });
  }

  /** Commit every pending proposal queued for the group. Returns the CommitResult. */
  async commitPendingProposals(groupIdB64) {
    return this.#mls('mls_commit_pending', { group_id_b64: groupIdB64 });
  }

  /** Discard any locally-prepared-but-not-yet-published commit. Void. */
  async rollbackPendingCommit(groupIdB64) {
    await this.#mls('mls_rollback_pending', { group_id_b64: groupIdB64 });
  }

  /**
   * No-op — the broker auto-persists after every state-mutating op, so node has
   * nothing to flush. Kept for MlsClient source compatibility.
   */
  async persist() {
    /* broker owns durability */
  }

  /**
   * No-op — the broker owns the MLS handle's lifecycle; node holds no wasm handle
   * to free. Kept for MlsClient source compatibility (the listener's shutdown
   * calls free() on whatever client it built).
   */
  free() {
    /* broker owns the handle */
  }
}

/**
 * Factory mirroring the MlsClient construction sites — build a broker-backed MLS
 * client duck-typed to MlsClient. The listener uses this for a brokerNative zDn…
 * agent so no node wasm orchestrator is built (which would split MLS state with
 * the broker's).
 *
 * @param {MlsBrokerClientOptions} opts
 * @returns {MlsBrokerClient}
 */
export function makeMlsBrokerClient(opts) {
  return new MlsBrokerClient(opts);
}
