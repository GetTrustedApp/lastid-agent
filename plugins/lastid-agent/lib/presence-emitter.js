/**
 * Stateful wrapper that turns presence-state-machine actions into WebSocket
 * frames on the listener (the sole WS writer). Holds one window per conversation
 * (keyed by the IdP group id) and emits:
 *   - group_chat.typing with BOTH `is_typing` (sending a message) and `working`
 *     (processing the turn) — the IdP relays the full payload, so no IdP change.
 *   - group_chat.read (the receipt) on the first `received` action.
 * Clock + send are injected so it's unit-testable.
 *
 * See typing-presence.js for the pure decision logic. Channel-vs-CLI
 * differentiation is structural: only `onOperatorMessage` opens a window.
 */
import {
  reducePresence,
  initialPresence,
  DEFAULT_PRESENCE_CONFIG,
} from './typing-presence.js';
import { reactionWireName } from './reactions.js';

export class PresenceEmitter {
  #send;
  #userDid;
  #now;
  #config;
  #byGroup = new Map();
  // Per group: the last operator message's { messageId, senderDid }, so the
  // `received` action can emit a read receipt the IdP can proxy back to the
  // operator (it needs both the message_id and the recipient/operator DID).
  #lastMessageByGroup = new Map();

  /**
   * @param {object} opts
   * @param {(frame: object) => void} opts.send  the listener's ws.send
   * @param {string} opts.userDid  the agent's DID (the "typer"/worker)
   * @param {() => number} [opts.now]  injectable clock (ms)
   * @param {{idleMs:number,maxMs:number}} [opts.config]
   */
  constructor({ send, userDid, now = () => Date.now(), config = DEFAULT_PRESENCE_CONFIG }) {
    if (typeof send !== 'function') throw new Error('PresenceEmitter: send required');
    this.#send = send;
    this.#userDid = userDid ?? null;
    this.#now = now;
    this.#config = config;
  }

  #apply(groupId, event) {
    if (!groupId) return;
    const prev = this.#byGroup.get(groupId) ?? initialPresence();
    const { state, actions } = reducePresence(prev, event, this.#now(), this.#config);
    this.#byGroup.set(groupId, state);
    if (actions.includes('received')) this.#emitRead(groupId);
    // Any working/typing transition → emit the CURRENT combined presence once
    // (one frame carrying both flags, not one per action).
    if (
      actions.some(
        (a) => a === 'working_on' || a === 'working_off' || a === 'typing_on' || a === 'typing_off',
      )
    ) {
      this.#emitPresence(groupId, state);
    }
  }

  /**
   * Inbound operator chat message decrypted → confirm receipt (read) + start the
   * working status. `info` carries `{ messageId, senderDid }` so the read
   * receipt can name the message and route back to the operator (both required;
   * absent → working only, no receipt).
   */
  onOperatorMessage(groupId, info = {}) {
    const messageId = typeof info?.messageId === 'string' ? info.messageId : null;
    const senderDid = typeof info?.senderDid === 'string' ? info.senderDid : null;
    if (groupId && messageId && senderDid) {
      this.#lastMessageByGroup.set(groupId, { messageId, senderDid });
    }
    this.#apply(groupId, { type: 'operator_message' });
  }

  /** The agent is sending a message (pre-tool-use on the send tool) → typing on
   *  for every open window (the send goes to the operator we're working with). */
  onSending() {
    for (const groupId of this.#byGroup.keys()) this.#apply(groupId, { type: 'sending' });
  }

  /** A reply landed for this group → clear the typing dots (working continues). */
  onAgentReply(groupId) {
    this.#apply(groupId, { type: 'agent_reply' });
  }

  /** The agent's turn ended (before-stop hook) → clear working + typing and
   *  close every open window. */
  onTurnEnd() {
    for (const groupId of [...this.#byGroup.keys()]) {
      this.#apply(groupId, { type: 'turn_end' });
      const st = this.#byGroup.get(groupId);
      if (st && st.openedAt === null) this.#byGroup.delete(groupId);
    }
  }

  /** The agent did some work (a tool call) — keep every open window alive. */
  noteActivity() {
    for (const groupId of this.#byGroup.keys()) this.#apply(groupId, { type: 'activity' });
  }

  /** Heartbeat + timeout evaluation for every tracked window. Prunes closed ones. */
  tick() {
    for (const groupId of [...this.#byGroup.keys()]) {
      this.#apply(groupId, { type: 'tick' });
      const st = this.#byGroup.get(groupId);
      if (st && st.openedAt === null && !st.workingOn && !st.typingOn) this.#byGroup.delete(groupId);
    }
  }

  #emitPresence(groupId, state) {
    this.#send({
      type: 'group_chat.typing',
      timestamp: new Date().toISOString(),
      payload: {
        group_id: groupId,
        user_did: this.#userDid,
        // is_typing → "sending a message" dots; working → "processing the turn".
        is_typing: state.typingOn,
        working: state.workingOn,
      },
    });
  }

  /**
   * React to the operator's most recent message in `groupId` with `emoji`.
   * Sibling to #emitRead: it reuses the same `#lastMessageByGroup` record (the
   * read-receipt path already captured which message the operator sent) so the
   * agent never has to know — or be handed — a message id. Emits a plaintext
   * `group_chat.reaction` frame the IdP relays to the group; clients render the
   * badge on that message, exactly like a human tapping a reaction.
   *
   * Returns `{ sent, ... }`: `{sent:true, messageId, reaction}` on success;
   * `{sent:false, reason}` when there's no message to react to
   * ('no_target_message') or the emoji isn't a supported reaction
   * ('unsupported_emoji'). Neither failure is retryable, so the caller drops the
   * request rather than wedging the outbox.
   */
  reactToLastOperatorMessage(groupId, emoji, action = 'add') {
    if (!groupId) return { sent: false, reason: 'no_group' };
    const info = this.#lastMessageByGroup.get(groupId);
    if (!info || !info.messageId) return { sent: false, reason: 'no_target_message' };
    const wire = reactionWireName(emoji);
    if (!wire) return { sent: false, reason: 'unsupported_emoji' };
    const type =
      action === 'remove' ? 'group_chat.reaction_removed' : 'group_chat.reaction';
    const now = new Date().toISOString();
    this.#send({
      type,
      // Fresh UUID per outbound frame. Reusing the targeted message_id (the
      // earlier shape) collides with the operator's original group_chat.message
      // correlation_id and the IdP's replay detector rejects the frame with
      // REPLAY_ATTACK_DETECTED — silently dropping fanout, so no badge ever
      // lands on the recipient. Targeting is via payload.message_id; the
      // correlation_id is a per-EVENT request id, must be unique.
      correlation_id: freshCorrelationId(),
      timestamp: now,
      payload: {
        group_id: groupId,
        message_id: info.messageId,
        reactor_did: this.#userDid, // the agent is the reactor
        reaction: wire,
        timestamp: now,
      },
    });
    return { sent: true, messageId: info.messageId, reaction: wire, action };
  }

  #emitRead(groupId) {
    // Read receipt: the agent received + read the operator's message. Shape
    // matches the IdP's handleStatusEvent, which proxies the status back to
    // recipient_did (the operator who sent it). Both message_id and
    // recipient_did are required there — skip if we lack either.
    const info = this.#lastMessageByGroup.get(groupId);
    if (!info || !info.messageId || !info.senderDid) return;
    this.#send({
      type: 'group_chat.read',
      // Fresh UUID per outbound frame — reusing the targeted message_id (the
      // earlier shape) collided with the operator's original
      // group_chat.message correlation_id and tripped the IdP's replay
      // detector, so the receipt never landed. Targeting is via
      // payload.message_id; correlation_id is a per-EVENT request id.
      correlation_id: freshCorrelationId(),
      timestamp: new Date().toISOString(),
      payload: {
        group_id: groupId,
        message_id: info.messageId,
        sender_did: this.#userDid, // the reader (this agent) reporting the status
        recipient_did: info.senderDid, // the operator who sent it → receives the receipt
        read_at: new Date().toISOString(),
      },
    });
  }
}

/** Per-frame unique id for the IdP's replay-detection window. UUIDv4 from the
 *  platform crypto where available; small random fallback for older runtimes
 *  (still enough entropy for the dedupe window). */
function freshCorrelationId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
