/**
 * Stateful wrapper that turns presence-state-machine actions into WebSocket
 * frames. Lives in the listener (the sole WS writer). Holds one window per
 * conversation (keyed by the IdP group id) and emits `group_chat.typing`
 * frames; clock + send are injected so it's unit-testable.
 *
 * See typing-presence.js for the pure decision logic. Channel-vs-CLI
 * differentiation is structural: only `onOperatorMessage` opens a window, and
 * that's fired solely when the listener decrypts an inbound operator chat
 * message — command-line work never reaches it.
 */
import {
  reducePresence,
  initialPresence,
  DEFAULT_PRESENCE_CONFIG,
} from './typing-presence.js';

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
   * @param {string} opts.userDid  the agent's DID (the "typer")
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
    for (const action of actions) this.#emit(groupId, action);
  }

  /**
   * Inbound operator chat message decrypted → confirm receipt (read) + start
   * typing. `info` carries the operator message's `{ messageId, senderDid }` so
   * the read receipt can name the message and route back to the operator. Both
   * are required to emit a receipt (the IdP relay needs message_id +
   * recipient_did); absent → typing only, no receipt.
   */
  onOperatorMessage(groupId, info = {}) {
    const messageId = typeof info?.messageId === 'string' ? info.messageId : null;
    const senderDid = typeof info?.senderDid === 'string' ? info.senderDid : null;
    if (groupId && messageId && senderDid) {
      this.#lastMessageByGroup.set(groupId, { messageId, senderDid });
    }
    this.#apply(groupId, { type: 'operator_message' });
  }

  /** The agent sent a reply to this group → clear the typing indicator. */
  onAgentReply(groupId) {
    this.#apply(groupId, { type: 'agent_reply' });
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
      if (st && st.openedAt === null && !st.typingOn) this.#byGroup.delete(groupId);
    }
  }

  #emit(groupId, action) {
    if (action === 'typing_on' || action === 'typing_off') {
      this.#send({
        type: 'group_chat.typing',
        timestamp: new Date().toISOString(),
        payload: {
          group_id: groupId,
          user_did: this.#userDid,
          is_typing: action === 'typing_on',
        },
      });
      return;
    }
    if (action === 'received') {
      // Read receipt: the agent received + read the operator's message. Shape
      // matches the IdP's handleStatusEvent, which proxies the status back to
      // recipient_did (the operator who sent it). Both message_id and
      // recipient_did are required there — skip if we lack either (a malformed
      // receipt would error the relay).
      const info = this.#lastMessageByGroup.get(groupId);
      if (!info || !info.messageId || !info.senderDid) return;
      this.#send({
        type: 'group_chat.read',
        correlation_id: info.messageId,
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
}
