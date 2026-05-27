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

  /** Inbound operator chat message decrypted → confirm receipt + start typing. */
  onOperatorMessage(groupId) {
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
    }
    // 'received' → a `group_chat.read`-style receipt. Deferred to Phase 1b: it
    // needs the operator message_id + the IdP status-event payload shape. The
    // state machine already produces the action, so 1b is pure wiring here.
  }
}
