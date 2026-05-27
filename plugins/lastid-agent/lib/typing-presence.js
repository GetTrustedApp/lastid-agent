/**
 * Pure state machine for the operator-facing presence on a channel conversation.
 * Two INDEPENDENT signals:
 *   - working: the agent is processing the operator's turn. ON from the inbound
 *     message until the turn ends (the before-stop hook). Steady — it does NOT
 *     flicker off on each intermediate reply.
 *   - typing:  the agent is sending a message right now. ON when the agent calls
 *     the send-message tool (pre-tool-use), OFF when that message lands.
 * ("Typing when sending a message; working when working.")
 *
 * The listener daemon drives this — it's the sole WS writer and sees both ends
 * of a turn (decrypts the operator's inbound message, drains the agent's reply,
 * sees tool activity via the audit spool + a pre-send signal + a turn-end
 * signal). This module decides ONLY what to emit, with no I/O, so it's
 * unit-tested deterministically with an injected clock.
 *
 * Lifecycle of one conversation window:
 *   operator_message → open window; emit `received` (read receipt) + working_on.
 *   sending          → typing_on (a message is being composed/sent).
 *   agent_reply      → typing_off (the message landed). Working continues.
 *   activity         → refresh the window + (re)assert working.
 *   turn_end         → working_off (+ typing_off) and CLOSE — the precise end,
 *                      from the agent's before-stop hook.
 *   tick             → while open and under the hard cap, re-emit working_on as
 *                      a keep-alive (clients auto-clear after a few idle seconds).
 *                      Past maxMs (a missed before-stop) → close as a backstop.
 *
 * Channel-vs-CLI differentiation is STRUCTURAL: only an `operator_message` opens
 * a window, produced solely when the listener decrypts an inbound operator
 * message. CLI work never opens one, so nothing is ever emitted for it.
 */

export const DEFAULT_PRESENCE_CONFIG = Object.freeze({
  /** Retained for callers/tests; not used to close working (turn_end is the
   *  normal close). Working is turn-scoped, not idle-scoped. */
  idleMs: 12_000,
  /** Hard cap on a single window — a backstop so a missed turn_end (crashed
   *  before-stop) can't pin "working" on forever. */
  maxMs: 15 * 60_000,
});

/** A fresh, closed presence window. */
export function initialPresence() {
  return { openedAt: null, lastActivityAt: 0, workingOn: false, typingOn: false };
}

/**
 * Apply one event to the presence state. Returns `{ state, actions }`, where
 * `actions` is an ordered subset of
 * `['received','working_on','working_off','typing_on','typing_off']` the caller
 * should reflect on the wire. PURE — no I/O, clock injected.
 *
 * @param {{openedAt:number|null,lastActivityAt:number,workingOn:boolean,typingOn:boolean}} state
 * @param {{type:'operator_message'|'sending'|'activity'|'agent_reply'|'turn_end'|'tick'}} event
 * @param {number} now epoch ms
 * @param {{idleMs:number,maxMs:number}} [config]
 * @returns {{state:object, actions:string[]}}
 */
export function reducePresence(state, event, now, config = DEFAULT_PRESENCE_CONFIG) {
  switch (event?.type) {
    case 'operator_message':
      // New inbound: confirm receipt (read) + start the WORKING status for the
      // whole turn. Not typing — typing is only for an actual message send.
      return {
        state: { openedAt: now, lastActivityAt: now, workingOn: true, typingOn: false },
        actions: ['received', 'working_on'],
      };

    case 'sending': {
      // The agent is sending a message (pre-tool-use on the send tool) → show
      // the typing dots until it lands. Only meaningful inside an open turn.
      if (state.openedAt === null || state.typingOn) return { state, actions: [] };
      return { state: { ...state, typingOn: true }, actions: ['typing_on'] };
    }

    case 'agent_reply':
      // The message landed → clear the typing dots. Working CONTINUES (the turn
      // isn't over just because one message went out — that's the whole point).
      if (!state.typingOn) return { state, actions: [] };
      return { state: { ...state, typingOn: false }, actions: ['typing_off'] };

    case 'activity': {
      // A tool call → the agent is working. Refresh the window + (re)assert
      // working. Ignored with no open window — CLI work never leaks presence.
      if (state.openedAt === null) return { state, actions: [] };
      const next = { ...state, lastActivityAt: now };
      if (!next.workingOn) {
        next.workingOn = true;
        return { state: next, actions: ['working_on'] };
      }
      return { state: next, actions: [] };
    }

    case 'turn_end': {
      // The agent's turn ended (before-stop hook) — the precise close. Clear
      // working + any lingering typing and close the window.
      if (state.openedAt === null) return { state, actions: [] };
      const actions = [];
      if (state.typingOn) actions.push('typing_off');
      if (state.workingOn) actions.push('working_off');
      return { state: initialPresence(), actions };
    }

    case 'tick': {
      if (state.openedAt === null) return { state, actions: [] };
      if (now - state.openedAt < config.maxMs) {
        // Keep-alive: re-assert working while the window is open. A tick never
        // turns typing on/off (only sending/agent_reply do).
        return { state, actions: state.workingOn ? ['working_on'] : [] };
      }
      // Past the hard cap (a missed turn_end) → close as a backstop.
      const actions = [];
      if (state.typingOn) actions.push('typing_off');
      if (state.workingOn) actions.push('working_off');
      return { state: initialPresence(), actions };
    }

    default:
      return { state, actions: [] };
  }
}
