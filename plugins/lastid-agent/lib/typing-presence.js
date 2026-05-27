/**
 * Pure state machine for the operator-facing "received + typing" presence on a
 * channel conversation.
 *
 * The listener daemon drives this — it's the sole WS writer and already sees
 * both ends of a channel turn (it decrypts the operator's inbound message and
 * drains the agent's reply) plus the agent's tool activity via the audit spool.
 * This module decides ONLY what to emit, with no I/O, so it's unit-tested
 * deterministically with an injected clock.
 *
 * Lifecycle of one conversation window:
 *   operator_message → open window; emit `received` (delivered → seen by agent)
 *                      and start `typing`.
 *   activity (agent tool call) → resets the idle timer; if a prior reply had
 *                      cleared typing but work continues, turn typing back on.
 *   agent_reply → clear typing (the message itself is the signal). The window
 *                      stays open so continued tool activity re-shows typing.
 *   tick → while the window is live AND typing is on, RE-EMIT typing as a
 *                      keep-alive (clients auto-clear a typing indicator after a
 *                      few seconds without a refresh). After `idleMs` with no
 *                      activity, or `maxMs` since open, close the window.
 *
 * Channel-vs-CLI differentiation is STRUCTURAL: only an `operator_message`
 * opens a window, and that event is produced solely when the listener decrypts
 * an inbound operator message. Command-line work never produces one, so no
 * window opens and no typing is ever emitted for it — there is no flag to get
 * wrong.
 */

export const DEFAULT_PRESENCE_CONFIG = Object.freeze({
  /** Stop showing typing after this long with no agent tool activity. */
  idleMs: 12_000,
  /** Hard cap on a single window — safety so typing can't get stuck on. */
  maxMs: 15 * 60_000,
});

/** A fresh, closed presence window. */
export function initialPresence() {
  return { openedAt: null, lastActivityAt: 0, typingOn: false };
}

/**
 * Apply one event to the presence state. Returns `{ state, actions }`, where
 * `actions` is an ordered subset of `['received','typing_on','typing_off']`
 * the caller should emit as wire frames. PURE — no I/O, clock is injected.
 *
 * @param {{openedAt:number|null,lastActivityAt:number,typingOn:boolean}} state
 * @param {{type:'operator_message'|'activity'|'agent_reply'|'tick'}} event
 * @param {number} now epoch ms
 * @param {{idleMs:number,maxMs:number}} [config]
 * @returns {{state:object, actions:string[]}}
 */
export function reducePresence(state, event, now, config = DEFAULT_PRESENCE_CONFIG) {
  switch (event?.type) {
    case 'operator_message':
      // New inbound from the operator: confirm receipt + start showing work.
      return {
        state: { openedAt: now, lastActivityAt: now, typingOn: true },
        actions: ['received', 'typing_on'],
      };

    case 'activity': {
      // A tool call by the agent. Only meaningful inside an open window — CLI
      // activity has no window, so it's ignored and never leaks typing.
      if (state.openedAt === null) return { state, actions: [] };
      const next = { ...state, lastActivityAt: now };
      // Resume typing if a reply had cleared it but the agent is still working
      // (and we're under the hard cap).
      if (!next.typingOn && now - next.openedAt < config.maxMs) {
        next.typingOn = true;
        return { state: next, actions: ['typing_on'] };
      }
      return { state: next, actions: [] };
    }

    case 'agent_reply':
      // The reply lands in the chat, which clears the indicator. Do NOT bump
      // activity (a reply isn't "still working") and do NOT close the window:
      // continued tool activity re-shows typing; if the agent is done, the idle
      // timer closes it.
      if (!state.typingOn) return { state, actions: [] };
      return { state: { ...state, typingOn: false }, actions: ['typing_off'] };

    case 'tick': {
      if (state.openedAt === null) return { state, actions: [] };
      const live =
        now - state.openedAt < config.maxMs && now - state.lastActivityAt < config.idleMs;
      if (live) {
        // Keep-alive heartbeat — only while typing is already on. A tick never
        // turns typing ON (that would flicker it back on right after a reply);
        // only operator_message / activity do.
        return { state, actions: state.typingOn ? ['typing_on'] : [] };
      }
      // Idle or capped → close the window; clear typing if it was on.
      return {
        state: { openedAt: null, lastActivityAt: state.lastActivityAt, typingOn: false },
        actions: state.typingOn ? ['typing_off'] : [],
      };
    }

    default:
      return { state, actions: [] };
  }
}
