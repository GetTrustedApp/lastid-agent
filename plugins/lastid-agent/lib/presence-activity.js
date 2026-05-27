/**
 * Agent presence signals — tiny timestamp files the short-lived hook processes
 * touch, and the long-lived listener reads on each presence tick. Channel-
 * agnostic (a hook fired); the listener only consults them while a conversation
 * window is open, so CLI work never surfaces as presence.
 *
 * Three signals drive the operator-facing presence (see typing-presence.js):
 *   - activity:  PostToolUse touched it (any tool ran) → keep "working" alive.
 *   - sending:   PreToolUse on the send-message tool touched it → "typing"
 *                (the agent is composing/sending a message right now).
 *   - turn_end:  the before-stop hook touched it (the agent's turn ended) →
 *                clear "working"/"typing" precisely, not on an idle timeout.
 *
 * Best-effort + synchronous (hooks are short-lived) — a write failure just
 * means the indicator doesn't refresh; it never blocks the tool or the turn.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

/** Valid signal names (file basenames under the scope dir). */
const SIGNALS = Object.freeze({
  activity: 'presence-activity',
  sending: 'presence-sending',
  turn_end: 'presence-turn-end',
});

function signalPath(scope, signal) {
  const base = SIGNALS[signal];
  if (!base) throw new Error(`unknown presence signal: ${signal}`);
  return join(homedir(), '.lastid-agent', scope ?? 'main', base);
}

/** Back-compat: the original activity-file path accessor. */
export function activityPath(scope) {
  return signalPath(scope, 'activity');
}

/** Record a presence signal (timestamp, ms). Best-effort + synchronous. */
export function touchSignal(scope, signal, now = Date.now()) {
  try {
    const p = signalPath(scope, signal);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, String(now));
  } catch {
    /* best-effort — the indicator just won't refresh */
  }
}

/** Last timestamp (ms) for a signal, or 0 if none/unreadable. */
export function readSignalTs(scope, signal) {
  try {
    const v = Number.parseInt(readFileSync(signalPath(scope, signal), 'utf-8').trim(), 10);
    return Number.isFinite(v) ? v : 0;
  } catch {
    return 0;
  }
}

/** Record that the agent just did something (any tool). Back-compat wrapper. */
export function touchActivity(scope, now = Date.now()) {
  touchSignal(scope, 'activity', now);
}

/** Last activity timestamp (ms), or 0. Back-compat wrapper. */
export function readActivityTs(scope) {
  return readSignalTs(scope, 'activity');
}
