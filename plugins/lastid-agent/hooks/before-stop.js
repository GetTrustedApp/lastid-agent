#!/usr/bin/env node
/**
 * Stop hook (Claude Code fires it when the agent's turn ends).
 *
 * Two responsibilities, both best-effort and non-blocking:
 *
 * 1. **Presence turn-end.** Touch the `turn_end` signal so the listener
 *    clears the "working"/"typing" status at the PRECISE end of the turn
 *    rather than waiting on the slow maxMs idle backstop. This is the whole
 *    point of working-until-turn-end — without it, "working" lingers for the
 *    full backstop window after the agent stops.
 *
 * 2. **Audit flush.** Flush any buffered audit records (currently a no-op
 *    stub; the listener is the real chain writer).
 *
 * IMPORTANT: this file is SELF-RUNNING — it executes on `node before-stop.js`,
 * the way hooks.json invokes it. It must NOT be a bare `export default` that
 * never runs (that was the bug: the function was defined but never called, AND
 * the hook wasn't wired). It is registered in hooks.json under the "Stop"
 * event; tests/hooks-wiring.test.js locks BOTH the wiring and the
 * self-run-fires-turn_end behaviour — losing either silently breaks the clear.
 */
import { flushAuditLog } from '../lib/audit-log.js';
import { resolveScope } from '../lib/scope.js';
import { touchSignal } from '../lib/presence-activity.js';

try {
  touchSignal(resolveScope(), 'turn_end');
} catch {
  /* best-effort — the status will still clear on the maxMs backstop */
}

try {
  await flushAuditLog();
} catch (err) {
  process.stderr.write(`[lastid-agent] audit-log flush failed: ${err?.message ?? err}\n`);
}

process.exit(0);
