#!/usr/bin/env node
/**
 * BeforeStop hook.
 *
 * Flushes any buffered audit records to the IdP's audit endpoint
 * before the session terminates. Audit emission is best-effort —
 * failures here MUST NOT block session shutdown.
 */

import { flushAuditLog } from '../lib/audit-log.js';
import { resolveScope } from '../lib/scope.js';
import { touchSignal } from '../lib/presence-activity.js';

export default async function beforeStop(_context) {
  // Presence: the agent's turn just ended → signal turn-end so the listener
  // clears the "working"/"typing" status at the precise end of the turn (not on
  // an idle timeout). Best-effort; never blocks shutdown.
  try {
    touchSignal(resolveScope(), 'turn_end');
  } catch {
    /* best-effort */
  }
  try {
    await flushAuditLog();
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] audit-log flush failed: ${err?.message ?? err}\n`
    );
  }
  return { ok: true };
}
