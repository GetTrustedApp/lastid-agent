#!/usr/bin/env node
/**
 * SessionEnd hook — graceful listener cleanup.
 *
 * Stops THIS scope's listener when the Claude session ends cleanly (the docs'
 * reasons: clear / logout / resume / prompt_input_exit / other). This is the
 * fast, clean path: no waiting for the listener's poll.
 *
 * It is NOT the only guard — and can't be: SessionEnd does NOT fire on
 * Ctrl-C-twice / hard-kill / crash. Those are covered by:
 *   - the listener's parent-PID WATCHDOG (self-exits when its owning session
 *     dies), and
 *   - reap-on-SessionStart (the next session reaps any stray for the scope
 *     before spawning its own).
 * Three layers so a stray listener can never race the scope's MLS state.
 *
 * Scoped: only ever stops THIS scope's listener (never another scope's).
 * Best-effort + never throws — the session is already closing.
 */
import { resolveScope } from '../lib/scope.js';
import { stopListener } from '../lib/listener-daemon.js';

const scope = resolveScope();
try {
  const r = await stopListener({ scope });
  process.stderr.write(
    `[lastid-agent] session-end: listener ${r.status}${r.pid ? ` (pid=${r.pid})` : ''} scope=${scope}\n`,
  );
} catch (err) {
  process.stderr.write(`[lastid-agent] session-end cleanup failed: ${err?.message ?? err}\n`);
}
process.exit(0);
