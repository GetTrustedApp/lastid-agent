/**
 * Ambient active scope for the current process.
 *
 * A long-lived agent process (the listener) runs for exactly ONE scope. Phase 2
 * of the broker-credential-custody plan routes the shared `authedIdpFetch`
 * through the signed broker, which needs the scope to locate that scope's
 * `~/.lastid-agent/<scope>/broker.{sock,token}`. Rather than thread `scope`
 * through the ~30 list-A call sites, the listener records its scope ONCE here at
 * startup and the dispatch reads it.
 *
 * Falls back to `resolveScope()` (the `LASTID_AGENT_SCOPE` env / `main`) when not
 * explicitly set — correct for env-pinned sessions (e.g. the MCP tool server),
 * where the broker, if any, is the one the listener for that scope is running.
 */
import { resolveScope } from './scope.js';

let _activeScope = null;

/** Record the scope this process is operating as (call once at startup). */
export function setActiveScope(scope) {
  if (typeof scope === 'string' && scope.trim()) {
    _activeScope = scope.trim();
  }
}

/** The active scope: an explicitly-set one, else the env/default via resolveScope(). */
export function getActiveScope() {
  return _activeScope ?? resolveScope();
}
