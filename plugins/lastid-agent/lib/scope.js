/**
 * Active agent scope for this session.
 *
 * One LastID host can run several distinct agents — each its own identity
 * (keychain), state dir (~/.lastid-agent/<scope>/), and listener lock — by
 * varying the scope. Resolution order:
 *
 *   1. an explicit `--scope X` CLI flag (a single command targeting a scope),
 *   2. the `LASTID_AGENT_SCOPE` env var (pins a whole Claude Code session to an
 *      agent: `LASTID_AGENT_SCOPE=lastid claude …`, usable in any directory),
 *   3. `main` — the default when nothing is set.
 *
 * Hook-spawned CLI children inherit the parent's env, so setting
 * LASTID_AGENT_SCOPE once on the `claude` process flows to every hook and every
 * CLI subprocess (status / sync / listen / policy-check / memory-retrieve)
 * without threading `--scope` by hand.
 */
import { env } from 'node:process';

export function resolveScope(flags = {}) {
  if (flags && typeof flags.scope === 'string' && flags.scope.trim()) {
    return flags.scope.trim();
  }
  const fromEnv = env.LASTID_AGENT_SCOPE;
  if (typeof fromEnv === 'string' && fromEnv.trim()) return fromEnv.trim();
  return 'main';
}
