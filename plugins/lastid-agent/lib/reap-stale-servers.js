/**
 * Stale MCP-server reaper.
 *
 * The MCP `serve` process is spawned by the AGENT RUNTIME (Claude Code,
 * via .mcp.json), not by us — so unlike the listener daemon (which the
 * SessionStart hook version-recycles via listener-daemon.js), nothing
 * reaps a `serve` left over from an OLD plugin version. After
 * `/plugin update`, the runtime launches a fresh serve from the new
 * version's path but a serve from a PRIOR session can linger on the old
 * code (observed: a 0.8.16 serve still running hours after the update to
 * 0.8.19), competing for the agent's shared on-disk state (operator
 * inbox cursor, etc.) and confusing reconnects.
 *
 * Fix: when a serve starts, it reaps any OTHER serve running a DIFFERENT
 * (older) plugin version. It deliberately leaves SAME-version serves
 * alone — those are legitimate concurrent Claude Code sessions, and
 * killing them would break multi-window use. A dev/working-copy serve
 * (no version segment in its path) reaps nothing (we never want a dev
 * run nuking the user's real installed server).
 *
 * The pure selection logic is split out (selectStaleServerPids /
 * versionFromPath) so it's unit-testable without spawning anything.
 */
import { spawnSync } from 'node:child_process';

/**
 * Extract the plugin version from a serve process's binary path. Cache
 * paths look like:
 *   …/plugins/cache/lastid-agent/lastid-agent/0.8.19/bin/lastid-agent.js
 * Returns the semver string, or null when there's no version segment
 * (a dev / working-copy checkout).
 */
export function versionFromPath(p) {
  if (typeof p !== 'string') return null;
  const m = p.match(/lastid-agent\/(\d+\.\d+\.\d+)\/bin\/lastid-agent\.js/);
  return m ? m[1] : null;
}

/**
 * Pure: given my pid + version and a list of discovered serve processes
 * ({ pid, version }), return the pids to kill — other serves on a
 * different, KNOWN version. Never self; never same-version; never
 * unknown-version peers. If my own version is unknown (dev), reap
 * nothing.
 */
export function selectStaleServerPids({ selfPid, selfVersion, processes }) {
  if (!selfVersion) return [];
  const out = [];
  for (const p of processes ?? []) {
    if (!p || p.pid === selfPid) continue;
    if (!p.version) continue; // unknown version (dev peer) — leave it
    if (p.version === selfVersion) continue; // concurrent same-version session — leave it
    out.push(p.pid);
  }
  return out;
}

/** Parse `ps -axo pid=,args=` output into [{ pid, version, args }] for
 *  lines that are a `lastid-agent.js serve` invocation. Exported for tests. */
export function parseServeProcesses(psStdout) {
  const procs = [];
  for (const line of String(psStdout ?? '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const sp = t.indexOf(' ');
    if (sp < 0) continue;
    const pid = Number.parseInt(t.slice(0, sp), 10);
    const args = t.slice(sp + 1);
    if (!Number.isInteger(pid)) continue;
    if (!/lastid-agent\.js\s+serve(\s|$)/.test(args)) continue;
    procs.push({ pid, version: versionFromPath(args), args });
  }
  return procs;
}

/**
 * Impure driver: enumerate serve processes via `ps`, pick the stale
 * old-version ones, and SIGTERM them. Best-effort and synchronous (a
 * single `ps` + a few kills at startup); never throws, never writes to
 * stdout (serve's stdout is the JSON-RPC channel — only stderr is safe).
 * Returns { reaped: number[] }.
 */
export function reapStaleServers({ selfPid = process.pid, selfPath = process.argv[1] } = {}) {
  try {
    const selfVersion = versionFromPath(selfPath);
    if (!selfVersion) return { reaped: [], reason: 'self version unknown (dev) — skip' };
    const ps = spawnSync('ps', ['-axo', 'pid=,args='], { encoding: 'utf-8', timeout: 5_000 });
    if (ps.status !== 0 || typeof ps.stdout !== 'string') {
      return { reaped: [], reason: 'ps unavailable' };
    }
    const processes = parseServeProcesses(ps.stdout);
    const stale = selectStaleServerPids({ selfPid, selfVersion, processes });
    const reaped = [];
    for (const pid of stale) {
      try {
        process.kill(pid); // SIGTERM
        reaped.push(pid);
      } catch {
        // already gone / not ours — ignore
      }
    }
    if (reaped.length > 0) {
      process.stderr.write(
        `[lastid-agent] reaped ${reaped.length} stale-version MCP serve process(es) ` +
          `(self v${selfVersion}): ${reaped.join(', ')}\n`,
      );
    }
    return { reaped };
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] stale-server reap failed (non-fatal): ${err?.message ?? err}\n`,
    );
    return { reaped: [], error: String(err?.message ?? err) };
  }
}
