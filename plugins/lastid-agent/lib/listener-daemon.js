/**
 * Listener daemon supervisor.
 *
 * Goal: as long as the plugin is installed + provisioned, an MLS
 * listener process for the agent is running in the background.
 * Survives across Claude Code session restarts so the agent can
 * receive Welcome / inbound messages from the operator without
 * requiring a session to be open.
 *
 * Pattern: PID file. SessionStart hook calls `ensureListenerRunning`
 * which:
 *   1. Reads `~/.lastid-agent/<scope>/listener.pid` if present.
 *   2. If the process is alive, returns no-op.
 *   3. Otherwise spawns `lastid-agent listen` detached with
 *      stdout/stderr redirected to a log file, writes the new PID,
 *      and returns.
 *
 * On Claude Code exit the detached child keeps running because we
 * `unref` it and disown stdio. It dies on reboot or when explicitly
 * killed via `lastid-agent listener stop`.
 *
 * Concurrency: multiple SessionStart hooks running near-simultaneously
 * race on the PID file. Worst case: two daemons briefly. Both will
 * try to bind the same MLS state file and one will lose, exit, and
 * the other survives. The PID file write itself uses O_EXCL so only
 * one process wins the slot.
 */
import { spawn, execFile } from 'node:child_process';
import { mkdir, readFile, writeFile, unlink, open, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { existsSync } from 'node:fs';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const PID_LOCKFILE_FLAGS = 'wx'; // exclusive create — fails if exists

function dataDirFor(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main');
}

export function listenerPidPath(scope) {
  return join(dataDirFor(scope), 'listener.pid');
}

export function listenerLogPath(scope) {
  return join(dataDirFor(scope), 'listener.log');
}

// Records which binary (and thus which plugin version — the cache
// path embeds the version, e.g. `.../lastid-agent/0.8.13/bin/...`)
// the running listener was spawned from. Lets us detect + recycle a
// listener left over from an OLD version after `/plugin update` (the
// PID is alive so `ensureListenerRunning` would otherwise leave the
// stale code running — exactly the bug where a 0.8.11 listener kept
// 502'ing on superseded auth while 0.8.13 sat unused on disk).
function listenerMetaPath(scope) {
  return join(dataDirFor(scope), 'listener.meta.json');
}

async function readMeta(scope) {
  try {
    const raw = await readFile(listenerMetaPath(scope), 'utf-8');
    const m = JSON.parse(raw);
    return m && typeof m === 'object' ? m : null;
  } catch {
    return null;
  }
}

async function writeMeta(scope, meta) {
  try {
    await writeFile(listenerMetaPath(scope), `${JSON.stringify(meta)}\n`, 'utf-8');
  } catch {
    // best-effort — meta is informational; the pid file is the lock.
  }
}

async function clearMeta(scope) {
  try {
    await unlink(listenerMetaPath(scope));
  } catch {
    // best-effort
  }
}

/**
 * Check whether `pid` corresponds to a live process. `process.kill(pid, 0)`
 * doesn't send a signal — it just probes existence and permissions. Throws
 * ESRCH for "no such process", EPERM for "exists but you don't own it".
 */
function isAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

async function readPid(scope) {
  try {
    const raw = await readFile(listenerPidPath(scope), 'utf-8');
    const n = Number.parseInt(raw.trim(), 10);
    return Number.isFinite(n) ? n : null;
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

async function clearStalePid(scope) {
  try {
    await unlink(listenerPidPath(scope));
  } catch {
    // best-effort
  }
}

/**
 * Parse `ps` output lines ("<pid> <full command>") into the PIDs of live
 * processes running `lastid-agent.js listen` for EXACTLY `scope`.
 *
 * Why enumeration (not just the pid-lock): the lock holds ONE pid. A listener
 * from a PREVIOUS plugin version has a different cliPath, was never recorded in
 * the current lock, and so survives `/plugin update` + every SessionStart —
 * then it races the current listener on the scope's shared MLS state + sync
 * cursor. Two listeners both decrypt the same inbound group message and advance
 * the MLS ratchet, desyncing the epoch so `processInbound` throws and operator
 * channel messages are "delivered" but never surface. Reaping by enumeration
 * kills those strays the lock can't see.
 *
 * SCOPE-ISOLATED: only matches `--scope <scope>` (absent → 'main'), so reaping
 * 'main' never touches a 'lastid'-scope listener. Pure + injectable for tests.
 */
export function parseScopeListenerPids(psLines, scope) {
  const out = [];
  for (const raw of psLines) {
    const line = String(raw);
    const m = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    const cmd = m[2];
    if (!Number.isInteger(pid) || pid <= 0) continue;
    // Our listener subcommand specifically — NOT `serve` (MCP) or `sync`.
    if (!/lastid-agent\.js['"]?\s+listen(?:\s|$)/.test(cmd)) continue;
    const sm = cmd.match(/--scope\s+(\S+)/);
    const cmdScope = sm ? sm[1] : 'main';
    if (cmdScope !== scope) continue;
    out.push(pid);
  }
  return out;
}

async function defaultPsLines() {
  // `-A` all procs, `-o pid + full command`. Works on macOS + Linux. Best-
  // effort: any failure → no enumeration (the pid-lock stays the primary guard).
  const { stdout } = await execFileAsync('ps', ['-Ao', 'pid=,command='], {
    maxBuffer: 8 * 1024 * 1024,
  });
  return stdout.split('\n').filter((l) => l.trim().length > 0);
}

/** Live PIDs of `listen --scope <scope>` processes. `psImpl` injectable. */
export async function findScopeListeners(scope, { psImpl } = {}) {
  let lines;
  try {
    lines = psImpl ? await psImpl() : await defaultPsLines();
  } catch {
    return [];
  }
  return parseScopeListenerPids(lines, scope);
}

/**
 * SIGTERM every `listen --scope <scope>` process except `keep` (and never the
 * caller itself). Returns { found, reaped }. `psImpl`/`killImpl` injectable.
 */
export async function reapScopeListeners({ scope, keep = null, psImpl, killImpl } = {}) {
  const found = await findScopeListeners(scope, { psImpl });
  const kill =
    killImpl ??
    ((pid) => {
      try {
        process.kill(pid, 'SIGTERM');
        return true;
      } catch {
        return false;
      }
    });
  const reaped = [];
  for (const pid of found) {
    if (keep !== null && pid === keep) continue;
    if (pid === process.pid) continue; // never reap the caller
    if (kill(pid)) reaped.push(pid);
  }
  return { found, reaped };
}

/**
 * Idempotent. Returns { status: 'already-running'|'spawned'|'skipped', pid? }.
 *
 * `cliPath` is the absolute path to `bin/lastid-agent.js`. The caller
 * supplies it because hooks live in a sibling dir and Node resolution
 * via `import.meta.url` is awkward to pre-thread.
 */
export async function ensureListenerRunning({ scope = 'main', cliPath, parentPid = null } = {}) {
  if (!cliPath || !existsSync(cliPath)) {
    return { status: 'skipped', reason: `cliPath missing: ${cliPath}` };
  }
  const dir = dataDirFor(scope);
  await mkdir(dir, { recursive: true });

  // Singleton enforcement by PROCESS ENUMERATION, not just the pid-lock. The
  // lock tracks one pid; a listener left from a previous plugin version (or any
  // untracked stray) is invisible to it and races on the scope's MLS state +
  // sync cursor (the channel-desync bug). Converge to exactly ONE
  // current-version listener for this scope.
  const existing = await readPid(scope);
  const meta = await readMeta(scope);
  const procs = await findScopeListeners(scope);
  const lockedIsCurrent =
    existing &&
    isAlive(existing) &&
    meta &&
    meta.cliPath === cliPath &&
    procs.includes(existing);

  if (lockedIsCurrent) {
    // Keep the valid current-version listener; reap every OTHER stray
    // (old-version / untracked) listener for THIS scope.
    await reapScopeListeners({ scope, keep: existing });
    return { status: 'already-running', pid: existing };
  }

  // No valid current listener — reap EVERY listener for this scope (current
  // lock holder, stale-version strays, manual dev runs), then respawn fresh.
  await reapScopeListeners({ scope, keep: null });
  // A SIGTERM'd listener releases its own lock/meta, but a stray that never
  // wrote this lock won't — clear it ourselves so the fresh spawn owns it.
  await clearStalePid(scope);
  await clearMeta(scope);

  // Open the log file as appended sink for the detached child.
  // Both fds are owned by the child after spawn — parent closes
  // its copy via `unref` semantics.
  const logFh = await open(listenerLogPath(scope), 'a');
  // `--parent-pid` ties the detached listener's life to the Claude session
  // that spawned it: the listener watchdogs this pid and self-exits when it's
  // gone (covers Ctrl-C-twice / hard-kill, where SessionEnd never fires).
  const listenArgs = [cliPath, 'listen', '--scope', scope];
  if (Number.isInteger(parentPid) && parentPid > 0) {
    listenArgs.push('--parent-pid', String(parentPid));
  }
  const child = spawn(process.execPath, listenArgs, {
    detached: true,
    stdio: ['ignore', logFh.fd, logFh.fd],
    env: { ...process.env },
  });

  // Persist the PID. Use O_EXCL so two parallel spawns don't
  // overwrite each other's slot without noticing — second writer
  // sees EEXIST and double-checks the file.
  try {
    await writeFile(listenerPidPath(scope), String(child.pid), {
      flag: PID_LOCKFILE_FLAGS,
    });
  } catch (err) {
    if (err.code === 'EEXIST') {
      // Another supervisor instance won the race. Verify its PID is
      // alive; if so, kill ours.
      const other = await readPid(scope);
      if (other && isAlive(other) && other !== child.pid) {
        try {
          process.kill(child.pid);
        } catch {
          // ignore
        }
        await logFh.close().catch(() => {});
        child.unref();
        return { status: 'already-running', pid: other };
      }
      // Stale lock — clobber.
      await writeFile(listenerPidPath(scope), String(child.pid));
    } else {
      throw err;
    }
  }

  // Stamp the version/binary this listener was spawned from so a
  // later ensureListenerRunning can detect a stale-version daemon
  // and recycle it.
  await writeMeta(scope, {
    pid: child.pid,
    cliPath,
    startedAt: new Date().toISOString(),
    ...(Number.isInteger(parentPid) && parentPid > 0 ? { parentPid } : {}),
  });

  // Detach. The child now owns the log fd; parent can exit freely.
  child.unref();
  await logFh.close().catch(() => {});
  return { status: 'spawned', pid: child.pid };
}

/**
 * Pure: decide whether a STARTING listener should evict the listener
 * currently recorded in the pid file. Evict iff there is a recorded pid,
 * it is alive, and it isn't us (the daemon supervisor pre-writes the
 * child's own pid before the child runs, so seeing our own pid is normal
 * and must NOT trigger a self-kill). Exported for unit tests.
 */
export function shouldEvictListener({ existingPid, selfPid, alive }) {
  return Boolean(existingPid) && existingPid !== selfPid && alive === true;
}

/**
 * Single-instance enforcement for the listener process itself — independent
 * of how it was launched (daemon-supervised OR a manual `lastid-agent listen`
 * for dev/testing).
 *
 * Why this is load-bearing: the listener is the SINGLE MLS-state writer AND
 * the sole owner of the agent-state sync cursor for its scope. Two listeners
 * on one scope race on shared on-disk state — both receive a `rules.changed`/
 * `memory.changed` doorbell, both pull `?since=<cursor>`, and whichever wins
 * advances the shared cursor so the other applies nothing. Worse, a listener
 * from an OLDER build (e.g. a stray dev run that predates memory sync) eats
 * the cursor advance while dropping the memory records entirely — so published
 * memories silently never reach the agent. (Root-caused live: a manual dev
 * listener coexisting with the installed daemon listener did exactly this.)
 *
 * `ensureListenerRunning` only tracks listeners IT spawned; a manually-run
 * listener was invisible to it and coexisted. So enforce the invariant in the
 * listener itself: on startup become the sole listener for the scope by
 * evicting any OTHER live listener holding the pid file (takeover — the
 * most-recently-started listener wins, matching the human's intent when they
 * run `listen`) and claiming the pid file + meta for ourselves.
 */
export async function acquireListenerLock({
  scope = 'main',
  selfPid = process.pid,
  selfPath = process.argv[1],
  parentPid = null,
  psImpl,
  killImpl,
} = {}) {
  const dir = dataDirFor(scope);
  await mkdir(dir, { recursive: true });
  const existing = await readPid(scope);
  let evicted = null;
  if (shouldEvictListener({ existingPid: existing, selfPid, alive: isAlive(existing) })) {
    try {
      process.kill(existing); // SIGTERM — let it release cleanly
      evicted = existing;
    } catch {
      // already gone / not ours — fall through and claim the slot anyway
    }
  }
  // Defense in depth: the lock holds ONE pid, but other `listen --scope <scope>`
  // strays (a previous plugin version, a manual dev run) won't be in it. Reap
  // every other listener for THIS scope so we truly become the sole MLS-state
  // writer — the lock-holder eviction above only covers the recorded pid.
  const { reaped } = await reapScopeListeners({ scope, keep: selfPid, psImpl, killImpl });
  await writeFile(listenerPidPath(scope), String(selfPid), 'utf-8');
  await writeMeta(scope, {
    pid: selfPid,
    cliPath: selfPath,
    startedAt: new Date().toISOString(),
    ...(Number.isInteger(parentPid) && parentPid > 0 ? { parentPid } : {}),
  });
  return { pid: selfPid, evicted, reaped };
}

/**
 * Release the listener lock on shutdown — but ONLY if it's still ours. If
 * another listener took over while we were running (its `acquireListenerLock`
 * overwrote the pid file with its own pid), leave its lock intact so we don't
 * delete a live owner's pid file out from under it.
 */
export async function releaseListenerLock({ scope = 'main', selfPid = process.pid } = {}) {
  const cur = await readPid(scope);
  if (cur === selfPid) {
    await clearStalePid(scope);
    await clearMeta(scope);
    return { released: true };
  }
  return { released: false };
}

/**
 * Wipe a scope's local runtime state — used by REISSUE (provision replacing an
 * existing identity). Removes the synced operator store (rules/memories), the
 * agent's own memories + audit, MLS group state, the inbox/outbox + cursors,
 * and metrics. The agent's CREDENTIAL lives in the OS keychain, NOT here, so a
 * reissued identity re-syncs from scratch and never trips over records sealed
 * to the old slot_seed or signed by the old key (which is how a reissue
 * otherwise leaks a stale sync cursor + undecryptable MLS state).
 *
 * Caller MUST stop the listener first (it writes into this dir). `scope` is
 * validated to a safe slug so a bad value can't escalate the recursive remove
 * beyond `~/.lastid-agent/<scope>`. `dir` overrides the target for tests only.
 */
export async function clearScopeState(scope, { dir } = {}) {
  // No default scope: a destructive recursive remove must NOT silently fall
  // back to wiping 'main'. The caller passes an explicit scope; anything that
  // isn't a safe slug (incl. undefined/empty) is refused so a bad value can't
  // escalate the remove beyond ~/.lastid-agent/<scope>.
  if (dir === undefined) {
    const ok =
      typeof scope === 'string' &&
      /^[A-Za-z0-9_.-]+$/.test(scope) &&
      scope !== '.' &&
      scope !== '..';
    if (!ok) throw new Error(`refusing to clear unsafe scope: ${JSON.stringify(scope)}`);
  }
  const target = dir ?? dataDirFor(scope);
  await rm(target, { recursive: true, force: true });
  await mkdir(target, { recursive: true });
  return { cleared: target };
}

/**
 * Stop the listener if running. Used by an explicit `listener stop`
 * subcommand; SessionStart never calls this.
 */
export async function stopListener({ scope = 'main' } = {}) {
  const pid = await readPid(scope);
  if (!pid) return { status: 'not-running' };
  if (!isAlive(pid)) {
    await clearStalePid(scope);
    return { status: 'not-running' };
  }
  try {
    process.kill(pid);
  } catch (err) {
    return { status: 'kill-failed', error: err.message };
  }
  await clearStalePid(scope);
  await clearMeta(scope);
  return { status: 'stopped', pid };
}
