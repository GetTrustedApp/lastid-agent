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
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile, unlink, open } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { existsSync } from 'node:fs';

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
 * Idempotent. Returns { status: 'already-running'|'spawned'|'skipped', pid? }.
 *
 * `cliPath` is the absolute path to `bin/lastid-agent.js`. The caller
 * supplies it because hooks live in a sibling dir and Node resolution
 * via `import.meta.url` is awkward to pre-thread.
 */
export async function ensureListenerRunning({ scope = 'main', cliPath } = {}) {
  if (!cliPath || !existsSync(cliPath)) {
    return { status: 'skipped', reason: `cliPath missing: ${cliPath}` };
  }
  const dir = dataDirFor(scope);
  await mkdir(dir, { recursive: true });

  const existing = await readPid(scope);
  if (existing && isAlive(existing)) {
    return { status: 'already-running', pid: existing };
  }
  if (existing) {
    await clearStalePid(scope);
  }

  // Open the log file as appended sink for the detached child.
  // Both fds are owned by the child after spawn — parent closes
  // its copy via `unref` semantics.
  const logFh = await open(listenerLogPath(scope), 'a');
  const child = spawn(process.execPath, [cliPath, 'listen', '--scope', scope], {
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

  // Detach. The child now owns the log fd; parent can exit freely.
  child.unref();
  await logFh.close().catch(() => {});
  return { status: 'spawned', pid: child.pid };
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
  return { status: 'stopped', pid };
}
