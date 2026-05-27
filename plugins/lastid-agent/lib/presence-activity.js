/**
 * Agent activity heartbeat — the "is the agent actively working" signal that
 * drives the typing indicator's keep-alive.
 *
 * The PostToolUse hook touches a tiny timestamp file on every tool call
 * (cheap, best-effort, in line with the per-tool audit-spool write it already
 * does). The listener reads it on each presence tick: a timestamp newer than
 * the last one it saw means the agent did work → keep typing alive. The file
 * is channel-agnostic ("a tool ran"); the listener only consults it while a
 * conversation window is open, so CLI tool calls never surface as typing.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

export function activityPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'presence-activity');
}

/** Record that the agent just did something. Best-effort + synchronous (it runs
 *  in a short-lived hook process) — a write failure never blocks the tool. */
export function touchActivity(scope, now = Date.now()) {
  try {
    const p = activityPath(scope);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, String(now));
  } catch {
    /* best-effort — the indicator just won't refresh */
  }
}

/** Last activity timestamp (ms), or 0 if none/unreadable. */
export function readActivityTs(scope) {
  try {
    const v = Number.parseInt(readFileSync(activityPath(scope), 'utf-8').trim(), 10);
    return Number.isFinite(v) ? v : 0;
  } catch {
    return 0;
  }
}
