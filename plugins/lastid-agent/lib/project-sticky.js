/**
 * Sticky last-project tracker.
 *
 * The injection that matters most for project memories happens per-tool-call
 * (PreToolUse knows the operative path → the repo). But UserPromptSubmit fires
 * at the START of a turn, before any tool runs, so it doesn't yet know which
 * repo the turn will touch. We bridge that with a tiny sticky file: PreToolUse
 * records the last repo key it resolved, and UserPromptSubmit reads it so the
 * first message of a turn already carries the repo the agent was just in.
 *
 * Best-effort and bounded: a single small file under the scope dir, ignored
 * (treated as "no project") on any read/parse error. We also store a timestamp
 * so a very stale sticky (agent idle for a long time, likely a new context)
 * can be disregarded by the reader.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

/** Sticky file path for a scope: ~/.lastid-agent/<scope>/last-project.json */
export function lastProjectPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'last-project.json');
}

/**
 * Read the last-resolved project key. Returns null when absent/corrupt, or when
 * older than `maxAgeMs` (default 12h) — a long gap likely means unrelated work,
 * and a stale repo bedrock injected at turn-start would be misleading.
 */
export function readLastProject(scope = 'main', { maxAgeMs = 12 * 60 * 60 * 1000 } = {}) {
  try {
    const raw = JSON.parse(readFileSync(lastProjectPath(scope), 'utf-8'));
    if (!raw || typeof raw.project_key !== 'string' || raw.project_key.length === 0) return null;
    if (typeof raw.at === 'number' && Number.isFinite(maxAgeMs) && Date.now() - raw.at > maxAgeMs) {
      return null;
    }
    return raw.project_key;
  } catch {
    return null;
  }
}

/** Record the last-resolved project key. No-op on error (best-effort). */
export function writeLastProject(scope = 'main', projectKey) {
  if (typeof projectKey !== 'string' || projectKey.length === 0) return;
  try {
    const p = lastProjectPath(scope);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify({ project_key: projectKey, at: Date.now() }), { mode: 0o600 });
  } catch {
    /* best-effort */
  }
}
