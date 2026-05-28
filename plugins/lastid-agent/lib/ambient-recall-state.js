/**
 * Throttle + dedup state for the PreToolUse ambient memory injection.
 *
 * Background: the hook fires `runAmbientMemoryRetrieve` on every Bash / Edit /
 * Write / Task / NotebookEdit. That spawnSyncs a node process + a desktop
 * round-trip per tool call, AND pushes the rendered `<lastid-memory
 * source="ambient">` block into the tool's permission-reason context — which
 * surfaces to the agent as a system-reminder. In a busy session that means an
 * ambient block fires every few seconds and is often THE SAME memories as the
 * last 3 calls. Two costs:
 *
 *   1. Latency / I/O on every tool call (5s timeout window per spawn).
 *   2. Cognitive noise — the agent reads identical memories every tool call
 *      and treats each as a fresh turn boundary.
 *
 * This module persists last-injection state and gates the hook on it:
 *
 *   - **Throttle** by wall-clock: skip the spawn entirely when `now -
 *     last_inject_at < throttleMs`. Cheap, bounds worst-case rate.
 *   - **Dedup** by memory-id set: even after the throttle window passes, if
 *     the retrieved memory_ids are byte-equal to the previous injection, skip
 *     pushing the block (the spawn already ran — we just don't surface noise).
 *
 * State lives at `~/.lastid-agent/<scope>/ambient-recall.json`. Concurrent
 * hook invocations are handled by best-effort tmp + rename (the file is tiny
 * and the cost of a lost write is "one extra ambient block" — never wrong).
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

/** Default throttle window between ambient injections (30 s). */
export const DEFAULT_THROTTLE_MS = 30_000;

/**
 * On-disk path for the per-scope state file. Mirrors the
 * `~/.lastid-agent/<scope>/...` convention the rest of the plugin uses for
 * agent-local state (listener.pid, mls-state.b64, …).
 */
export function ambientRecallStatePath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'ambient-recall.json');
}

/**
 * Read the persisted state. Missing file / parse errors degrade silently to
 * an empty state — the hook should never block on a corrupt scratch file.
 *
 * @returns {{ last_inject_at: number, last_memory_ids: string[], skip_count: number }}
 */
export function readState(scope, { readFile = readFileSync } = {}) {
  try {
    const raw = readFile(ambientRecallStatePath(scope), 'utf-8');
    const parsed = JSON.parse(raw);
    return normalizeState(parsed);
  } catch {
    return emptyState();
  }
}

/**
 * Persist the state. Best-effort: tmp + rename for atomicity on POSIX, no
 * fsync (it's a scratch file). Any error swallowed — the worst case is one
 * stale state read on the next tool call, which only loses ONE throttle
 * decision; the next-next call self-corrects.
 */
export function writeState(scope, state, { writeFile = writeFileSync, rename = renameSync } = {}) {
  try {
    const path = ambientRecallStatePath(scope);
    const dir = dirname(path);
    mkdirSync(dir, { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFile(tmp, JSON.stringify(normalizeState(state)), { mode: 0o600 });
    rename(tmp, path);
  } catch {
    /* best-effort scratch state — never block a tool call */
  }
}

/**
 * Decide whether to RUN the ambient memory-search spawn given the previous
 * injection state. Returns `true` to spawn, `false` to skip-entirely.
 *
 * - Always spawn on first call (`last_inject_at === 0`).
 * - Skip while inside the throttle window.
 */
export function shouldRunAmbientRecall(state, { now = Date.now(), throttleMs = DEFAULT_THROTTLE_MS } = {}) {
  const last = Number(state?.last_inject_at ?? 0);
  if (!Number.isFinite(last) || last <= 0) return true;
  return now - last >= throttleMs;
}

/**
 * Extract memory ids (`mem_*` markers) from a rendered ambient block. Pure
 * substring scan — same shape the CLI's memory-search output uses
 * (`[mem_xxx]` per line). Returns a sorted unique array for stable dedup.
 */
export function extractMemoryIds(renderedBlock) {
  if (typeof renderedBlock !== 'string' || renderedBlock.length === 0) return [];
  const matches = renderedBlock.match(/mem_[A-Za-z0-9_]+/g) ?? [];
  const seen = new Set();
  for (const m of matches) seen.add(m);
  return [...seen].sort();
}

/**
 * Should we PUSH the (just-retrieved) block into the agent's contextParts?
 * `true` when the memory-id set differs from the last injection — pure dedup.
 * Defaults to `true` when last set was empty (first injection always lands).
 */
export function shouldInjectBlock(state, currentMemoryIds) {
  const prev = Array.isArray(state?.last_memory_ids) ? state.last_memory_ids : [];
  if (prev.length === 0) return true;
  if (currentMemoryIds.length === 0) return false;
  if (prev.length !== currentMemoryIds.length) return true;
  for (let i = 0; i < prev.length; i++) {
    if (prev[i] !== currentMemoryIds[i]) return true;
  }
  return false;
}

/** Build the next state after a successful injection — call BEFORE writeState. */
export function nextStateAfterInject(state, { now = Date.now(), memoryIds = [] } = {}) {
  return {
    last_inject_at: now,
    last_memory_ids: [...memoryIds],
    skip_count: 0,
  };
}

/** Build the next state after a SKIPPED call (throttled or duped) — purely telemetry. */
export function nextStateAfterSkip(state) {
  const s = normalizeState(state);
  return {
    last_inject_at: s.last_inject_at,
    last_memory_ids: s.last_memory_ids,
    skip_count: s.skip_count + 1,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function emptyState() {
  return { last_inject_at: 0, last_memory_ids: [], skip_count: 0 };
}

function normalizeState(value) {
  if (!value || typeof value !== 'object') return emptyState();
  return {
    last_inject_at: Number.isFinite(value.last_inject_at) ? value.last_inject_at : 0,
    last_memory_ids: Array.isArray(value.last_memory_ids)
      ? value.last_memory_ids.filter((s) => typeof s === 'string')
      : [],
    skip_count: Number.isFinite(value.skip_count) ? value.skip_count : 0,
  };
}
