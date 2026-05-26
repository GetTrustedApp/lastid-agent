/**
 * Audit spool — the lock-free WRITE side of the agent's signed audit chain.
 *
 * The signed, hash-linked chain (memory-audit.js) requires a SINGLE serialized
 * writer: each record's prev_hash links to its predecessor, so two processes
 * appending at once would fork the chain. But audit events originate from MANY
 * short-lived processes — the MCP tool server (memory CUD), the PreToolUse hook
 * (tool calls), the PostToolUse hook (tool results) — and Claude runs tools in
 * parallel, so those processes overlap.
 *
 * So writers NEVER touch the chain. Each drops its event as its own file in a
 * spool dir via write-temp + atomic rename — no read-modify-write, no lock,
 * safe under any concurrency. The listener (the single chain writer, exactly as
 * it's the single MLS-state writer) drains the spool IN ORDER on its tick,
 * appends each event to the signed chain, and ships. This mirrors the MLS
 * outbox pattern (cli.js: tool appends to the outbox, listener drains + sends).
 */
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  renameSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { appendMemoryAudit } from './memory-audit.js';

export function auditSpoolDir(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'audit-spool');
}

// Cap so a host that enqueues but never drains (unprovisioned, or no listener
// ever runs) can't grow the spool without bound. Over the cap we drop the NEW
// event — a never-draining host has no chain to extend anyway, and keeping the
// dir bounded matters more than the newest tool call.
export const SPOOL_CAP = 5000;

// Monotonic within this process; zero-padded into the filename so same-ms
// events from one process keep their order under a lexical filename sort.
let counter = 0;

/**
 * Drop one audit event into the spool. Lock-free + atomic (tmp + rename). NEVER
 * throws into the caller — a failed enqueue must not break a tool call or a
 * memory write. Returns the published path, or null if skipped/failed.
 */
export function enqueueAuditEvent({ scope = 'main', eventType, memoryId = null, metadata = {}, toolUseId = null } = {}) {
  if (!eventType) return null;
  try {
    const dir = auditSpoolDir(scope);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    let pending = 0;
    try {
      pending = readdirSync(dir).filter((f) => f.endsWith('.json')).length;
    } catch {
      pending = 0;
    }
    if (pending >= SPOOL_CAP) return null;
    const enqueuedAt = Date.now();
    const seq = counter++;
    const base =
      `${String(enqueuedAt).padStart(15, '0')}-${String(seq).padStart(9, '0')}` +
      `-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
    const rec = {
      event_type: eventType,
      memory_id: memoryId,
      metadata: metadata ?? {},
      tool_use_id: toolUseId,
      enqueued_at: enqueuedAt,
    };
    const tmp = join(dir, `.${base}.tmp`);
    const final = join(dir, `${base}.json`);
    writeFileSync(tmp, JSON.stringify(rec), { mode: 0o600 });
    renameSync(tmp, final); // atomic publish — a reader sees the whole file or nothing
    return final;
  } catch {
    return null; // best-effort — never disrupt the caller's path
  }
}

/** Spooled events in drain order (by enqueued_at, then filename for ties). A
 *  corrupt/partial file can never be chained, so it's dropped here. */
export function listSpooled(scope = 'main') {
  const dir = auditSpoolDir(scope);
  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
  const out = [];
  for (const f of files) {
    const path = join(dir, f);
    try {
      out.push({ file: path, rec: JSON.parse(readFileSync(path, 'utf8')) });
    } catch {
      try {
        unlinkSync(path);
      } catch {
        /* already gone */
      }
    }
  }
  out.sort((a, b) => {
    const ae = Number(a.rec.enqueued_at) || 0;
    const be = Number(b.rec.enqueued_at) || 0;
    if (ae !== be) return ae - be;
    return a.file < b.file ? -1 : a.file > b.file ? 1 : 0;
  });
  return out;
}

/**
 * Drain the spool into the signed chain. THE ONLY caller is the listener (the
 * single chain writer). For each spooled event in order: append to the chain,
 * then unlink. On an append throw, stop and leave the remaining files for the
 * next tick — the already-appended ones are unlinked, so no double-append. The
 * tool_use_id rides in metadata so a PostToolUse 'tool_result' correlates to
 * its PreToolUse 'tool_call'. `append` is injectable for tests.
 */
export function drainAuditSpool({ scope = 'main', signingKey, agentDid = null, append = appendMemoryAudit } = {}) {
  const pending = listSpooled(scope);
  let chained = 0;
  for (const { file, rec } of pending) {
    try {
      append({
        scope,
        signingKey,
        agentDid,
        eventType: rec.event_type,
        memoryId: rec.memory_id ?? null,
        metadata: {
          ...(rec.metadata ?? {}),
          ...(rec.tool_use_id ? { tool_use_id: rec.tool_use_id } : {}),
        },
      });
    } catch {
      break; // leave this file + the rest for the next tick
    }
    try {
      unlinkSync(file);
    } catch {
      /* already gone */
    }
    chained += 1;
  }
  return chained;
}
