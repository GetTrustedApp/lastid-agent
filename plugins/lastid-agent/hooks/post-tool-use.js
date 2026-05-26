#!/usr/bin/env node
/**
 * PostToolUse / PostToolUseFailure hook.
 *
 * Records the OUTCOME of a tool call. Enqueues a `tool_result` event into the
 * audit spool, correlated to the PreToolUse `tool_call` via `tool_use_id` (the
 * same id Claude Code stamps on both events). One script serves both the
 * success event (`PostToolUse`) and, where the runtime emits it, the failure
 * event (`PostToolUseFailure`) — we branch on `hook_event_name` / an `error`
 * field. Registering the failure event is harmless on runtimes that don't emit
 * it (the hook simply never fires there).
 *
 * Like the call side this is lock-free + best-effort: it only appends one
 * atomic file to the spool; the listener (the single chain writer) signs +
 * hash-links + ships it. The result text is secret-redacted and capped so a
 * tool that echoes a credential can't leak it into the chain.
 */
import { readFileSync } from 'node:fs';
import { enqueueAuditEvent } from '../lib/audit-spool.js';
import { redactSecrets } from '../lib/bug-report.js';
import { resolveScope } from '../lib/scope.js';

const RESULT_CAP = 2000;

let event = {};
try {
  event = JSON.parse(readFileSync(0, 'utf-8'));
} catch {
  process.exit(0);
}

const toolName = event?.tool_name ?? event?.toolName ?? '';
const toolUseId = event?.tool_use_id ?? event?.toolUseId ?? null;
const eventName = event?.hook_event_name ?? event?.hookEventName ?? '';
const failed = eventName === 'PostToolUseFailure' || event?.error != null;

if (toolName || toolUseId) {
  try {
    const rawResult = failed
      ? (event?.error ?? event?.stderr ?? '')
      : (event?.tool_result ?? event?.tool_response ?? '');
    const asText = typeof rawResult === 'string' ? rawResult : safeStringify(rawResult);
    const { text, count } = redactSecrets(asText);
    enqueueAuditEvent({
      scope: resolveScope(),
      eventType: 'tool_result',
      metadata: {
        tool: toolName,
        status: failed ? 'error' : 'success',
        result: text.length > RESULT_CAP ? text.slice(0, RESULT_CAP) : text,
        result_redactions: count,
        result_truncated: text.length > RESULT_CAP,
      },
      toolUseId,
    });
  } catch {
    /* audit is best-effort — never disrupt the turn */
  }
}
process.exit(0);

function safeStringify(v) {
  try {
    return JSON.stringify(v ?? '');
  } catch {
    return String(v ?? '');
  }
}
