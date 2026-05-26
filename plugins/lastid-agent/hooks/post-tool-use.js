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
      eventType: failed ? 'AgentToolFailed' : 'AgentToolSucceeded',
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

  // file_access class: a richer, file-specific record (path + change size) for
  // the file tools — distinct from the generic tool_calls event so the operator
  // can audit file activity separately. Only on success; NEVER the file content,
  // only a path + a byte/char delta. Gated by the policy (default off — opt-in).
  if (!failed) {
    try {
      const fileEvent = fileAccessEvent(toolName, event?.tool_input ?? event?.toolInput ?? {});
      if (fileEvent) {
        enqueueAuditEvent({ scope: resolveScope(), eventType: fileEvent.eventType, metadata: fileEvent.metadata, toolUseId });
      }
    } catch {
      /* best-effort */
    }
  }
}
process.exit(0);

// Map a file tool + its input to a file_access event (path + change size, no
// content). Returns null for non-file tools. Path basename only would lose
// context the operator wants, so we keep the path but never the bytes.
function fileAccessEvent(tool, input) {
  const path = typeof input?.file_path === 'string' ? input.file_path
    : typeof input?.notebook_path === 'string' ? input.notebook_path
    : null;
  if (!path) return null;
  const len = (v) => (typeof v === 'string' ? v.length : 0);
  switch (tool) {
    case 'Read':
    case 'NotebookRead':
      return { eventType: 'AgentFileRead', metadata: { path } };
    case 'Write':
      return { eventType: 'AgentFileWritten', metadata: { path, op: 'write', bytes: len(input?.content) } };
    case 'Edit':
      return { eventType: 'AgentFileWritten', metadata: { path, op: 'edit', delta: len(input?.new_string) - len(input?.old_string) } };
    case 'MultiEdit':
      return { eventType: 'AgentFileWritten', metadata: { path, op: 'multiedit', edits: Array.isArray(input?.edits) ? input.edits.length : 0 } };
    case 'NotebookEdit':
      return { eventType: 'AgentFileWritten', metadata: { path, op: 'notebook_edit' } };
    default:
      return null;
  }
}

function safeStringify(v) {
  try {
    return JSON.stringify(v ?? '');
  } catch {
    return String(v ?? '');
  }
}
