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
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { enqueueAuditEvent } from '../lib/audit-spool.js';
import { redactSecrets } from '../lib/bug-report.js';
import { redactSelfProtected, selfProtectionAuditEvent } from '../lib/self-protection.js';
import { resolveScope } from '../lib/scope.js';

const RESULT_CAP = 2000;

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

// Is agent self-protection currently ON? Honors the SAME MAC-verified keyed
// operator-store the PreToolUse deny path uses (a signed opt-out disables it; an
// unsigned disk edit is ignored), via the `self-protection-status` CLI. Called
// ONLY when the output-net already found self-protection material, so the
// subprocess cost is paid on a hit, not every result. Fails SAFE → protected.
function selfProtectionEnabled() {
  try {
    const r = spawnSync('node', [cliPath, 'self-protection-status'], {
      encoding: 'utf-8',
      timeout: 5_000,
      input: '',
    });
    if (r.status !== 0 || !r.stdout) return true;
    const start = r.stdout.indexOf('{');
    if (start === -1) return true;
    return JSON.parse(r.stdout.slice(start)).enabled !== false;
  } catch {
    return true; // fail safe → protected
  }
}

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

let flaggedKeyMaterial = false;

if (toolName || toolUseId) {
  try {
    const rawResult = failed
      ? (event?.error ?? event?.stderr ?? '')
      : (event?.tool_result ?? event?.tool_response ?? '');
    const asText = typeof rawResult === 'string' ? rawResult : safeStringify(rawResult);
    // Self-protection OUTPUT net. redactSelfProtected (cheap, in-process) flags
    // LastID's own key-material tokens / guard source in the result. Only on a
    // HIT do we consult the MAC-verified on/off state — so an operator who turned
    // self-protection OFF sees no redaction or block, and the status subprocess
    // is paid only when there's something to act on. A PostToolUse hook can warn
    // + record but (verified live) cannot remove output already shown to the
    // model, so the flag drives a best-effort block + a dedicated audit event.
    const sp = redactSelfProtected(asText);
    let auditText = asText;
    let spApplied = 0;
    if (sp.count > 0 && selfProtectionEnabled()) {
      auditText = sp.text; // mask the self-protection material in the audit copy
      spApplied = sp.count;
      if (sp.keyMaterial > 0) flaggedKeyMaterial = true;
    }
    const { text, count } = redactSecrets(auditText);
    enqueueAuditEvent({
      scope: resolveScope(),
      eventType: failed ? 'AgentToolFailed' : 'AgentToolSucceeded',
      metadata: {
        tool: toolName,
        status: failed ? 'error' : 'success',
        result: text.length > RESULT_CAP ? text.slice(0, RESULT_CAP) : text,
        result_redactions: count,
        self_protection_redactions: spApplied,
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
// A PostToolUse `decision:block` surfaces this reason but — verified live on
// 2026-05-26 — does NOT remove output already shown to the model. So this can
// flag + record, not truly withhold. The audit copy above is redacted
// regardless; real prevention of an obfuscated read is the OS-ACL / daemon layer.
if (flaggedKeyMaterial) {
  // Security event: key material surfaced in a tool's output while
  // self-protection is ON. Record it (ungated) so the operator always sees it.
  try {
    const ev = selfProtectionAuditEvent({ tool: toolName, phase: 'output' });
    if (ev) enqueueAuditEvent({ scope: resolveScope(), ...ev, toolUseId });
  } catch {
    /* audit is best-effort */
  }
  process.stdout.write(
    JSON.stringify({
      decision: 'block',
      reason:
        "LastID self-protection: this tool output contained LastID key-material identifiers. Do not store, repeat, or act on them, and tell your operator. (Recorded redacted in the audit chain; it could not be withheld after the fact.)",
    }),
  );
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
