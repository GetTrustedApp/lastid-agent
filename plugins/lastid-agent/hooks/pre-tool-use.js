#!/usr/bin/env node
/**
 * PreToolUse hook.
 *
 * Runs before every tool invocation. Two responsibilities:
 *
 * 1. **Policy enforcement (M7 policy-as-memory).** For EVERY tool call,
 *    posts `{ tool, input }` to the desktop MCP's `/policy/check`
 *    endpoint. The desktop walks the operator's Rule-kind memories
 *    and returns allow / deny / warn. On deny, we emit the
 *    `permissionDecision: "deny"` envelope so Claude Code refuses
 *    the tool call BEFORE it runs. On warn, we emit an
 *    `additionalContext` reminder and let the call proceed.
 *
 * 2. **Sub-agent briefing (Task tool only).** Emits a context block
 *    to the spawned sub-agent that names its parent and explains
 *    the harness's current sub-agent-enrollment posture.
 *
 * Time budget: 15s total per the hooks.json declaration. Policy
 * check is a localhost HTTP round-trip (~5–20ms). On any error /
 * unreachable desktop we fail OPEN — the tool call proceeds. The
 * tradeoff: a one-time policy outage shouldn't brick every tool;
 * a malicious offline branch can't bypass enforcement either
 * because the operator's bedrock memory still ships in the
 * UserPromptSubmit packet, which the agent has been instructed to
 * follow.
 */

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

const input = readStdin();
let event = {};
try {
  event = JSON.parse(input);
} catch {
  process.exit(0);
}

const toolName = event?.tool_name ?? event?.toolName ?? '';
const toolInput = event?.tool_input ?? event?.toolInput ?? {};

// ─── 1. Policy check ───────────────────────────────────────────────

// Skip if the tool name is unknown — nothing to check against.
if (toolName) {
  const decision = runPolicyCheck(toolName, toolInput);
  if (decision?.allow === false && decision?.matched) {
    const m = decision.matched;
    if (m.severity === 'deny') {
      // Hard deny — refuse the tool call. The agent sees the reason
      // and the memory id; can surface to the operator.
      console.log(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason:
              `Blocked by operator-authored memory [${m.memory_id}]: ${m.reason} ` +
              `(rule matched pattern "${m.pattern}" on tool ${m.tool})`,
          },
        }),
      );
      process.exit(0);
    }
    if (m.severity === 'warn') {
      // Soft warn — emit an additionalContext reminder to the agent
      // and fall through to the existing logic. The agent should
      // see the reminder before deciding to proceed.
      console.log(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            additionalContext:
              `⚠ Operator policy warning [${m.memory_id}]: ${m.reason} ` +
              `(rule matched pattern "${m.pattern}" on tool ${m.tool}). ` +
              `Proceed only if you have a clear reason; cite the memory id.`,
          },
        }),
      );
      // Continue to the Task-specific branch below. Don't exit yet.
    }
    if (m.severity === 'rewrite' && m.replacement) {
      // Silent redirect — substring-replace pattern → replacement in
      // the tool input, return `updatedInput` so Claude Code
      // executes the modified command. Agent never sees the
      // unwrapped form. Used to route risky invocations through a
      // safer wrapper (`npm install` → `sfw npm install` via Socket
      // Firewall; `curl` → `curl --proto =https`; etc.).
      //
      // For v1 we only rewrite Bash.command and Bash.description.
      // Extending to other tools (Edit, Write, etc.) just means
      // adding their string fields to this list.
      const updated = rewriteToolInput(toolInput, m.pattern, m.replacement);
      if (updated) {
        console.log(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'allow',
              permissionDecisionReason:
                `Rewrote per operator-authored memory [${m.memory_id}]: ${m.reason} ` +
                `(pattern "${m.pattern}" → "${m.replacement}" on tool ${m.tool})`,
              updatedInput: updated,
            },
          }),
        );
        process.exit(0);
      }
      // Pattern matched the flattened input but didn't appear in any
      // rewritable field (e.g. matched on the `description` but the
      // operator only wants `command` rewritten — or the toolInput
      // shape is one we don't handle yet). Fall through and let the
      // tool proceed unmodified; the audit chain still recorded the
      // hit. Failing closed here would block legitimate calls based
      // on stale flattening logic.
    }
  }
}

// Substring-replace `pattern` → `replacement` (case-insensitive) on
// the string fields of toolInput that we know are command-shaped.
// Returns a new object with the modified fields, or null if no
// field's content changed (caller falls through to no-op).
//
// Two modes, matching the Rust runtime's `apply_rewrite`:
//   * Literal (default): regex metacharacters escaped so the
//     pattern matches verbatim. Used for the common case
//     `pattern:npm install` → `replacement:sfw npm install`.
//   * Regex: pattern with a leading `regex:` prefix is used as-is.
//     Lets one rule cover an alternation like
//     `regex:\b(npm|yarn|pnpm|pip|uv|cargo)\b` → `sfw $1` and
//     redirect every supported package manager in one rule.
//     JS native `String.replace` honours `$1`, `$2`, `$&`, etc.
function rewriteToolInput(toolInput, pattern, replacement) {
  if (!pattern || !toolInput || typeof toolInput !== 'object') return null;
  const rewritable = ['command', 'description'];
  const next = { ...toolInput };
  let changed = false;
  const isRegex = pattern.startsWith('regex:');
  const rawSrc = isRegex ? pattern.slice('regex:'.length) : pattern;
  const reSrc = isRegex
    ? rawSrc
    : rawSrc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let re;
  try {
    re = new RegExp(reSrc, 'gi');
  } catch (e) {
    // Malformed regex from operator — fail closed for this rule
    // (no rewrite, hook falls through and the tool runs unmodified;
    // the audit chain already recorded the rule hit).
    process.stderr.write(
      `[lastid-agent] rewrite skipped — invalid regex "${reSrc}": ${e?.message ?? e}\n`,
    );
    return null;
  }
  for (const field of rewritable) {
    const v = next[field];
    if (typeof v !== 'string' || v.length === 0) continue;
    if (!re.test(v)) continue;
    re.lastIndex = 0; // reset after .test()
    next[field] = v.replace(re, replacement);
    changed = true;
  }
  return changed ? next : null;
}

// ─── 2. Sub-agent briefing (Task only) ─────────────────────────────

if (toolName !== 'Task') {
  process.exit(0);
}

const status = readStatus(cliPath);
if (!status?.provisioned) {
  process.exit(0);
}

const classSlug = String(toolInput?.subagent_type ?? 'general')
  .toLowerCase()
  .replace(/[^a-z0-9._:-]+/g, '-');

const note = buildSubAgentNote({
  parentDid: status.agent_did,
  parentHumanDid: status.parent_human_did,
  classSlug,
  parentMayDelegate: status.may_delegate === true,
});

process.stderr.write(
  `[lastid-agent] Task spawn observed (class=${classSlug}, parent=${status.agent_did}); ` +
    `sub-agent auto-enrollment is pending FFI bindings\n`,
);

console.log(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: note,
    },
  }),
);
process.exit(0);

// ---

function readStdin() {
  try {
    return readFileSync(0, 'utf-8');
  } catch {
    return '';
  }
}

function runPolicyCheck(tool, toolInputObj) {
  // Best-effort serialise of the tool input. For Bash it's
  // `command` + maybe `description`; we join everything string-y
  // so any string field can match the pattern.
  const inputStr = stringifyToolInput(toolInputObj);
  const result = spawnSync(
    'node',
    [cliPath, 'policy-check', '--tool', tool, '--input', inputStr],
    {
      encoding: 'utf-8',
      timeout: 5_000,
      input: '',
    },
  );
  if (result.error || result.status !== 0) {
    // Fail open. Stderr noise is logged.
    if (result.stderr) {
      process.stderr.write(`[lastid-agent] policy-check failed: ${result.stderr}\n`);
    }
    return null;
  }
  return parseJsonTolerant(result.stdout || '');
}

// Robust JSON parse — finds the first `{` and parses from there.
// First-run dependency install on the bin shim used to leak npm
// output to stdout, prepending noise to our JSON and silently
// failing the parse (which caused git stash to slip past the
// PreToolUse policy check on the very first run after a clean
// install). The root cause is fixed in bin/lastid-agent.js
// (npm stdio routed to stderr), but defensive parsing here keeps
// the hook safe against any future contamination.
function parseJsonTolerant(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const start = raw.indexOf('{');
  if (start === -1) return null;
  const candidate = raw.slice(start).trim();
  try {
    return JSON.parse(candidate);
  } catch (e) {
    process.stderr.write(
      `[lastid-agent] policy-check JSON parse failed (raw len=${raw.length}): ${e?.message ?? e}\n`,
    );
    return null;
  }
}

function stringifyToolInput(obj) {
  if (!obj || typeof obj !== 'object') return String(obj ?? '');
  // Flatten one level of string-typed values. Avoids serialising
  // the entire object (file_text on Write can be huge) but keeps
  // command-like fields visible to the matcher.
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      parts.push(`${k}=${v}`);
    } else if (typeof v === 'number' || typeof v === 'boolean') {
      parts.push(`${k}=${v}`);
    }
  }
  return parts.join('\n');
}

function readStatus(cliPath) {
  const result = spawnSync('node', [cliPath, 'status', '--json'], {
    encoding: 'utf-8',
    timeout: 5_000,
  });
  if (result.error || result.status !== 0) return null;
  try {
    return JSON.parse(result.stdout || '{}');
  } catch {
    return null;
  }
}

function buildSubAgentNote({ parentDid, parentHumanDid, classSlug, parentMayDelegate }) {
  const provenance = [
    'You are a sub-agent. Provenance:',
    `- Parent agent: ${parentDid}`,
    `- Parent human: ${parentHumanDid ?? '(unknown)'}`,
    `- Sub-agent class: ${classSlug}`,
  ].join('\n');

  if (!parentMayDelegate) {
    return [
      '# LastID Agent — sub-agent context',
      '',
      provenance,
      '',
      'Your parent agent has `may_delegate: false`. The LastID harness',
      'cannot issue you a VC. You have no agent DID, no vault access,',
      'and no audit chain in this run. Any credential-touching work',
      'must be done by the parent — surface back to the operator.',
    ].join('\n');
  }

  return [
    '# LastID Agent — sub-agent context',
    '',
    provenance,
    '',
    'Sub-agent auto-enrollment via the IdP is not active in this',
    'plugin build yet. You are running without your own LastID',
    'credential — no agent DID of your own, no separate vault access,',
    'no independent audit chain. You inherit the parent\'s working',
    'context only.',
    '',
    'If you need to touch credentials, defer to the parent agent and',
    'return the task. Do NOT attempt to access the parent\'s vault',
    'directly; you have no handle.',
  ].join('\n');
}
