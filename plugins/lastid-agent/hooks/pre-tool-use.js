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
import { applyRewrite } from '../lib/operator-store.js';

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

// Accumulator for `additionalContext` blocks. We may surface a
// policy warn, an ambient-memory recall, and a sub-agent briefing —
// all on the same tool call. Claude Code only honours one JSON
// envelope from the hook, so we join everything at the bottom.
const contextParts = [];

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
      // Soft warn — queue a reminder for the final envelope.
      contextParts.push(
        `⚠ Operator policy warning [${m.memory_id}]: ${m.reason} ` +
          `(rule matched pattern "${m.pattern}" on tool ${m.tool}). ` +
          `Proceed only if you have a clear reason; cite the memory id.`,
      );
    }
    if (m.severity === 'rewrite' && m.replacement) {
      // Silent redirect — substring-replace pattern → replacement in
      // the tool input, return `updatedInput` so Claude Code
      // executes the modified command. Rewrites short-circuit
      // ambient memory injection — once we've established the
      // command needs to change, additional reminders are noise.
      const updated = applyRewrite(toolInput, m.pattern, m.replacement, m.is_regex);
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
      // rewritable field. Fall through — the audit chain already
      // recorded the hit, and ambient retrieval may still surface
      // useful context below.
    }
  }
}

// ─── 1b. Ambient memory injection ──────────────────────────────────
//
// For high-signal tools, semantic-search the operator's memory store
// using the flattened tool input as the query and surface the
// top-K non-bedrock topical hits as additionalContext. Bedrock
// memories are excluded via the runtime's `exclude_bedrock=true`
// path because they're already in the agent's UserPromptSubmit
// packet — re-surfacing them on tool calls is noise.
//
// Skipped for low-signal tools (Read/Glob/Grep) where the
// noise:signal ratio would be bad on every file probe.
//
// Resilience: `runAmbientMemoryRetrieve` uses spawnSync with a 5s
// timeout. Desktop offline → CLI exits cleanly with no stdout →
// hook treats as "no ambient context" and the tool proceeds
// unaffected. The hook never blocks the agent indefinitely.
const AMBIENT_RETRIEVE_TOOLS = new Set([
  'Bash',
  'Edit',
  'Write',
  'Task',
  'NotebookEdit',
]);
if (toolName && AMBIENT_RETRIEVE_TOOLS.has(toolName)) {
  const query = stringifyToolInput(toolInput);
  if (query && query.length > 0) {
    const ambient = runAmbientMemoryRetrieve(query);
    if (ambient && ambient.trim().length > 0) {
      contextParts.push(ambient.trim());
    }
  }
}

// NOTE: the rewrite logic lives in operator-store.js::applyRewrite (imported
// above) so the PreToolUse rewriter and the matcher (patternMatches) share
// ONE pattern grammar. Previously a local copy here only honoured the
// `regex:` prefix and ignored the rule's `is_regex` flag, so a checkbox-
// authored regex rule matched but escaped its own pattern into a literal
// and rewrote nothing — the `sfw $1$2` supply-chain rule silently no-op'd.

// ─── 2. Sub-agent briefing (Task only) ─────────────────────────────

if (toolName === 'Task') {
  const status = readStatus(cliPath);
  if (status?.provisioned) {
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

    contextParts.push(note);
  }
}

// ─── 3. Final emit ─────────────────────────────────────────────────
//
// Anything we accumulated above (policy warn, sub-agent briefing,
// future ambient hits) emits as a single JSON envelope so Claude
// Code sees one consistent decision. Empty buffer → silent allow.
if (contextParts.length > 0) {
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext: contextParts.join('\n\n'),
      },
    }),
  );
}
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

/**
 * Synchronous semantic search against the operator's memory store
 * for the M11 ambient-injection path. Always passes
 * `--exclude-bedrock` so we never re-surface memories the
 * UserPromptSubmit packet already carries.
 *
 * Returns the CLI's stdout (a rendered `<lastid-memory>` block)
 * verbatim, or an empty string when there's nothing relevant /
 * the desktop isn't reachable / anything went wrong. ALWAYS
 * non-fatal — the calling hook treats empty output as "no
 * additional context" and lets the tool proceed.
 *
 * Resilience contract:
 *   - 5s spawn timeout bounds the worst-case latency hit on every
 *     ambient-eligible tool call.
 *   - CLI exits 0 with no stdout when desktop is unreachable.
 *   - Any caught error here returns '' so the hook never blocks
 *     a tool call because of a memory subsystem hiccup.
 */
function runAmbientMemoryRetrieve(query) {
  // Cap the query at a reasonable size — flattened tool input for
  // a big Write/Edit could otherwise be tens of KB and embedding
  // a giant string just slows the round-trip without adding
  // signal beyond the first paragraph or two.
  const truncated = query.length > 4000 ? query.slice(0, 4000) : query;
  const result = spawnSync(
    'node',
    [
      cliPath,
      'memory-search',
      '--prompt',
      truncated,
      '--exclude-bedrock',
      '--limit',
      '5',
    ],
    {
      encoding: 'utf-8',
      timeout: 5_000,
      input: '',
    },
  );
  if (result.error || result.status !== 0) {
    if (result.stderr) {
      process.stderr.write(
        `[lastid-agent] ambient memory-search soft-failed: ${result.stderr}\n`,
      );
    }
    return '';
  }
  return result.stdout || '';
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
