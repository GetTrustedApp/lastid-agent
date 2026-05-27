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
import { projectKeyForPath, operativePathFromToolInput } from '../lib/project-key.js';
import { writeLastProject } from '../lib/project-sticky.js';
import { recordRuleHit } from '../lib/rule-metrics.js';
import { hostMemoryWriteWarning } from '../lib/memory-guidance.js';
import { resolveScope } from '../lib/scope.js';
import { enqueueAuditEvent } from '../lib/audit-spool.js';
import { isAuditEnabled, loadAuditPolicy } from '../lib/audit-policy.js';
import { redactSecrets } from '../lib/bug-report.js';
import { selfProtectionAuditEvent } from '../lib/self-protection.js';
import { readCliBindings } from '../lib/vault-cache.js';
import { planCliRewrite } from '../lib/cli-rewrite.js';
import { isOwnPluginTool } from '../lib/own-tools.js';

// This session's agent scope (LASTID_AGENT_SCOPE → 'main'). The policy-check /
// memory-search CLI children inherit the env and resolve it themselves; this
// is for the in-process metric record below.
const activeScope = resolveScope();

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

// ─── 0. Audit: record the tool CALL ────────────────────────────────
//
// Every tool invocation drops a `tool_call` event into the audit spool; the
// listener (the single chain writer) signs + hash-links + ships it. Lock-free,
// best-effort, off the latency path (one small atomic file write — no chain
// read-modify-write here, which is what lets parallel tool calls be safe). The
// recorded input is secret-redacted and capped so a huge Write payload can't
// bloat the chain or leak a key. `tool_use_id` correlates this to its
// PostToolUse `tool_result`.
if (toolName) {
  try {
    let raw;
    try {
      raw = JSON.stringify(toolInput ?? {});
    } catch {
      raw = String(toolInput ?? '');
    }
    const { text, count } = redactSecrets(raw);
    const CAP = 4000;
    enqueueAuditEvent({
      scope: activeScope,
      eventType: 'AgentToolInvoked',
      metadata: {
        tool: toolName,
        input: text.length > CAP ? text.slice(0, CAP) : text,
        input_redactions: count,
        input_truncated: text.length > CAP,
      },
      toolUseId: event?.tool_use_id ?? event?.toolUseId ?? null,
    });
  } catch {
    /* audit is best-effort — never block a tool call */
  }
}

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
    // Record the fire for metrics (local append, shipped by the listener),
    // unless the operator disabled the 'rule_fires' audit class. Best-effort +
    // off the latency path; no command/pattern text — only the rule id,
    // severity, tool category, and curated provenance.
    try {
      if (isAuditEnabled(loadAuditPolicy(activeScope), 'AgentRuleFired')) {
        recordRuleHit({
          scope: activeScope,
          ruleId: m.memory_id,
          severity: m.severity,
          tool: m.tool,
          curated: m.curated === true,
          pack: m.pack ?? null,
          rule: m.rule ?? null,
        });
      }
    } catch {
      /* metrics are best-effort — never block a tool call */
    }
    if (m.severity === 'deny') {
      // Security event: when a SELF-PROTECTION rule blocks a call, record it in
      // the audit chain UNGATED so the operator always sees the agent reached
      // for LastID's own key material / guard source (distinct from the
      // toggle-able rule_fires metric above).
      try {
        const ev = selfProtectionAuditEvent({ matched: m, tool: toolName, phase: 'input' });
        if (ev) {
          enqueueAuditEvent({
            scope: activeScope,
            ...ev,
            toolUseId: event?.tool_use_id ?? event?.toolUseId ?? null,
          });
        }
      } catch {
        /* audit is best-effort — never block the deny */
      }
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

// ─── 1·5. Transparent CLI credential proxy rewrite ─────────────────
//
// If a Bash command's leading binary is bound to a shared env-injection vault
// credential, rewrite it to run under `lastid-agent run` — the secret is
// injected into the child process's env (never shown to the agent), exactly
// like the socket-firewall rewrite but for credentials. Reads the non-secret
// binding index (no keychain / no decrypt here). planCliRewrite only rewrites a
// SIMPLE command (refuses pipes / compound / env-prefixed); an ambiguous
// binary→item match warns instead of guessing.
if (toolName === 'Bash') {
  try {
    const bindings = readCliBindings(activeScope);
    if (bindings.length > 0) {
      const plan = planCliRewrite(toolInput?.command, bindings, { cliPath });
      if (plan?.rewritten) {
        console.log(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'allow',
              permissionDecisionReason:
                `LastID: injecting the '${plan.binary}' credential from the vault (item ${plan.item_id}) ` +
                'as env vars for this command. The secret is added to the child process only — you never see it.' +
                (contextParts.length ? `\n\n${contextParts.join('\n\n')}` : ''),
              updatedInput: { ...toolInput, command: plan.command },
            },
          }),
        );
        process.exit(0);
      }
      if (plan?.ambiguous) {
        contextParts.push(
          `⚠ Multiple shared credentials bind '${plan.binary}' (${plan.items.join(', ')}). ` +
            `Run it explicitly and pick one: \`lastid-agent run --item <id> -- ${plan.binary} …\`.`,
        );
      }
    }
  } catch {
    /* best-effort — never block a tool call on the credential rewrite */
  }
}

// ─── 1b. Host file-memory write warning (warn, never block) ────────
//
// The runtime's own memory prompt nudges the agent to record durable facts in
// a host file-memory store (`~/.claude/.../memory/`). Those facts belong in
// LastID memory (provable, synced, governed, auto-injected). When a tool call
// targets that store, surface a hint to route it to `lastid_memory_draft`
// instead — but ALLOW the write: a hook deny can't be overridden by the
// operator, and host-local scratch is occasionally legitimate.
if (toolName) {
  const warning = hostMemoryWriteWarning(toolName, toolInput);
  if (warning) contextParts.push(warning);
}

// ─── 1c. Ambient memory injection ──────────────────────────────────
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
  // Resolve the repo this tool is acting on (project memory follows the WORK,
  // not the session cwd). Record it as the sticky last-project so the next
  // turn's UserPromptSubmit can inject this repo's memories from message one.
  let projectKey = null;
  try {
    const opPath = operativePathFromToolInput(toolInput);
    projectKey = opPath ? projectKeyForPath(opPath) : null;
    if (projectKey) writeLastProject('main', projectKey);
  } catch {
    projectKey = null; // best-effort — never block a tool on project resolution
  }
  const query = stringifyToolInput(toolInput);
  if (query && query.length > 0) {
    const ambient = runAmbientMemoryRetrieve(query, projectKey);
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

    // Audit chain: a delegated sub-agent was spawned (the 'sub_agents' class).
    // Gated + spooled by audit-policy; non-sensitive (the sub-agent class only).
    try {
      enqueueAuditEvent({ scope: activeScope, eventType: 'AgentSpawned', metadata: { subagent_class: classSlug } });
    } catch {
      /* best-effort */
    }

    contextParts.push(note);
  }
}

// ─── 3. Final emit ─────────────────────────────────────────────────
//
// Anything we accumulated above (policy warn, sub-agent briefing,
// ambient hits) emits as `additionalContext`.
//
// AND: the plugin's OWN MCP tools are auto-ALLOWED here. A PreToolUse
// `allow` decision is authoritative — it skips Claude Code's auto-mode
// safety classifier, which otherwise (wrongly) denied legitimate calls
// like replying to the operator via `lastid_send_message` ("sends to a
// third party"). These tools are ALREADY governed by three layers the
// classifier can't see: the agent's bounded VC capabilities, the
// operator's Rule-memory policy check run above (which can still
// deny/warn/rewrite — a deny already exited before here), and the signed
// audit chain. So the generic classifier is redundant for them. Scope is
// strictly OUR namespace (`mcp__plugin_lastid-agent_…`); every other
// tool keeps its normal gating (silent allow → classifier/rules decide).
const additionalContext = contextParts.length > 0 ? contextParts.join('\n\n') : null;

if (isOwnPluginTool(toolName)) {
  const out = {
    hookEventName: 'PreToolUse',
    permissionDecision: 'allow',
    permissionDecisionReason:
      'LastID plugin tool: governed by the agent credential, the operator rule ' +
      'policy check, and the signed audit chain — no extra approval needed.',
  };
  if (additionalContext) out.additionalContext = additionalContext;
  console.log(JSON.stringify({ hookSpecificOutput: out }));
  process.exit(0);
}

if (additionalContext) {
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext,
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
function runAmbientMemoryRetrieve(query, projectKey = null) {
  // Cap the query at a reasonable size — flattened tool input for
  // a big Write/Edit could otherwise be tens of KB and embedding
  // a giant string just slows the round-trip without adding
  // signal beyond the first paragraph or two.
  const truncated = query.length > 4000 ? query.slice(0, 4000) : query;
  const args = [
    cliPath,
    'memory-search',
    '--prompt',
    truncated,
    '--exclude-bedrock',
    '--limit',
    '5',
  ];
  // Surface THIS repo's project memories (incl. its bedrock ground truth)
  // ambiently. Omitted when the tool isn't in a recognizable repo.
  if (typeof projectKey === 'string' && projectKey.length > 0) {
    args.push('--project-key', projectKey);
  }
  const result = spawnSync(
    'node',
    args,
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
