#!/usr/bin/env node
/**
 * SessionStart hook.
 *
 * Two jobs:
 *
 *   1. If the host has no provisioned agent: print a one-line hint
 *      pointing the operator at `/lastid-agent:provision`.
 *   2. If provisioned: inject an `additionalContext` block that
 *      teaches the runtime LLM (Claude Code or any other MCP-aware
 *      agent runtime) WHO it is, WHAT credentials it has, HOW to use
 *      them safely (never plaintext, never guess), and what audit
 *      guarantees travel with every action it takes.
 *
 * The hook itself is intentionally thin — it shells out to
 * `lastid-agent status --json` for the actual identity probe so all
 * keychain/IdP I/O lives in one place. Hooks run in a constrained
 * context (no interactive stdin); the heavy lifting belongs in the
 * CLI.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureListenerRunning } from '../lib/listener-daemon.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

const result = spawnSync('node', [cliPath, 'status', '--json'], {
  encoding: 'utf-8',
  timeout: 8_000,
});

if (result.error || result.status !== 0) {
  // Don't block the session on a missing/broken CLI. Surface a hint
  // and continue — the operator can manually run the slash command.
  process.stderr.write(
    `[lastid-agent] status check failed: ${result.error?.message ?? result.stderr ?? 'unknown error'}\n`,
  );
  process.exit(0);
}

let status;
try {
  status = JSON.parse(result.stdout || '{}');
} catch {
  process.exit(0);
}

if (!status.provisioned) {
  emit(
    [
      'LastID Agent is installed but not provisioned for this host yet.',
      'Run `/lastid-agent:provision` to approve this agent in your LastID wallet.',
    ].join('\n'),
  );
  process.exit(0);
}

// Provisioned — emit the operating context.
const context = buildOperatingContext(status);
process.stderr.write(
  `[lastid-agent] provisioned: ${status.agent_did}\n`,
);

// Ensure the MLS listener daemon is alive in the background. This
// is the listener that receives Welcome / inbound MLS messages from
// the operator so the agent can be added to chat groups + receive
// memory-update / rule-update broadcasts even between Claude Code
// sessions. Idempotent — if a prior session already spawned the
// daemon and it's still alive, this returns immediately.
try {
  const result = await ensureListenerRunning({
    scope: status.scope ?? 'main',
    cliPath,
  });
  process.stderr.write(
    `[lastid-agent] listener: ${result.status}${
      result.pid ? ` (pid=${result.pid})` : ''
    }\n`,
  );
} catch (err) {
  process.stderr.write(
    `[lastid-agent] listener spawn failed: ${err.message}\n`,
  );
}

emit(context);
process.exit(0);

// ---

function emit(additionalContext) {
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext,
      },
    }),
  );
}

function buildOperatingContext(s) {
  const caps = (s.capabilities ?? [])
    .map((c) => `- ${c.resource}: ${(c.actions ?? []).join(', ')}`)
    .join('\n');
  const expIso = s.exp ? new Date(s.exp * 1000).toISOString() : 'no expiry';
  const role = s.sub_agent_class
    ? `Sub-agent (class: ${s.sub_agent_class})`
    : 'Top-level agent';
  const parentLine = s.parent_agent_did
    ? `Parent agent: ${s.parent_agent_did}\nParent human: ${s.parent_human_did ?? '(unknown)'}`
    : `Parent human: ${s.parent_human_did ?? '(unknown)'}`;

  return [
    '# LastID Agent — operating context',
    '',
    'You are operating inside the LastID Agent harness. Your identity is',
    'cryptographically verifiable. The operator (a human) approved this',
    'agent in their LastID wallet and issued you a bounded credential.',
    '',
    '## Who you are',
    '',
    `${role}`,
    `Agent DID: ${s.agent_did}`,
    parentLine,
    `BIP85 slot: #${s.slot_index ?? '?'}`,
    `May delegate (spawn sub-agents): ${s.may_delegate ? 'yes' : 'no'}`,
    `Credential expires: ${expIso}`,
    '',
    '## Your capabilities',
    '',
    caps.length > 0 ? caps : '- (none granted)',
    '',
    'These are the only resource/action pairs you are authorized for.',
    'Any request to act beyond this list should be refused and surfaced',
    'to the operator. Call `lastid_whoami` any time you want to confirm',
    'your own identity card — that tool reads the live VC.',
    '',
    '## How credentials work here (read this carefully)',
    '',
    'The operator may share vault items with you (API keys, OAuth',
    'tokens, basic-auth credentials). You will NEVER see the underlying',
    'credential value. The model is:',
    '',
    '1. `vault_list` — discover items the operator has shared with you.',
    '   You see titles, services, hosts, granted actions, and injection',
    '   metadata. You do NOT see the credential value.',
    '2. `vault_use(item_id)` — mint a single-use, short-lived (5 min)',
    '   opaque handle for a specific item. The response includes an',
    '   "injection summary" telling you how the credential will be',
    '   attached (header, bearer, query param, basic auth, oauth_bearer).',
    '3. `http_fetch(url, vault_handle)` — make the outbound request.',
    '   The LastID desktop unfurls the handle at the network boundary,',
    '   attaches the credential per the injection summary, and returns',
    '   the response to you. The credential value never enters your',
    '   context window.',
    '',
    'Rules you MUST follow:',
    '',
    '- Never fabricate, guess, or paste a credential value. You do not',
    '  have one to paste.',
    '- If the operator asks you to perform a task that requires a',
    '  credential not in `vault_list`, tell them which specific item',
    '  you need (service + purpose) and stop. Do NOT fall back to',
    '  environment variables, do NOT read files, do NOT improvise.',
    '- Handles are single-use. Mint a fresh handle per request via',
    '  `vault_use` — do not try to reuse one.',
    '- If `http_fetch` returns a credential-related error (401, 403),',
    '  report it. Do not silently retry with a different credential.',
    '',
    '## What lands in the audit chain',
    '',
    'Every tool call you make appends a record to a blake3-linked,',
    'device-key-signed audit chain on the operator\'s machine. The chain',
    'includes the tool name, the agent DID (yours), the input shape,',
    'the result, and key metadata (item_id, url host, response status,',
    'injection kind). The operator views this chain in the desktop\'s',
    'Agents → Activity tab. Be precise and intentional — your actions',
    'are evidence.',
    '',
    '## Sub-agents (if you spawn one)',
    s.may_delegate
      ? [
          '',
          'You have `may_delegate: true`. When you spawn a Task tool',
          'sub-agent, the harness auto-enrolls it with its own LastID',
          'credential — a subset of your capabilities, your VC as the',
          'parent in its chain. You do not need to manage the sub-',
          'agent\'s identity manually.',
        ].join('\n')
      : [
          '',
          'You have `may_delegate: false`. Sub-agents you spawn will',
          'run uncredentialed (no LastID identity, no vault, no audit',
          'chain). Avoid spawning sub-agents for credential-touching',
          'work.',
        ].join('\n'),
    '',
    '## Memory (persistent across sessions)',
    '',
    'You have a persistent memory store keyed to this operator and to',
    'you (per-agent tier). Every turn, the harness auto-injects the',
    "operator's bedrock memories — rules of engagement that beat your",
    'training data when they conflict. Cite a memory by id (e.g.',
    '`[mem_abc]`) when you act on one.',
    '',
    'Two writing patterns:',
    '',
    '- `lastid_memory_write` — the operator EXPLICITLY asked you to',
    '  remember something ("save this", "from now on", "we decided").',
    '  Commits immediately, surfaces in retrieve, citable next turn.',
    '- `lastid_memory_draft` — YOU inferred something durable from',
    '  conversation but the operator did NOT explicitly ask you to',
    '  save. Queues for review in the wallet UI. Does not influence',
    '  future turns until the operator promotes it. Always include a',
    '  `source_quote` from the conversation so the operator can',
    '  evaluate the proposal.',
    '',
    'Heuristic for when to draft: did the operator just teach you a',
    'preference, decision, named entity, or workflow rule that you',
    'would want to remember next time? If yes and they did not ask',
    'you to save it explicitly, draft it. If no, do not.',
    '',
    'Do NOT draft: ephemeral task state, transient debugging notes,',
    'speculative inferences, or anything you would not want surfaced',
    "back as ground truth. The operator's bandwidth for reviewing",
    'drafts is finite; high signal only.',
    '',
    '## Quick reference',
    '',
    '- `lastid_whoami` — confirm your identity card.',
    '- `vault_list` — discover shared credentials.',
    '- `vault_use(item_id, purpose?)` — mint a handle.',
    '- `http_fetch(url, vault_handle, method?, headers?, body?)` — call.',
    '- `lastid_memory_write({kind, subject, claim, source_kind, …})` — '
        + 'commit a memory now (operator-instructed).',
    '- `lastid_memory_draft({kind, subject, claim, source_kind, '
        + 'source_quote, …})` — propose for operator review.',
    '',
    'When in doubt: refuse, surface to the operator, ask them to share',
    'what you actually need.',
  ].join('\n');
}
