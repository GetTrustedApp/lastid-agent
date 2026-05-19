#!/usr/bin/env node
/**
 * PreToolUse hook.
 *
 * Fires before every tool invocation. We only care about `Task` — the
 * built-in tool the runtime uses to spawn sub-agents. For everything
 * else this hook exits silently with no body, which Claude Code treats
 * as "no opinion, continue".
 *
 * Today's behaviour for Task: emit an `additionalContext` block to the
 * spawned sub-agent that names its parent and tells it the sub-agent
 * is currently running **uncredentialed** in the LastID sense — the
 * harness does not yet auto-issue sub-agent VCs (that path needs the
 * lastid-agent-ffi crate to land so Node can derive the sub keypair
 * via HKDF and DPoP-sign the parent's OID4VCI proof).
 *
 * The plumbing for the real flow lives in:
 *   - lib/oauth-device-code.js → requestSubAgentOffer / claimVcFromOffer
 *   - lib/sdk-bindings.js → deriveSubAgentKeypair (stubbed until FFI ships)
 *
 * Once those are live, replace the stub branch below with an actual
 * enrollment: derive sub seed, request sub-offer, claim VC, persist to
 * keychain under the sub-agent's class slug, emit context to the new
 * runtime.
 */

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const input = readStdin();
let event = {};
try {
  event = JSON.parse(input);
} catch {
  // Malformed stdin → bail without blocking. The runtime continues
  // normally; the hook just has no opinion.
  process.exit(0);
}

const toolName = event?.tool_name ?? event?.toolName;
if (toolName !== 'Task') {
  process.exit(0);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

// Probe the parent's identity so we can name it in the sub-agent's
// briefing. status --json is cheap (keychain read).
const status = readStatus(cliPath);
if (!status?.provisioned) {
  // Parent isn't provisioned. Nothing to brief; allow silently.
  process.exit(0);
}

const toolInput = event?.tool_input ?? event?.toolInput ?? {};
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
  `[lastid-agent] Task spawn observed (class=${classSlug}, parent=${status.agent_did}); sub-agent auto-enrollment is pending FFI bindings\n`,
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
