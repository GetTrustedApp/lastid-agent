#!/usr/bin/env node
/**
 * SessionStart hook — CLI shell.
 *
 * Runs `lastid-agent status` and reports whether the agent is
 * provisioned. Hooks run in a constrained context (no interactive
 * stdin, restricted keychain prompts), so this hook deliberately does
 * NOT drive provisioning itself. If no agent identity is present, it
 * prints a one-liner directing the operator to run
 * `/lastid-agent:provision` from inside the session, where the CLI can
 * surface the OAuth verification URL + user_code interactively.
 *
 * CLI-first by design: every helper that touches the keychain or talks
 * to the IdP lives in `bin/lastid-agent.js`. Hooks shell out to it.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

const result = spawnSync('node', [cliPath, 'status', '--json'], {
  encoding: 'utf-8',
  timeout: 8_000,
});

if (result.error || result.status !== 0) {
  // Don't block the session on a missing/broken CLI. Surface a hint and
  // continue — the operator can manually run the slash command.
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

if (status.provisioned) {
  // Steady state — nothing to do. Optionally log to stderr (visible in
  // hook debug output, not in the Claude transcript).
  process.stderr.write(
    `[lastid-agent] provisioned: ${status.agent_did}\n`,
  );
  process.exit(0);
}

// Unprovisioned. Print a system-additional-context message Claude can
// surface to the operator: how to run the provisioning flow.
const message = [
  'LastID Agent is installed but not provisioned for this host yet.',
  'Run `/lastid-agent:provision` to approve this agent in your LastID wallet.',
].join('\n');

console.log(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext: message,
    },
  }),
);
process.exit(0);
