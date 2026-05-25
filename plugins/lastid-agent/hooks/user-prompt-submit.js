#!/usr/bin/env node
/**
 * UserPromptSubmit hook.
 *
 * Runs BEFORE every user message reaches the model. Calls the
 * desktop MCP server's /memory/retrieve endpoint, gets back the
 * bedrock memory packet, and injects it as `additionalContext` so
 * the model can't skip memory — the runtime puts the packet in the
 * context window, not the model.
 *
 * Per agent-memory.md §4: this is the M4 enforcement of "memory
 * must be used." The model sees a system-reminder block with the
 * precedence directive ("memories WIN over training data") + the
 * memory list before it reads the user's prompt.
 *
 * Hook posture:
 *   - Time budget: 2s (declared in hooks.json). Best-effort. On
 *     timeout / desktop unavailable / no memories, we exit 0 with
 *     no additionalContext — the agent runs without memory for
 *     that turn rather than blocking the user.
 *   - We re-handshake the session every turn because the hook
 *     process is short-lived. ~50ms overhead on a localhost
 *     loop; well inside the time budget.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'bin', 'lastid-agent.js');

// Read the hook payload from stdin. Claude Code sends JSON with
// the user's prompt + session metadata.
const stdin = await readStdin();
let payload;
try {
  payload = JSON.parse(stdin);
} catch {
  // Malformed payload → silent no-op.
  process.exit(0);
}

const userPrompt =
  payload.prompt ?? payload.userPrompt ?? payload.user_prompt ?? '';
if (typeof userPrompt !== 'string' || userPrompt.trim().length === 0) {
  process.exit(0);
}

// Use the CLI's memory-retrieve subcommand to avoid duplicating the
// desktop handshake logic here. The CLI returns the formatted packet
// on stdout when there's anything to inject; empty stdout means no
// bedrock memories.
const result = spawnSync(
  'node',
  [cliPath, 'memory-retrieve', '--prompt', userPrompt],
  {
    encoding: 'utf-8',
    // Generous enough for a warm-daemon embed (~tens of ms) OR a one-time
    // in-process model load (~0.2s) on the topical path; still imperceptible.
    timeout: 5_000,
    input: '',
  },
);

if (result.error || result.status !== 0) {
  // Soft fail — log and exit.
  process.stderr.write(
    `[lastid-agent] memory retrieve failed: ${result.error?.message ?? result.stderr ?? 'unknown error'}\n`,
  );
  process.exit(0);
}

// NOTE: inbound operator chat messages are NOT surfaced here. A
// UserPromptSubmit hook only fires when the agent's own human takes
// a turn — useless for an idle agent waiting on a message. Real-time
// delivery is the MCP server's `notifications/claude/channel` push
// (see lib/mcp-server.js + lib/agent-inbox.js), the same mechanism
// the iMessage plugin uses. This hook stays memory-only.
const packetMarkdown = (result.stdout ?? '').trim();
if (packetMarkdown.length === 0) {
  // Nothing to inject this turn.
  process.exit(0);
}

console.log(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: packetMarkdown,
    },
  }),
);
process.exit(0);

// ---

function readStdin() {
  return new Promise((resolve) => {
    let buf = '';
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => {
      buf += chunk;
    });
    process.stdin.on('end', () => resolve(buf));
    // Defensive timeout — if the runtime doesn't close stdin we
    // shouldn't block forever.
    setTimeout(() => resolve(buf), 800);
  });
}
