/**
 * Operator-inbox reader for the MCP server's real-time channel.
 *
 * The MLS dispatcher (in the listener daemon) decrypts inbound
 * operator messages and appends them to
 * `~/.lastid-agent/<scope>/operator-inbox.jsonl`. The plugin's MCP
 * server tails this and pushes each new one into the agent's Claude
 * Code session as a `notifications/claude/channel` notification —
 * the same real-time mechanism the iMessage plugin uses. That's how
 * an idle agent learns the operator said something WITHOUT waiting
 * for the agent's own human to take a turn: the MCP server is
 * long-lived (connected to the session over stdio) and can push.
 *
 * Read cursor: `~/.lastid-agent/<scope>/inbox-cursor.json` holds
 * `{ "consumed": <line count> }`. The MCP server is the single
 * consumer of this cursor — it surfaces only lines past it, then
 * advances, so each operator message is pushed to the session
 * exactly once.
 *
 * Only `operator.message.text` envelopes surface here (the chat
 * vocabulary). Other operator.* types (memory write, rule publish)
 * are handled by their own paths, not the chat reply flow.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

function inboxPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'operator-inbox.jsonl');
}

function cursorPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'inbox-cursor.json');
}

async function readCursor(scope) {
  try {
    const raw = await readFile(cursorPath(scope), 'utf-8');
    const parsed = JSON.parse(raw);
    return Number.isInteger(parsed?.consumed) ? parsed.consumed : 0;
  } catch {
    return 0;
  }
}

async function writeCursor(scope, consumed) {
  const path = cursorPath(scope);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify({ consumed })}\n`, 'utf-8');
}

/**
 * Return the operator chat messages the agent hasn't seen yet, and
 * advance the cursor past every scanned line. Best-effort: any read
 * error returns [] so the caller never throws.
 *
 * @param {object} args
 * @param {string} [args.scope]
 * @returns {Promise<Array<{ group_id: string, received_at: string, text: string }>>}
 */
export async function readUnreadMessages({ scope } = {}) {
  let raw;
  try {
    raw = await readFile(inboxPath(scope), 'utf-8');
  } catch {
    return [];
  }
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  const consumed = await readCursor(scope);
  if (lines.length <= consumed) {
    // Cursor caught up, or the file rotated smaller — reset so a
    // freshly-rotated file doesn't get skipped.
    if (consumed > lines.length) await writeCursor(scope, lines.length);
    return [];
  }

  const fresh = lines.slice(consumed);
  const items = [];
  for (const line of fresh) {
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    const env = rec?.envelope;
    const type = typeof env?.type === 'string' ? env.type : '';
    if (!type.startsWith('operator.message')) continue;
    const text =
      typeof env?.payload?.text === 'string'
        ? env.payload.text
        : typeof env?.payload === 'string'
          ? env.payload
          : null;
    if (!text) continue;
    items.push({
      group_id: rec.group_id_b64 ?? rec.idp_group_id ?? '?',
      received_at: rec.received_at ?? '',
      text,
    });
  }

  // Advance past every line scanned (not just chat ones) so non-chat
  // entries aren't re-scanned forever.
  await writeCursor(scope, lines.length);
  return items;
}
