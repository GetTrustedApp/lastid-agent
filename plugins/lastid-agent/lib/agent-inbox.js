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
import { OperatorStore, redactMatches } from './operator-store.js';
import { enqueueAuditEvent } from './audit-spool.js';

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

  // Load the operator's synced rule set once for inbound channel
  // enforcement (the `message_in` surface). Best-effort: if the store
  // is unreadable / never synced, `store` stays null and every message
  // surfaces unfiltered (fail open — a rule subsystem hiccup must never
  // silently swallow the operator's messages).
  let store = null;
  try {
    store = new OperatorStore(scope ?? 'main');
  } catch {
    store = null;
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
    const enforced = enforceInbound(store, text);
    const groupId = rec.group_id_b64 ?? rec.idp_group_id ?? '?';
    items.push({
      group_id: groupId,
      received_at: rec.received_at ?? '',
      text: enforced.text,
      ...(enforced.policy_action ? { policy_action: enforced.policy_action } : {}),
    });
    // Audit chain: an inbound operator message (the 'messages' class). The
    // cursor advances past each line, so a message is surfaced + audited once.
    // NON-sensitive — never the text; only that one arrived (+ any policy action).
    try {
      enqueueAuditEvent({
        scope,
        eventType: 'MessageReceived',
        metadata: { from: 'operator', group_id: groupId, ...(enforced.policy_action ? { policy_action: enforced.policy_action } : {}) },
      });
    } catch {
      /* best-effort */
    }
  }

  // Advance past every line scanned (not just chat ones) so non-chat
  // entries aren't re-scanned forever.
  await writeCursor(scope, lines.length);
  return items;
}

/**
 * Apply the operator's inbound channel rules (`message_in`) to one
 * decrypted message before the agent sees it. Returns the (possibly
 * transformed) text plus the action taken:
 *
 *   - deny    → withhold the content; surface a policy notice instead so
 *               the agent knows a message was blocked (and can ask the
 *               operator) rather than acting on phantom content.
 *   - warn    → surface the message, prefixed with a caution banner.
 *   - rewrite → redact the matched span(s) before surfacing.
 *   - (no match / no store / error) → surface unchanged.
 *
 * Only rules the operator explicitly scoped to `message_in` apply here
 * (exactToolOnly) — a generic "deny X on any tool" rule is about tool
 * execution and must not silently swallow a message that mentions X.
 * Wrapped so any matcher error fails open to the original text.
 */
export function enforceInbound(store, text) {
  if (!store) return { text };
  let decision;
  try {
    decision = store.matchRules('message_in', text, { exactToolOnly: true });
  } catch {
    return { text }; // matcher error → fail open
  }
  if (!decision || decision.allow !== false || !decision.matched) return { text };
  const m = decision.matched;
  const tag = `[${m.memory_id}]${m.reason ? `: ${m.reason}` : ''}`;
  if (m.severity === 'deny') {
    return {
      text:
        `⛔ A message from your operator was withheld by their own inbound ` +
        `channel rule ${tag}. The content matched a pattern they configured ` +
        `to block before it reaches you. If you need it, reply via ` +
        `lastid_send_message and ask them to rephrase.`,
      policy_action: 'deny',
    };
  }
  if (m.severity === 'rewrite') {
    return {
      text: redactMatches(text, m.pattern, m.replacement, m.is_regex),
      policy_action: 'rewrite',
    };
  }
  // warn (and any unknown severity) — surface with a caution banner.
  return {
    text:
      `⚠ Operator inbound channel policy ${tag} — treat the message below ` +
      `with caution:\n\n${text}`,
    policy_action: 'warn',
  };
}
