/**
 * Agent outbound chat — outbox enqueue (any process) + drain (the
 * listener only).
 *
 * Single-writer invariant: MLS application-message encryption
 * advances the group's ratchet, so it MUST happen in exactly one
 * process. The listener daemon owns the live MLS state + the WS, so
 * it is the sole sender. Other processes (the MCP server handling a
 * `lastid_send_message` tool call from Claude) cannot encrypt
 * directly — they'd fork the ratchet. Instead they append a plain
 * request to the outbox; the listener drains it, encrypts with the
 * live client, sends over its WS, and persists. One listener, shared
 * state, one writer.
 *
 * Outbox: `~/.lastid-agent/<scope>/outbox.jsonl`, one JSON request
 * per line:
 *
 *   { "id": "<uuid>", "operator_did": "did:lastid:z…", "text": "<plaintext>",
 *     "enqueued_at": "<ISO-8601>" }
 *
 * Keyed by operator DID (not a fixed group id) so the drain resolves
 * the operator's current group at send time — a rotated group is
 * handled without the queued message getting stuck.
 *
 * Transport: application messages ride the WebSocket as
 * `group_chat.message` frames (NOT a REST endpoint — /v1/groups/:id/
 * commits is for MLS epoch commits). Payload shape matches the IdP's
 * GroupMessageSendPayload: { group_id, mls_message, epoch,
 * sender_did, message_type, message_id }.
 *
 * Envelope shape: the inner chat envelope mirrors the operator side
 * (`operator.message.text`) so a human reading the agent's reply in
 * the dock and the agent reading the operator's message use the same
 * vocabulary:
 *
 *   { version: 1, type: "operator.message.text",
 *     issued_at: <ISO>, payload: { text } }
 */

import { Buffer } from 'node:buffer';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { resolveActiveGroupForOperator } from './agent-groups.js';

function outboxPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'outbox.jsonl');
}

function newId() {
  return typeof globalThis.crypto?.randomUUID === 'function'
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/**
 * Append a send request to the outbox. Safe to call from any process
 * (the MCP tool does) — it never touches MLS state. The listener
 * picks it up on its next drain tick. Returns the request id.
 */
export async function enqueueSend({ scope, operatorDid, text }) {
  if (!operatorDid || typeof operatorDid !== 'string') {
    throw new Error('enqueueSend: operatorDid required');
  }
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('enqueueSend: text required');
  }
  // Store the OPERATOR did, not a fixed group id. The drain resolves
  // the operator's current active group at send time, so if the
  // group rotated (recovery — the operator recreated it and we
  // rejoined via welcome) the queued message rides the new group
  // automatically instead of being stuck on a dead one.
  const req = {
    id: newId(),
    operator_did: operatorDid,
    text,
    enqueued_at: new Date().toISOString(),
  };
  const path = outboxPath(scope);
  await mkdir(dirname(path), { recursive: true });
  // Append-only; the listener truncates after a successful drain.
  await writeFile(path, `${JSON.stringify(req)}\n`, { flag: 'a' });
  return req.id;
}

function textToB64(text) {
  return Buffer.from(text, 'utf-8').toString('base64');
}

/**
 * Drain the outbox: for each pending request, resolve its group,
 * encrypt the envelope, send a `group_chat.message` frame, and
 * persist MLS state. Called by the listener on a poll tick — it is
 * the single MLS-state writer, so this is the only place encryption
 * happens.
 *
 * Crash safety: we read the whole outbox, process in order, and
 * rewrite the file with only the requests that did NOT succeed.
 * A crash mid-drain leaves the request in the outbox → redelivered
 * next tick. At-least-once: a request whose send landed but whose
 * rewrite didn't could be re-sent (MLS de-dupes nothing here, so the
 * operator might see a dup) — acceptable for v1; message_id gives the
 * IdP/clients an ACK/dedup key to tighten later.
 *
 * @param {object} args
 * @param {string} args.scope
 * @param {import('./mls-client.js').MlsClient} args.mls  Live client (listener-owned).
 * @param {string} args.agentDid
 * @param {(frame: object) => void} args.send  ws.send-style sender.
 * @param {(line: string) => void} [args.log]
 */
export async function drainOutbox({ scope, mls, agentDid, send, log }) {
  const path = outboxPath(scope);
  const logLine = log ?? ((l) => process.stderr.write(`${l}\n`));
  let raw;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (err.code === 'ENOENT') return; // nothing queued
    throw err;
  }
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length === 0) return;

  const remaining = [];
  for (const line of lines) {
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      // Malformed line — drop it (can't act on it; keeping it would
      // wedge the drain forever).
      logLine('[lastid-agent] outbox: dropping malformed line');
      continue;
    }
    try {
      await sendOne({ scope, mls, agentDid, send, req });
      logLine(
        `[lastid-agent] outbox: sent ${req.id} → operator ${req.operator_did}`,
      );
    } catch (err) {
      const msg = err?.message ?? String(err);
      logLine(`[lastid-agent] outbox: send ${req.id} failed: ${msg}`);
      // Keep it for retry on the next tick.
      remaining.push(line);
    }
  }

  // Rewrite atomically: write the survivors to a temp file, rename.
  const tmp = `${path}.tmp`;
  await writeFile(tmp, remaining.length ? `${remaining.join('\n')}\n` : '', 'utf-8');
  await rename(tmp, path);
}

async function sendOne({ scope, mls, agentDid, send, req }) {
  // Resolve the operator's CURRENT active group at send time (not a
  // group id baked in at enqueue) so a rotated group is picked up
  // automatically. Strict operator match — we never send to anyone
  // but the operator.
  const resolved = await resolveActiveGroupForOperator({
    scope,
    operatorDid: req.operator_did,
  });
  if (!resolved) {
    throw new Error(
      `no active group with operator ${req.operator_did} — waiting for a group to be established`,
    );
  }
  const { groupIdB64, idpGroupId } = resolved;

  const envelope = {
    version: 1,
    type: 'operator.message.text',
    issued_at: new Date().toISOString(),
    payload: { text: req.text },
  };
  const envelopeB64 = textToB64(JSON.stringify(envelope));
  const mlsMessage = mls.encryptApplicationMessage(groupIdB64, envelopeB64);
  // Persist immediately — the ratchet advanced. If the send below
  // fails the state is still consistent (the message generation was
  // consumed; a retry re-encrypts at the next generation).
  await mls.persist();

  const epoch = Number(mls.groupEpoch(groupIdB64));
  send({
    type: 'group_chat.message',
    correlation_id: req.id,
    timestamp: new Date().toISOString(),
    payload: {
      group_id: idpGroupId,
      mls_message: mlsMessage,
      epoch: Number.isFinite(epoch) ? epoch : 0,
      sender_did: agentDid,
      message_type: 'text',
      message_id: req.id,
    },
  });
}
