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
import { enqueueAuditEvent } from './audit-spool.js';

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
    kind: 'message',
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

/**
 * Append a REACTION request to the outbox. Like enqueueSend, safe from any
 * process — it never touches MLS state (a reaction is a plaintext control
 * frame, not an encrypted message). The listener drains it, resolves the
 * operator's live group, and reacts to the operator's last message there (the
 * agent never handles a message id — the listener already tracks it for the
 * read-receipt path). `emoji` is validated at the tool boundary; we re-map it
 * to the wire name at drain. Returns the request id.
 */
export async function enqueueReaction({ scope, operatorDid, emoji, action = 'add' }) {
  if (!operatorDid || typeof operatorDid !== 'string') {
    throw new Error('enqueueReaction: operatorDid required');
  }
  if (typeof emoji !== 'string' || emoji.length === 0) {
    throw new Error('enqueueReaction: emoji required');
  }
  const req = {
    id: newId(),
    kind: 'reaction',
    operator_did: operatorDid,
    emoji,
    reaction_action: action === 'remove' ? 'remove' : 'add',
    enqueued_at: new Date().toISOString(),
  };
  const path = outboxPath(scope);
  await mkdir(dirname(path), { recursive: true });
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
 * @param {string} [args.idpUrl]      - enables self-heal (create a group when none exists).
 * @param {string} [args.vcCompact]   - agent VC SD-JWT (bearer) for IdP group calls.
 * @param {import('node:crypto').KeyObject} [args.signingKey] - agent Ed25519 (DPoP).
 */
export async function drainOutbox({ scope, mls, agentDid, send, log, idpUrl, vcCompact, signingKey, reactToLastMessage }) {
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
      if (req.kind === 'reaction') {
        // Reaction: no MLS encryption. Resolve the operator's group and react to
        // their last message (the listener tracks it). A "can't react" outcome
        // (no target message / unsupported emoji) is NOT retryable — drop it
        // rather than wedge the drain; only a transient send/resolve error is
        // kept (thrown below) for retry.
        const dropped = await reactOne({ scope, req, reactToLastMessage, log: logLine });
        if (dropped) {
          logLine(`[lastid-agent] outbox: dropped reaction ${req.id} (${dropped})`);
        } else {
          logLine(`[lastid-agent] outbox: reacted ${req.id} → operator ${req.operator_did}`);
        }
      } else {
        await sendOne({ scope, mls, agentDid, send, req, idpUrl, vcCompact, signingKey, log: logLine });
        logLine(
          `[lastid-agent] outbox: sent ${req.id} → operator ${req.operator_did}`,
        );
      }
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

async function sendOne({ scope, mls, agentDid, send, req, idpUrl, vcCompact, signingKey, log }) {
  // Resolve the operator's CURRENT active group at send time (not a
  // group id baked in at enqueue) so a rotated group is picked up
  // automatically. Strict operator match — we never send to anyone
  // but the operator.
  let resolved = await resolveActiveGroupForOperator({
    scope,
    operatorDid: req.operator_did,
  });
  if (!resolved) {
    // Self-heal: no conversation yet → the agent creates one and invites
    // the operator's device(s), then sends. Only attempted when the
    // listener handed us the auth material (idpUrl + VC + signing key);
    // without it we keep the message queued for the next tick.
    if (idpUrl && vcCompact && signingKey) {
      const { ensureConversation } = await import('./ensure-conversation.js');
      resolved = await ensureConversation({
        scope,
        mls,
        agentDid,
        operatorDid: req.operator_did,
        idpUrl,
        vcCompact,
        signingKey,
        log,
      });
    }
    if (!resolved) {
      throw new Error(
        `no active group with operator ${req.operator_did} — waiting for a group to be established`,
      );
    }
  }
  const { groupIdB64, idpGroupId } = resolved;

  const envelope = {
    version: 1,
    type: 'operator.message.text',
    issued_at: new Date().toISOString(),
    payload: { text: req.text },
  };
  const envelopeB64 = textToB64(JSON.stringify(envelope));
  const mlsMessage = await mls.encryptApplicationMessage(groupIdB64, envelopeB64);
  // encryptApplicationMessage auto-flushes through the storage-provider
  // callback before the Promise resolves; persist() is a kept-for-compat
  // no-op.
  await mls.persist();

  const epoch = Number(await mls.groupEpoch(groupIdB64));
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
  // Audit chain: an outbound message to the operator (the 'messages' class).
  // NON-sensitive — never the text; only that a message was sent + its id/epoch.
  try {
    enqueueAuditEvent({
      scope,
      eventType: 'MessageSent',
      metadata: { to: 'operator', message_id: req.id, epoch: Number.isFinite(epoch) ? epoch : 0 },
    });
  } catch {
    /* best-effort */
  }
}

/**
 * Drain one reaction request. Resolves the operator's CURRENT active group
 * (same as sendOne — handles rotation), then asks the listener to react to the
 * operator's last message there via the injected `reactToLastMessage` callback
 * (backed by PresenceEmitter, which holds the target message id). Returns a
 * drop-reason string when the request is non-retryable (so the caller logs +
 * discards it), or null on success. Throws only on a transient error worth a
 * retry (no group yet, or no reactor wired).
 */
async function reactOne({ scope, req, reactToLastMessage, log }) {
  if (typeof reactToLastMessage !== 'function') {
    // The listener didn't wire a reactor (shouldn't happen in the daemon) —
    // keep the request for a retry once it does.
    throw new Error('no reactToLastMessage reactor wired');
  }
  const resolved = await resolveActiveGroupForOperator({
    scope,
    operatorDid: req.operator_did,
  });
  // No group yet → there's nothing to react to, but a conversation may be
  // establishing. Retry on the next tick (do NOT self-heal/create one — you
  // can't react to a message that was never received).
  if (!resolved) {
    throw new Error(
      `no active group with operator ${req.operator_did} — waiting for one`,
    );
  }
  const { idpGroupId } = resolved;
  const action = req.reaction_action === 'remove' ? 'remove' : 'add';
  const result = reactToLastMessage(idpGroupId, req.emoji, action);
  if (!result || result.sent !== true) {
    // Non-retryable: there's no target message in this group (e.g. the listener
    // restarted and lost the in-memory pointer) or the emoji isn't a supported
    // reaction. Either way, re-trying won't help — drop it.
    return result?.reason ?? 'react_failed';
  }
  // Audit chain: an outbound reaction to the operator (the 'messages' class).
  // NON-sensitive — the reaction name + targeted message id, never any content.
  try {
    enqueueAuditEvent({
      scope,
      eventType: 'ReactionSent',
      metadata: {
        to: 'operator',
        request_id: req.id,
        reaction: result.reaction,
        action,
        message_id: result.messageId,
      },
    });
  } catch {
    /* best-effort */
  }
  if (typeof log === 'function') {
    log(`[lastid-agent] reaction ${result.reaction} (${action}) → message ${result.messageId}`);
  }
  return null;
}
