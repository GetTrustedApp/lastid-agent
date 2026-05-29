/**
 * PresenceEmitter turns state-machine actions into wire frames on the listener's
 * WS: group_chat.typing carrying BOTH `is_typing` (sending a message) and
 * `working` (processing the turn), plus a group_chat.read receipt. These tests
 * assert the actual frames, with an injected clock + a capturing `send`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PresenceEmitter } from '../lib/presence-emitter.js';

const GROUP = 'idp-group-uuid-1';
const AGENT = 'did:lastid:agent:z6MkAgent';
const OPERATOR = 'did:lastid:z5cZOperatorHuman';

function harness() {
  const sent = [];
  let now = 1_000;
  const emitter = new PresenceEmitter({
    send: (f) => sent.push(f),
    userDid: AGENT,
    now: () => now,
    config: { idleMs: 10_000, maxMs: 60_000 },
  });
  return { sent, emitter, setNow: (t) => (now = t), advance: (d) => (now += d) };
}

/** Latest group_chat.typing frame's presence flags, or null. */
function lastPresence(sent) {
  const f = [...sent].reverse().find((x) => x.type === 'group_chat.typing');
  return f ? { is_typing: f.payload.is_typing, working: f.payload.working } : null;
}
function lastRead(sent) {
  return [...sent].reverse().find((x) => x.type === 'group_chat.read') ?? null;
}
const openTurn = (h) =>
  h.emitter.onOperatorMessage(GROUP, { messageId: 'm1', senderDid: OPERATOR });

test('operator message → read receipt + working:true (NOT typing)', () => {
  const h = harness();
  openTurn(h);
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: true });
  const read = lastRead(h.sent);
  assert.ok(read, 'read receipt emitted');
  assert.equal(read.payload.message_id, 'm1');
  assert.equal(read.payload.sender_did, AGENT);
  assert.equal(read.payload.recipient_did, OPERATOR);
  // REGRESSION GUARD: same as the reaction — the read receipt's correlation_id
  // must be a FRESH per-frame id, NOT the targeted message_id. The older shape
  // collided with the operator's original group_chat.message correlation_id and
  // the IdP's replay detector rejected it, silently dropping every read tick.
  assert.ok(typeof read.correlation_id === 'string' && read.correlation_id.length > 0);
  assert.notEqual(read.correlation_id, 'm1');
  // Native wire parity (WebSocketManager.send_group_read_receipt): the receipt
  // routes to all of the original sender's devices.
  assert.deepEqual(read.target, { type: 'all_devices', recipient_did: OPERATOR });
  // Native wire parity: typing frame fans out to the group + carries timestamp.
  const typing = [...h.sent].reverse().find((x) => x.type === 'group_chat.typing');
  assert.deepEqual(typing.target, { type: 'group' });
  assert.equal(typeof typing.payload.timestamp, 'string');
});

test('sending → typing:true (working stays true); reply → typing:false (working STILL true)', () => {
  const h = harness();
  openTurn(h);
  h.emitter.onSending();
  assert.deepEqual(lastPresence(h.sent), { is_typing: true, working: true });
  h.emitter.onAgentReply(GROUP);
  // The dots clear but WORKING persists — the whole point of B.
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: true });
});

test('REGRESSION: working does not flip off on an intermediate reply', () => {
  const h = harness();
  openTurn(h);
  h.emitter.onSending();
  h.emitter.onAgentReply(GROUP);
  h.emitter.onSending();
  h.emitter.onAgentReply(GROUP);
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: true });
});

test('tick re-emits working:true as a keep-alive while the turn is open', () => {
  const h = harness();
  openTurn(h);
  h.sent.length = 0;
  h.advance(4000);
  h.emitter.tick();
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: true });
});

test('turn_end clears working + typing and prunes the window', () => {
  const h = harness();
  openTurn(h);
  h.emitter.onSending();
  h.sent.length = 0;
  h.emitter.onTurnEnd();
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: false });
  // Pruned: a later tick emits nothing.
  h.sent.length = 0;
  h.advance(3000);
  h.emitter.tick();
  assert.deepEqual(h.sent, []);
});

test('tick past maxMs closes the window as a backstop', () => {
  const h = harness();
  openTurn(h);
  h.sent.length = 0;
  h.advance(60_001); // past maxMs
  h.emitter.tick();
  assert.deepEqual(lastPresence(h.sent), { is_typing: false, working: false });
});

test('NEGATIVE: sending / turn_end with NO open window (CLI work) emit nothing', () => {
  const h = harness();
  h.emitter.onSending();
  h.emitter.onTurnEnd();
  h.emitter.tick();
  assert.deepEqual(h.sent, []);
});

test('NEGATIVE: read receipt is skipped without message_id or sender_did', () => {
  const h1 = harness();
  h1.emitter.onOperatorMessage(GROUP, { messageId: null, senderDid: OPERATOR });
  assert.equal(lastRead(h1.sent), null);
  assert.deepEqual(lastPresence(h1.sent), { is_typing: false, working: true }); // working still starts

  const h2 = harness();
  h2.emitter.onOperatorMessage(GROUP, { messageId: 'm1', senderDid: null });
  assert.equal(lastRead(h2.sent), null);

  const h3 = harness();
  h3.emitter.onOperatorMessage(GROUP); // bare call (back-compat)
  assert.equal(lastRead(h3.sent), null);
});

test('constructor requires a send function', () => {
  assert.throws(() => new PresenceEmitter({ userDid: AGENT }), /send required/);
});

// ── reactToLastOperatorMessage: real reaction badge on the operator's message ──

function lastReaction(sent) {
  return [...sent].reverse().find((x) => x.type === 'group_chat.reaction') ?? null;
}

test('reacts to the operator’s last message with the wire name + agent as reactor', () => {
  const h = harness();
  openTurn(h); // records { messageId: 'm1', senderDid: OPERATOR } for GROUP
  h.sent.length = 0;
  const r = h.emitter.reactToLastOperatorMessage(GROUP, '👍');
  assert.deepEqual(r, { sent: true, messageId: 'm1', reaction: 'thumbs_up', action: 'add' });
  const frame = lastReaction(h.sent);
  assert.ok(frame, 'group_chat.reaction emitted');
  assert.equal(frame.payload.group_id, GROUP);
  assert.equal(frame.payload.message_id, 'm1');
  assert.equal(frame.payload.reactor_did, AGENT);
  assert.equal(frame.payload.reaction, 'thumbs_up');
  // REGRESSION GUARD: correlation_id must be a FRESH per-frame id, NOT the
  // targeted message_id. Reusing the message_id collides with the operator's
  // original group_chat.message correlation_id and the IdP's replay detector
  // rejects the frame (REPLAY_ATTACK_DETECTED), silently dropping the badge.
  assert.ok(typeof frame.correlation_id === 'string' && frame.correlation_id.length > 0);
  assert.notEqual(frame.correlation_id, 'm1');
  // Native wire parity (WebSocketManager.send_group_reaction): group-fanout target.
  assert.deepEqual(frame.target, { type: 'group' });
});

test('action:remove emits group_chat.reaction_removed', () => {
  const h = harness();
  openTurn(h);
  h.sent.length = 0;
  const r = h.emitter.reactToLastOperatorMessage(GROUP, '🙏', 'remove');
  assert.equal(r.sent, true);
  assert.equal(r.action, 'remove');
  const removed = [...h.sent].reverse().find((x) => x.type === 'group_chat.reaction_removed');
  assert.ok(removed, 'reaction_removed emitted');
  assert.equal(removed.payload.reaction, 'pray');
  assert.equal(lastReaction(h.sent), null, 'no add frame');
});

test('NEGATIVE: no message recorded for the group → no_target_message, no frame', () => {
  const h = harness();
  const r = h.emitter.reactToLastOperatorMessage('unseen-group', '👍');
  assert.deepEqual(r, { sent: false, reason: 'no_target_message' });
  assert.equal(lastReaction(h.sent), null);
});

test('NEGATIVE: unsupported emoji → unsupported_emoji, no frame', () => {
  const h = harness();
  openTurn(h);
  h.sent.length = 0;
  const r = h.emitter.reactToLastOperatorMessage(GROUP, '🍕');
  assert.deepEqual(r, { sent: false, reason: 'unsupported_emoji' });
  assert.equal(lastReaction(h.sent), null);
});

test('NEGATIVE: a message recorded without senderDid is not a target (gate matches read receipt)', () => {
  const h = harness();
  // The recording gate requires BOTH messageId and senderDid (same as the read
  // receipt) — a half-populated message never becomes a reaction target.
  h.emitter.onOperatorMessage(GROUP, { messageId: 'm9', senderDid: null });
  const r = h.emitter.reactToLastOperatorMessage(GROUP, '👍');
  assert.deepEqual(r, { sent: false, reason: 'no_target_message' });
});

test('NEGATIVE: no group id → no_group', () => {
  const h = harness();
  assert.deepEqual(h.emitter.reactToLastOperatorMessage('', '👍'), { sent: false, reason: 'no_group' });
});
