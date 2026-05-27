/**
 * PresenceEmitter turns state-machine actions into `group_chat.typing` frames
 * on the listener's WS. These tests assert the actual frames emitted across a
 * conversation, with an injected clock + a capturing `send`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PresenceEmitter } from '../lib/presence-emitter.js';

const GROUP = 'idp-group-uuid-1';
const AGENT = 'did:lastid:agent:z6MkAgent';

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

const typing = (is_typing) => ({
  type: 'group_chat.typing',
  payload: { group_id: GROUP, user_did: AGENT, is_typing },
});

function lastTyping(sent) {
  const f = [...sent].reverse().find((x) => x.type === 'group_chat.typing');
  return f ? { type: f.type, payload: f.payload } : null;
}

test('operator message emits typing(true) for that group', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  assert.deepEqual(lastTyping(h.sent), typing(true));
  // user_did is the agent (the typer); group is the IdP group id.
  assert.equal(h.sent[0].payload.user_did, AGENT);
});

test('tick within idle re-emits typing(true) as a keep-alive', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  h.sent.length = 0;
  h.advance(4000);
  h.emitter.tick();
  assert.deepEqual(lastTyping(h.sent), typing(true));
});

test('agent reply emits typing(false)', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  h.sent.length = 0;
  h.emitter.onAgentReply(GROUP);
  assert.deepEqual(lastTyping(h.sent), typing(false));
});

test('a tick right after a reply emits nothing (no flicker)', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  h.emitter.onAgentReply(GROUP);
  h.sent.length = 0;
  h.advance(3000);
  h.emitter.tick();
  assert.deepEqual(h.sent, []);
});

test('activity after a reply resumes typing(true)', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  h.emitter.onAgentReply(GROUP);
  h.sent.length = 0;
  h.advance(2000);
  h.emitter.noteActivity();
  assert.deepEqual(lastTyping(h.sent), typing(true));
});

test('idle timeout emits typing(false) and prunes the window', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP);
  h.sent.length = 0;
  h.advance(10_001); // past idleMs
  h.emitter.tick();
  assert.deepEqual(lastTyping(h.sent), typing(false));
  // Pruned: a further tick does nothing.
  h.sent.length = 0;
  h.advance(4000);
  h.emitter.tick();
  assert.deepEqual(h.sent, []);
});

test('activity with no open window (CLI work) emits nothing', () => {
  const h = harness();
  h.emitter.noteActivity();
  h.emitter.tick();
  assert.deepEqual(h.sent, []);
});

test('constructor requires a send function', () => {
  assert.throws(() => new PresenceEmitter({ userDid: AGENT }), /send required/);
});

// ── read receipts (the `received` action → group_chat.read) ───────────────

const OPERATOR = 'did:lastid:z5cZOperatorHuman';
function lastRead(sent) {
  return [...sent].reverse().find((x) => x.type === 'group_chat.read') ?? null;
}

test('POSITIVE: operator message with {messageId, senderDid} emits a group_chat.read receipt in the IdP shape', () => {
  const h = harness();
  h.emitter.onOperatorMessage(GROUP, { messageId: 'msg-42', senderDid: OPERATOR });
  // Still starts typing.
  assert.deepEqual(lastTyping(h.sent), typing(true));
  // And emits a read receipt the IdP's handleStatusEvent can proxy to the operator.
  const read = lastRead(h.sent);
  assert.ok(read, 'a group_chat.read frame was emitted');
  assert.equal(read.correlation_id, 'msg-42');
  assert.equal(read.payload.group_id, GROUP);
  assert.equal(read.payload.message_id, 'msg-42');
  assert.equal(read.payload.sender_did, AGENT); // the reader (this agent) reports the status
  assert.equal(read.payload.recipient_did, OPERATOR); // the operator who sent it receives the receipt
  assert.equal(typeof read.payload.read_at, 'string');
});

test('NEGATIVE: operator message missing message_id or sender_did emits typing but NO read receipt', () => {
  // Missing message_id → no receipt (a receipt without message_id would error
  // the IdP relay, which does message_id.substring()).
  const h = harness();
  h.emitter.onOperatorMessage(GROUP, { messageId: null, senderDid: OPERATOR });
  assert.deepEqual(lastTyping(h.sent), typing(true));
  assert.equal(lastRead(h.sent), null);

  // Missing sender_did → no recipient to proxy to → no receipt.
  const h2 = harness();
  h2.emitter.onOperatorMessage(GROUP, { messageId: 'msg-1', senderDid: null });
  assert.equal(lastRead(h2.sent), null);

  // Bare call (back-compat) → no receipt.
  const h3 = harness();
  h3.emitter.onOperatorMessage(GROUP);
  assert.equal(lastRead(h3.sent), null);
});
