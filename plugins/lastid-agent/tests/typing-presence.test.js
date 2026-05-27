/**
 * The presence state machine decides when the listener emits `received` +
 * `typing` for a channel conversation. These tests pin the behaviors that
 * matter: typing shows while the agent works, clears on a reply, RESUMES on
 * fresh activity (not on a bare tick — no flicker after the final reply),
 * fades on idle, is capped, and — critically — never opens for command-line
 * work (no operator_message → no window → no typing).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  reducePresence,
  initialPresence,
  DEFAULT_PRESENCE_CONFIG as CFG,
} from '../lib/typing-presence.js';

test('operator_message opens the window: emits received + typing_on', () => {
  const { state, actions } = reducePresence(initialPresence(), { type: 'operator_message' }, 1000);
  assert.deepEqual(actions, ['received', 'typing_on']);
  assert.equal(state.openedAt, 1000);
  assert.equal(state.typingOn, true);
});

test('tick keep-alives typing while live + on', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  const { actions } = reducePresence(s, { type: 'tick' }, 4000); // within idle
  assert.deepEqual(actions, ['typing_on']); // heartbeat re-emit
});

test('agent_reply clears typing but keeps the window open', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  const r = reducePresence(s, { type: 'agent_reply' }, 2000);
  assert.deepEqual(r.actions, ['typing_off']);
  assert.equal(r.state.typingOn, false);
  assert.notEqual(r.state.openedAt, null); // still open
});

test('a bare tick after a reply does NOT re-show typing (no flicker)', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  s = reducePresence(s, { type: 'agent_reply' }, 2000).state; // typing off, window open
  const { actions } = reducePresence(s, { type: 'tick' }, 4000); // still within idle
  assert.deepEqual(actions, []); // ticks never turn typing back on
});

test('fresh activity after a reply RESUMES typing (agent kept working)', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  s = reducePresence(s, { type: 'agent_reply' }, 2000).state;
  const r = reducePresence(s, { type: 'activity' }, 3000);
  assert.deepEqual(r.actions, ['typing_on']);
  assert.equal(r.state.typingOn, true);
});

test('tick after idleMs of no activity fades typing + closes the window', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  const r = reducePresence(s, { type: 'tick' }, CFG.idleMs + 1);
  assert.deepEqual(r.actions, ['typing_off']);
  assert.equal(r.state.openedAt, null);
});

test('tick past maxMs closes even with continuous activity', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  // Activity right up to the cap keeps idle fresh, but the hard cap still wins.
  s = reducePresence(s, { type: 'activity' }, CFG.maxMs - 10).state;
  const r = reducePresence(s, { type: 'tick' }, CFG.maxMs + 1);
  assert.deepEqual(r.actions, ['typing_off']);
  assert.equal(r.state.openedAt, null);
});

test('activity with NO open window is ignored — CLI work never emits typing', () => {
  const r = reducePresence(initialPresence(), { type: 'activity' }, 5000);
  assert.deepEqual(r.actions, []);
  assert.equal(r.state.openedAt, null);
  assert.equal(r.state.typingOn, false);
});

test('tick with no open window does nothing', () => {
  const r = reducePresence(initialPresence(), { type: 'tick' }, 5000);
  assert.deepEqual(r.actions, []);
  assert.equal(r.state.openedAt, null);
});

test('agent_reply with typing already off is a no-op', () => {
  const r = reducePresence(initialPresence(), { type: 'agent_reply' }, 1000);
  assert.deepEqual(r.actions, []);
});

test('idle window: a tick when typing already faded just closes it (no dup typing_off)', () => {
  let s = reducePresence(initialPresence(), { type: 'operator_message' }, 0).state;
  s = reducePresence(s, { type: 'agent_reply' }, 1000).state; // typing off, window open
  const r = reducePresence(s, { type: 'tick' }, CFG.idleMs + 1); // idle now
  assert.deepEqual(r.actions, []); // typing already off → nothing to emit
  assert.equal(r.state.openedAt, null); // window closed
});

test('a full working turn: message → work → reply → idle', () => {
  const seq = [];
  let s = initialPresence();
  const step = (type, now) => {
    const r = reducePresence(s, { type }, now);
    s = r.state;
    seq.push([now, type, r.actions]);
  };
  step('operator_message', 0); // received + typing_on
  step('tick', 4000); // keep-alive typing_on
  step('activity', 5000); // working (no change, already on)
  step('tick', 8000); // keep-alive
  step('agent_reply', 9000); // typing_off
  step('tick', 12000); // no flicker → []
  step('tick', 9000 + CFG.idleMs + 1); // idle → close, already off → []
  assert.deepEqual(seq[0][2], ['received', 'typing_on']);
  assert.deepEqual(seq[1][2], ['typing_on']);
  assert.deepEqual(seq[4][2], ['typing_off']);
  assert.deepEqual(seq[5][2], []);
  assert.equal(s.openedAt, null);
});
