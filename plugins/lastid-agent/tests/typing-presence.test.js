/**
 * Pure presence state machine: working (processing the turn) + typing (sending a
 * message) as INDEPENDENT signals. Deterministic with an injected clock.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  reducePresence,
  initialPresence,
  DEFAULT_PRESENCE_CONFIG,
} from '../lib/typing-presence.js';

const CFG = { idleMs: 10_000, maxMs: 60_000 };

// Apply a sequence of [type, now] events from a fresh window; return the final
// state + the flat list of actions emitted along the way.
function run(events) {
  let state = initialPresence();
  const actions = [];
  for (const [type, now] of events) {
    const r = reducePresence(state, { type }, now, CFG);
    state = r.state;
    actions.push(...r.actions);
  }
  return { state, actions };
}

test('operator_message: read receipt + WORKING on (not typing)', () => {
  const r = reducePresence(initialPresence(), { type: 'operator_message' }, 1000, CFG);
  assert.deepEqual(r.actions, ['received', 'working_on']);
  assert.equal(r.state.workingOn, true);
  assert.equal(r.state.typingOn, false);
});

test('sending → typing_on; agent_reply → typing_off; WORKING stays on the whole time (no flicker)', () => {
  const { state, actions } = run([
    ['operator_message', 1000],
    ['sending', 1100], // about to send a message
    ['agent_reply', 1200], // it landed
    ['sending', 1300], // sending another
    ['agent_reply', 1400],
  ]);
  // Working never went off across the intermediate replies — the regression.
  assert.equal(state.workingOn, true);
  assert.equal(state.typingOn, false);
  assert.deepEqual(actions, [
    'received',
    'working_on',
    'typing_on',
    'typing_off',
    'typing_on',
    'typing_off',
  ]);
});

test('REGRESSION: an agent_reply does NOT clear working (the old flicker-off-on-reply bug)', () => {
  const { state } = run([['operator_message', 1000]]);
  // A reply with no prior typing is a no-op on typing and MUST NOT touch working.
  const r = reducePresence(state, { type: 'agent_reply' }, 1100, CFG);
  assert.deepEqual(r.actions, []);
  assert.equal(r.state.workingOn, true, 'working still on after a reply');
});

test('activity keeps working alive (refreshes lastActivityAt, no dup working_on)', () => {
  let state = initialPresence();
  state = reducePresence(state, { type: 'operator_message' }, 1000, CFG).state;
  const r = reducePresence(state, { type: 'activity' }, 2000, CFG);
  assert.deepEqual(r.actions, []); // already working
  assert.equal(r.state.lastActivityAt, 2000);
  assert.equal(r.state.workingOn, true);
});

test('turn_end clears working + typing and closes the window (the precise end)', () => {
  let state = initialPresence();
  state = reducePresence(state, { type: 'operator_message' }, 1000, CFG).state;
  state = reducePresence(state, { type: 'sending' }, 1100, CFG).state;
  const r = reducePresence(state, { type: 'turn_end' }, 1200, CFG);
  assert.deepEqual(r.actions, ['typing_off', 'working_off']);
  assert.deepEqual(r.state, initialPresence());
});

test('tick re-emits working_on as a keep-alive while open and under the cap', () => {
  let state = initialPresence();
  state = reducePresence(state, { type: 'operator_message' }, 1000, CFG).state;
  const r = reducePresence(state, { type: 'tick' }, 5000, CFG);
  assert.deepEqual(r.actions, ['working_on']);
});

test('tick past maxMs closes the window as a backstop (missed turn_end)', () => {
  let state = initialPresence();
  state = reducePresence(state, { type: 'operator_message' }, 1000, CFG).state;
  const r = reducePresence(state, { type: 'tick' }, 1000 + CFG.maxMs + 1, CFG);
  assert.deepEqual(r.actions, ['working_off']);
  assert.deepEqual(r.state, initialPresence());
});

test('NEGATIVE: sending / activity / turn_end / tick with NO open window emit nothing (CLI work)', () => {
  for (const type of ['sending', 'activity', 'turn_end', 'tick']) {
    const r = reducePresence(initialPresence(), { type }, 1000, CFG);
    assert.deepEqual(r.actions, [], `${type} with no window`);
    assert.equal(r.state.openedAt, null);
  }
});

test('NEGATIVE: a second `sending` while already typing does not re-emit', () => {
  let state = initialPresence();
  state = reducePresence(state, { type: 'operator_message' }, 1000, CFG).state;
  state = reducePresence(state, { type: 'sending' }, 1100, CFG).state;
  const r = reducePresence(state, { type: 'sending' }, 1150, CFG);
  assert.deepEqual(r.actions, []);
});

test('a full turn: message → work → send → reply → more work → turn_end', () => {
  const { actions } = run([
    ['operator_message', 1000],
    ['activity', 1500], // already working → no action
    ['sending', 2000],
    ['agent_reply', 2100],
    ['activity', 3000], // already working → no action
    ['turn_end', 4000],
  ]);
  assert.deepEqual(actions, ['received', 'working_on', 'typing_on', 'typing_off', 'working_off']);
});

test('DEFAULT_PRESENCE_CONFIG exposes maxMs (the backstop cap)', () => {
  assert.equal(typeof DEFAULT_PRESENCE_CONFIG.maxMs, 'number');
});
