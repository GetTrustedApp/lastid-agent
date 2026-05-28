/**
 * MlsDispatcher single-flight chain — regression for the
 * "recursive use of an object detected which would lead to unsafe aliasing
 * in rust" wasm-bindgen panic. The wasm MLS client is RefCell-backed, so
 * two concurrent calls on the same handle trip the borrow tracker and
 * throw from inside a wasm future — which Node v15+ surfaces as an
 * unhandledRejection and kills the listener process.
 *
 * The fix: MlsDispatcher.onEvent now queues every dispatch through a
 * private #chain, so even when callers fire-and-forget (as cli.js's WS
 * callback used to), back-to-back WS frames run sequentially on the wasm
 * handle. These tests lock that invariant from outside: a fake "mls" with
 * a borrow counter must never see in-flight > 1.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MlsDispatcher } from '../lib/mls-dispatch.js';

/** Build a fake MlsClient whose every async method asserts no concurrent borrow. */
function makeBorrowTracker() {
  let inFlight = 0;
  let maxConcurrent = 0;
  const trip = { recorded: false };
  // Record entry/exit around an async body. If any caller starts work
  // while another is in-flight, maxConcurrent goes above 1 and we record
  // the trip (mirrors what wasm-bindgen's borrow_fail would catch).
  const guarded = (asyncBody) => async (...args) => {
    inFlight += 1;
    if (inFlight > maxConcurrent) maxConcurrent = inFlight;
    if (inFlight > 1) trip.recorded = true;
    try {
      return await asyncBody(...args);
    } finally {
      inFlight -= 1;
    }
  };
  // Stub MlsClient surface the dispatcher touches in the welcome /
  // message paths. Delays simulate the wasm side doing async work.
  const tick = () => new Promise((r) => setImmediate(r));
  const mls = {
    agentDid: 'did:lastid:agent:test',
    processWelcome: guarded(async () => {
      await tick();
      await tick();
      return { group_id_b64: 'g==', member_count: 2 };
    }),
    processInbound: guarded(async () => {
      await tick();
      await tick();
      return { kind: 'application_message_text', text: 'hi', group_id_b64: 'g==' };
    }),
    persist: guarded(async () => {
      await tick();
    }),
    forgetGroup: guarded(async () => { await tick(); }),
    commitPendingProposals: guarded(async () => { await tick(); }),
    rollbackPendingCommit: guarded(async () => { await tick(); }),
  };
  return { mls, get inFlight() { return inFlight; }, get maxConcurrent() { return maxConcurrent; }, get tripped() { return trip.recorded; } };
}

function silentDispatcher(mls) {
  return new MlsDispatcher({
    mls,
    scope: 'test',
    log: () => {},
    requestSend: () => {},
  });
}

test('onEvent serializes concurrent calls — wasm handle never re-entered', async () => {
  const tracker = makeBorrowTracker();
  const d = silentDispatcher(tracker.mls);
  // Fire welcome + message concurrently — exactly the burst pattern the
  // listener log showed before the fix (welcome.204 → live message.363).
  // Old code: dispatcher.onEvent(evt) (no await) for both → race.
  // New code: each onEvent queues onto #chain → second waits for first.
  const a = d.onEvent({
    type: 'group_chat.welcome',
    payload: { mls_welcome: 'AA==', group_id: 'idp-uuid' },
  });
  const b = d.onEvent({
    type: 'group_chat.message',
    payload: { mls_message: 'AA==', group_id: 'idp-uuid' },
  });
  await Promise.all([a, b]);
  assert.equal(tracker.tripped, false, 'concurrent borrow detected — mutex did not hold');
  assert.equal(tracker.maxConcurrent, 1, `expected max 1 in-flight, saw ${tracker.maxConcurrent}`);
});

test('a failing handler does not stall the chain — next onEvent still runs', async () => {
  const tracker = makeBorrowTracker();
  let firstStarted = false;
  let secondCompleted = false;
  // First processWelcome rejects; the second event must still get its
  // turn at the wasm handle. Captures the "one bad frame strands the
  // listener" failure mode the old `dispatcher.onEvent(evt)` (no await)
  // also hid — the chain pattern handles it via `.then(task, task)`.
  tracker.mls.processWelcome = async () => {
    firstStarted = true;
    throw new Error('synthetic processWelcome failure');
  };
  tracker.mls.processInbound = async () => {
    secondCompleted = true;
    return { kind: 'application_message_text', text: 'hi', group_id_b64: 'g==' };
  };
  const d = silentDispatcher(tracker.mls);
  const a = d.onEvent({
    type: 'group_chat.welcome',
    payload: { mls_welcome: 'AA==', group_id: 'idp-uuid' },
  });
  const b = d.onEvent({
    type: 'group_chat.message',
    payload: { mls_message: 'AA==', group_id: 'idp-uuid' },
  });
  // The dispatcher itself swallows handler failures (try/catch in
  // #dispatchEvent), so onEvent should resolve cleanly for both.
  await Promise.all([a, b]);
  assert.equal(firstStarted, true, 'first handler never ran');
  assert.equal(secondCompleted, true, 'second handler never ran — chain stalled');
});

test('queue_batch replay does not deadlock — recursive dispatch bypasses outer mutex', async () => {
  const tracker = makeBorrowTracker();
  const d = silentDispatcher(tracker.mls);
  // queue_batch carries a nested group_chat.message; the dispatcher
  // replays each entry via #dispatchEvent (NOT onEvent) so it does not
  // wait on the outer mutex it is already holding. If we accidentally
  // re-entered through onEvent the await would never resolve and this
  // test would time out (node:test default timeout = process default).
  let inboundCalls = 0;
  tracker.mls.processInbound = async () => {
    inboundCalls += 1;
    return { kind: 'application_message_text', text: 'hi', group_id_b64: 'g==' };
  };
  await d.onEvent({
    type: 'group_chat.queue_batch',
    payload: {
      group_id: 'idp-uuid',
      messages: [
        { type: 'group_chat.message', payload: { mls_message: 'AA==', group_id: 'idp-uuid' } },
        { type: 'group_chat.message', payload: { mls_message: 'BB==', group_id: 'idp-uuid' } },
      ],
      total_queued: 2,
      has_more: false,
    },
  });
  assert.equal(inboundCalls, 2, 'queue_batch replay did not process both queued messages');
  assert.equal(tracker.maxConcurrent, 1, 'queue_batch replay re-entered the wasm handle concurrently');
});

test('onEvent returns a real promise — caller `await` reflects completion', async () => {
  // Before the fix the WS callback fire-and-forget pattern hid handler
  // throws from the WS layer's try/catch; the dispatcher now returns its
  // chain promise so an awaiting caller sees completion synchronously
  // ordered with the dispatch.
  const tracker = makeBorrowTracker();
  let inboundFinished = false;
  tracker.mls.processInbound = async () => {
    await new Promise((r) => setTimeout(r, 5));
    inboundFinished = true;
    return { kind: 'application_message_text', text: 'hi', group_id_b64: 'g==' };
  };
  const d = silentDispatcher(tracker.mls);
  await d.onEvent({
    type: 'group_chat.message',
    payload: { mls_message: 'AA==', group_id: 'idp-uuid' },
  });
  assert.equal(inboundFinished, true, 'onEvent returned before its handler resolved');
});
