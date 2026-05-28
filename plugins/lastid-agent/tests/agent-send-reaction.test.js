/**
 * Reaction outbox path (lib/agent-send.js): enqueueReaction writes a
 * kind:'reaction' line, and drainOutbox routes it to the injected
 * reactToLastMessage reactor — dropping a non-retryable outcome (no target
 * message / unsupported emoji) so it can't wedge the drain, and RETAINING a
 * transient one (no group yet) for the next tick. Uses a temp HOME so the
 * outbox + group store land in an isolated dir (the libs read os.homedir()).
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { enqueueReaction, enqueueSend, drainOutbox } from '../lib/agent-send.js';
import { recordGroup } from '../lib/agent-groups.js';

const OPERATOR = 'did:lastid:z5cZOperatorHuman';
const AGENT = 'did:lastid:agent:z6MkAgent';
const SCOPE = 'react-test';
const IDP_GROUP = 'idp-group-uuid-1';

let home;
let prevHome;
const outboxPath = () => join(home, '.lastid-agent', SCOPE, 'outbox.jsonl');

before(async () => {
  prevHome = process.env.HOME;
  home = await mkdtemp(join(tmpdir(), 'lastid-react-'));
  process.env.HOME = home;
});
after(async () => {
  process.env.HOME = prevHome;
  await rm(home, { recursive: true, force: true });
});
beforeEach(async () => {
  // Clean outbox + groups between tests.
  await rm(join(home, '.lastid-agent', SCOPE), { recursive: true, force: true });
});

async function readOutboxLines() {
  try {
    const raw = await readFile(outboxPath(), 'utf-8');
    return raw.split('\n').filter((l) => l.trim().length > 0);
  } catch {
    return [];
  }
}

// Minimal stubs — the reaction path never touches MLS/send (those are the
// message path); only reactToLastMessage is exercised.
const noopMls = { encryptApplicationMessage: () => '', persist: async () => {}, groupEpoch: () => 0 };
const noopSend = () => {};

test('enqueueReaction writes a kind:reaction line with the emoji', async () => {
  const id = await enqueueReaction({ scope: SCOPE, operatorDid: OPERATOR, emoji: '👍' });
  const lines = await readOutboxLines();
  assert.equal(lines.length, 1);
  const req = JSON.parse(lines[0]);
  assert.equal(req.kind, 'reaction');
  assert.equal(req.operator_did, OPERATOR);
  assert.equal(req.emoji, '👍');
  assert.equal(req.reaction_action, 'add');
  assert.equal(req.id, id);
});

test('drain routes a reaction to reactToLastMessage and clears the outbox on success', async () => {
  await recordGroup({ scope: SCOPE, idpGroupId: IDP_GROUP, groupIdB64: 'gb1', operatorDid: OPERATOR, deviceIds: [] });
  await enqueueReaction({ scope: SCOPE, operatorDid: OPERATOR, emoji: '🙏' });

  const calls = [];
  await drainOutbox({
    scope: SCOPE,
    mls: noopMls,
    agentDid: AGENT,
    send: noopSend,
    reactToLastMessage: (groupId, emoji, action) => {
      calls.push({ groupId, emoji, action });
      return { sent: true, messageId: 'm1', reaction: 'pray', action };
    },
  });

  assert.deepEqual(calls, [{ groupId: IDP_GROUP, emoji: '🙏', action: 'add' }]);
  assert.deepEqual(await readOutboxLines(), [], 'outbox cleared after a successful react');
});

test('NEGATIVE: a no_target_message outcome is DROPPED (not retried forever)', async () => {
  await recordGroup({ scope: SCOPE, idpGroupId: IDP_GROUP, groupIdB64: 'gb1', operatorDid: OPERATOR, deviceIds: [] });
  await enqueueReaction({ scope: SCOPE, operatorDid: OPERATOR, emoji: '👍' });

  await drainOutbox({
    scope: SCOPE,
    mls: noopMls,
    agentDid: AGENT,
    send: noopSend,
    reactToLastMessage: () => ({ sent: false, reason: 'no_target_message' }),
  });
  assert.deepEqual(await readOutboxLines(), [], 'non-retryable reaction dropped');
});

test('NEGATIVE: no group yet → the reaction is RETAINED for a retry', async () => {
  // No recordGroup → resolveActiveGroupForOperator returns null → reactOne throws
  // → the drain keeps the line.
  await enqueueReaction({ scope: SCOPE, operatorDid: OPERATOR, emoji: '👍' });
  let reactorCalled = false;
  await drainOutbox({
    scope: SCOPE,
    mls: noopMls,
    agentDid: AGENT,
    send: noopSend,
    reactToLastMessage: () => {
      reactorCalled = true;
      return { sent: true };
    },
  });
  assert.equal(reactorCalled, false, 'reactor not reached without a group');
  const lines = await readOutboxLines();
  assert.equal(lines.length, 1, 'reaction retained for the next tick');
  assert.equal(JSON.parse(lines[0]).kind, 'reaction');
});

test('a message and a reaction in the same outbox each take their own path', async () => {
  await recordGroup({ scope: SCOPE, idpGroupId: IDP_GROUP, groupIdB64: 'gb1', operatorDid: OPERATOR, deviceIds: [] });
  // A legacy message line (kind defaults to message); we stub its send path by
  // failing it (so it's retained) while the reaction succeeds — proving routing.
  await enqueueSend({ scope: SCOPE, operatorDid: OPERATOR, text: 'hello' });
  await enqueueReaction({ scope: SCOPE, operatorDid: OPERATOR, emoji: '👍' });

  let reacted = false;
  await drainOutbox({
    scope: SCOPE,
    mls: { ...noopMls, encryptApplicationMessage: () => { throw new Error('boom'); } },
    agentDid: AGENT,
    send: noopSend,
    reactToLastMessage: () => { reacted = true; return { sent: true, messageId: 'm1', reaction: 'thumbs_up', action: 'add' }; },
  });

  assert.equal(reacted, true, 'reaction path ran');
  const lines = await readOutboxLines();
  // The message (encrypt threw) is retained; the reaction is gone.
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).kind, 'message');
});
