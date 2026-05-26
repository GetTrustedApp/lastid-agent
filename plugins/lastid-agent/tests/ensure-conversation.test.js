/**
 * ensureConversation (lib/ensure-conversation.js) — the agent-initiated
 * self-heal. Locks the contract: reuse an existing group (never fork),
 * else create + register + invite the operator + record; and the negative
 * paths (no operator key packages, IdP returns no group id). Everything
 * external is injected, so no network/wasm.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ensureConversation } from '../lib/ensure-conversation.js';

const BASE = {
  scope: 'main',
  agentDid: 'did:lastid:agent:zAgent',
  operatorDid: 'did:lastid:zOperator',
  idpUrl: 'https://idp.test',
  vcCompact: 'vc',
  signingKey: {},
};

/** A fake MlsClient recording the calls the orchestration makes. */
function fakeMls(trace) {
  return {
    createGroup(id) {
      trace.push(`createGroup:${id}`);
      return { group_id_b64: id, member_count: 1, epoch: 0 };
    },
    exportGroupInfo(id) {
      trace.push(`exportGroupInfo:${id}`);
      return 'GINFO';
    },
    addMember(id, kp) {
      trace.push(`addMember:${id}:${kp}`);
      return { commit_b64: 'COMMIT', welcome_b64: 'WELCOME', new_epoch: 1 };
    },
    async persist() {
      trace.push('persist');
    },
  };
}

test('reuses an existing group with the operator (never forks)', async () => {
  const trace = [];
  const existing = { idpGroupId: 'g-existing', groupIdB64: 'gid', operatorDid: BASE.operatorDid };
  const out = await ensureConversation({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => existing,
      // These must NOT be called.
      fetchPeerKeyPackages: async () => assert.fail('should not fetch'),
      createGroupOnIdp: async () => assert.fail('should not create'),
      addGroupMember: async () => assert.fail('should not invite'),
      recordGroup: async () => assert.fail('should not record'),
    },
  });
  assert.deepEqual(out, existing);
  assert.deepEqual(trace, []); // no MLS ops either
});

test('creates + registers + invites + records when no group exists', async () => {
  const trace = [];
  const calls = {};
  const out = await ensureConversation({
    ...BASE,
    mls: fakeMls(trace),
    deps: {
      resolveActiveGroupForOperator: async () => null,
      fetchPeerKeyPackages: async (a) => {
        calls.fetch = a;
        return { keyPackages: [{ keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' }], remainingCount: 0 };
      },
      randomGroupIdB64: () => 'NEWGID',
      createGroupOnIdp: async (a) => {
        calls.create = a;
        return { id: 'idp-uuid-1', mls_group_id: 'mgid' };
      },
      addGroupMember: async (a) => {
        calls.add = a;
        return { ok: true };
      },
      recordGroup: async (a) => {
        calls.record = a;
      },
    },
  });

  assert.deepEqual(out, {
    idpGroupId: 'idp-uuid-1',
    groupIdB64: 'NEWGID',
    operatorDid: BASE.operatorDid,
  });

  // MLS ops happened in order, each followed by a persist.
  assert.deepEqual(trace, [
    'createGroup:NEWGID',
    'persist',
    'exportGroupInfo:NEWGID',
    'addMember:NEWGID:KP-A',
    'persist',
  ]);

  // IdP register got the exported GroupInfo.
  assert.equal(calls.create.mlsGroupInitB64, 'GINFO');
  assert.equal(calls.create.groupType, 'direct');
  // Invite delivered the welcome + commit from addMember to the operator.
  assert.deepEqual(
    { groupId: calls.add.groupId, inviteeDid: calls.add.inviteeDid, w: calls.add.mlsWelcomeB64, c: calls.add.mlsCommitB64 },
    { groupId: 'idp-uuid-1', inviteeDid: BASE.operatorDid, w: 'WELCOME', c: 'COMMIT' },
  );
  // Recorded the mapping so future sends resolve it.
  assert.deepEqual(
    { idpGroupId: calls.record.idpGroupId, groupIdB64: calls.record.groupIdB64, operatorDid: calls.record.operatorDid },
    { idpGroupId: 'idp-uuid-1', groupIdB64: 'NEWGID', operatorDid: BASE.operatorDid },
  );
});

test('throws when the operator has no key packages published', async () => {
  const trace = [];
  await assert.rejects(
    () =>
      ensureConversation({
        ...BASE,
        mls: fakeMls(trace),
        deps: {
          resolveActiveGroupForOperator: async () => null,
          fetchPeerKeyPackages: async () => ({ keyPackages: [], remainingCount: 0 }),
        },
      }),
    /no MLS key packages published/,
  );
  assert.deepEqual(trace, []); // never touched MLS state
});

test('throws if the IdP returns no group id', async () => {
  const trace = [];
  await assert.rejects(
    () =>
      ensureConversation({
        ...BASE,
        mls: fakeMls(trace),
        deps: {
          resolveActiveGroupForOperator: async () => null,
          fetchPeerKeyPackages: async () => ({ keyPackages: [{ keyPackageB64: 'KP', ref: 'r' }], remainingCount: 0 }),
          randomGroupIdB64: () => 'GID',
          createGroupOnIdp: async () => ({ /* no id */ }),
          addGroupMember: async () => assert.fail('should not invite without a group id'),
          recordGroup: async () => assert.fail('should not record'),
        },
      }),
    /no group id/,
  );
});

test('requires an operatorDid', async () => {
  await assert.rejects(
    () => ensureConversation({ ...BASE, operatorDid: '', mls: fakeMls([]), deps: {} }),
    /operatorDid required/,
  );
});
