/**
 * Tests for lib/mls-broker-client.js — the node-side broker-backed MLS client
 * (MLS-into-broker, unit B3). No real broker is spawned: we inject a fake
 * `call` (the brokerMlsCall seam) that records the {kind, fields} each method
 * sends and returns a canned success body, so the tests pin BOTH the request
 * shape AND that each method returns the EXACT shape the wasm-backed MlsClient
 * returns (objects vs. extracted strings vs. void).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MlsBrokerClient, makeMlsBrokerClient } from '../lib/mls-broker-client.js';

const AGENT_DID = 'did:lastid:agent:zDnAbc';
const DEVICE_ID = 'md-deadbeef';

/**
 * Build a client whose `call` returns the next canned body per invocation and
 * records every call. `bodies` is either a single body (reused) or a function
 * (kind, fields) → body for per-kind control.
 */
function clientWith(bodyResolver) {
  const calls = [];
  const call = async ({ scope, kind, fields }) => {
    calls.push({ scope, kind, fields });
    const body = typeof bodyResolver === 'function' ? bodyResolver(kind, fields) : bodyResolver;
    return body ?? {};
  };
  const client = new MlsBrokerClient({ scope: 'main', agentDid: AGENT_DID, deviceId: DEVICE_ID, call });
  return { client, calls };
}

test('constructor requires agentDid', () => {
  assert.throws(() => new MlsBrokerClient({ scope: 'main' }), /agentDid required/);
});

test('agentDid / deviceId getters return the threaded values', () => {
  const { client } = clientWith({});
  assert.equal(client.agentDid, AGENT_DID);
  assert.equal(client.deviceId, DEVICE_ID);
});

test('makeMlsBrokerClient builds a duck-typed MlsBrokerClient', () => {
  const client = makeMlsBrokerClient({ agentDid: AGENT_DID, deviceId: DEVICE_ID, call: async () => ({}) });
  assert.ok(client instanceof MlsBrokerClient);
  assert.equal(client.agentDid, AGENT_DID);
});

test('generateKeyPackage → body.key_package string + kind mls_generate_key_package', async () => {
  const { client, calls } = clientWith({ key_package: 'KP_B64' });
  const out = await client.generateKeyPackage();
  assert.equal(out, 'KP_B64');
  assert.equal(typeof out, 'string');
  assert.equal(calls[0].kind, 'mls_generate_key_package');
  assert.deepEqual(calls[0].fields, {});
  assert.equal(calls[0].scope, 'main');
});

test('processWelcome → returns the JoinedGroupInfo object; idp_group_id passed only when given', async () => {
  const info = { group_id_b64: 'GID', member_count: 2, epoch: 0 };
  const { client, calls } = clientWith(info);

  const out = await client.processWelcome('WELCOME_B64', 'idp-uuid-123');
  assert.deepEqual(out, info, 'returns the body object, not a string');
  assert.equal(calls[0].kind, 'mls_process_welcome');
  assert.deepEqual(calls[0].fields, { welcome_b64: 'WELCOME_B64', idp_group_id: 'idp-uuid-123' });

  await client.processWelcome('WELCOME_B64');
  assert.deepEqual(
    calls[1].fields,
    { welcome_b64: 'WELCOME_B64' },
    'idp_group_id omitted entirely when not provided',
  );
  await client.processWelcome('WELCOME_B64', null);
  assert.deepEqual(calls[2].fields, { welcome_b64: 'WELCOME_B64' }, 'null idp_group_id also omitted');
});

test('createGroup → returns the JoinedGroupInfo object', async () => {
  const info = { group_id_b64: 'GID', member_count: 1, epoch: 0 };
  const { client, calls } = clientWith(info);
  const out = await client.createGroup('GID');
  assert.deepEqual(out, info);
  assert.equal(calls[0].kind, 'mls_create_group');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('exportGroupInfo → body.group_info string', async () => {
  const { client, calls } = clientWith({ group_info: 'GI_B64' });
  const out = await client.exportGroupInfo('GID');
  assert.equal(out, 'GI_B64');
  assert.equal(calls[0].kind, 'mls_export_group_info');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('addMember → returns the AddMemberResult object', async () => {
  const result = { commit_b64: 'C', welcome_b64: 'W', new_epoch: 1, assigned_leaf_indices: [1] };
  const { client, calls } = clientWith(result);
  const out = await client.addMember('GID', 'KP_B64');
  assert.deepEqual(out, result);
  assert.equal(calls[0].kind, 'mls_add_member');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID', key_package_b64: 'KP_B64' });
});

test('addMembers → returns the AddMemberResult object; key_packages_b64 is the array', async () => {
  const result = { commit_b64: 'C', welcome_b64: 'W', new_epoch: 2, assigned_leaf_indices: [1, 2] };
  const { client, calls } = clientWith(result);
  const out = await client.addMembers('GID', ['KP1', 'KP2']);
  assert.deepEqual(out, result);
  assert.equal(calls[0].kind, 'mls_add_members');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID', key_packages_b64: ['KP1', 'KP2'] });
});

test('removeMember → returns the CommitResult object', async () => {
  const result = { commit_b64: 'C', new_epoch: 3 };
  const { client, calls } = clientWith(result);
  const out = await client.removeMember('GID', 2);
  assert.deepEqual(out, result);
  assert.equal(calls[0].kind, 'mls_remove_member');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID', leaf_index: 2 });
});

test('processInbound → returns the InboundResult object', async () => {
  const inbound = {
    kind: 'application',
    group_id_b64: 'GID',
    plaintext_b64: 'PT',
    sender_credential_b64: 'CRED',
  };
  const { client, calls } = clientWith(inbound);
  const out = await client.processInbound('MSG_B64');
  assert.deepEqual(out, inbound);
  assert.equal(calls[0].kind, 'mls_process_inbound');
  assert.deepEqual(calls[0].fields, { message_b64: 'MSG_B64' });
});

test('encryptApplicationMessage → body.message string', async () => {
  const { client, calls } = clientWith({ message: 'WIRE_B64' });
  const out = await client.encryptApplicationMessage('GID', 'PT_B64');
  assert.equal(out, 'WIRE_B64');
  assert.equal(typeof out, 'string');
  assert.equal(calls[0].kind, 'mls_encrypt_app_message');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID', plaintext_b64: 'PT_B64' });
});

test('groupEpoch → Number(body.epoch) (lone consumer Number()-wraps; no BigInt math)', async () => {
  const { client, calls } = clientWith({ epoch: 7 });
  const out = await client.groupEpoch('GID');
  assert.equal(out, 7);
  assert.equal(typeof out, 'number', 'returns a Number, not a BigInt');
  assert.equal(calls[0].kind, 'mls_group_epoch');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('groupEpoch → coerces a stringified epoch to Number', async () => {
  const { client } = clientWith({ epoch: '42' });
  assert.equal(await client.groupEpoch('GID'), 42);
});

test('commitPendingProposals → returns the CommitResult object', async () => {
  const result = { commit_b64: 'C', new_epoch: 4 };
  const { client, calls } = clientWith(result);
  const out = await client.commitPendingProposals('GID');
  assert.deepEqual(out, result);
  assert.equal(calls[0].kind, 'mls_commit_pending');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('rollbackPendingCommit → undefined; kind mls_rollback_pending', async () => {
  const { client, calls } = clientWith({});
  const out = await client.rollbackPendingCommit('GID');
  assert.equal(out, undefined);
  assert.equal(calls[0].kind, 'mls_rollback_pending');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('forgetGroup → undefined; kind mls_forget_group', async () => {
  const { client, calls } = clientWith({});
  const out = await client.forgetGroup('GID');
  assert.equal(out, undefined);
  assert.equal(calls[0].kind, 'mls_forget_group');
  assert.deepEqual(calls[0].fields, { group_id_b64: 'GID' });
});

test('bindGroupIdMapping → undefined; kind mls_bind_group_id with both fields', async () => {
  const { client, calls } = clientWith({});
  const out = await client.bindGroupIdMapping('idp-uuid', 'OPENMLS_B64');
  assert.equal(out, undefined);
  assert.equal(calls[0].kind, 'mls_bind_group_id');
  assert.deepEqual(calls[0].fields, { idp_group_id: 'idp-uuid', openmls_b64: 'OPENMLS_B64' });
});

test('reconcileGroup → Boolean(body.changed); kind mls_reconcile_group with group_id (IdP uuid)', async () => {
  const { client, calls } = clientWith({ changed: true });
  const out = await client.reconcileGroup('idp-uuid-123');
  assert.equal(out, true);
  assert.equal(typeof out, 'boolean');
  assert.equal(calls[0].kind, 'mls_reconcile_group');
  // group_id is the IdP UUID string (NOT the openmls base64 id).
  assert.deepEqual(calls[0].fields, { group_id: 'idp-uuid-123' });
});

test('reconcileGroup → returns false for a no-op (changed:false) and for a missing/empty body', async () => {
  const noop = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => ({ changed: false }),
  });
  assert.equal(await noop.reconcileGroup('g'), false);

  const empty = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => ({}),
  });
  assert.equal(await empty.reconcileGroup('g'), false, 'empty body coerces to false');
});

test('reconcileGroup → a broker rejection propagates', async () => {
  const client = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => {
      throw new Error('mls_reconcile_group failed: broker bad_request: GroupDeviceMembershipStale');
    },
  });
  await assert.rejects(client.reconcileGroup('g'), /GroupDeviceMembershipStale/);
});

test('ensureDirectGroup → returns the broker body; kind mls_ensure_direct_group with peer_did', async () => {
  const body = { idp_group_id: 'idp-uuid-77', local_group_id: 'GID_B64', existing: false };
  const { client, calls } = clientWith(body);
  const out = await client.ensureDirectGroup('did:lastid:zOperator');
  assert.deepEqual(out, body, 'returns the broker body verbatim');
  assert.equal(calls[0].kind, 'mls_ensure_direct_group');
  assert.deepEqual(calls[0].fields, { peer_did: 'did:lastid:zOperator' });
  assert.equal(calls[0].scope, 'main');
});

test('ensureDirectGroup → surfaces the existing flag when the broker adopts a canonical group', async () => {
  const { client } = clientWith({ idp_group_id: 'idp-uuid-9', local_group_id: 'GID', existing: true });
  const out = await client.ensureDirectGroup('did:lastid:zOperator');
  assert.equal(out.existing, true);
});

test('ensureDirectGroup → a broker rejection propagates', async () => {
  const client = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => {
      throw new Error('mls_ensure_direct_group failed: broker bad_request: No key packages available');
    },
  });
  await assert.rejects(client.ensureDirectGroup('did:lastid:zOperator'), /No key packages available/);
});

test('persist() and free() are no-ops (broker owns durability + handle lifecycle)', async () => {
  let called = false;
  const client = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => {
      called = true;
      return {};
    },
  });
  await client.persist();
  client.free();
  assert.equal(called, false, 'neither persist nor free touches the broker');
});

test('every call threads the configured scope', async () => {
  const calls = [];
  const client = new MlsBrokerClient({
    scope: 'alpha',
    agentDid: AGENT_DID,
    deviceId: DEVICE_ID,
    call: async (a) => {
      calls.push(a);
      return { key_package: 'x' };
    },
  });
  await client.generateKeyPackage();
  assert.equal(calls[0].scope, 'alpha');
});

test('a broker rejection propagates (the IPC layer throws on Response::err)', async () => {
  const client = new MlsBrokerClient({
    agentDid: AGENT_DID,
    call: async () => {
      throw new Error('mls_process_welcome failed: broker bad_request: NoMatchingKeyPackage');
    },
  });
  await assert.rejects(client.processWelcome('W'), /NoMatchingKeyPackage/);
});
