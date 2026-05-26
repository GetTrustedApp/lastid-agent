/**
 * mls-groups-api (lib/mls-groups-api.js) — the agent-side IdP group REST
 * calls used by the conversation self-heal. These lock the HTTP shaping
 * (method, URL, Bearer + DPoP headers, JSON body), the response parsing,
 * and the argument validation. A real Ed25519 key is generated so the
 * DPoP minting runs for real; the network is stubbed via fetchImpl.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  authedIdpFetch,
  fetchPeerKeyPackages,
  createGroupOnIdp,
  addGroupMember,
} from '../lib/mls-groups-api.js';

const { privateKey: signingKey } = generateKeyPairSync('ed25519');
const AUTH = {
  idpUrl: 'https://idp.test/',
  agentDid: 'did:lastid:agent:zAgentTest',
  vcCompact: 'header.payload.sig',
  signingKey,
};

function res(obj, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => obj, text: async () => JSON.stringify(obj) };
}

/** A fetch stub that records calls and returns a canned (or computed) response. */
function recordingFetch(response) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return typeof response === 'function' ? response(url, init) : response;
  };
  fn.calls = calls;
  return fn;
}

test('authedIdpFetch: GET sends Bearer + DPoP, no body, strips trailing slash', async () => {
  const fetchImpl = recordingFetch(res({ ok: 1 }));
  const out = await authedIdpFetch({ ...AUTH, method: 'GET', path: '/v1/thing', fetchImpl });
  assert.deepEqual(out, { ok: 1 });
  assert.equal(fetchImpl.calls.length, 1);
  const { url, init } = fetchImpl.calls[0];
  assert.equal(url, 'https://idp.test/v1/thing'); // trailing slash trimmed, no query
  assert.equal(init.method, 'GET');
  assert.equal(init.body, undefined);
  assert.equal(init.headers.Authorization, 'Bearer header.payload.sig');
  assert.match(init.headers.DPoP, /^[\w-]+\.[\w-]+\.[\w-]+$/); // a real JWS
  assert.equal(init.headers['content-type'], undefined);
});

test('authedIdpFetch: POST JSON-encodes the body + sets content-type', async () => {
  const fetchImpl = recordingFetch(res({ id: 'g1' }));
  await authedIdpFetch({ ...AUTH, method: 'POST', path: '/v1/groups', body: { a: 1 }, fetchImpl });
  const { init } = fetchImpl.calls[0];
  assert.equal(init.method, 'POST');
  assert.equal(init.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(init.body), { a: 1 });
});

test('authedIdpFetch: throws on non-2xx with status + body text', async () => {
  const fetchImpl = recordingFetch(res({ error: 'nope' }, { ok: false, status: 403 }));
  await assert.rejects(
    () => authedIdpFetch({ ...AUTH, method: 'GET', path: '/v1/x', fetchImpl }),
    /GET \/v1\/x failed: HTTP 403/,
  );
});

test('fetchPeerKeyPackages: claims + maps the peer KeyPackages and remaining count', async () => {
  const fetchImpl = recordingFetch(
    res({
      key_packages: [
        { ref: 'r1', key_package: 'kp1', device_id: 'devA' },
        { ref: 'r2', key_package: 'kp2', device_id: 'devB' },
        { ref: null, key_package: null }, // incomplete → dropped
      ],
      remaining_count: 3,
    }),
  );
  const out = await fetchPeerKeyPackages({ ...AUTH, targetDid: 'did:lastid:zOperator', fetchImpl });
  assert.equal(fetchImpl.calls[0].url, 'https://idp.test/v1/mls/keypackages/did%3Alastid%3AzOperator');
  assert.deepEqual(out.keyPackages, [
    { keyPackageB64: 'kp1', ref: 'r1', deviceId: 'devA' },
    { keyPackageB64: 'kp2', ref: 'r2', deviceId: 'devB' },
  ]);
  assert.equal(out.remainingCount, 3);
});

test('fetchPeerKeyPackages: empty list → empty result (no throw)', async () => {
  const fetchImpl = recordingFetch(res({ key_packages: [] }));
  const out = await fetchPeerKeyPackages({ ...AUTH, targetDid: 'did:lastid:zX', fetchImpl });
  assert.deepEqual(out.keyPackages, []);
  assert.equal(out.remainingCount, 0);
});

test('createGroupOnIdp: posts name + mls_group_init + group_type, returns descriptor', async () => {
  const fetchImpl = recordingFetch(res({ id: 'uuid-1', mls_group_id: 'mgid' }));
  const out = await createGroupOnIdp({
    ...AUTH,
    name: 'Chat with Atlas',
    mlsGroupInitB64: 'GINFO',
    groupType: 'direct',
    fetchImpl,
  });
  assert.equal(out.id, 'uuid-1');
  const { url, init } = fetchImpl.calls[0];
  assert.equal(url, 'https://idp.test/v1/groups');
  assert.deepEqual(JSON.parse(init.body), {
    name: 'Chat with Atlas',
    mls_group_init: 'GINFO',
    group_type: 'direct',
  });
});

test('createGroupOnIdp: requires mls_group_init', async () => {
  await assert.rejects(
    () => createGroupOnIdp({ ...AUTH, name: 'x', mlsGroupInitB64: '', fetchImpl: recordingFetch(res({})) }),
    /mlsGroupInitB64 required/,
  );
});

test('addGroupMember: posts invitee_did + welcome (+ commit when given)', async () => {
  const fetchImpl = recordingFetch(res({ ok: true }));
  await addGroupMember({
    ...AUTH,
    groupId: 'uuid-1',
    inviteeDid: 'did:lastid:zOperator',
    mlsWelcomeB64: 'WEL',
    mlsCommitB64: 'COM',
    fetchImpl,
  });
  const { url, init } = fetchImpl.calls[0];
  assert.equal(url, 'https://idp.test/v1/groups/uuid-1/members');
  assert.deepEqual(JSON.parse(init.body), {
    invitee_did: 'did:lastid:zOperator',
    mls_welcome: 'WEL',
    mls_commit: 'COM',
  });
});

test('addGroupMember: omits mls_commit when not provided', async () => {
  const fetchImpl = recordingFetch(res({ ok: true }));
  await addGroupMember({
    ...AUTH,
    groupId: 'g',
    inviteeDid: 'did:lastid:zOp',
    mlsWelcomeB64: 'WEL',
    fetchImpl,
  });
  assert.deepEqual(JSON.parse(fetchImpl.calls[0].init.body), {
    invitee_did: 'did:lastid:zOp',
    mls_welcome: 'WEL',
  });
});

test('addGroupMember: validates required fields', async () => {
  const f = recordingFetch(res({}));
  await assert.rejects(() => addGroupMember({ ...AUTH, inviteeDid: 'd', mlsWelcomeB64: 'w', fetchImpl: f }), /groupId required/);
  await assert.rejects(() => addGroupMember({ ...AUTH, groupId: 'g', mlsWelcomeB64: 'w', fetchImpl: f }), /inviteeDid required/);
  await assert.rejects(() => addGroupMember({ ...AUTH, groupId: 'g', inviteeDid: 'd', fetchImpl: f }), /mlsWelcomeB64 required/);
});
