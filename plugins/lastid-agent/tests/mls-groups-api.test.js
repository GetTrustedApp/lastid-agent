/**
 * mls-groups-api (lib/mls-groups-api.js) — the agent-side IdP group REST
 * calls used by the conversation self-heal. These lock the HTTP shaping
 * (method, URL, Bearer + DPoP headers, JSON body), the response parsing,
 * and the argument validation. A real P-256 key is generated so the
 * DPoP minting (ES256) runs for real; the network is stubbed via fetchImpl.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  authedIdpFetch,
  fetchPeerKeyPackages,
  listOwnDevices,
  fetchActiveDevicesForDid,
  createGroupOnIdp,
  addGroupMember,
  revokeAgentDevice,
} from '../lib/mls-groups-api.js';

const { privateKey: signingKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
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
  // per_device=true by default → one KeyPackage per device, in one fetch.
  assert.equal(
    fetchImpl.calls[0].url,
    'https://idp.test/v1/mls/keypackages/did%3Alastid%3AzOperator?per_device=true',
  );
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

test('fetchPeerKeyPackages: perDevice:false omits the query string', async () => {
  const fetchImpl = recordingFetch(res({ key_packages: [] }));
  await fetchPeerKeyPackages({ ...AUTH, targetDid: 'did:lastid:zX', perDevice: false, fetchImpl });
  assert.equal(fetchImpl.calls[0].url, 'https://idp.test/v1/mls/keypackages/did%3Alastid%3AzX');
});

test('listOwnDevices: self-resolves via GET /v1/trust/:agentDid/devices (the durable resolver)', async () => {
  // The agent resolves its OWN device through the SAME peer endpoint everyone
  // uses to resolve it — NOT the old /v1/identity/devices V1 path (which 400s
  // for agents). Locks the URL + the {device_id, device_identity, last_seen,
  // active} mapping reconcile depends on. device_identity == device_id (agents
  // own one device whose id is its identity; endpoint carries no separate field).
  const fetchImpl = recordingFetch(
    res({
      peer_did: AUTH.agentDid,
      devices: [
        { device_id: 'ad-aaa', last_seen: '2026-05-28T15:00:00.000Z', active: true },
      ],
    }),
  );
  const out = await listOwnDevices({ ...AUTH, fetchImpl });
  assert.equal(
    fetchImpl.calls[0].url,
    'https://idp.test/v1/trust/did%3Alastid%3Aagent%3AzAgentTest/devices',
  );
  assert.deepEqual(out, [
    {
      device_id: 'ad-aaa',
      device_identity: 'ad-aaa',
      last_seen: '2026-05-28T15:00:00.000Z',
      active: true,
    },
  ]);
});

test('fetchActiveDevicesForDid: resolves a PEER did at GET /v1/trust/:did/devices, signs auth with the AGENT did, maps active flag', async () => {
  // Used by reconcile to gate peer devices on the IdP's authoritative active
  // set (the same resolveDurableActiveDeviceIdsForDid the eligibility check
  // uses). The path carries the PEER did; the DPoP/Bearer auth is still the
  // agent's (authorized via the owned-agent ownership carve-out on the route).
  const peerDid = 'did:lastid:zOperator';
  const fetchImpl = recordingFetch(
    res({
      peer_did: peerDid,
      devices: [
        { device_id: 'device-live', last_seen: null, active: true },
        { device_id: 'device-revoked', last_seen: null, active: false },
        { device_id: 'device-default' }, // missing active flag → defaults true
      ],
    }),
  );
  const out = await fetchActiveDevicesForDid({ ...AUTH, did: peerDid, fetchImpl });
  assert.equal(
    fetchImpl.calls[0].url,
    'https://idp.test/v1/trust/did%3Alastid%3AzOperator/devices',
  );
  // DPoP proof is signed for the agent (kid = agent did), not the peer.
  assert.match(fetchImpl.calls[0].init.headers.DPoP, /^eyJ/);
  assert.deepEqual(out, [
    { device_id: 'device-live', device_identity: 'device-live', last_seen: null, active: true },
    { device_id: 'device-revoked', device_identity: 'device-revoked', last_seen: null, active: false },
    { device_id: 'device-default', device_identity: 'device-default', last_seen: null, active: true },
  ]);
});

test('fetchActiveDevicesForDid: requires did and agentDid', async () => {
  await assert.rejects(
    () => fetchActiveDevicesForDid({ ...AUTH, did: undefined, fetchImpl: recordingFetch(res({})) }),
    /did required/,
  );
});

test('listOwnDevices: empty device set → [] (agent not active/registered, no throw)', async () => {
  const fetchImpl = recordingFetch(res({ peer_did: AUTH.agentDid, devices: [] }));
  const out = await listOwnDevices({ ...AUTH, fetchImpl });
  assert.deepEqual(out, []);
});

test('listOwnDevices: active flag — missing → true, explicit false → false; blank device_id dropped', async () => {
  const fetchImpl = recordingFetch(
    res({
      devices: [
        { device_id: 'ad-present' }, // no active flag → defaults active
        { device_id: 'ad-off', active: false }, // explicit false preserved
        { device_id: '', active: true }, // blank id → dropped
      ],
    }),
  );
  const out = await listOwnDevices({ ...AUTH, fetchImpl });
  assert.deepEqual(out, [
    { device_id: 'ad-present', device_identity: 'ad-present', last_seen: null, active: true },
    { device_id: 'ad-off', device_identity: 'ad-off', last_seen: null, active: false },
  ]);
});

test('listOwnDevices: requires agentDid', async () => {
  const fetchImpl = recordingFetch(res({ devices: [] }));
  await assert.rejects(
    () => listOwnDevices({ ...AUTH, agentDid: undefined, fetchImpl }),
    /listOwnDevices: agentDid required/,
  );
  assert.equal(fetchImpl.calls.length, 0); // throws before any network call
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

test('addGroupMember: welcomeSelf adds welcome_self to the body (single-commit own-device add)', async () => {
  const fetchImpl = recordingFetch(res({ ok: true }));
  await addGroupMember({
    ...AUTH,
    groupId: 'uuid-1',
    inviteeDid: 'did:lastid:zOperator',
    mlsWelcomeB64: 'WEL',
    mlsCommitB64: 'COM',
    welcomeSelf: true,
    fetchImpl,
  });
  assert.deepEqual(JSON.parse(fetchImpl.calls[0].init.body), {
    invitee_did: 'did:lastid:zOperator',
    mls_welcome: 'WEL',
    mls_commit: 'COM',
    welcome_self: true,
  });
});

test('addGroupMember: omits welcome_self when not requested', async () => {
  const fetchImpl = recordingFetch(res({ ok: true }));
  await addGroupMember({
    ...AUTH,
    groupId: 'g',
    inviteeDid: 'did:lastid:zOp',
    mlsWelcomeB64: 'WEL',
    fetchImpl,
  });
  assert.equal('welcome_self' in JSON.parse(fetchImpl.calls[0].init.body), false);
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

// ── revokeAgentDevice — reissue self-revoke of the OLD device ──────────────

test('revokeAgentDevice: DELETEs /v1/identity/devices/{id} with Bearer + DPoP, no body', async () => {
  const fetchImpl = recordingFetch(res({ success: true }));
  const out = await revokeAgentDevice({ ...AUTH, deviceId: 'ad-1ef73378e49013f06656bc0a223f46ad', fetchImpl });
  assert.deepEqual(out, { success: true });
  assert.equal(fetchImpl.calls.length, 1);
  const { url, init } = fetchImpl.calls[0];
  assert.equal(url, 'https://idp.test/v1/identity/devices/ad-1ef73378e49013f06656bc0a223f46ad');
  assert.equal(init.method, 'DELETE');
  assert.equal(init.body, undefined);
  assert.equal(init.headers.Authorization, 'Bearer header.payload.sig');
  assert.match(init.headers.DPoP, /^[\w-]+\.[\w-]+\.[\w-]+$/); // a real ES256 JWS
});

test('revokeAgentDevice: an md- device id round-trips unescaped (no reserved chars)', async () => {
  const fetchImpl = recordingFetch(res({ success: true }));
  await revokeAgentDevice({ ...AUTH, deviceId: 'md-deadbeefdeadbeefdeadbeefdeadbeef', fetchImpl });
  assert.equal(
    fetchImpl.calls[0].url,
    'https://idp.test/v1/identity/devices/md-deadbeefdeadbeefdeadbeefdeadbeef',
  );
});

test('revokeAgentDevice: missing deviceId throws (never DELETEs the collection)', async () => {
  const fetchImpl = recordingFetch(res({}));
  await assert.rejects(() => revokeAgentDevice({ ...AUTH, fetchImpl }), /deviceId required/);
  assert.equal(fetchImpl.calls.length, 0);
});

// ── FORK1 broker dispatch (Phase 2) ──────────────────────────────────────────
// When LASTID_BROKER_IDP is on AND a broker is up for the scope, authedIdpFetch
// routes through the signed broker (no node DPoP minting); otherwise legacy.

test('authedIdpFetch: routes to the broker when enabled + a broker is available', async () => {
  const fetchImpl = recordingFetch(res({}));
  let brokerCall = null;
  const out = await authedIdpFetch({
    ...AUTH,
    method: 'POST',
    path: '/v1/groups',
    body: { name: 'x' },
    fetchImpl,
    scope: 'tscope',
    _brokerEnabled: () => true,
    _brokerAvailable: async () => true,
    _brokerIdpFetch: async (a) => {
      brokerCall = a;
      return { ok: true };
    },
  });
  assert.deepEqual(brokerCall, { method: 'POST', path: '/v1/groups', body: { name: 'x' }, scope: 'tscope' });
  assert.deepEqual(out, { ok: true });
  assert.equal(fetchImpl.calls.length, 0, 'legacy node DPoP fetch must NOT run when routed to broker');
});

test('authedIdpFetch: legacy node path when broker routing is disabled', async () => {
  const fetchImpl = recordingFetch(res({ ok: 1 }));
  let brokerCalled = false;
  await authedIdpFetch({
    ...AUTH,
    method: 'GET',
    path: '/v1/thing',
    fetchImpl,
    _brokerEnabled: () => false,
    _brokerAvailable: async () => true, // available, but disabled → legacy
    _brokerIdpFetch: async () => {
      brokerCalled = true;
      return {};
    },
  });
  assert.equal(brokerCalled, false);
  assert.equal(fetchImpl.calls.length, 1, 'legacy DPoP fetch runs when the flag is off');
  assert.ok(fetchImpl.calls[0].init.headers.DPoP, 'DPoP header minted on the legacy path');
});

test('authedIdpFetch: falls back to legacy when enabled but NO broker is up (no-flag-day)', async () => {
  const fetchImpl = recordingFetch(res({ ok: 1 }));
  let brokerCalled = false;
  await authedIdpFetch({
    ...AUTH,
    method: 'GET',
    path: '/v1/thing',
    fetchImpl,
    _brokerEnabled: () => true,
    _brokerAvailable: async () => false, // flag on, but broker not running
    _brokerIdpFetch: async () => {
      brokerCalled = true;
      return {};
    },
  });
  assert.equal(brokerCalled, false, 'must NOT route to a broker that is not up');
  assert.equal(fetchImpl.calls.length, 1, 'falls back to the legacy node path');
});

test('authedIdpFetch: signingKey null + NO broker up → REFUSES to node-sign (broker-bound agent)', async () => {
  // A broker-bound agent (md- device) passes signingKey:null to delegate IdP
  // auth to the broker. If the broker isn't up we must NOT node-sign with a
  // (possibly stale) key — that is the reissue 401. Fail loud + retryable.
  const fetchImpl = recordingFetch(res({ ok: 1 }));
  await assert.rejects(
    () =>
      authedIdpFetch({
        ...AUTH,
        signingKey: null,
        method: 'POST',
        path: '/v1/mls/keypackages/batch',
        body: { key_packages: [] },
        fetchImpl,
        _brokerEnabled: () => true,
        _brokerAvailable: async () => false,
      }),
    /broker-bound agent requires the signed broker/,
  );
  assert.equal(fetchImpl.calls.length, 0, 'must not hit the network with an unsigned/stale proof');
});

test('authedIdpFetch: signingKey null + broker UP → routes through the broker (never node-signs)', async () => {
  const fetchImpl = recordingFetch(res({ ok: 1 }));
  let brokerCall = null;
  const out = await authedIdpFetch({
    ...AUTH,
    signingKey: null,
    method: 'POST',
    path: '/v1/mls/keypackages/batch',
    body: { key_packages: [] },
    scope: 'tscope',
    fetchImpl,
    _brokerEnabled: () => true,
    _brokerAvailable: async () => true,
    _brokerIdpFetch: async (a) => {
      brokerCall = a;
      return { ok: true };
    },
  });
  assert.deepEqual(out, { ok: true });
  assert.equal(brokerCall.path, '/v1/mls/keypackages/batch');
  assert.equal(fetchImpl.calls.length, 0, 'broker-bound publish must not node-sign');
});
