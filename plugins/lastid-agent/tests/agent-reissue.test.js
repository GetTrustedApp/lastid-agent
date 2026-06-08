/**
 * Reissue old-device revoke (lib/agent-reissue.js). The correctness pivot: a
 * BROKER-NATIVE agent's old key is in the broker, so the revoke must route
 * through the OLD broker (agent-mode), NOT derive a key in node — which is why it
 * silently skipped before. All collaborators are injected; no real broker/IdP.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { revokeOldAgentDeviceForReissue } from '../lib/agent-reissue.js';

const LEGACY = {
  deviceId: 'ad-legacydevice',
  slotSeed: Buffer.alloc(32, 7),
  agentDid: 'did:lastid:agent:z6MkLegacy',
  vcCompact: 'old.vc.legacy',
  idpUrl: 'https://idp.example',
};
const BROKER_NATIVE = {
  deviceId: 'md-machinedevice',
  slotSeed: null, // seed lives ONLY in the broker's protected store
  agentDid: 'did:lastid:agent:zDnBrokerNative',
  vcCompact: 'old.vc.broker',
  idpUrl: 'https://idp.example',
};

test('LEGACY: derives the old key in node + revokes with that signingKey (no broker)', async () => {
  const calls = { derive: 0, revoke: null, spawned: 0 };
  const id = await revokeOldAgentDeviceForReissue({
    existing: LEGACY,
    scope: 'main',
    idpUrl: 'https://fallback.example',
    deps: {
      resolveAgentDeviceId: ({ persistedDeviceId }) => persistedDeviceId,
      brokerAvailable: async () => false,
      deriveAgentKeypair: () => {
        calls.derive += 1;
        return { signingKey: { fake: 'old-key' } };
      },
      revokeAgentDevice: (args) => {
        calls.revoke = args;
        return Promise.resolve({ ok: true });
      },
      startBrokerSupervisor: () => {
        calls.spawned += 1;
        return Promise.resolve({ ready: true, stop() {} });
      },
    },
  });
  assert.equal(id, 'ad-legacydevice');
  assert.equal(calls.derive, 1, 'legacy mints the DPoP key in node');
  assert.equal(calls.spawned, 0, 'legacy must NOT start a broker');
  assert.deepEqual(calls.revoke.signingKey, { fake: 'old-key' }, 'revoke uses the derived old key');
  assert.equal(calls.revoke.deviceId, 'ad-legacydevice');
  assert.equal(calls.revoke.scope, 'main', 'scope is pinned so the route is correct');
  assert.equal(calls.revoke.idpUrl, 'https://idp.example', 'prefers the old bundle idpUrl');
});

test('BROKER-NATIVE: starts the OLD broker agent-mode + revokes through it (signingKey null), then stops it', async () => {
  const calls = { derive: 0, revoke: null, started: null, stopped: 0 };
  const id = await revokeOldAgentDeviceForReissue({
    existing: BROKER_NATIVE,
    scope: 'test',
    idpUrl: 'https://fallback.example',
    deps: {
      resolveAgentDeviceId: ({ persistedDeviceId }) => persistedDeviceId,
      brokerAvailable: async () => false,
      deriveAgentKeypair: () => {
        calls.derive += 1;
        return { signingKey: {} };
      },
      revokeAgentDevice: (args) => {
        calls.revoke = args;
        return Promise.resolve({ ok: true });
      },
      startBrokerSupervisor: (opts) => {
        calls.started = opts;
        return Promise.resolve({ ready: true, stop: () => { calls.stopped += 1; } });
      },
    },
  });
  assert.equal(id, 'md-machinedevice');
  assert.equal(calls.derive, 0, 'broker-native NEVER derives the key in node (it has no seed)');
  assert.equal(calls.started.scope, 'test');
  assert.equal(calls.started.enabled, true, 'force the broker up (kill-switch must not strand the revoke)');
  assert.equal(calls.revoke.signingKey, null, 'the broker mints the DPoP — node passes no key');
  assert.equal(calls.revoke.deviceId, 'md-machinedevice');
  assert.equal(calls.revoke.scope, 'test', 'routes the DELETE to THIS scope’s broker');
  assert.equal(calls.stopped, 1, 'the old broker is stopped after the revoke');
});

test('BROKER-NATIVE: REUSES a running broker (no temp start, no socket race) when one is up', async () => {
  const calls = { revoke: null, started: 0, stopped: 0 };
  const id = await revokeOldAgentDeviceForReissue({
    existing: BROKER_NATIVE,
    scope: 'test',
    idpUrl: 'https://fallback.example',
    deps: {
      resolveAgentDeviceId: ({ persistedDeviceId }) => persistedDeviceId,
      // A broker is ALREADY up for this scope (the running listener's, agent-mode,
      // old seed) — the caller revokes BEFORE stopping the listener.
      brokerAvailable: async () => true,
      revokeAgentDevice: (args) => {
        calls.revoke = args;
        return Promise.resolve({ ok: true });
      },
      startBrokerSupervisor: () => {
        calls.started += 1;
        return Promise.resolve({ ready: true, stop: () => { calls.stopped += 1; } });
      },
    },
  });
  assert.equal(id, 'md-machinedevice');
  assert.equal(calls.started, 0, 'must NOT start a temp broker when one is up — that is the socket race');
  assert.equal(calls.stopped, 0, 'does not stop the running listener broker (the caller stops it after)');
  assert.equal(calls.revoke.signingKey, null, 'the broker mints the DPoP');
  assert.equal(calls.revoke.scope, 'test', 'routes the DELETE to THIS scope’s running broker');
  assert.equal(calls.revoke.deviceId, 'md-machinedevice');
});

test('BROKER-NATIVE NEGATIVE: old broker fails to come up → throws, never revokes', async () => {
  const calls = { revoke: 0, stopped: 0 };
  await assert.rejects(
    revokeOldAgentDeviceForReissue({
      existing: BROKER_NATIVE,
      scope: 'test',
      idpUrl: 'https://fallback.example',
      deps: {
        resolveAgentDeviceId: ({ persistedDeviceId }) => persistedDeviceId,
      brokerAvailable: async () => false,
        revokeAgentDevice: () => {
          calls.revoke += 1;
          return Promise.resolve({});
        },
        startBrokerSupervisor: () => Promise.resolve({ ready: false, stop: () => { calls.stopped += 1; } }),
      },
    }),
    /old broker .* did not come up/,
  );
  assert.equal(calls.revoke, 0, 'no revoke attempted when the broker is not ready');
  assert.equal(calls.stopped, 1, 'a not-ready broker handle is still stopped');
});

test('BROKER-NATIVE: a revoke failure still stops the old broker (no leak)', async () => {
  const calls = { stopped: 0 };
  await assert.rejects(
    revokeOldAgentDeviceForReissue({
      existing: BROKER_NATIVE,
      scope: 'test',
      idpUrl: 'https://fallback.example',
      deps: {
        resolveAgentDeviceId: ({ persistedDeviceId }) => persistedDeviceId,
      brokerAvailable: async () => false,
        revokeAgentDevice: () => Promise.reject(new Error('IdP 500')),
        startBrokerSupervisor: () => Promise.resolve({ ready: true, stop: () => { calls.stopped += 1; } }),
      },
    }),
    /IdP 500/,
  );
  assert.equal(calls.stopped, 1, 'broker stopped even when the revoke throws (finally)');
});

test('NEGATIVE: unresolvable device_id throws (no persisted id and no seed)', async () => {
  await assert.rejects(
    revokeOldAgentDeviceForReissue({
      existing: { ...BROKER_NATIVE, deviceId: null },
      scope: 'test',
      idpUrl: 'https://fallback.example',
      deps: {
        resolveAgentDeviceId: () => null, // can't derive without a seed/persisted id
        revokeAgentDevice: () => Promise.resolve({}),
        startBrokerSupervisor: () => Promise.resolve({ ready: true, stop() {} }),
      },
    }),
    /could not resolve the old device_id/,
  );
});
