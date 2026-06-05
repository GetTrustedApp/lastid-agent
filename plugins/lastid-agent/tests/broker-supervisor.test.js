/**
 * Tests for lib/broker-supervisor.js — the listener-owned signed-broker daemon
 * supervisor. No real broker: spawn, health, socket-readiness, and timing are
 * all injected, so we test the lifecycle logic (gate → spawn args → readiness →
 * restart-on-death → stop) deterministically.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { brokerIdpEnabled, startBrokerSupervisor } from '../lib/broker-supervisor.js';

function fakeChild(pid = 4242) {
  const ee = new EventEmitter();
  ee.pid = pid;
  ee.stdout = null;
  ee.stderr = null;
  ee.killed = false;
  ee.kill = (sig) => {
    ee.killed = sig ?? true;
    return true;
  };
  return ee;
}

const baseOpts = {
  scope: 'tscope',
  idpUrl: 'http://127.0.0.1:3000',
  platform: 'darwin',
  enabled: true,
  brokerPath: '/fake/broker',
  healthImpl: async () => ({ ok: true, body: { device_provisioned: true } }),
  socketReady: async () => true,
  sleepImpl: async () => {},
  restartBackoffMs: 0,
};

const tick = () => new Promise((r) => setImmediate(r));

test('brokerIdpEnabled: off by default, on for 1/true/on/yes', () => {
  assert.equal(brokerIdpEnabled({}), false);
  assert.equal(brokerIdpEnabled({ LASTID_BROKER_IDP: '' }), false);
  assert.equal(brokerIdpEnabled({ LASTID_BROKER_IDP: '0' }), false);
  assert.equal(brokerIdpEnabled({ LASTID_BROKER_IDP: 'off' }), false);
  for (const v of ['1', 'true', 'TRUE', 'on', 'yes']) {
    assert.equal(brokerIdpEnabled({ LASTID_BROKER_IDP: v }), true, v);
  }
});

test('returns null (legacy path) when the flag is off', async () => {
  let spawned = 0;
  const h = await startBrokerSupervisor({
    ...baseOpts,
    enabled: false,
    spawnImpl: () => {
      spawned += 1;
      return fakeChild();
    },
  });
  assert.equal(h, null);
  assert.equal(spawned, 0, 'must not spawn the broker when disabled');
});

test('returns null (legacy path) on non-macOS', async () => {
  let spawned = 0;
  const h = await startBrokerSupervisor({
    ...baseOpts,
    platform: 'linux',
    spawnImpl: () => {
      spawned += 1;
      return fakeChild();
    },
  });
  assert.equal(h, null);
  assert.equal(spawned, 0);
});

test('spawns the broker with --scope (+--idp), NO serve subcommand, and reports ready on Health', async () => {
  const calls = [];
  const h = await startBrokerSupervisor({
    ...baseOpts,
    spawnImpl: (bin, args, opts) => {
      calls.push({ bin, args, opts });
      return fakeChild(777);
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].bin, '/fake/broker');
  assert.deepEqual(calls[0].args, ['--scope', 'tscope', '--idp', 'http://127.0.0.1:3000']);
  assert.ok(!calls[0].args.includes('serve'), 'must NOT pass a serve subcommand');
  assert.equal(h.ready, true);
  assert.equal(h.pid, 777);
});

test('not-ready within timeout → handle returned with ready:false (still supervising)', async () => {
  const h = await startBrokerSupervisor({
    ...baseOpts,
    spawnImpl: () => fakeChild(),
    socketReady: async () => false, // never appears
    readyTimeoutMs: 5,
    pollMs: 1,
    now: (() => {
      let t = 0;
      return () => (t += 3); // advances past the 5ms deadline quickly
    })(),
  });
  assert.equal(h.ready, false);
});

test('restarts the broker on unexpected exit, then stop() prevents further restarts', async () => {
  let n = 0;
  const children = [];
  const spawnImpl = () => {
    n += 1;
    const c = fakeChild(1000 + n);
    children.push(c);
    return c;
  };
  const h = await startBrokerSupervisor({ ...baseOpts, spawnImpl });
  assert.equal(n, 1);

  // Unexpected death → supervisor respawns (backoff 0, sleep immediate).
  children[0].emit('exit', 1, null);
  await tick();
  await tick();
  assert.equal(n, 2, 'broker should be respawned after an unexpected exit');

  // stop() sets the stopping flag + SIGTERMs the child; a subsequent exit must
  // NOT trigger another spawn.
  h.stop();
  assert.equal(children[1].killed, 'SIGTERM');
  children[1].emit('exit', null, 'SIGTERM');
  await tick();
  await tick();
  assert.equal(n, 2, 'no respawn after stop()');
});

test('omits --idp when no idpUrl is given', async () => {
  const calls = [];
  await startBrokerSupervisor({
    ...baseOpts,
    idpUrl: undefined,
    spawnImpl: (_bin, args) => {
      calls.push(args);
      return fakeChild();
    },
  });
  assert.deepEqual(calls[0], ['--scope', 'tscope']);
});
