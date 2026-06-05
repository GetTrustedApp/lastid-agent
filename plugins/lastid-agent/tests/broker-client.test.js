/**
 * Tests for the plugin → signed-broker bridge (machine pubkey for provisioning).
 * No real broker is spawned — `spawnImpl` is injected.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseMachinePubkeyOutput,
  getMachineSePubkeyJwk,
  resolveBrokerPath,
} from '../lib/broker-client.js';
import { initiateProvisioning } from '../lib/agent-provisioning.js';

const VALID_JWK = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'BBBB' };
const VALID_STDOUT = JSON.stringify({ machine_se_pubkey_jwk: VALID_JWK });

test('parseMachinePubkeyOutput: valid output → the P-256 JWK', () => {
  assert.deepEqual(parseMachinePubkeyOutput(VALID_STDOUT), VALID_JWK);
});

test('parseMachinePubkeyOutput: garbage / empty / wrong-shape → null', () => {
  assert.equal(parseMachinePubkeyOutput(''), null);
  assert.equal(parseMachinePubkeyOutput('not json'), null);
  assert.equal(parseMachinePubkeyOutput('{}'), null);
  assert.equal(
    parseMachinePubkeyOutput(JSON.stringify({ machine_se_pubkey_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'z' } })),
    null,
    'an Ed25519 key is not a valid machine SE key',
  );
  assert.equal(
    parseMachinePubkeyOutput(JSON.stringify({ machine_se_pubkey_jwk: { kty: 'EC', crv: 'P-256', x: 'AAAA' } })),
    null,
    'missing y',
  );
});

test('getMachineSePubkeyJwk: broker exits 0 with valid output → JWK', () => {
  const spawnImpl = (_bin, args) => {
    assert.deepEqual(args, ['machine-pubkey']);
    return { status: 0, stdout: VALID_STDOUT };
  };
  assert.deepEqual(
    getMachineSePubkeyJwk({ spawnImpl, brokerPath: '/fake/broker', platform: 'darwin' }),
    VALID_JWK,
  );
});

test('getMachineSePubkeyJwk: non-zero exit → null (legacy no-flag-day)', () => {
  const spawnImpl = () => ({ status: 1, stdout: '', stderr: 'machine-pubkey: ensure_key failed' });
  assert.equal(
    getMachineSePubkeyJwk({ spawnImpl, brokerPath: '/fake/broker', platform: 'darwin' }),
    null,
  );
});

test('getMachineSePubkeyJwk: spawn throws (ENOENT — no broker shipped) → null', () => {
  const spawnImpl = () => {
    throw Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' });
  };
  assert.equal(
    getMachineSePubkeyJwk({ spawnImpl, brokerPath: '/missing/broker', platform: 'darwin' }),
    null,
  );
});

test('getMachineSePubkeyJwk: non-macOS platform → null WITHOUT spawning (broker is macOS-only)', () => {
  let spawned = false;
  const spawnImpl = () => {
    spawned = true;
    return { status: 0, stdout: VALID_STDOUT };
  };
  assert.equal(
    getMachineSePubkeyJwk({ spawnImpl, brokerPath: '/fake/broker', platform: 'win32' }),
    null,
  );
  assert.equal(getMachineSePubkeyJwk({ spawnImpl, brokerPath: '/fake/broker', platform: 'linux' }), null);
  assert.equal(spawned, false, 'must not even attempt to spawn the broker off macOS');
});

test('resolveBrokerPath: env override wins; default points at the plugin native/ dir', () => {
  const prev = process.env.LASTID_AGENT_BROKER_BIN;
  process.env.LASTID_AGENT_BROKER_BIN = '/custom/broker';
  assert.equal(resolveBrokerPath(), '/custom/broker');
  delete process.env.LASTID_AGENT_BROKER_BIN;
  // The broker ships as a code-signed .app bundle; we exec the inner Mach-O.
  assert.match(
    resolveBrokerPath(),
    /[/\\]native[/\\]lastid-agent-broker\.app[/\\]Contents[/\\]MacOS[/\\]lastid-agent-broker$/,
  );
  if (prev !== undefined) process.env.LASTID_AGENT_BROKER_BIN = prev;
});

test('initiateProvisioning: includes machine_se_pubkey_jwk only when supplied', async () => {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    calls.push(JSON.parse(init.body));
    return { ok: true, json: async () => ({ user_code: 'AB-CD', device_code: 'dc' }) };
  };
  try {
    await initiateProvisioning({
      idpUrl: 'http://idp.test',
      ephemeralPubkeyJwk: VALID_JWK,
      machineSePubkeyJwk: VALID_JWK,
    });
    await initiateProvisioning({
      idpUrl: 'http://idp.test',
      ephemeralPubkeyJwk: VALID_JWK,
      // no machineSePubkeyJwk
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(calls[0].machine_se_pubkey_jwk, VALID_JWK, 'present when supplied');
  assert.equal('machine_se_pubkey_jwk' in calls[1], false, 'omitted when not supplied (legacy)');
});
