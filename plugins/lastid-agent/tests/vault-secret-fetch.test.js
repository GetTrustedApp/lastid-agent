/**
 * Regression: the JIT credential-release call (POST
 * /v1/agent-state/vault/:id/secret) MUST emit a DPoP whose `alg` matches
 * the agent's actual signing key — EdDSA for Ed25519 agents, ES256 for
 * P-256 agents. The IdP rejects mismatches with
 *   `agent_pop: header.alg must be 'EdDSA' for a Ed25519 cnf.jwk, got 'ES256'`
 * and the listener surfaces that as `secret_unavailable`, which manifests
 * to the operator as a vault_handle that mints fine but releases nothing.
 *
 * This exercises the same dual-algo contract `dpop.test.js` proves for the
 * helper, but at this consumer's exact boundary — so a future regression
 * that bypasses `mintDpopJwt` (e.g. re-introduces a single-alg WASM call)
 * is caught here too.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { fetchWrappedVaultSecret } from '../lib/vault-secret-fetch.js';

function decodeJwtHeader(jwt) {
  const headB64 = jwt.split('.')[0];
  const padded = headB64 + '='.repeat((4 - (headB64.length % 4)) % 4);
  return JSON.parse(
    Buffer.from(
      padded.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    ).toString('utf-8'),
  );
}

function fetchStub(captured) {
  return async (_url, init) => {
    captured.headers = init?.headers ?? {};
    return {
      status: 200,
      ok: true,
      async json() {
        return { wrapped_secret_b64: 'WRAP' };
      },
      async text() {
        return '';
      },
    };
  };
}

test('fetchWrappedVaultSecret signs DPoP EdDSA for an Ed25519 signingKey', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const captured = {};
  await fetchWrappedVaultSecret({
    idpUrl: 'https://idp.example.com',
    agentDid: 'did:lastid:agent:z6MkEdRegression',
    vcCompact: 'vc.compact.stub',
    signingKey: privateKey,
    id: 'vault_1',
    handlePubB64: 'PUBKEY',
    handleId: 'h-1',
    fetchImpl: fetchStub(captured),
  });
  assert.ok(captured.headers?.DPoP, 'expected DPoP header on outbound POST');
  assert.equal(decodeJwtHeader(captured.headers.DPoP).alg, 'EdDSA');
});

test('fetchWrappedVaultSecret signs DPoP ES256 for a P-256 signingKey', async () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const captured = {};
  await fetchWrappedVaultSecret({
    idpUrl: 'https://idp.example.com',
    agentDid: 'did:lastid:agent:zDnRegression',
    vcCompact: 'vc.compact.stub',
    signingKey: privateKey,
    id: 'vault_1',
    handlePubB64: 'PUBKEY',
    handleId: 'h-1',
    fetchImpl: fetchStub(captured),
  });
  assert.equal(decodeJwtHeader(captured.headers.DPoP).alg, 'ES256');
});

// REGRESSION — broker-native (ES256) agent's JIT secret fetch died because it
// threw on a null signingKey (no seed in node by custody design); the broker
// covers the DPoP via authedIdpFetch and the returned secret's slot-unseal is
// already broker-wired in vault-cache.js decryptVaultEnvelope. The fetch must
// REACH authedIdpFetch with a null signingKey, not throw at the guard.
test('fetchWrappedVaultSecret: broker-native (null signingKey) reaches authedIdpFetch and returns the secret', async () => {
  let reached = null;
  const secret = await fetchWrappedVaultSecret({
    idpUrl: 'https://idp.example.com',
    agentDid: 'did:lastid:agent:zDnBrokerNative',
    vcCompact: 'vc.compact.stub',
    signingKey: null, // broker-native: no key in node
    id: 'vault_1',
    handlePubB64: 'PUBKEY',
    handleId: 'h-1',
    _authedIdpFetch: async (opts) => { reached = opts; return { wrapped_secret_b64: 'WRAP' }; },
  });
  assert.equal(secret, 'WRAP', 'returned the wrapped secret via the broker path');
  assert.ok(reached, 'authedIdpFetch WAS called (did not bail on null signingKey)');
  assert.equal(reached.signingKey, null);
  assert.ok(reached.path.includes('/vault/'));
});

test('fetchWrappedVaultSecret: missing vcCompact still throws WITHOUT calling authedIdpFetch (no regression)', async () => {
  let called = false;
  await assert.rejects(
    fetchWrappedVaultSecret({
      idpUrl: 'https://idp.example.com',
      agentDid: 'did:lastid:agent:zX',
      vcCompact: '', // missing VC → throws before the fetch
      signingKey: null,
      id: 'vault_1',
      handlePubB64: 'PUBKEY',
      handleId: 'h-1',
      _authedIdpFetch: async () => { called = true; return {}; },
    }),
    /no agent VC/,
  );
  assert.equal(called, false, 'never reached the IdP call');
});

test('fetchWrappedVaultSecret: legacy path unchanged — a real signingKey reaches authedIdpFetch', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  let reached = null;
  await fetchWrappedVaultSecret({
    idpUrl: 'https://idp.example.com',
    agentDid: 'did:lastid:agent:z6MkLegacy',
    vcCompact: 'vc.compact.stub',
    signingKey: privateKey,
    id: 'vault_1',
    handlePubB64: 'PUBKEY',
    handleId: 'h-1',
    _authedIdpFetch: async (opts) => { reached = opts; return { wrapped_secret_b64: 'WRAP' }; },
  });
  assert.equal(reached.signingKey, privateKey, 'legacy signingKey forwarded unchanged');
});

test('fetchWrappedVaultSecret returns null on 404 (revoked / not shared / wrong agent)', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const r = await fetchWrappedVaultSecret({
    idpUrl: 'https://idp.example.com',
    agentDid: 'did:lastid:agent:zED',
    vcCompact: 'vc.compact.stub',
    signingKey: privateKey,
    id: 'vault_1',
    handlePubB64: 'PUBKEY',
    handleId: 'h-1',
    fetchImpl: async () => ({ status: 404, ok: false, async text() { return ''; } }),
  });
  assert.equal(r, null);
});
