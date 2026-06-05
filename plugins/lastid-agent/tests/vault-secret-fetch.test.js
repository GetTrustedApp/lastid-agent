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

test('fetchWrappedVaultSecret throws a clear error when signingKey is missing', async () => {
  await assert.rejects(
    fetchWrappedVaultSecret({
      idpUrl: 'https://idp.example.com',
      agentDid: 'did:lastid:agent:zX',
      vcCompact: 'vc.compact.stub',
      id: 'vault_1',
      handlePubB64: 'PUBKEY',
      handleId: 'h-1',
      fetchImpl: fetchStub({}),
    }),
    /no signingKey/,
  );
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
