/**
 * exchangeClientCredentials (lib/oauth-exchange.js) — the listener mints a fresh
 * access token from the sealed client_secret at use-time (we never store a
 * minted token; it would go stale). Must POST the standard client_credentials
 * form, return the access_token, and throw LOUD on any failure (so a broken
 * exchange surfaces as an error, never a silently un-credentialed call).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { exchangeClientCredentials } from '../lib/oauth-exchange.js';

function fetchStub(impl) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return impl(url, opts);
  };
  fn.calls = calls;
  return fn;
}

test('posts the client_credentials form and returns the access_token', async () => {
  const fetchImpl = fetchStub(async () => ({ status: 200, json: async () => ({ access_token: 'AT-123', token_type: 'Bearer' }) }));
  const tok = await exchangeClientCredentials(
    { tokenEndpoint: 'https://idp.example.com/oauth/token', clientId: 'cid', clientSecret: 'csecret', scope: 'read write' },
    fetchImpl,
  );
  assert.equal(tok, 'AT-123');
  const { url, opts } = fetchImpl.calls[0];
  assert.equal(url, 'https://idp.example.com/oauth/token');
  assert.equal(opts.method, 'POST');
  assert.match(opts.headers['Content-Type'], /application\/x-www-form-urlencoded/);
  const body = new URLSearchParams(opts.body);
  assert.equal(body.get('grant_type'), 'client_credentials');
  assert.equal(body.get('client_id'), 'cid');
  assert.equal(body.get('client_secret'), 'csecret');
  assert.equal(body.get('scope'), 'read write');
});

test('omits scope when not provided', async () => {
  const fetchImpl = fetchStub(async () => ({ status: 200, json: async () => ({ access_token: 'AT' }) }));
  await exchangeClientCredentials({ tokenEndpoint: 'https://t', clientId: 'c', clientSecret: 's' }, fetchImpl);
  assert.equal(new URLSearchParams(fetchImpl.calls[0].opts.body).has('scope'), false);
});

test('throws when required fields are missing (no fetch attempted)', async () => {
  const fetchImpl = fetchStub(async () => ({ status: 200, json: async () => ({ access_token: 'AT' }) }));
  await assert.rejects(
    () => exchangeClientCredentials({ tokenEndpoint: 'https://t', clientId: 'c' /* no secret */ }, fetchImpl),
    /needs token_endpoint, client_id, and client_secret/,
  );
  assert.equal(fetchImpl.calls.length, 0);
});

test('throws on a non-2xx response, surfacing the provider error', async () => {
  const fetchImpl = fetchStub(async () => ({ status: 401, json: async () => ({ error: 'invalid_client', error_description: 'bad secret' }) }));
  await assert.rejects(
    () => exchangeClientCredentials({ tokenEndpoint: 'https://t', clientId: 'c', clientSecret: 's' }, fetchImpl),
    /token exchange failed: bad secret/,
  );
});

test('throws when the body carries no access_token', async () => {
  const fetchImpl = fetchStub(async () => ({ status: 200, json: async () => ({ token_type: 'Bearer' }) }));
  await assert.rejects(
    () => exchangeClientCredentials({ tokenEndpoint: 'https://t', clientId: 'c', clientSecret: 's' }, fetchImpl),
    /token exchange failed/,
  );
});

test('throws when the token endpoint is unreachable', async () => {
  const fetchImpl = async () => {
    throw new Error('ECONNREFUSED');
  };
  await assert.rejects(
    () => exchangeClientCredentials({ tokenEndpoint: 'https://t', clientId: 'c', clientSecret: 's' }, fetchImpl),
    /token endpoint unreachable: ECONNREFUSED/,
  );
});
