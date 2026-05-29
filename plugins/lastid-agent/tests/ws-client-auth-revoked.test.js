/**
 * ws-client `isRevocationResponse` — the classifier that drives the
 * "stop reconnecting forever, this credential is dead" behavior on the
 * WS upgrade response. The motivation: a stale listener
 * (dev-testy-mctestface, attempt #871 observed live 2026-05-29) was
 * hammering prod /v1/ws with a revoked VC after an edit-caps
 * revoke+reissue cycle orphaned its scope.
 *
 * The pure classifier is the load-bearing logic; the surrounding ws
 * event wiring (attach `unexpected-response` → read body → call
 * onAuthRevoked → process.exit) is mechanical Node EventEmitter glue
 * that we validate via live observability, not unit tests.
 *
 * Match criteria — MUST match EXACTLY, no broader:
 *   - HTTP status === 401
 *   - body is JSON with `error: 'invalid_token'`
 *   - body's `error_description` contains (case-insensitive)
 *     "credential has been revoked"
 *
 * Any deviation (different status, different error code, non-JSON body,
 * "revoked" appearing in a non-description context) MUST return false
 * so the normal reconnect-with-backoff path runs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { isRevocationResponse } from '../lib/ws-client.js';

test('isRevocationResponse: HAPPY — exact IdP-emitted shape returns true', () => {
  const body = JSON.stringify({
    error: 'invalid_token',
    error_description: 'Credential has been revoked',
  });
  assert.equal(isRevocationResponse(401, body), true);
});

test('isRevocationResponse: case-insensitive on the description', () => {
  // The IdP wrapper might recase the description in future. The
  // classifier should still catch it.
  for (const desc of [
    'Credential has been revoked',
    'credential has been revoked',
    'CREDENTIAL HAS BEEN REVOKED',
    'Credential has  been  revoked', // extra whitespace
  ]) {
    const body = JSON.stringify({ error: 'invalid_token', error_description: desc });
    assert.equal(isRevocationResponse(401, body), true, `failed for: ${desc}`);
  }
});

test('isRevocationResponse: tolerates extra description context (substring match)', () => {
  // A future IdP rewording like "Credential has been revoked at
  // 2026-05-29..." should still trip; substring (not equality).
  const body = JSON.stringify({
    error: 'invalid_token',
    error_description: 'Credential has been revoked at 2026-05-29T12:33Z',
  });
  assert.equal(isRevocationResponse(401, body), true);
});

test('isRevocationResponse: non-401 status NEVER trips, even with matching body', () => {
  // The IdP would never emit this combo, but defense in depth — only
  // 401 + revoke description should fire scope cleanup.
  const body = JSON.stringify({
    error: 'invalid_token',
    error_description: 'Credential has been revoked',
  });
  for (const status of [200, 400, 403, 500, 503, 0]) {
    assert.equal(isRevocationResponse(status, body), false, `failed for status=${status}`);
  }
});

test('isRevocationResponse: transient 401 with different error code does NOT trip', () => {
  // Clock-skew / DPoP JTI replay produces invalid_dpop_proof, NOT
  // invalid_token. Must let the normal reconnect path run.
  for (const code of ['invalid_dpop_proof', 'invalid_request', 'insufficient_scope']) {
    const body = JSON.stringify({
      error: code,
      error_description: 'iat outside acceptance window',
    });
    assert.equal(isRevocationResponse(401, body), false, `failed for code=${code}`);
  }
});

test('isRevocationResponse: 401 mentioning "revoked" in a non-description field does NOT trip', () => {
  // The match is anchored to error_description specifically. A
  // wrong-error-code body that happens to mention revocation
  // elsewhere should not tear down a scope.
  const body = JSON.stringify({
    error: 'wrong_audience',
    error_description: 'audience mismatch',
    hint: 'note: revoked sessions are not allowed here',
  });
  assert.equal(isRevocationResponse(401, body), false);
});

test('isRevocationResponse: non-JSON body returns false (proxy-injected HTML, etc.)', () => {
  assert.equal(isRevocationResponse(401, '<html>401 Unauthorized</html>'), false);
  assert.equal(isRevocationResponse(401, ''), false);
  assert.equal(isRevocationResponse(401, 'not json at all'), false);
});

test('isRevocationResponse: empty / non-string body inputs return false (defensive)', () => {
  // @ts-expect-error — passing non-string is the defensive path
  assert.equal(isRevocationResponse(401, null), false);
  // @ts-expect-error
  assert.equal(isRevocationResponse(401, undefined), false);
  // @ts-expect-error
  assert.equal(isRevocationResponse(401, 42), false);
});

test('isRevocationResponse: missing error_description does NOT trip even with matching code', () => {
  const body = JSON.stringify({ error: 'invalid_token' });
  assert.equal(isRevocationResponse(401, body), false);
});

test('isRevocationResponse: missing error code does NOT trip even with revoke wording', () => {
  const body = JSON.stringify({
    error_description: 'Credential has been revoked',
  });
  assert.equal(isRevocationResponse(401, body), false);
});
