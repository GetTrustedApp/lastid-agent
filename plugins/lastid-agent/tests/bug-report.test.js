/**
 * Bug-report tool (lib/bug-report.js). The privacy guarantee is the headline:
 * the payload can carry ONLY operator-provided fields + the plugin version —
 * never identity or system data. These lock that, plus the POST behavior.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildBugReportPayload, submitBugReport, redactSecrets, BUG_REPORT_PATH } from '../lib/bug-report.js';

const ALLOWED_KEYS = new Set(['summary', 'source', 'details', 'email', 'plugin_version', 'redacted_count']);

test('buildBugReportPayload: ALLOWLIST — only operator fields + version, never identity/system', () => {
  // Even if a caller smuggles extra keys, none survive into the payload.
  const payload = buildBugReportPayload(
    {
      summary: 'agent crashed on claim',
      details: 'stack trace …',
      email: 'matt@example.com',
      // hostile extras that MUST NOT be forwarded:
      agent_did: 'did:lastid:agent:zLEAK',
      hostname: 'matts-mac',
      env: { TOKEN: 'secret' },
    },
    '0.10.2',
  );
  for (const k of Object.keys(payload)) {
    assert.ok(ALLOWED_KEYS.has(k), `payload leaked a disallowed key: ${k}`);
  }
  assert.equal(payload.source, 'lastid-agent');
  assert.equal(payload.summary, 'agent crashed on claim');
  assert.equal(payload.email, 'matt@example.com');
  assert.equal(payload.plugin_version, '0.10.2');
  assert.equal('agent_did' in payload, false);
  assert.equal('hostname' in payload, false);
  assert.equal('env' in payload, false);
});

test('buildBugReportPayload: omits empty details/email/version', () => {
  const p = buildBugReportPayload({ summary: 'x', details: '   ', email: '' }, null);
  assert.deepEqual(Object.keys(p).sort(), ['source', 'summary']);
});

test('buildBugReportPayload: requires a summary', () => {
  assert.throws(() => buildBugReportPayload({ details: 'no summary' }, '0.1.0'), /summary/);
  assert.throws(() => buildBugReportPayload({ summary: '   ' }, '0.1.0'), /summary/);
});

test('buildBugReportPayload: caps field lengths', () => {
  const p = buildBugReportPayload({ summary: 'a'.repeat(5000), details: 'b'.repeat(20000) }, null);
  assert.equal(p.summary.length, 2000);
  assert.equal(p.details.length, 8000);
});

test('submitBugReport: POSTs the payload to the IdP and returns the id', async () => {
  let seen = null;
  const okFetch = async (url, opts) => {
    seen = { url, body: JSON.parse(opts.body), method: opts.method };
    return { ok: true, status: 200, json: async () => ({ ok: true, id: 'bug_123' }) };
  };
  const r = await submitBugReport({
    idpUrl: 'https://human.test.lastid.co',
    report: { summary: 'boom', email: 'm@x.co' },
    version: '0.10.2',
    fetchImpl: okFetch,
  });
  assert.deepEqual(r, { ok: true, id: 'bug_123' });
  assert.equal(seen.method, 'POST');
  assert.equal(seen.url, `https://human.test.lastid.co${BUG_REPORT_PATH}`);
  assert.equal(seen.body.summary, 'boom');
  assert.equal(seen.body.source, 'lastid-agent');
  // No identity leaked over the wire.
  assert.equal('agent_did' in seen.body, false);
});

test('submitBugReport: throws on a non-2xx with the server reason', async () => {
  const failFetch = async () => ({ ok: false, status: 429, text: async () => 'rate limited' });
  await assert.rejects(
    submitBugReport({ idpUrl: 'https://idp.test', report: { summary: 'x' }, version: '0.1.0', fetchImpl: failFetch }),
    /rejected by server \(429\).*rate limited/,
  );
});

test('redactSecrets: scrubs known secret shapes, counts them, leaves clean text alone', () => {
  assert.deepEqual(redactSecrets('all good here'), { text: 'all good here', count: 0 });

  const jwt = redactSecrets('token was eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456');
  assert.match(jwt.text, /\[REDACTED JWT\]/);
  assert.equal(jwt.text.includes('eyJzdWIiOiIxIn0'), false);
  assert.ok(jwt.count >= 1);

  const labeled = redactSecrets('config: password=hunter2hunter');
  assert.equal(labeled.text, 'config: password=[REDACTED]');
  assert.equal(labeled.count, 1);

  const pem = redactSecrets('-----BEGIN EC PRIVATE KEY-----\nMHcCAQE...\n-----END EC PRIVATE KEY-----');
  assert.match(pem.text, /\[REDACTED PRIVATE KEY\]/);
  assert.equal(pem.text.includes('MHcCAQE'), false);
});

test('REGRESSION: a secret pasted into the report is scrubbed before it can be sent', () => {
  const payload = buildBugReportPayload(
    { summary: 'claim failed', details: 'curl -H "Authorization: Bearer sk-abcd1234efgh5678ijkl" failed' },
    '0.10.2',
  );
  assert.equal(payload.details.includes('sk-abcd1234efgh5678ijkl'), false, 'the sk- key must not survive');
  assert.match(payload.details, /\[REDACTED\]/);
  assert.ok(payload.redacted_count >= 1, 'redaction is reported so triage knows it was scrubbed');
  // Only allowlisted keys, even with redaction metadata.
  for (const k of Object.keys(payload)) assert.ok(ALLOWED_KEYS.has(k), `leaked key: ${k}`);
});

test('submitBugReport: a missing summary never reaches the network', async () => {
  let called = false;
  const spy = async () => ((called = true), { ok: true, status: 200, json: async () => ({}) });
  await assert.rejects(
    submitBugReport({ idpUrl: 'https://idp.test', report: { details: 'no summary' }, fetchImpl: spy }),
    /summary/,
  );
  assert.equal(called, false, 'must validate before posting');
});
